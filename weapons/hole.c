/*
 * Xury — No-Server P2P NAT Traversal Engine (Repo: Xury)
 * Copyright (C) 2026 ASBM Team
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * ============================================================================
 * XURY WEAPONS — HOLE PUNCH (Phase H, weapon 6/7)
 * ============================================================================
 *
 * Real implementation of weapons/internal/hole.h.
 *
 * Sends XHOL punch packets toward ctx->peer at a steady interval
 * while listening on the same socket for XHOL packets from that
 * peer. When both sides run this code at the same time, each side's
 * NAT opens an outbound mapping; an inbound packet from the peer can
 * then cross that mapping, and the two sides observe each other.
 *
 * ----------------------------------------------------------------------------
 * The XHOL protocol
 * ----------------------------------------------------------------------------
 *
 * A single packet type, exactly four bytes:
 *
 *   offset  size  field
 *   0       4     magic   "XHOL"
 *
 * There is no nonce, no type field, and no payload. The four magic
 * bytes identify the packet as an Xury punch. A packet that begins
 * with these four bytes and arrives from ctx->peer is accepted.
 *
 * Why no nonce:
 *   The XPRB protocol in scan/probing.c uses a nonce so that a
 *   response can be correlated to a request. HOLE is not a request/
 *   response exchange: each side sends punches independently, and
 *   neither side is responding to a specific request. A nonce would
 *   have no one to verify it. Adding one would suggest a security
 *   property that the protocol does not provide. See the file header
 *   of probing.h for the XPRB contract, and the HOLE audit in
 *   docs/ for why the format was reduced to magic only.
 *
 * Why no type field:
 *   There is only one packet type. A type discriminator with a single
 *   value would be an invented field with no consumer.
 *
 * Security note:
 *   The magic bytes are a marker, not a cryptographic mechanism. Any
 *   host that knows the peer's endpoint and sends a four-byte
 *   "XHOL" packet would be accepted. This matches the trust model
 *   of every Phase H weapon: the caller supplies the peer, and the
 *   caller is responsible for knowing who that peer is.
 *
 * ----------------------------------------------------------------------------
 * What success means
 * ----------------------------------------------------------------------------
 *
 * Success means: a valid XHOL packet was received from ctx->peer
 * during the attempt window. This proves observed inbound
 * reachability for this attempt.
 *
 * It does NOT prove:
 *   - that the NAT mapping will remain open indefinitely,
 *   - that a transport connection can be established,
 *   - that traversal will succeed for any subsequent attempt.
 *
 * The mapping may close as soon as this function returns. The
 * caller (blitz/race.c) is responsible for acting on the result
 * before that happens.
 *
 * ----------------------------------------------------------------------------
 * Send interval
 * ----------------------------------------------------------------------------
 *
 * XHOL_SEND_INTERVAL_MS is a provisional implementation parameter,
 * not a scientifically derived threshold. Xury's repository does not
 * define a retry cadence for NAT traversal:
 *
 *   - upnp.c's SSDP MX is defined by the UPnP specification, not
 *     chosen by Xury.
 *   - natpmp.c and pcp.c use a single request/response exchange
 *     with a total timeout; they do not retry.
 *   - probing.c sends its samples back to back, with no delay.
 *   - ipv6.c and mirror.c send a single probe.
 *
 * HOLE is the first weapon that needs repeated sends without a
 * response. Since no existing convention applies, the value is a
 * named constant so it can be tuned later against real measurement.
 * It is NOT claimed to be optimal, and it is NOT claimed to be
 * conservative. A future revision may replace it with a measured
 * value, or may derive it from ctx->timeout_ms if the measurement
 * supports that.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - Does not contact any server. Xury is no-server.
 *
 *   - Does not coordinate with the peer through any third party.
 *     Both sides run this same code independently. There is no
 *     signaling channel, because a signaling channel would require a
 *     server.
 *
 *   - Does not create a transport connection. It sends and receives
 *     small UDP punch packets. The caller gets a socket that has
 *     observed the peer, not a connected session.
 *
 *   - Does not maintain state across calls. Each call creates a
 *     fresh socket, sends punches for the duration of ctx->timeout_ms,
 *     and closes the socket.
 *
 *   - Does not use ctx->local_port. HOLE exposes no local service;
 *     see the local_port note in weapon_ops.h.
 *
 * ----------------------------------------------------------------------------
 * Dependencies (per docs/DEPENDENCY.md, "What weapons/ may include")
 * ----------------------------------------------------------------------------
 *
 *   core/internal/sock.h            UDP socket primitives
 *   platform/platform.h             monotonic time, sleep
 *   weapons/internal/weapon_ops.h   the weapon contract
 *   weapons/internal/hole.h         this weapon's entry point
 *
 * No allocation, no global state.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/types.h>
#include <xury/err.h>

#include "core/internal/sock.h"
#include "platform/platform.h"

#include "weapons/internal/weapon_ops.h"
#include "weapons/internal/hole.h"

/*
 * ============================================================================
 * CONSTANTS
 * ============================================================================
 */

/*
 * The XHOL magic bytes. Four bytes, the entire packet.
 *
 * 'X' 'H' 'O' 'L'
 */
static const uint8_t XHOL_MAGIC[4] = {
    0x58u, 0x48u, 0x4Fu, 0x4Cu
};

/*
 * XHOL packet size. The whole packet is the magic.
 */
#define XHOL_PACKET_SIZE 4u

/*
 * Send interval between punch packets, in milliseconds.
 *
 * PROVISIONAL / TUNABLE. See the "Send interval" section in the
 * file header. This value is not derived from measurement, is not
 * claimed to be optimal, and is not claimed to be conservative.
 * It is a named constant so that a future revision can replace it
 * with a measured value without touching the rest of the code.
 */
#define XHOL_SEND_INTERVAL_MS 200u

/*
 * Receive buffer. Larger than XHOL_PACKET_SIZE so that an unexpected
 * larger datagram can be received without truncation, then discarded
 * by the length check in the accept test.
 */
#define XHOL_RECV_CAP 64u

/*
 * ============================================================================
 * INTERNAL — PEER VALIDATION
 * ============================================================================
 */

/*
 * True if the peer endpoint is usable as a punch target.
 *
 * Both IPv4 and IPv6 are accepted; the family determines the socket
 * family. An unusable peer is a programming error (XURY_ERR_INVAL),
 * not a real-world failure.
 */
static bool peer_usable(const xury_endpoint_t *peer)
{
    if (peer == NULL) {
        return false;
    }
    if (peer->family != XURY_AF_INET && peer->family != XURY_AF_INET6) {
        return false;
    }
    if (peer->ip[0] == '\0') {
        return false;
    }
    if (peer->port == 0u) {
        return false;
    }
    return true;
}

/*
 * ============================================================================
 * INTERNAL — PACKET CHECK
 * ============================================================================
 */

/*
 * True if buf[0..len) is a valid XHOL packet.
 *
 * The entire check is the four magic bytes. There is no nonce to
 * verify and no type to check. See the file header for why the
 * packet is this small.
 */
static bool is_xhol_packet(const uint8_t *buf, size_t len)
{
    if (buf == NULL) {
        return false;
    }
    if (len < XHOL_PACKET_SIZE) {
        return false;
    }
    return memcmp(buf, XHOL_MAGIC, XHOL_PACKET_SIZE) == 0;
}

/*
 * ============================================================================
 * INTERNAL — SEND ONE PUNCH
 * ============================================================================
 */

/*
 * Send a single XHOL packet to peer.
 *
 * Returns XURY_OK on success, or the platform error from sendto.
 * A short send is reported as XURY_ERR_PARTIAL_WRITE by
 * xury_sock_sendto; for a four-byte UDP datagram, a short send is
 * not expected, and the caller treats it as a transport error.
 */
static xury_err_t send_punch(xury_sock_t s,
                             const xury_endpoint_t *peer)
{
    size_t sent = 0u;
    xury_err_t rc = xury_sock_sendto(s, XHOL_MAGIC, XHOL_PACKET_SIZE,
                                     peer, &sent);
    if (rc != XURY_OK) {
        return rc;
    }
    if (sent != XHOL_PACKET_SIZE) {
        return XURY_ERR_PARTIAL_WRITE;
    }
    return XURY_OK;
}

/*
 * ============================================================================
 * INTERNAL — CHECK FOR INCOMING PUNCH
 * ============================================================================
 *
 * Polls the socket with zero timeout. If an XHOL packet from the
 * expected peer is present, returns XURY_OK with *out_got set to
 * true. If no packet is ready, returns XURY_OK with *out_got set to
 * false. Any other result is a transport error.
 *
 * Datagrams that do not carry the XHOL magic, or that come from a
 * different address than the peer, are discarded and the function
 * returns with *out_got = false. The main loop will send another
 * punch and poll again.
 */

static xury_err_t check_incoming(xury_sock_t s,
                                 const xury_endpoint_t *peer,
                                 bool *out_got)
{
    *out_got = false;

    uint8_t buf[XHOL_RECV_CAP];
    xury_endpoint_t from;
    size_t recvd = 0u;

    xury_err_t rc = xury_sock_recvfrom(s, buf, sizeof(buf),
                                       &from, &recvd, 0u);
    if (rc == XURY_ERR_TIMEOUT || rc == XURY_ERR_WOULD_BLOCK) {
        return XURY_OK;   /* nothing ready right now */
    }
    if (rc != XURY_OK) {
        return rc;
    }

    /*
     * Source check: the packet must come from the peer we are
     * punching toward. A packet from anywhere else is discarded.
     *
     * The source port is not checked. A NAT may rewrite the peer's
     * source port; a symmetric NAT on the peer's side may present a
     * different port than the endpoint the caller supplied. The
     * source IP is the meaningful check here.
     */
    if (from.family != peer->family) {
        return XURY_OK;
    }
    if (strcmp(from.ip, peer->ip) != 0) {
        return XURY_OK;
    }

    if (!is_xhol_packet(buf, recvd)) {
        return XURY_OK;
    }

    *out_got = true;
    return XURY_OK;
}

/*
 * ============================================================================
 * PUBLIC ENTRY POINT
 * ============================================================================
 */

xury_err_t xury_weapon_hole_try(const xury_weapon_attempt_ctx_t *ctx,
                                xury_weapon_attempt_result_t *out)
{
    /*
     * ------------------------------------------------------------------
     * Argument validation
     * ------------------------------------------------------------------
     */
    if (ctx == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (!peer_usable(&ctx->peer)) {
        return XURY_ERR_INVAL;
    }

    memset(out, 0, sizeof(*out));

    /*
     * ------------------------------------------------------------------
     * Fast-path applicability rejection
     * ------------------------------------------------------------------
     */
    if (!ctx->applicability_ctx.peer_reachable &&
        !ctx->applicability_ctx.helper_available) {
        /*
         * No peer to punch toward. This is not an error; the
         * selection layer decided that HOLE cannot be attempted,
         * or the caller passed a context that says so.
         *
         * Note: HOLE does not require helper_available to succeed,
         * but the applicability rules treat "no peer at all" as
         * disqualifying. The check here mirrors
         * xury_weapon_applicable() for XURY_WEAPON_HOLE.
         */
        return XURY_OK;   /* success = false, elapsed_ms = 0 */
    }

    uint64_t t0 = xury_platform_time_ms();

    /*
     * ------------------------------------------------------------------
     * Create and bind a UDP socket in the peer's family.
     * ------------------------------------------------------------------
     */
    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = xury_sock_create(ctx->peer.family, XURY_SOCK_UDP, &s);
    if (rc != XURY_OK) {
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;   /* platform refused; real-world failure */
    }

    xury_endpoint_t bind_ep;
    memset(&bind_ep, 0, sizeof(bind_ep));
    bind_ep.family = ctx->peer.family;
    bind_ep.port = 0u;
    /*
     * Wildcard bind. For IPv4 the literal "0.0.0.0" is required —
     * inet_pton rejects an empty string. For IPv6 the literal "::"
     * is required for the same reason.
     */
    if (ctx->peer.family == XURY_AF_INET) {
        bind_ep.ip[0] = '0'; bind_ep.ip[1] = '.'; bind_ep.ip[2] = '0';
        bind_ep.ip[3] = '.'; bind_ep.ip[4] = '0'; bind_ep.ip[5] = '.';
        bind_ep.ip[6] = '0'; bind_ep.ip[7] = '\0';
    } else {
        bind_ep.ip[0] = ':'; bind_ep.ip[1] = ':'; bind_ep.ip[2] = '\0';
    }

    rc = xury_sock_bind(s, &bind_ep);
    if (rc != XURY_OK) {
        (void)xury_sock_close(s);
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;
    }

    /*
     * ------------------------------------------------------------------
     * Punch loop
     * ------------------------------------------------------------------
     *
     * Until the deadline:
     *   1. Send one XHOL punch toward the peer.
     *   2. Poll for an incoming XHOL packet from the peer.
     *   3. If one arrived, mark success and exit.
     *   4. Otherwise sleep for XHOL_SEND_INTERVAL_MS, minus the
     *      time already spent, and loop.
     *
     * ctx->timeout_ms == 0 means "no deadline". In that case the
     * loop runs until a punch is observed. The caller controls the
     * upper bound; a zero timeout here is the caller's choice, not
     * a default.
     */
    bool got_punch = false;
    uint64_t deadline_ms = 0u;
    if (ctx->timeout_ms != 0u) {
        deadline_ms = t0 + (uint64_t)ctx->timeout_ms;
    }

    for (;;) {
        rc = send_punch(s, &ctx->peer);
        if (rc != XURY_OK) {
            /*
             * A send failure is a transport error. It is not a
             * programming error, but it means the attempt cannot
             * continue. We report an honest failure; the caller
             * decides whether to retry or fall through.
             */
            (void)xury_sock_close(s);
            out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
            return XURY_OK;
        }

        rc = check_incoming(s, &ctx->peer, &got_punch);
        if (rc != XURY_OK) {
            (void)xury_sock_close(s);
            out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
            return XURY_OK;
        }
        if (got_punch) {
            break;
        }

        if (deadline_ms != 0u) {
            uint64_t now = xury_platform_time_ms();
            if (now >= deadline_ms) {
                break;
            }
            uint64_t remaining = deadline_ms - now;
            if (remaining > XHOL_SEND_INTERVAL_MS) {
                remaining = XHOL_SEND_INTERVAL_MS;
            }
            if (remaining > 0u) {
                xury_platform_sleep_ms((uint32_t)remaining);
            }
        } else {
            xury_platform_sleep_ms(XHOL_SEND_INTERVAL_MS);
        }
    }

    (void)xury_sock_close(s);

    out->success = got_punch;
    if (got_punch) {
        /*
         * Success means an XHOL packet arrived from the peer. It
         * proves observed inbound reachability for this attempt; it
         * is not a claim that the mapping will remain open. See the
         * file header for the full semantics.
         */
        out->established_peer = ctx->peer;
    }
    out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
    return XURY_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
