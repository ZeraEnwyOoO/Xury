 
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
 * XURY WEAPONS — IPV6 DIRECT (Phase H, weapon 1/7)
 * ============================================================================
 *
 * Implements xury_weapon_ipv6_try() from weapons/internal/weapon_ops.h.
 *
 * Goal: confirm reachability of ctx->peer over IPv6 by sending one
 * UDP probe and waiting for any reply within ctx->timeout_ms.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - Does not contact any server. Xury is no-server.
 *
 *   - Does not embed any address. ctx->peer is caller-supplied;
 *     this file never constructs an endpoint literal.
 *
 *   - Does not resolve hostnames. ctx->peer.ip must already be a
 *     textual IPv6 address.
 *
 *   - Does not select among multiple addresses. One peer, one try.
 *
 *   - Does not establish a transport connection. Success means
 *     "peer replied to a probe", not "TCP/UDP session is open".
 *     Transport handoff is the host's responsibility (see
 *     docs/AI_CONTEXT.md, "What Xury is NOT").
 *
 *   - Does not measure RTT distribution, classify NAT, or score.
 *     Those are scan/ and analysis/ concerns.
 *
 * ----------------------------------------------------------------------------
 * Return-code convention
 * ----------------------------------------------------------------------------
 *
 * This file follows the Phase H weapon return-code convention
 * documented in weapon_ops.h:
 *
 *   XURY_ERR_INVAL  — programming error: NULL ctx, NULL out, bad
 *                     family, unset peer.
 *
 *   XURY_OK         — the attempt ran. Whether it succeeded is in
 *                     out->success. Real-world network outcomes
 *                     (no route to the peer, no reply within the
 *                     timeout) are encoded in the result struct,
 *                     not in the return code.
 *
 *   other errors    — a genuine platform failure that prevented
 *                     the attempt from running at all: socket
 *                     creation, socket binding, or a malformed
 *                     endpoint the platform refused to encode.
 *
 * A send failure is classified by asking: "did the probe leave
 * the local host?" If the platform reports "no route" or "host
 * unreachable" or "network unreachable", the probe could not be
 * sent because the network itself could not carry it — a
 * real-world outcome, not a programming error, not a platform
 * malfunction. The attempt is reported as success = false. If the
 * platform reports a malformed endpoint, that is a programming
 * error and is surfaced as XURY_ERR_INVAL. If the platform reports
 * a genuine I/O failure (closed socket, out of memory), that is a
 * platform failure and is surfaced as the corresponding error.
 *
 * ----------------------------------------------------------------------------
 * Dependencies (per docs/DEPENDENCY.md, "What weapons/ may include")
 * ----------------------------------------------------------------------------
 *
 *   platform/platform.h             sockets, monotonic time
 *   xury/types.h                    xury_endpoint_t, xury_family_t
 *   xury/err.h                      xury_err_t
 *   weapons/internal/weapon_ops.h   the contract implemented here
 *
 * Deliberately NOT included:
 *   - core/sock.h  (scan/probing.c calls the platform layer directly;
 *     this file matches that pattern so a single convention exists
 *     for "send a UDP datagram and wait for a reply")
 *   - scan/, analysis/, smart/, blitz/, engine/  (wrong layer)
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

#include "platform/platform.h"
#include "weapons/internal/weapon_ops.h"

/*
 * ============================================================================
 * PROBE PAYLOAD
 * ============================================================================
 *
 * A single-byte payload. The content is deliberately minimal: the
 * peer's cooperation contract is "reply to any datagram you receive
 * on the probe port", which is the same contract scan/probing.c
 * establishes with its XPRB REQUEST. We do not reuse XPRB here
 * because ipv6.c is not a probing exchange — it is a single
 * reachability check, and inventing a second wire format with the
 * same name would be misleading.
 *
 * If, later, blitz/race.c wants weapons to share a wire format, the
 * change belongs in weapon_ops.h as an explicit decision, not
 * smuggled into one weapon's .c file.
 */
#define XURY_IPV6_PROBE_BYTE  0x00u

/*
 * Receive buffer size. Large enough for any plausible reply, small
 * enough to stay on the stack. The reply's content is not
 * interpreted — only its arrival matters.
 */
#define XURY_IPV6_RECV_CAP    64u

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

/*
 * True if the endpoint is a usable IPv6 target:
 *   - family is XURY_AF_INET6
 *   - ip string is non-empty
 *   - port is non-zero
 *
 * Does not validate the address text itself. platform_sock_sendto()
 * will fail with XURY_ERR_BAD_ENDPOINT if the text is malformed,
 * and that error propagates as a real error (not a silent failure).
 */
static bool ipv6_peer_usable(const xury_endpoint_t *ep)
{
    if (ep == NULL) {
        return false;
    }
    if (ep->family != XURY_AF_INET6) {
        return false;
    }
    if (ep->ip[0] == '\0') {
        return false;
    }
    if (ep->port == 0u) {
        return false;
    }
    return true;
}

/*
 * True if the error code represents a real-world network outcome
 * that should be encoded as success = false in the result struct,
 * rather than propagated as an error return.
 *
 * The classification is deliberately conservative. Only errors
 * that clearly describe "the network could not carry this packet"
 * are treated as real-world outcomes. Everything else propagates.
 *
 *   XURY_ERR_NET_UNREACHABLE   — no route to the peer's network
 *   XURY_ERR_HOST_UNREACHABLE  — no route to the peer's host
 *   XURY_ERR_NO_ROUTE          — no route at all
 *   XURY_ERR_NETWORK... (future codes go here)
 *
 * XURY_ERR_TIMEOUT is not in this list because recvfrom already
 * returns it as a distinct "no reply" outcome and the call site
 * handles it explicitly.
 *
 * XURY_ERR_BAD_ENDPOINT is not in this list: a malformed endpoint
 * is a programming error (the caller supplied bad text), not a
 * network outcome.
 */
static bool is_real_world_send_error(xury_err_t rc)
{
    switch (rc) {
    case XURY_ERR_NET_UNREACHABLE:
    case XURY_ERR_HOST_UNREACHABLE:
    case XURY_ERR_NO_ROUTE:
        return true;
    default:
        return false;
    }
}

/*
 * ============================================================================
 * PUBLIC ENTRY POINT
 * ============================================================================
 */

xury_err_t xury_weapon_ipv6_try(const xury_weapon_attempt_ctx_t *ctx,
                                xury_weapon_attempt_result_t *out)
{
    /*
     * ------------------------------------------------------------------
     * Argument validation
     * ------------------------------------------------------------------
     *
     * These are programming errors, not network outcomes. They map to
     * XURY_ERR_INVAL, matching the convention in scan/probing.c.
     */
    if (ctx == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (!ipv6_peer_usable(&ctx->peer)) {
        return XURY_ERR_INVAL;
    }

    /*
     * Zero the result first, so that any early return below leaves
     * the caller with a well-defined "nothing happened" struct.
     */
    memset(out, 0, sizeof(*out));

    /*
     * ------------------------------------------------------------------
     * Fast-path applicability rejection
     * ------------------------------------------------------------------
     *
     * If the selection layer already knows there is no global IPv6
     * on this host, or the peer did not answer on IPv6 during the
     * scan, there is no point spending a round trip. Report an
     * honest "did not succeed" with elapsed_ms = 0.
     *
     * This is XURY_OK, not an error: the caller asked us to try a
     * weapon that the context says cannot work, and we are telling
     * it so without pretending a probe was sent.
     *
     * Note: we do NOT skip the probe if only peer_reachable is
     * false. That flag is about the peer's general reachability,
     * which ipv6.c is specifically trying to confirm for the IPv6
     * path. Skipping on that would make the weapon untestable.
     */
    const xury_weapon_context_t *ac = &ctx->applicability_ctx;
    if (!ac->ipv6_present || !ac->ipv6_global || !ac->peer_has_ipv6) {
        return XURY_OK;   /* success = false, elapsed_ms = 0 */
    }

    /*
     * ------------------------------------------------------------------
     * Open an IPv6 UDP socket
     * ------------------------------------------------------------------
     */
    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = xury_platform_sock_create(XURY_AF_INET6,
                                              XURY_PLATFORM_SOCK_UDP,
                                              &s);
    if (rc != XURY_OK) {
        return rc;   /* out untouched beyond the memset above */
    }

    /*
     * Bind to an ephemeral local port on the IPv6 wildcard.
     *
     * The literal "::" is required: platform/posix/sock.c
     * ep_to_sockaddr() calls inet_pton(AF_INET6, ep->ip, ...), and
     * inet_pton() rejects an empty string. An empty ip[] would make
     * bind() fail every time with XURY_ERR_BAD_ENDPOINT before any
     * probe is sent.
     */
    xury_endpoint_t bind_ep;
    memset(&bind_ep, 0, sizeof(bind_ep));
    bind_ep.family = XURY_AF_INET6;
    bind_ep.port   = 0u;
    bind_ep.ip[0]  = ':';
    bind_ep.ip[1]  = ':';
    bind_ep.ip[2]  = '\0';

    rc = xury_platform_sock_bind(s, &bind_ep);
    if (rc != XURY_OK) {
        (void)xury_platform_sock_close(s);
        return rc;
    }

    /*
     * ------------------------------------------------------------------
     * Send one probe
     * ------------------------------------------------------------------
     */
    uint64_t t0 = xury_platform_time_ms();

    const uint8_t probe[1] = { XURY_IPV6_PROBE_BYTE };
    size_t sent = 0u;
    rc = xury_platform_sock_sendto(s, probe, sizeof(probe),
                                   &ctx->peer, &sent);
    if (rc != XURY_OK) {
        (void)xury_platform_sock_close(s);
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);

        /*
         * A send failure is either a real-world network outcome
         * ("no route to the peer") or a genuine platform error.
         * The contract in weapon_ops.h puts real-world outcomes
         * in the result struct, not in the return code.
         *
         * The helper is_real_world_send_error() classifies the
         * platform error. Real-world errors become success = false
         * with XURY_OK; anything else propagates.
         */
        if (is_real_world_send_error(rc)) {
            return XURY_OK;   /* success = false, elapsed_ms set */
        }
        return rc;
    }
    if (sent != sizeof(probe)) {
        (void)xury_platform_sock_close(s);
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_ERR_PARTIAL_WRITE;
    }

    /*
     * ------------------------------------------------------------------
     * Wait for any reply
     * ------------------------------------------------------------------
     *
     * We do not care who the reply is from (the peer may answer
     * from a different source port than we sent to; that is normal
     * NAT behavior). We do not care what is in it. Arrival within
     * the timeout is the entire success criterion.
     *
     * timeout_ms == 0 means "no deadline": we pass UINT32_MAX to
     * the platform recvfrom, which the platform contract defines
     * as "wait forever" (see core/internal/sock.h).
     */
    uint32_t wait = (ctx->timeout_ms == 0u)
                        ? UINT32_MAX
                        : ctx->timeout_ms;

    uint8_t buf[XURY_IPV6_RECV_CAP];
    xury_endpoint_t from;
    size_t recvd = 0u;

    rc = xury_platform_sock_recvfrom(s, buf, sizeof(buf),
                                     &from, &recvd, wait);

    (void)xury_platform_sock_close(s);

    out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);

    if (rc == XURY_OK) {
        /*
         * Any datagram counts. We do not validate the source:
         * the caller supplied exactly one target and we sent
         * exactly one probe; a reply arriving on the bound socket
         * within the deadline is the signal we were looking for.
         */
        out->success = true;
        out->established_peer = ctx->peer;
        return XURY_OK;
    }
    if (rc == XURY_ERR_TIMEOUT || rc == XURY_ERR_WOULD_BLOCK) {
        /*
         * Real-world outcome: no reply within the deadline.
         * success stays false; established_peer stays zeroed.
         */
        return XURY_OK;
    }

    /*
     * Any other recvfrom failure is a genuine platform error
     * (socket torn down, ICMP unreachable, etc.). Propagate it
     * with elapsed_ms set.
     *
     * Note: XURY_ERR_CONNECTION_RESET can be produced by ICMP
     * port unreachable on a connected UDP socket, but ipv6.c uses
     * an unconnected socket, so that path does not arise here.
     */
    return rc;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
