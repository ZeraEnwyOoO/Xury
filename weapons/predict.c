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
 * XURY WEAPONS — PORT PREDICTION (Phase H, weapon 7/7)
 * ============================================================================
 *
 * Real implementation of weapons/internal/predict.h.
 *
 * Some NATs allocate external ports from a predictable sequence.
 * When the caller has observed that pattern via scan, it passes the
 * predicted next port through ctx->predicted_peer_port. PREDICT
 * probes both the peer's current endpoint and the predicted one and
 * treats any valid response as success.
 *
 * PREDICT does not compute the prediction. The caller does. This
 * file only uses whatever the caller provided.
 *
 * ----------------------------------------------------------------------------
 * The XPRB exchange
 * ----------------------------------------------------------------------------
 *
 * The wire format is XPRB, defined in scan/internal/probing.h. We
 * do not include that header; its XPRB helpers are static and not
 * exported. The format is duplicated here, on purpose, and is kept
 * byte-compatible with probing.c and with peer/mirror.c. If the
 * format ever changes, all three copies must change together.
 *
 *   REQUEST (15 bytes):
 *     offset  size  field
 *     0       4     magic       "XPRB"
 *     4       1     type        0x01
 *     5       8     nonce       big-endian
 *     13      2     local_port  big-endian (our bound port)
 *
 *   RESPONSE (36 bytes):
 *     offset  size  field
 *     0       4     magic       "XPRB"
 *     4       1     type        0x02
 *     5       8     nonce       big-endian (echoed)
 *     13      2     observed_port   big-endian
 *     15      4     observed_ipv4   big-endian, 0 for IPv6
 *     19      16    observed_ipv6   big-endian, 0 for IPv4
 *     35      1     observed_family 0=UNSPEC, 4=INET, 6=INET6
 *
 * The nonce ties a response to its request. A response with a
 * mismatched nonce is discarded.
 *
 * ----------------------------------------------------------------------------
 * Probes sent
 * ----------------------------------------------------------------------------
 *
 * One XPRB REQUEST is sent to ctx->peer. If ctx->predicted_peer_port
 * is non-zero and differs from ctx->peer.port, a second XPRB REQUEST
 * is sent to ctx->peer.ip at ctx->predicted_peer_port.
 *
 * Both probes use the same nonce so that either response can be
 * matched. The wait loop accepts a response from either address.
 *
 * ----------------------------------------------------------------------------
 * What success means
 * ----------------------------------------------------------------------------
 *
 * Success means: a valid XPRB RESPONSE was received from the peer
 * during the attempt window. This proves the peer was reachable at
 * either its current endpoint or the predicted port.
 *
 * It does NOT prove:
 *   - that a transport connection can be established,
 *   - that the peer is still listening at that endpoint,
 *   - that the prediction will be correct on any subsequent attempt.
 *
 * A successful probe is a momentary observation, not a durable
 * guarantee.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - Does not contact any server. Xury is no-server.
 *
 *   - Does not compute the prediction. The caller supplies it.
 *
 *   - Does not spray a range of ports. Two probes, one wait.
 *     Port-range spraying is BIRTHDAY's job.
 *
 *   - Does not retry. One probe per endpoint. Orchestrator
 *     concerns (blitz/race.c) handle retries.
 *
 *   - Does not use ctx->local_port. PREDICT exposes no local
 *     service; see the local_port note in weapon_ops.h.
 *
 * ----------------------------------------------------------------------------
 * Dependencies (per docs/DEPENDENCY.md, "What weapons/ may include")
 * ----------------------------------------------------------------------------
 *
 *   core/internal/sock.h            UDP socket primitives
 *   core/internal/bytes.h           big-endian encode/decode
 *   core/internal/rand.h            nonce generation
 *   platform/platform.h             monotonic time
 *   api/internal/types.h            xury_format_ip
 *   weapons/internal/weapon_ops.h   the weapon contract
 *   weapons/internal/predict.h      this weapon's entry point
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
#include "core/internal/bytes.h"
#include "core/internal/rand.h"
#include "platform/platform.h"
#include "api/internal/types.h"

#include "weapons/internal/weapon_ops.h"
#include "weapons/internal/predict.h"

/*
 * ============================================================================
 * XPRB PROTOCOL CONSTANTS
 * ============================================================================
 *
 * These mirror the constants in scan/probing.c and peer/mirror.c.
 * See the file header for why the format is duplicated.
 */

#define XPRB_MAGIC_0   0x58u   /* 'X' */
#define XPRB_MAGIC_1   0x50u   /* 'P' */
#define XPRB_MAGIC_2   0x52u   /* 'R' */
#define XPRB_MAGIC_3   0x42u   /* 'B' */

#define XPRB_TYPE_REQUEST   0x01u
#define XPRB_TYPE_RESPONSE  0x02u

#define XPRB_REQUEST_SIZE   15u
#define XPRB_RESPONSE_SIZE  36u

#define XPRB_FAMILY_UNSPEC  0u
#define XPRB_FAMILY_INET    4u
#define XPRB_FAMILY_INET6   6u

/*
 * Receive buffer. Larger than XPRB_RESPONSE_SIZE so an unexpected
 * larger datagram can be received without truncation, then
 * discarded by the length check in the decoder.
 */
#define XPRB_RECV_CAP      64u

/*
 * ============================================================================
 * INTERNAL — REQUEST ENCODE
 * ============================================================================
 */

/*
 * Encode an XPRB REQUEST into buf.
 *
 * buf must have room for XPRB_REQUEST_SIZE bytes.
 */
static xury_err_t encode_request(uint8_t *buf, size_t cap,
                                 uint64_t nonce,
                                 uint16_t local_port)
{
    if (buf == NULL) {
        return XURY_ERR_INVAL;
    }
    if (cap < XPRB_REQUEST_SIZE) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }

    xury_cursor_t c;
    xury_cursor_init(&c, buf, cap);

    uint8_t magic[4] = {
        XPRB_MAGIC_0, XPRB_MAGIC_1, XPRB_MAGIC_2, XPRB_MAGIC_3
    };
    (void)xury_bytes_put(&c, magic, 4u);
    uint8_t type = XPRB_TYPE_REQUEST;
    (void)xury_bytes_put(&c, &type, 1u);
    (void)xury_bytes_put_be64(&c, nonce);
    (void)xury_bytes_put_be16(&c, local_port);

    return XURY_OK;
}

/*
 * ============================================================================
 * INTERNAL — RESPONSE DECODE
 * ============================================================================
 */

typedef struct {
    uint8_t  type;
    uint64_t nonce;
    uint16_t observed_port;
    uint8_t  observed_ipv4[4];
    uint8_t  observed_ipv6[16];
    uint8_t  observed_family;
} xprb_response_t;

/*
 * Verify the 4-byte magic at the start of buf.
 */
static bool magic_ok(const uint8_t *buf, size_t len)
{
    if (buf == NULL || len < 4u) {
        return false;
    }
    return buf[0] == XPRB_MAGIC_0 &&
           buf[1] == XPRB_MAGIC_1 &&
           buf[2] == XPRB_MAGIC_2 &&
           buf[3] == XPRB_MAGIC_3;
}

/*
 * Decode an XPRB RESPONSE.
 *
 * Returns:
 *   XURY_OK                    decoded
 *   XURY_ERR_INVAL             buf or out is NULL
 *   XURY_ERR_BAD_ENDPOINT      magic mismatch, short packet, or
 *                              wrong type
 */
static xury_err_t decode_response(const uint8_t *buf, size_t len,
                                  xprb_response_t *out)
{
    if (buf == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (!magic_ok(buf, len)) {
        return XURY_ERR_BAD_ENDPOINT;
    }
    if (len < XPRB_RESPONSE_SIZE) {
        return XURY_ERR_BAD_ENDPOINT;
    }

    memset(out, 0, sizeof(*out));

    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, len);

    const uint8_t *magic = NULL;
    (void)xury_bytes_get_slice(&c, &magic, 4u);

    uint8_t type = 0u;
    if (xury_bytes_get(&c, &type, 1u) != XURY_OK) {
        return XURY_ERR_BAD_ENDPOINT;
    }
    if (type != XPRB_TYPE_RESPONSE) {
        return XURY_ERR_BAD_ENDPOINT;
    }
    out->type = type;

    uint64_t nonce = 0u;
    if (xury_bytes_get_be64(&c, &nonce) != XURY_OK) {
        return XURY_ERR_BAD_ENDPOINT;
    }
    out->nonce = nonce;

    uint16_t port = 0u;
    if (xury_bytes_get_be16(&c, &port) != XURY_OK) {
        return XURY_ERR_BAD_ENDPOINT;
    }
    out->observed_port = port;

    const uint8_t *v4 = NULL;
    if (xury_bytes_get_slice(&c, &v4, 4u) != XURY_OK) {
        return XURY_ERR_BAD_ENDPOINT;
    }
    memcpy(out->observed_ipv4, v4, 4u);

    const uint8_t *v6 = NULL;
    if (xury_bytes_get_slice(&c, &v6, 16u) != XURY_OK) {
        return XURY_ERR_BAD_ENDPOINT;
    }
    memcpy(out->observed_ipv6, v6, 16u);

    uint8_t fam = 0u;
    if (xury_bytes_get(&c, &fam, 1u) != XURY_OK) {
        return XURY_ERR_BAD_ENDPOINT;
    }
    out->observed_family = fam;

    return XURY_OK;
}

/*
 * ============================================================================
 * INTERNAL — NONCE
 * ============================================================================
 */

/*
 * Generate a random nonce. Same approach as probe/mirror: secure
 * RNG with a fast-RNG fallback, and avoid zero so a zeroed buffer
 * is unambiguously not a valid request.
 */
static uint64_t make_nonce(void)
{
    uint64_t n = 0u;
    if (xury_rand_secure_u64(&n) == XURY_OK && n != 0u) {
        return n;
    }
    n = xury_rand_fast_u64();
    if (n == 0u) {
        n = 1u;
    }
    return n;
}

/*
 * ============================================================================
 * INTERNAL — PEER VALIDATION
 * ============================================================================
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
 * INTERNAL — SEND ONE PROBE
 * ============================================================================
 */

static xury_err_t send_probe(xury_sock_t s,
                             const xury_endpoint_t *to,
                             uint64_t nonce,
                             uint16_t local_port)
{
    uint8_t req[XPRB_REQUEST_SIZE];
    xury_err_t rc = encode_request(req, sizeof(req), nonce, local_port);
    if (rc != XURY_OK) {
        return rc;
    }

    size_t sent = 0u;
    rc = xury_sock_sendto(s, req, sizeof(req), to, &sent);
    if (rc != XURY_OK) {
        return rc;
    }
    if (sent != sizeof(req)) {
        return XURY_ERR_PARTIAL_WRITE;
    }
    return XURY_OK;
}

/*
 * ============================================================================
 * PUBLIC ENTRY POINT
 * ============================================================================
 */

xury_err_t xury_weapon_predict_try(const xury_weapon_attempt_ctx_t *ctx,
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
    if (!ctx->applicability_ctx.peer_reachable) {
        return XURY_OK;   /* success = false, elapsed_ms = 0 */
    }

    /*
     * PREDICT requires a prediction. The caller computes it from
     * scan results; if it did not, there is nothing to try. Fail
     * honestly rather than invent a port.
     */
    if (ctx->predicted_peer_port == 0u) {
        return XURY_OK;   /* success = false, elapsed_ms = 0 */
    }

    uint64_t t0 = xury_platform_time_ms();

    /*
     * ------------------------------------------------------------------
     * Build the predicted endpoint.
     * ------------------------------------------------------------------
     *
     * Same ip as ctx->peer, port replaced with the predicted one.
     * If the predicted port matches the peer's current port, we
     * will only send one probe.
     */
    xury_endpoint_t predicted = ctx->peer;
    predicted.port = ctx->predicted_peer_port;

    bool predicted_differs =
        (predicted.port != ctx->peer.port);

    /*
     * ------------------------------------------------------------------
     * Create and bind a UDP socket in the peer's family.
     * ------------------------------------------------------------------
     */
    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = xury_sock_create(ctx->peer.family, XURY_SOCK_UDP, &s);
    if (rc != XURY_OK) {
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;
    }

    xury_endpoint_t bind_ep;
    memset(&bind_ep, 0, sizeof(bind_ep));
    bind_ep.family = ctx->peer.family;
    bind_ep.port = 0u;
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
     * Discover our local port; the XPRB REQUEST carries it. It is
     * not used by the responder in any way that matters for PREDICT,
     * but keeping the shape identical to probing.c and mirror.c
     * means any XPRB-speaking peer answers the same way.
     */
    xury_endpoint_t local;
    memset(&local, 0, sizeof(local));
    rc = xury_sock_local(s, &local);
    if (rc != XURY_OK) {
        (void)xury_sock_close(s);
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;
    }

    /*
     * ------------------------------------------------------------------
     * Send both probes with the same nonce.
     * ------------------------------------------------------------------
     */
    uint64_t nonce = make_nonce();

    rc = send_probe(s, &ctx->peer, nonce, local.port);
    if (rc != XURY_OK) {
        (void)xury_sock_close(s);
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;
    }

    if (predicted_differs) {
        rc = send_probe(s, &predicted, nonce, local.port);
        if (rc != XURY_OK) {
            (void)xury_sock_close(s);
            out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
            return XURY_OK;
        }
    }

    /*
     * ------------------------------------------------------------------
     * Wait for a response from either endpoint.
     * ------------------------------------------------------------------
     *
     * A response is accepted if:
     *   - the source ip matches ctx->peer.ip,
     *   - the source port matches either ctx->peer.port or
     *     ctx->predicted_peer_port,
     *   - the packet decodes as XPRB RESPONSE,
     *   - the nonce matches.
     *
     * Any other datagram is discarded and the loop continues until
     * the deadline.
     */
    uint64_t deadline_ms = 0u;
    if (ctx->timeout_ms != 0u) {
        deadline_ms = xury_platform_time_ms() + (uint64_t)ctx->timeout_ms;
    }

    bool success = false;

    for (;;) {
        uint32_t wait = 0u;
        if (deadline_ms != 0u) {
            uint64_t now = xury_platform_time_ms();
            if (now >= deadline_ms) {
                break;
            }
            uint64_t remaining = deadline_ms - now;
            if (remaining > 0xFFFFFFFFu) {
                remaining = 0xFFFFFFFFu;
            }
            wait = (uint32_t)remaining;
        } else {
            wait = UINT32_MAX;
        }

        uint8_t recvbuf[XPRB_RECV_CAP];
        xury_endpoint_t from;
        size_t recvd = 0u;

        rc = xury_sock_recvfrom(s, recvbuf, sizeof(recvbuf),
                                &from, &recvd, wait);
        if (rc == XURY_ERR_TIMEOUT) {
            continue;
        }
        if (rc != XURY_OK) {
            break;
        }

        if (from.family != ctx->peer.family) {
            continue;
        }
        if (strcmp(from.ip, ctx->peer.ip) != 0) {
            continue;
        }
        if (from.port != ctx->peer.port &&
            from.port != ctx->predicted_peer_port) {
            continue;
        }

        xprb_response_t resp;
        rc = decode_response(recvbuf, recvd, &resp);
        if (rc != XURY_OK) {
            continue;
        }
        if (resp.nonce != nonce) {
            continue;
        }

        success = true;
        break;
    }

    (void)xury_sock_close(s);

    out->success = success;
    if (success) {
        /*
         * established_peer semantics for PREDICT: the weapon probed
         * the peer's current endpoint and the predicted one, and a
         * response came back from one of them. The endpoint the
         * caller supplied is the endpoint this weapon established a
         * path to. See the file header of weapon_ops.h.
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
