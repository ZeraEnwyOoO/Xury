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
 * XURY PEER — MIRROR (Phase I, minimal)
 * ============================================================================
 *
 * Real implementation of peer/internal/mirror.h.
 *
 * Asks a cooperating peer what public endpoint it observes for us.
 * This is the "no-STUN" primitive: instead of a third-party STUN
 * server, the caller supplies a peer endpoint, and the peer reports
 * the source address it saw on our probe.
 *
 * ----------------------------------------------------------------------------
 * Why this file is small
 * ----------------------------------------------------------------------------
 *
 * The only consumer is weapons/hole.c. hole.c needs to know our
 * public endpoint before it can tell the target peer where to aim
 * its punch. That is the whole job of this file: one probe, one
 * response, one observed endpoint.
 *
 * The public peer.h API — relay, upgrade, NAT classification, the
 * optional mirror-server role — depends on xury_engine_t (Phase M).
 * None of that is here. See peer/internal/mirror.h for the full
 * scope note.
 *
 * ----------------------------------------------------------------------------
 * The XPRB exchange
 * ----------------------------------------------------------------------------
 *
 * The wire format is XPRB, defined in scan/internal/probing.h. We
 * do not include that header; its XPRB helpers are static and not
 * exported. The format is duplicated here, on purpose, and is kept
 * byte-compatible with probing.c. If the format ever changes, both
 * copies must change together.
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
 * mismatched nonce is discarded, not accepted.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No server side. A Xury process that wants to answer mirror
 *     probes is a Phase N feature. This file never listens for
 *     probes from other peers.
 *
 *   - No NAT classification. The result is one endpoint, from one
 *     peer. Classification requires multiple peers and is a future
 *     feature.
 *
 *   - No retry. One probe, one wait, one answer. If the peer does
 *     not respond, the caller can try a different peer.
 *
 *   - No allocation. All buffers are stack-local.
 *
 *   - No global state. The function is reentrant.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   core/internal/sock.h            UDP socket primitives
 *   core/internal/bytes.h           big-endian encode/decode
 *   core/internal/rand.h            nonce generation
 *   platform/platform.h             monotonic time
 *   weapons/internal/...            none
 *   peer/internal/mirror.h          the interface
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

#include "peer/internal/mirror.h"

/*
 * ============================================================================
 * XPRB PROTOCOL CONSTANTS
 * ============================================================================
 *
 * These mirror the constants in scan/probing.c. See the file header
 * for why the format is duplicated.
 */

#define XPRB_MAGIC_0   0x58u   /* 'X' */
#define XPRB_MAGIC_1   0x50u   /* 'P' */
#define XPRB_MAGIC_2   0x52u   /* 'R' */
#define XPRB_MAGIC_3   0x42u   /* 'B' */

#define XPRB_TYPE_REQUEST   0x01u
#define XPRB_TYPE_RESPONSE  0x02u

#define XPRB_REQUEST_SIZE   15u
#define XPRB_RESPONSE_SIZE  36u

/*
 * observed_family values. Deliberately not the AF_* numeric values:
 * the wire format must not depend on the host's AF_* layout.
 */
#define XPRB_FAMILY_UNSPEC  0u
#define XPRB_FAMILY_INET    4u
#define XPRB_FAMILY_INET6   6u

/*
 * Receive buffer. Larger than XPRB_RESPONSE_SIZE so that a stray
 * larger datagram can be received without truncation and then
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
 * buf must have room for XPRB_REQUEST_SIZE bytes. local_port is
 * written big-endian; nonce likewise.
 *
 * Returns:
 *   XURY_OK                   encoded
 *   XURY_ERR_INVAL            buf is NULL
 *   XURY_ERR_BUFFER_TOO_SMALL cap < XPRB_REQUEST_SIZE
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
    (void)xury_bytes_put(&c, &(uint8_t){XPRB_TYPE_REQUEST}, 1u);
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
 *   XURY_ERR_MIRROR_BAD_RESPONSE  magic mismatch, short packet, or
 *                              wrong type
 */
static xury_err_t decode_response(const uint8_t *buf, size_t len,
                                  xprb_response_t *out)
{
    if (buf == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (!magic_ok(buf, len)) {
        return XURY_ERR_MIRROR_BAD_RESPONSE;
    }
    if (len < XPRB_RESPONSE_SIZE) {
        return XURY_ERR_MIRROR_BAD_RESPONSE;
    }

    memset(out, 0, sizeof(*out));

    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, len);

    const uint8_t *magic = NULL;
    (void)xury_bytes_get_slice(&c, &magic, 4u);

    uint8_t type = 0u;
    if (xury_bytes_get(&c, &type, 1u) != XURY_OK) {
        return XURY_ERR_MIRROR_BAD_RESPONSE;
    }
    if (type != XPRB_TYPE_RESPONSE) {
        return XURY_ERR_MIRROR_BAD_RESPONSE;
    }
    out->type = type;

    uint64_t nonce = 0u;
    if (xury_bytes_get_be64(&c, &nonce) != XURY_OK) {
        return XURY_ERR_MIRROR_BAD_RESPONSE;
    }
    out->nonce = nonce;

    uint16_t port = 0u;
    if (xury_bytes_get_be16(&c, &port) != XURY_OK) {
        return XURY_ERR_MIRROR_BAD_RESPONSE;
    }
    out->observed_port = port;

    const uint8_t *v4 = NULL;
    if (xury_bytes_get_slice(&c, &v4, 4u) != XURY_OK) {
        return XURY_ERR_MIRROR_BAD_RESPONSE;
    }
    memcpy(out->observed_ipv4, v4, 4u);

    const uint8_t *v6 = NULL;
    if (xury_bytes_get_slice(&c, &v6, 16u) != XURY_OK) {
        return XURY_ERR_MIRROR_BAD_RESPONSE;
    }
    memcpy(out->observed_ipv6, v6, 16u);

    uint8_t fam = 0u;
    if (xury_bytes_get(&c, &fam, 1u) != XURY_OK) {
        return XURY_ERR_MIRROR_BAD_RESPONSE;
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
 * Generate a random nonce for the query.
 *
 * Uses the secure RNG. If it is not available, the fast generator
 * is used as a fallback; the nonce is a correlation token, not a
 * secret, so this is acceptable. A nonce of 0 is valid but we avoid
 * it, so a zeroed buffer is unambiguously not a valid request.
 *
 * This mirrors make_nonce() in scan/probing.c.
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
 * INTERNAL — OBSERVED ENDPOINT TO xury_endpoint_t
 * ============================================================================
 */

/*
 * Fill an xury_endpoint_t from the response's observed_* fields.
 *
 * Uses xury_format_ip, the same helper probing.c uses for the same
 * conversion. It lives in api/internal/types.h and is part of the
 * foundational api subset that weapons and peer layers may include.
 *
 * Returns:
 *   XURY_OK            *out filled
 *   XURY_ERR_MIRROR_BAD_RESPONSE  family unknown, or format failed
 */
static xury_err_t endpoint_from_response(const xprb_response_t *resp,
                                         xury_endpoint_t *out)
{
    memset(out, 0, sizeof(*out));
    out->family = XURY_AF_UNSPEC;

    if (resp->observed_family == XPRB_FAMILY_INET) {
        if (xury_format_ip(XURY_AF_INET,
                           resp->observed_ipv4, 4u,
                           out->ip, sizeof(out->ip)) != XURY_OK) {
            return XURY_ERR_MIRROR_BAD_RESPONSE;
        }
        out->family = XURY_AF_INET;
        out->port = resp->observed_port;
        return XURY_OK;
    }

    if (resp->observed_family == XPRB_FAMILY_INET6) {
        if (xury_format_ip(XURY_AF_INET6,
                           resp->observed_ipv6, 16u,
                           out->ip, sizeof(out->ip)) != XURY_OK) {
            return XURY_ERR_MIRROR_BAD_RESPONSE;
        }
        out->family = XURY_AF_INET6;
        out->port = resp->observed_port;
        return XURY_OK;
    }

    return XURY_ERR_MIRROR_BAD_RESPONSE;
}

/*
 * ============================================================================
 * INTERNAL — ENDPOINT VALIDATION
 * ============================================================================
 */

/*
 * True if the peer endpoint is usable as a query target.
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
 * PUBLIC ENTRY POINT
 * ============================================================================
 */

xury_err_t xury_peer_mirror_query(const xury_endpoint_t *peer,
                                  xury_endpoint_t *out_self,
                                  uint32_t timeout_ms)
{
    /*
     * ------------------------------------------------------------------
     * Argument validation
     * ------------------------------------------------------------------
     */
    if (out_self == NULL) {
        return XURY_ERR_INVAL;
    }
    memset(out_self, 0, sizeof(*out_self));
    out_self->family = XURY_AF_UNSPEC;

    if (!peer_usable(peer)) {
        return XURY_ERR_INVAL;
    }

    /*
     * ------------------------------------------------------------------
     * Open a UDP socket and bind to an ephemeral local port.
     * ------------------------------------------------------------------
     */
    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = xury_sock_create(peer->family, XURY_SOCK_UDP, &s);
    if (rc != XURY_OK) {
        return XURY_ERR_IO;
    }

    xury_endpoint_t bind_ep;
    memset(&bind_ep, 0, sizeof(bind_ep));
    bind_ep.family = peer->family;
    bind_ep.port = 0u;
    /*
     * Wildcard bind. For IPv4 the literal "0.0.0.0" is required —
     * inet_pton rejects an empty string. For IPv6 the literal "::"
     * is required for the same reason.
     */
    if (peer->family == XURY_AF_INET) {
        bind_ep.ip[0] = '0'; bind_ep.ip[1] = '.'; bind_ep.ip[2] = '0';
        bind_ep.ip[3] = '.'; bind_ep.ip[4] = '0'; bind_ep.ip[5] = '.';
        bind_ep.ip[6] = '0'; bind_ep.ip[7] = '\0';
    } else {
        bind_ep.ip[0] = ':'; bind_ep.ip[1] = ':'; bind_ep.ip[2] = '\0';
    }

    rc = xury_sock_bind(s, &bind_ep);
    if (rc != XURY_OK) {
        (void)xury_sock_close(s);
        return XURY_ERR_IO;
    }

    /*
     * Discover our own bound local port. probing.c does this so
     * that the peer sees a meaningful local_port value; the mirror
     * side does not use it, but keeping the shape identical means
     * any peer that speaks XPRB (probing or mirror) can answer.
     */
    xury_endpoint_t local;
    memset(&local, 0, sizeof(local));
    rc = xury_sock_local(s, &local);
    if (rc != XURY_OK) {
        (void)xury_sock_close(s);
        return XURY_ERR_IO;
    }

    /*
     * ------------------------------------------------------------------
     * Build and send the XPRB REQUEST.
     * ------------------------------------------------------------------
     */
    uint64_t nonce = make_nonce();

    uint8_t req[XPRB_REQUEST_SIZE];
    rc = encode_request(req, sizeof(req), nonce, local.port);
    if (rc != XURY_OK) {
        (void)xury_sock_close(s);
        return rc;
    }

    size_t sent = 0u;
    rc = xury_sock_sendto(s, req, sizeof(req), peer, &sent);
    if (rc != XURY_OK || sent != sizeof(req)) {
        (void)xury_sock_close(s);
        return XURY_ERR_IO;
    }

    /*
     * ------------------------------------------------------------------
     * Wait for the matching response.
     * ------------------------------------------------------------------
     *
     * The response must:
     *   - come from the peer we queried (any source port is
     *     accepted; NATs sometimes rewrite the source port),
     *   - have the right magic and type,
     *   - echo our nonce.
     *
     * Datagrams that fail any of those checks are discarded and the
     * loop continues until the deadline.
     *
     * timeout_ms == 0 means "no deadline", matching
     * xury_sock_recvfrom()'s convention.
     */
    uint64_t deadline_ms = 0u;
    if (timeout_ms != 0u) {
        deadline_ms = xury_platform_time_ms() + (uint64_t)timeout_ms;
    }

    for (;;) {
        uint32_t wait = 0u;
        if (deadline_ms != 0u) {
            uint64_t now = xury_platform_time_ms();
            if (now >= deadline_ms) {
                (void)xury_sock_close(s);
                return XURY_ERR_TIMEOUT;
            }
            uint64_t remaining = deadline_ms - now;
            if (remaining > 0xFFFFFFFFu) {
                remaining = 0xFFFFFFFFu;
            }
            wait = (uint32_t)remaining;
        } else {
            /* No deadline: wait forever. The platform layer treats
             * UINT32_MAX as "wait forever" for recvfrom. */
            wait = UINT32_MAX;
        }

        uint8_t recvbuf[XPRB_RECV_CAP];
        xury_endpoint_t from;
        size_t recvd = 0u;

        rc = xury_sock_recvfrom(s, recvbuf, sizeof(recvbuf),
                                &from, &recvd, wait);
        if (rc == XURY_ERR_TIMEOUT) {
            /* Inner timeout in a no-deadline or long-deadline
             * case. Loop and re-check. */
            continue;
        }
        if (rc != XURY_OK) {
            (void)xury_sock_close(s);
            return XURY_ERR_IO;
        }

        /*
         * Source check: the response must come from the peer's ip.
         * We do not require the source port to match, because a
         * NAT may rewrite it. The nonce check below is what
         * actually ties the response to our request.
         */
        if (from.family != peer->family) {
            continue;
        }
        if (strcmp(from.ip, peer->ip) != 0) {
            continue;
        }

        xprb_response_t resp;
        rc = decode_response(recvbuf, recvd, &resp);
        if (rc != XURY_OK) {
            continue;   /* malformed or not a response; ignore */
        }

        if (resp.nonce != nonce) {
            continue;   /* not our response */
        }

        /*
         * Convert the observed endpoint and return it.
         */
        rc = endpoint_from_response(&resp, out_self);
        (void)xury_sock_close(s);

        if (rc != XURY_OK) {
            memset(out_self, 0, sizeof(*out_self));
            out_self->family = XURY_AF_UNSPEC;
            return rc;
        }
        return XURY_OK;
    }
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
