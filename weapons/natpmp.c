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
 * XURY WEAPONS — NAT-PMP (Phase H, weapon 3/7)
 * ============================================================================
 *
 * Real implementation of weapons/internal/natpmp.h.
 *
 * Implements the NAT-PMP protocol (RFC 6886) for creating a UDP
 * port mapping on the local gateway. The gateway is discovered via
 * the platform layer, which asks the kernel for the default route.
 *
 * Flow:
 *
 *   1. Ask the platform for the default gateway.
 *   2. Send a Map UDP Request (opcode 1) to the gateway on port 5351.
 *   3. Wait for a Map UDP Response.
 *   4. Interpret the result code.
 *
 * ----------------------------------------------------------------------------
 * Protocol notes (RFC 6886)
 * ----------------------------------------------------------------------------
 *
 * All NAT-PMP messages are UDP datagrams exchanged with the gateway
 * on port 5351. The address of the gateway is supplied by the
 * platform layer; this file contains no literal gateway address.
 *
 * Request format (Map UDP, opcode 1):
 *
 *   offset  size  field
 *   0       1     version     0
 *   1       1     opcode      1 (UDP), 2 (TCP)
 *   2       2     reserved    0
 *   4       2     internal_port    big-endian
 *   6       2     external_port    big-endian (0 = let gateway choose)
 *   8       4     lifetime         big-endian, seconds
 *
 * Total: 12 bytes.
 *
 * Response format (Map UDP, opcode 128+1 = 129):
 *
 *   offset  size  field
 *   0       1     version     0
 *   1       1     opcode      128 + request opcode
 *   2       2     result_code big-endian (0 = success)
 *   4       4     epoch       big-endian (gateway uptime seconds)
 *   8       2     internal_port    big-endian (echoed)
 *   10      2     external_port    big-endian (chosen by gateway)
 *   12      4     lifetime         big-endian
 *
 * Total: 16 bytes.
 *
 * The "128 +" on the response opcode is how RFC 6886 distinguishes
 * a response from a request. This file checks that the response
 * opcode is exactly 128 + NATPMP_OP_MAP_UDP before trusting it.
 *
 * ----------------------------------------------------------------------------
 * Scope of v1
 * ----------------------------------------------------------------------------
 *
 *   - IPv4 only. RFC 6886 is IPv4 only; there is no NAT-PMP for
 *     IPv6 (PCP covers that case, and is a separate weapon).
 *
 *   - UDP mapping only. Xury's traversal path is UDP.
 *
 *   - A single request/response exchange. No retry, no second
 *     gateway, no fallback. Those are orchestrator concerns.
 *
 *   - The gateway's chosen external port is not reported back
 *     through established_peer. established_peer is a copy of
 *     ctx->peer for well-formedness, exactly as upnp.c does it.
 *     See the established_peer note in weapon_ops.h.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - Does not contact any server. Xury is no-server.
 *
 *   - Does not embed any address. The gateway address comes from
 *     the platform layer; ctx->peer comes from the caller.
 *
 *   - Does not discover NAT type, classify ports, or score.
 *
 *   - Does not create, connect, or close sockets for the platform
 *     layer; it owns the socket lifecycle for its own attempt.
 *
 * ----------------------------------------------------------------------------
 * Dependencies (per docs/DEPENDENCY.md, "What weapons/ may include")
 * ----------------------------------------------------------------------------
 *
 *   core/internal/sock.h            UDP socket primitives
 *   core/internal/bytes.h           big-endian encode/decode helpers
 *   platform/platform.h             default gateway, monotonic time
 *   weapons/internal/weapon_ops.h   the weapon contract
 *   weapons/internal/natpmp.h       this weapon's entry point
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
#include "platform/platform.h"

#include "weapons/internal/weapon_ops.h"
#include "weapons/internal/natpmp.h"

/*
 * ============================================================================
 * CONSTANTS
 * ============================================================================
 *
 * All values here come directly from RFC 6886. None is invented.
 */

/* Protocol version. RFC 6886 defines only version 0. */
#define NATPMP_VERSION      0u

/* Opcodes. RFC 6886 section 3.2 and 3.3. */
#define NATPMP_OP_MAP_UDP   1u
#define NATPMP_OP_MAP_TCP   2u

/*
 * Response opcodes are the request opcode + 128.
 * RFC 6886 section 3.1: "The server responds with the same opcode
 * plus 128."
 */
#define NATPMP_RESPONSE_BIT 0x80u

/*
 * Gateway port. RFC 6886 section 3.1: "The client then sends a
 * request to the server on port 5351."
 */
#define NATPMP_PORT         5351u

/* Request and response sizes. Both are fixed by the protocol. */
#define NATPMP_REQ_LEN      12u
#define NATPMP_RESP_LEN     16u

/*
 * Lifetime we request. RFC 6886 does not mandate a specific value;
 * the recommendation is that the client renews before expiry. 3600
 * seconds is a common conservative value. The gateway may grant a
 * different lifetime in its response; we do not depend on it.
 */
#define NATPMP_LIFETIME_SEC 3600u

/*
 * Per-attempt timeout in milliseconds. RFC 6886 recommends a
 * client retransmit schedule starting at 250 ms with exponential
 * backoff. We do not retransmit; instead we wait up to this
 * timeout for the single response. 2000 ms is long enough for a
 * healthy gateway (the exchange is local) and short enough not to
 * stall a scan.
 */
#define NATPMP_TIMEOUT_MS   2000u

/*
 * Receive buffer size. The response is 16 bytes; this is generous
 * enough to absorb an unexpected datagram without truncation, and
 * small enough to stay on the stack.
 */
#define NATPMP_RECV_CAP     64u

/*
 * ============================================================================
 * INTERNAL — REQUEST BUILD
 * ============================================================================
 */

/*
 * Encode a Map UDP Request into buf.
 *
 * buf must have room for NATPMP_REQ_LEN bytes. Writes big-endian
 * fields via the core bytes helpers, which do not depend on the
 * host's byte order.
 *
 * Returns XURY_OK on success, XURY_ERR_INVAL if buf is NULL,
 * XURY_ERR_BUFFER_TOO_SMALL if cap is too small.
 */
static xury_err_t build_map_request(uint8_t *buf, size_t cap,
                                    uint16_t internal_port,
                                    uint16_t external_port,
                                    uint32_t lifetime)
{
    if (buf == NULL) {
        return XURY_ERR_INVAL;
    }
    if (cap < NATPMP_REQ_LEN) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }

    xury_cursor_t c;
    xury_cursor_init(&c, buf, cap);

    /* version, opcode, reserved */
    uint8_t header[4] = {
        NATPMP_VERSION,
        NATPMP_OP_MAP_UDP,
        0u,
        0u
    };
    (void)xury_bytes_put(&c, header, sizeof(header));

    /* internal_port, external_port, lifetime */
    (void)xury_bytes_put_be16(&c, internal_port);
    (void)xury_bytes_put_be16(&c, external_port);
    (void)xury_bytes_put_be32(&c, lifetime);

    return XURY_OK;
}

/*
 * ============================================================================
 * INTERNAL — RESPONSE DECODE
 * ============================================================================
 */

typedef struct {
    uint8_t  version;
    uint8_t  opcode;
    uint16_t result_code;
    uint32_t epoch;
    uint16_t internal_port;
    uint16_t external_port;
    uint32_t lifetime;
} natpmp_response_t;

/*
 * Decode a Map UDP Response.
 *
 * Returns:
 *   XURY_OK                   decoded
 *   XURY_ERR_INVAL            buf or out is NULL
 *   XURY_ERR_BUFFER_TOO_SMALL len < NATPMP_RESP_LEN
 */
static xury_err_t decode_map_response(const uint8_t *buf, size_t len,
                                      natpmp_response_t *out)
{
    if (buf == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (len < NATPMP_RESP_LEN) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }

    memset(out, 0, sizeof(*out));

    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, len);

    uint8_t version = 0u;
    (void)xury_bytes_get(&c, &version, 1u);
    out->version = version;

    uint8_t opcode = 0u;
    (void)xury_bytes_get(&c, &opcode, 1u);
    out->opcode = opcode;

    uint16_t result = 0u;
    (void)xury_bytes_get_be16(&c, &result);
    out->result_code = result;

    uint32_t epoch = 0u;
    (void)xury_bytes_get_be32(&c, &epoch);
    out->epoch = epoch;

    uint16_t int_port = 0u;
    (void)xury_bytes_get_be16(&c, &int_port);
    out->internal_port = int_port;

    uint16_t ext_port = 0u;
    (void)xury_bytes_get_be16(&c, &ext_port);
    out->external_port = ext_port;

    uint32_t lifetime = 0u;
    (void)xury_bytes_get_be32(&c, &lifetime);
    out->lifetime = lifetime;

    return XURY_OK;
}

/*
 * ============================================================================
 * INTERNAL — SEND / RECEIVE
 * ============================================================================
 */

/*
 * Send a Map UDP Request and wait for the matching response.
 *
 * The response must:
 *   - come from the gateway endpoint we sent to,
 *   - have version == NATPMP_VERSION,
 *   - have opcode == NATPMP_OP_MAP_UDP + 128.
 *
 * Datagrams that do not match are ignored; the loop continues until
 * the deadline. If the deadline passes with no matching datagram,
 * XURY_ERR_TIMEOUT is returned.
 *
 * On success, *out_resp holds the decoded response.
 */
static xury_err_t exchange_once(xury_sock_t s,
                                const xury_endpoint_t *gateway,
                                uint16_t internal_port,
                                uint32_t timeout_ms,
                                natpmp_response_t *out_resp)
{
    uint8_t req[NATPMP_REQ_LEN];
    xury_err_t rc = build_map_request(req, sizeof(req),
                                      internal_port,
                                      0u,  /* let gateway choose */
                                      NATPMP_LIFETIME_SEC);
    if (rc != XURY_OK) {
        return rc;
    }

    size_t sent = 0u;
    rc = xury_sock_sendto(s, req, sizeof(req), gateway, &sent);
    if (rc != XURY_OK) {
        return rc;
    }
    if (sent != sizeof(req)) {
        return XURY_ERR_PARTIAL_WRITE;
    }

    uint64_t deadline_ms = xury_platform_time_ms() +
                           (uint64_t)timeout_ms;

    for (;;) {
        uint64_t now = xury_platform_time_ms();
        if (now >= deadline_ms) {
            return XURY_ERR_TIMEOUT;
        }
        uint32_t wait = (uint32_t)(deadline_ms - now);
        if (wait == 0u) {
            wait = 1u;
        }

        uint8_t recvbuf[NATPMP_RECV_CAP];
        xury_endpoint_t from;
        size_t recvd = 0u;

        rc = xury_sock_recvfrom(s, recvbuf, sizeof(recvbuf),
                                &from, &recvd, wait);
        if (rc == XURY_ERR_TIMEOUT) {
            continue;
        }
        if (rc != XURY_OK) {
            return rc;
        }

        /*
         * The response must come from the gateway we sent to. A
         * stray datagram from another address is ignored.
         */
        if (from.family != gateway->family) {
            continue;
        }
        if (strcmp(from.ip, gateway->ip) != 0) {
            continue;
        }
        if (from.port != gateway->port) {
            continue;
        }

        natpmp_response_t resp;
        rc = decode_map_response(recvbuf, recvd, &resp);
        if (rc != XURY_OK) {
            continue;   /* malformed or short; ignore */
        }

        /* Version must match. RFC 6886 defines only version 0. */
        if (resp.version != NATPMP_VERSION) {
            continue;
        }

        /*
         * Opcode must be the response form of a Map UDP request.
         * Anything else is not for us.
         */
        if (resp.opcode !=
            (uint8_t)(NATPMP_OP_MAP_UDP + NATPMP_RESPONSE_BIT)) {
            continue;
        }

        *out_resp = resp;
        return XURY_OK;
    }
}

/*
 * ============================================================================
 * PUBLIC ENTRY POINT
 * ============================================================================
 */

xury_err_t xury_weapon_natpmp_try(const xury_weapon_attempt_ctx_t *ctx,
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
    if (ctx->peer.family != XURY_AF_INET) {
        return XURY_ERR_INVAL;
    }
    if (ctx->peer.ip[0] == '\0' || ctx->peer.port == 0u) {
        return XURY_ERR_INVAL;
    }

    memset(out, 0, sizeof(*out));

    /*
     * ------------------------------------------------------------------
     * Fast-path applicability rejection
     * ------------------------------------------------------------------
     */
    if (!ctx->applicability_ctx.natpmp_available) {
        return XURY_OK;   /* success = false, elapsed_ms = 0 */
    }

    /*
     * NAT-PMP creates a port mapping for a local listener. Without
     * a local port there is nothing to expose. See weapon_ops.h.
     */
    if (ctx->local_port == 0u) {
        return XURY_OK;   /* success = false, elapsed_ms = 0 */
    }

    uint64_t t0 = xury_platform_time_ms();

    /*
     * ------------------------------------------------------------------
     * Step 1: discover the default gateway
     * ------------------------------------------------------------------
     */
    xury_endpoint_t gateway;
    xury_err_t rc = xury_platform_gateway(&gateway);
    if (rc != XURY_OK) {
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;   /* no gateway -> success = false */
    }

    /*
     * The platform returns the gateway with port 0. NAT-PMP lives
     * on a fixed port; set it here.
     */
    gateway.port = (uint16_t)NATPMP_PORT;

    /*
     * ------------------------------------------------------------------
     * Step 2: open a UDP socket
     * ------------------------------------------------------------------
     */
    xury_sock_t s = XURY_SOCK_INVALID;
    rc = xury_sock_create(XURY_AF_INET, XURY_SOCK_UDP, &s);
    if (rc != XURY_OK) {
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;
    }

    /* Bind to an ephemeral local port. */
    xury_endpoint_t bind_ep;
    memset(&bind_ep, 0, sizeof(bind_ep));
    bind_ep.family = XURY_AF_INET;
    bind_ep.port = 0u;
    /* 0.0.0.0 wildcard bind — the literal is required, inet_pton
     * does not accept an empty string. */
    bind_ep.ip[0] = '0'; bind_ep.ip[1] = '.'; bind_ep.ip[2] = '0';
    bind_ep.ip[3] = '.'; bind_ep.ip[4] = '0'; bind_ep.ip[5] = '.';
    bind_ep.ip[6] = '0'; bind_ep.ip[7] = '\0';

    rc = xury_sock_bind(s, &bind_ep);
    if (rc != XURY_OK) {
        (void)xury_sock_close(s);
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;
    }

    /*
     * ------------------------------------------------------------------
     * Step 3: send Map UDP Request, wait for response
     * ------------------------------------------------------------------
     */
    natpmp_response_t resp;
    rc = exchange_once(s, &gateway, ctx->local_port,
                       NATPMP_TIMEOUT_MS, &resp);
    (void)xury_sock_close(s);

    if (rc != XURY_OK) {
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;   /* timeout or transport error -> success = false */
    }

    /*
     * ------------------------------------------------------------------
     * Step 4: interpret the result code
     * ------------------------------------------------------------------
     *
     * RFC 6886 section 3.3: result code 0 means success; any non-zero
     * value is a defined error code (1 = unsupported version, 2 =
     * not authorized, 3 = network failure, 4 = out of resources,
     * 5 = unsupported opcode). We do not need to distinguish them;
     * any non-zero value is an honest failure.
     */
    bool success = (resp.result_code == 0u);

    out->success = success;
    if (success) {
        /*
         * established_peer semantics for NAT-PMP match upnp.c: the
         * weapon created a mapping for ctx->peer; it did not contact
         * the peer. See weapon_ops.h for the full divergence note.
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
