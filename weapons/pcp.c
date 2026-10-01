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
 * XURY WEAPONS — PCP (Phase H, weapon 4/7)
 * ============================================================================
 *
 * Real implementation of weapons/internal/pcp.h.
 *
 * Implements the PCP protocol (RFC 6887) for creating a UDP port
 * mapping on the local gateway. The gateway is discovered via the
 * platform layer, which asks the kernel for the default route.
 *
 * Flow:
 *
 *   1. Ask the platform for the default gateway.
 *   2. Send a MAP request (opcode 1) to the gateway on port 5351.
 *   3. Wait for a MAP response.
 *   4. Interpret the result code.
 *
 * ----------------------------------------------------------------------------
 * Protocol notes (RFC 6887)
 * ----------------------------------------------------------------------------
 *
 * All PCP messages are UDP datagrams exchanged with the gateway on
 * port 5351. The gateway address is supplied by the platform layer;
 * this file contains no literal gateway address.
 *
 * Common header (24 bytes):
 *
 *   offset  size  field
 *   0       1     version      (2)
 *   1       1     opcode       (1 = MAP)
 *   2       2     reserved     (0)
 *   4       4     lifetime     big-endian, seconds
 *   8       16    client_ip    IPv4-mapped IPv6 for our IPv4 case
 *
 * MAP request body (36 bytes), request total 60 bytes:
 *
 *   offset  size  field
 *   24      12    nonce
 *   36      1     protocol     (17 = UDP)
 *   37      3     reserved     (0)
 *   40      2     internal_port            big-endian
 *   42      2     suggested_external_port  big-endian (0 = let gateway choose)
 *   44      16    suggested_external_ip    IPv4-mapped IPv6, all-zero
 *
 * MAP response body (36 bytes), response total 60 bytes:
 *
 *   offset  size  field
 *   24      12    nonce        echoed
 *   36      1     protocol     echoed
 *   37      3     reserved
 *   40      2     internal_port            echoed
 *   42      2     assigned_external_port   big-endian
 *   44      16    assigned_external_ip     IPv4-mapped IPv6
 *
 * The response opcode is the request opcode plus 0x80. For MAP, the
 * response opcode is 0x81.
 *
 * Result code 0 is SUCCESS. Any other value is a defined PCP error
 * code (see RFC 6887 §7.4).
 *
 * ----------------------------------------------------------------------------
 * IPv4-in-IPv6 encoding
 * ----------------------------------------------------------------------------
 *
 * PCP carries all addresses as 16-byte IPv6 addresses. An IPv4
 * address is encoded per RFC 4291 as an IPv4-mapped IPv6 address:
 *
 *   bytes 0..9   = 0x00
 *   bytes 10..11 = 0xFF 0xFF
 *   bytes 12..15 = the 4 IPv4 octets
 *
 * This is the same encoding used by the kernel for AF_INET sockets
 * bound to v4-mapped v6 addresses, and is what RFC 6887 §5
 * specifies for a client speaking PCP over IPv4.
 *
 * ----------------------------------------------------------------------------
 * Nonce
 * ----------------------------------------------------------------------------
 *
 * RFC 6887 requires a 96-bit nonce chosen by the client. The nonce
 * is echoed by the gateway in the response, and the client must
 * verify it. This file generates the nonce with two calls to
 * xury_rand_secure_u64() (12 bytes = 8 + 4), which is the secure
 * RNG Xury already exposes. If the secure RNG is unavailable, the
 * attempt fails honestly rather than falling back to a weak nonce.
 *
 * ----------------------------------------------------------------------------
 * Scope of v1
 * ----------------------------------------------------------------------------
 *
 *   - IPv4 only. The client_ip and suggested_external_ip fields are
 *     IPv4-mapped IPv6. The socket and gateway are IPv4.
 *
 *   - UDP mapping only. Xury's traversal path is UDP.
 *
 *   - A single MAP request/response exchange. No retry, no second
 *     gateway, no fallback. Those are orchestrator concerns.
 *
 *   - No authentication. RFC 6887 §8 defines optional PCP
 *     authentication; Xury does not use it.
 *
 *   - The assigned external port is not reported back through
 *     established_peer. established_peer is a copy of ctx->peer for
 *     well-formedness, exactly as upnp.c and natpmp.c do it. See
 *     the established_peer note in weapon_ops.h.
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
 *   core/internal/rand.h            secure nonce generation
 *   platform/platform.h             default gateway, monotonic time
 *   weapons/internal/weapon_ops.h   the weapon contract
 *   weapons/internal/pcp.h          this weapon's entry point
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

#include "weapons/internal/weapon_ops.h"
#include "weapons/internal/pcp.h"

/*
 * ============================================================================
 * CONSTANTS (RFC 6887)
 * ============================================================================
 */

/* PCP version. RFC 6887 §7: "version = 2". */
#define PCP_VERSION          2u

/* Opcodes. RFC 6887 §7.1 and §7.2. */
#define PCP_OP_MAP           1u

/* Response opcode = request opcode + 0x80. RFC 6887 §7.1. */
#define PCP_RESPONSE_BIT     0x80u

/*
 * IP protocol number for UDP. RFC 6887 §7.3: the MAP opcode uses
 * "IANA protocol number (6 = TCP, 17 = UDP)".
 */
#define PCP_PROTO_UDP        17u

/*
 * PCP gateway port. RFC 6887 §8.1: "the server listens on UDP
 * port 5351". Same port as NAT-PMP, by design.
 */
#define PCP_PORT             5351u

/* Total message size: 24-byte header + 36-byte body. */
#define PCP_MSG_LEN          60u

/* Offset of the body in both requests and responses. */
#define PCP_HDR_LEN          24u
#define PCP_BODY_LEN         36u

/*
 * Lifetime we request. RFC 6887 §7.3 does not mandate a specific
 * value. 3600 seconds is a common conservative value, matching
 * natpmp.c. The gateway may grant a different lifetime; we do not
 * depend on it.
 */
#define PCP_LIFETIME_SEC     3600u

/*
 * Per-attempt timeout in milliseconds. RFC 6887 §8.1.1 recommends
 * an initial retransmission timer of 250 ms with exponential
 * backoff. We do not retransmit; we wait up to this timeout for
 * the single response. 2000 ms matches natpmp.c.
 */
#define PCP_TIMEOUT_MS       2000u

/* Receive buffer size. The response is 60 bytes; this is generous. */
#define PCP_RECV_CAP         128u

/*
 * ============================================================================
 * INTERNAL — IPv4-MAPPED IPv6 ENCODING
 * ============================================================================
 *
 * RFC 4291 §2.5.5.2 and RFC 6887 §5. An IPv4-mapped IPv6 address
 * has the form:
 *
 *   00 00 00 00 00 00 00 00 00 00 FF FF A B C D
 *
 * where A.B.C.D are the four IPv4 octets.
 */

static void ipv4_to_mapped_ipv6(const uint8_t v4[4], uint8_t out[16])
{
    memset(out, 0, 16);
    out[10] = 0xFF;
    out[11] = 0xFF;
    memcpy(out + 12, v4, 4);
}

/*
 * ============================================================================
 * INTERNAL — REQUEST BUILD
 * ============================================================================
 */

/*
 * Encode a PCP MAP request into buf.
 *
 * buf must have room for PCP_MSG_LEN bytes.
 *
 * client_v4 is the client's own IPv4 address (4 bytes, big-endian
 * order as it appears on the wire). The caller must supply it; this
 * function does not invent one.
 *
 * nonce is 12 bytes. The caller generates it.
 *
 * Returns:
 *   XURY_OK                   encoded
 *   XURY_ERR_INVAL            buf or client_v4 or nonce is NULL
 *   XURY_ERR_BUFFER_TOO_SMALL cap < PCP_MSG_LEN
 */
static xury_err_t build_map_request(uint8_t *buf, size_t cap,
                                    const uint8_t client_v4[4],
                                    uint16_t internal_port,
                                    const uint8_t nonce[12])
{
    if (buf == NULL || client_v4 == NULL || nonce == NULL) {
        return XURY_ERR_INVAL;
    }
    if (cap < PCP_MSG_LEN) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }

    memset(buf, 0, PCP_MSG_LEN);

    xury_cursor_t c;
    xury_cursor_init(&c, buf, cap);

    /* --- Common header (24 bytes) --- */
    uint8_t version = PCP_VERSION;
    uint8_t opcode  = PCP_OP_MAP;
    (void)xury_bytes_put(&c, &version, 1u);
    (void)xury_bytes_put(&c, &opcode, 1u);
    (void)xury_bytes_put_be16(&c, 0u);                 /* reserved */
    (void)xury_bytes_put_be32(&c, PCP_LIFETIME_SEC);

    uint8_t client_v6[16];
    ipv4_to_mapped_ipv6(client_v4, client_v6);
    (void)xury_bytes_put(&c, client_v6, 16u);

    /* --- MAP body (36 bytes) --- */
    (void)xury_bytes_put(&c, nonce, 12u);

    uint8_t protocol = PCP_PROTO_UDP;
    (void)xury_bytes_put(&c, &protocol, 1u);
    uint8_t reserved3[3] = { 0u, 0u, 0u };
    (void)xury_bytes_put(&c, reserved3, 3u);

    (void)xury_bytes_put_be16(&c, internal_port);
    (void)xury_bytes_put_be16(&c, 0u);                 /* suggested external port: none */

    uint8_t zero_v6[16] = { 0u };
    (void)xury_bytes_put(&c, zero_v6, 16u);            /* suggested external ip: none */

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
    uint8_t  result_code;
    uint32_t lifetime;
    uint32_t epoch;
    uint8_t  nonce[12];
    uint8_t  protocol;
    uint16_t internal_port;
    uint16_t assigned_external_port;
} pcp_response_t;

/*
 * Decode a PCP MAP response.
 *
 * Returns:
 *   XURY_OK                   decoded
 *   XURY_ERR_INVAL            buf or out is NULL
 *   XURY_ERR_BUFFER_TOO_SMALL len < PCP_MSG_LEN
 */
static xury_err_t decode_map_response(const uint8_t *buf, size_t len,
                                      pcp_response_t *out)
{
    if (buf == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (len < PCP_MSG_LEN) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }

    memset(out, 0, sizeof(*out));

    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, len);

    /* --- Common header --- */
    uint8_t version = 0u;
    uint8_t opcode  = 0u;
    (void)xury_bytes_get(&c, &version, 1u);
    (void)xury_bytes_get(&c, &opcode, 1u);
    out->version = version;
    out->opcode  = opcode;

    uint8_t result_code = 0u;
    (void)xury_bytes_get(&c, &result_code, 1u);
    out->result_code = result_code;

    uint32_t lifetime = 0u;
    (void)xury_bytes_get_be32(&c, &lifetime);
    out->lifetime = lifetime;

    uint32_t epoch = 0u;
    (void)xury_bytes_get_be32(&c, &epoch);
    out->epoch = epoch;

    uint8_t reserved[12];
    (void)xury_bytes_get(&c, reserved, 12u);   /* reserved, ignored */

    /* --- MAP body --- */
    (void)xury_bytes_get(&c, out->nonce, 12u);

    uint8_t protocol = 0u;
    (void)xury_bytes_get(&c, &protocol, 1u);
    out->protocol = protocol;

    uint8_t reserved3[3];
    (void)xury_bytes_get(&c, reserved3, 3u);   /* reserved, ignored */

    uint16_t int_port = 0u;
    (void)xury_bytes_get_be16(&c, &int_port);
    out->internal_port = int_port;

    uint16_t ext_port = 0u;
    (void)xury_bytes_get_be16(&c, &ext_port);
    out->assigned_external_port = ext_port;

    /* assigned_external_ip (16 bytes) is ignored for v1. */
    return XURY_OK;
}

/*
 * ============================================================================
 * INTERNAL — NONCE
 * ============================================================================
 */

/*
 * Fill a 12-byte nonce using xury_rand_secure_u64().
 *
 * The 12 bytes are built as: 8 bytes from one u64, 4 bytes from
 * another. The two draws are independent.
 *
 * Returns XURY_OK on success, or the error from the secure RNG.
 * The secure RNG must be present; a weak nonce is not acceptable.
 */
static xury_err_t make_nonce(uint8_t nonce[12])
{
    if (nonce == NULL) {
        return XURY_ERR_INVAL;
    }

    uint64_t a = 0u;
    xury_err_t rc = xury_rand_secure_u64(&a);
    if (rc != XURY_OK) {
        return rc;
    }

    uint64_t b = 0u;
    rc = xury_rand_secure_u64(&b);
    if (rc != XURY_OK) {
        return rc;
    }

    /* Big-endian layout, 8 bytes then 4. */
    for (size_t i = 0u; i < 8u; i++) {
        nonce[i] = (uint8_t)(a >> (56u - 8u * i));
    }
    for (size_t i = 0u; i < 4u; i++) {
        nonce[8u + i] = (uint8_t)(b >> (56u - 8u * i));
    }
    return XURY_OK;
}

/*
 * Constant-time comparison of two 12-byte nonces.
 *
 * The nonce is not a secret in the cryptographic sense — it is a
 * correlation token, not key material — but the response must be
 * matched to our request. Constant-time comparison is not strictly
 * required here; it is used because the same shape of code appears
 * elsewhere in Xury and there is no cost to being uniform.
 */
static bool nonce_equal(const uint8_t a[12], const uint8_t b[12])
{
    uint8_t diff = 0u;
    for (size_t i = 0u; i < 12u; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0u;
}

/*
 * ============================================================================
 * INTERNAL — CLIENT IP LOOKUP
 * ============================================================================
 *
 * The PCP MAP request must carry the client's own IPv4 address.
 * Xury obtains this from the same interface enumeration the scan
 * layer uses.
 *
 * We do not infer an address; if the platform cannot tell us one,
 * the weapon fails honestly (success = false) rather than inventing
 * a value.
 */

static xury_err_t get_client_ipv4(uint8_t out_v4[4])
{
    if (out_v4 == NULL) {
        return XURY_ERR_INVAL;
    }

    xury_platform_iface_t ifaces[16];
    size_t count = 0u;
    xury_err_t rc = xury_platform_ifaces_list(ifaces,
                                              sizeof(ifaces) /
                                                  sizeof(ifaces[0]),
                                              &count);
    if (rc != XURY_OK) {
        return rc;
    }

    for (size_t i = 0u; i < count; i++) {
        if (ifaces[i].family != XURY_AF_INET) {
            continue;
        }
        if (ifaces[i].is_loopback) {
            continue;
        }

        /*
         * Parse the textual IPv4 address into four bytes. The
         * endpoint is already validated as AF_INET, so a simple
         * decimal parse is enough — no need for the full parser in
         * core. We do not accept anything but four decimal octets.
         */
        const char *ip = ifaces[i].addr.ip;
        unsigned octets[4] = {0u, 0u, 0u, 0u};
        size_t oct = 0u;
        const char *p = ip;
        bool ok = true;
        while (oct < 4u) {
            if (*p < '0' || *p > '9') {
                ok = false;
                break;
            }
            unsigned v = 0u;
            size_t digits = 0u;
            while (*p >= '0' && *p <= '9' && digits < 3u) {
                v = v * 10u + (unsigned)(*p - '0');
                p++;
                digits++;
            }
            if (v > 255u) {
                ok = false;
                break;
            }
            octets[oct] = v;
            oct++;
            if (oct == 4u) {
                break;
            }
            if (*p != '.') {
                ok = false;
                break;
            }
            p++;
        }
        if (!ok || oct != 4u || *p != '\0') {
            continue;
        }

        out_v4[0] = (uint8_t)octets[0];
        out_v4[1] = (uint8_t)octets[1];
        out_v4[2] = (uint8_t)octets[2];
        out_v4[3] = (uint8_t)octets[3];
        return XURY_OK;
    }

    return XURY_ERR_NOT_CONNECTED;
}

/*
 * ============================================================================
 * INTERNAL — SEND / RECEIVE
 * ============================================================================
 */

/*
 * Send a MAP request and wait for the matching response.
 *
 * The response must:
 *   - come from the gateway endpoint we sent to,
 *   - have version == PCP_VERSION,
 *   - have opcode == PCP_OP_MAP + 0x80,
 *   - echo our nonce.
 *
 * Datagrams that do not match are ignored; the loop continues until
 * the deadline. If the deadline passes with no matching datagram,
 * XURY_ERR_TIMEOUT is returned.
 */
static xury_err_t exchange_once(xury_sock_t s,
                                const xury_endpoint_t *gateway,
                                const uint8_t client_v4[4],
                                const uint8_t nonce[12],
                                uint16_t internal_port,
                                pcp_response_t *out_resp)
{
    uint8_t req[PCP_MSG_LEN];
    xury_err_t rc = build_map_request(req, sizeof(req),
                                      client_v4,
                                      internal_port,
                                      nonce);
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
                           (uint64_t)PCP_TIMEOUT_MS;

    for (;;) {
        uint64_t now = xury_platform_time_ms();
        if (now >= deadline_ms) {
            return XURY_ERR_TIMEOUT;
        }
        uint32_t wait = (uint32_t)(deadline_ms - now);
        if (wait == 0u) {
            wait = 1u;
        }

        uint8_t recvbuf[PCP_RECV_CAP];
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
         * The response must come from the gateway we sent to.
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

        pcp_response_t resp;
        rc = decode_map_response(recvbuf, recvd, &resp);
        if (rc != XURY_OK) {
            continue;
        }

        if (resp.version != PCP_VERSION) {
            continue;
        }

        /*
         * Response opcode must be MAP + 0x80. Anything else is a
         * different PCP opcode (or malformed); we are only waiting
         * for our own MAP response.
         */
        if (resp.opcode != (uint8_t)(PCP_OP_MAP + PCP_RESPONSE_BIT)) {
            continue;
        }

        /*
         * The nonce must match ours. A non-matching response is
         * not for this request.
         */
        if (!nonce_equal(resp.nonce, nonce)) {
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

xury_err_t xury_weapon_pcp_try(const xury_weapon_attempt_ctx_t *ctx,
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
    if (!ctx->applicability_ctx.pcp_available) {
        return XURY_OK;   /* success = false, elapsed_ms = 0 */
    }

    /*
     * PCP creates a port mapping for a local listener. Without a
     * local port there is nothing to expose. See weapon_ops.h.
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
        return XURY_OK;
    }
    gateway.port = (uint16_t)PCP_PORT;

    /*
     * ------------------------------------------------------------------
     * Step 2: obtain our own IPv4 address
     * ------------------------------------------------------------------
     *
     * PCP requires the client IP to be carried in the request. We
     * ask the platform for one of our non-loopback IPv4 addresses.
     * If there is none, the weapon fails honestly; it does not
     * invent an address.
     */
    uint8_t client_v4[4];
    rc = get_client_ipv4(client_v4);
    if (rc != XURY_OK) {
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;
    }

    /*
     * ------------------------------------------------------------------
     * Step 3: generate a nonce
     * ------------------------------------------------------------------
     *
     * A nonce is required by RFC 6887 and must be echoed by the
     * gateway. If the secure RNG is unavailable, fail honestly;
     * a weak nonce is not acceptable.
     */
    uint8_t nonce[12];
    rc = make_nonce(nonce);
    if (rc != XURY_OK) {
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;
    }

    /*
     * ------------------------------------------------------------------
     * Step 4: open a UDP socket
     * ------------------------------------------------------------------
     */
    xury_sock_t s = XURY_SOCK_INVALID;
    rc = xury_sock_create(XURY_AF_INET, XURY_SOCK_UDP, &s);
    if (rc != XURY_OK) {
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;
    }

    xury_endpoint_t bind_ep;
    memset(&bind_ep, 0, sizeof(bind_ep));
    bind_ep.family = XURY_AF_INET;
    bind_ep.port = 0u;
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
     * Step 5: send MAP request, wait for response
     * ------------------------------------------------------------------
     */
    pcp_response_t resp;
    rc = exchange_once(s, &gateway, client_v4, nonce,
                       ctx->local_port, &resp);
    (void)xury_sock_close(s);

    if (rc != XURY_OK) {
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;
    }

    /*
     * ------------------------------------------------------------------
     * Step 6: interpret the result code
     * ------------------------------------------------------------------
     *
     * RFC 6887 §7.4: result code 0 is SUCCESS. Any other value is a
     * defined error. We do not distinguish them for v1.
     */
    bool success = (resp.result_code == 0u);

    out->success = success;
    if (success) {
        /*
         * established_peer semantics for PCP match upnp.c and
         * natpmp.c: the weapon created a mapping for ctx->peer; it
         * did not contact the peer. See weapon_ops.h.
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
