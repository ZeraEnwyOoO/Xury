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
 * XURY SCAN — PROBING IMPLEMENTATION (F.2)
 * ============================================================================
 *
 * Real implementation of src/scan/internal/probing.h.
 *
 * Sends XPRB REQUEST packets to caller-supplied peers, collects
 * RESPONSE packets, and records observed external endpoints.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - Does not contact any server. Xury is no-server.
 *
 *   - Does not embed any address. All targets come from the caller.
 *
 *   - Does not measure TTL. ttl_gateway and ttl_peer stay at 0.
 *
 *   - Does not interpret observed endpoints. They are recorded in
 *     the order they arrive; any pattern is F.3b's concern.
 *
 *   - Does not assume that the observed port sequence is a NAT
 *     allocation sequence. It records what was observed.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 * - src/platform/platform.h     (sockets, monotonic time)
 * - src/core/internal/bytes.h   (packet encode/decode)
 * - src/core/internal/rand.h    (nonce generation)
 * - src/api/internal/types.h    (xury_format_ip, endpoint helpers)
 * - src/scan/internal/probing.h
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
#include <xury/scan.h>

#include "platform/platform.h"
#include "core/internal/bytes.h"
#include "core/internal/rand.h"
#include "api/internal/types.h"
#include "scan/internal/probing.h"

/*
 * ============================================================================
 * PROTOCOL CONSTANTS
 * ============================================================================
 *
 * These are wire-format constants, not policy knobs. They are defined
 * here because they are shared between encode and decode paths and
 * nowhere else. A peer that does not speak this exact format will
 * not be understood, which is the intended contract.
 */

/* Magic bytes: 'X' 'P' 'R' 'B' */
#define XPRB_MAGIC_0 0x58u
#define XPRB_MAGIC_1 0x50u
#define XPRB_MAGIC_2 0x52u
#define XPRB_MAGIC_3 0x42u

/* Type field */
#define XPRB_TYPE_REQUEST  0x01u
#define XPRB_TYPE_RESPONSE 0x02u

/* Packet sizes */
#define XPRB_REQUEST_SIZE  15u
#define XPRB_RESPONSE_SIZE 36u

/* observed_family values (deliberately NOT the AF_* numeric values,
 * because the wire format must not depend on the host's AF_* layout).
 */
#define XPRB_FAMILY_UNSPEC 0u
#define XPRB_FAMILY_INET   4u
#define XPRB_FAMILY_INET6  6u

/*
 * ============================================================================
 * INTERNAL — PACKET ENCODE
 * ============================================================================
 */

/*
 * Encode an XPRB REQUEST into buf.
 *
 * buf must have room for XPRB_REQUEST_SIZE bytes.
 * local_port is written in big-endian; nonce likewise.
 *
 * Returns XURY_OK on success, XURY_ERR_INVAL if buf is NULL.
 */
static xury_err_t xprb_encode_request(uint8_t *buf,
                                      size_t cap,
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
    (void)xury_bytes_put_be16(&c, (uint16_t)XPRB_TYPE_REQUEST);
    (void)xury_bytes_put_be64(&c, nonce);
    (void)xury_bytes_put_be16(&c, local_port);

    return XURY_OK;
}

/*
 * Encode an XPRB RESPONSE into buf.
 *
 * buf must have room for XPRB_RESPONSE_SIZE bytes.
 *
 * The observed_* arguments describe the source endpoint the responder
 * saw on the incoming REQUEST. Exactly one of ipv4_bytes / ipv6_bytes
 * is meaningful, selected by observed_family.
 *
 *   observed_family == XPRB_FAMILY_INET   -> ipv4_bytes[4] used
 *   observed_family == XPRB_FAMILY_INET6  -> ipv6_bytes[16] used
 *   observed_family == XPRB_FAMILY_UNSPEC -> both ignored
 *
 * Returns XURY_OK on success, XURY_ERR_INVAL if buf is NULL.
 */
static xury_err_t xprb_encode_response(uint8_t *buf,
                                       size_t cap,
                                       uint64_t nonce,
                                       uint16_t observed_port,
                                       const uint8_t *ipv4_bytes,
                                       const uint8_t *ipv6_bytes,
                                       uint8_t observed_family)
{
    if (buf == NULL) {
        return XURY_ERR_INVAL;
    }
    if (cap < XPRB_RESPONSE_SIZE) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }

    xury_cursor_t c;
    xury_cursor_init(&c, buf, cap);

    uint8_t magic[4] = {
        XPRB_MAGIC_0, XPRB_MAGIC_1, XPRB_MAGIC_2, XPRB_MAGIC_3
    };
    (void)xury_bytes_put(&c, magic, 4u);
    (void)xury_bytes_put_be16(&c, (uint16_t)XPRB_TYPE_RESPONSE);
    (void)xury_bytes_put_be64(&c, nonce);
    (void)xury_bytes_put_be16(&c, observed_port);

    uint8_t v4[4]  = { 0u, 0u, 0u, 0u };
    uint8_t v6[16] = { 0u };

    if (observed_family == XPRB_FAMILY_INET && ipv4_bytes != NULL) {
        memcpy(v4, ipv4_bytes, 4u);
    } else if (observed_family == XPRB_FAMILY_INET6 && ipv6_bytes != NULL) {
        memcpy(v6, ipv6_bytes, 16u);
    }

    (void)xury_bytes_put(&c, v4, 4u);
    (void)xury_bytes_put(&c, v6, 16u);
    (void)xury_bytes_put(&c, &observed_family, 1u);

    return XURY_OK;
}

/*
 * ============================================================================
 * INTERNAL — PACKET DECODE
 * ============================================================================
 */

typedef struct {
    uint8_t  type;
    uint64_t nonce;
    uint16_t port;              /* local_port (REQUEST) or observed_port (RESPONSE) */
    uint8_t  observed_ipv4[4];
    uint8_t  observed_ipv6[16];
    uint8_t  observed_family;
} xprb_packet_t;

/*
 * Verify the 4-byte magic at the start of buf.
 */
static bool xprb_magic_ok(const uint8_t *buf, size_t len)
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
 * Decode a packet into *out.
 *
 * Returns:
 *   XURY_OK                   decoded
 *   XURY_ERR_INVAL            buf or out is NULL
 *   XURY_ERR_BUFFER_TOO_SMALL len too short for the declared type
 *   XURY_ERR_BAD_ENDPOINT     magic mismatch or unknown type
 */
static xury_err_t xprb_decode(const uint8_t *buf,
                              size_t len,
                              xprb_packet_t *out)
{
    if (buf == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (!xprb_magic_ok(buf, len)) {
        return XURY_ERR_BAD_ENDPOINT;
    }

    memset(out, 0, sizeof(*out));

    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, len);

    const uint8_t *magic = NULL;
    (void)xury_bytes_get_slice(&c, &magic, 4u);

    uint16_t type = 0u;
    if (xury_bytes_get_be16(&c, &type) != XURY_OK) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    out->type = (uint8_t)type;

    uint64_t nonce = 0u;
    if (xury_bytes_get_be64(&c, &nonce) != XURY_OK) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    out->nonce = nonce;

    uint16_t port = 0u;
    if (xury_bytes_get_be16(&c, &port) != XURY_OK) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    out->port = port;

    if (out->type == XPRB_TYPE_REQUEST) {
        /* REQUEST ends here. */
        return XURY_OK;
    }
    if (out->type != XPRB_TYPE_RESPONSE) {
        return XURY_ERR_BAD_ENDPOINT;
    }

    /* RESPONSE continues: v4 + v6 + family. */
    const uint8_t *v4 = NULL;
    if (xury_bytes_get_slice(&c, &v4, 4u) != XURY_OK) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(out->observed_ipv4, v4, 4u);

    const uint8_t *v6 = NULL;
    if (xury_bytes_get_slice(&c, &v6, 16u) != XURY_OK) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(out->observed_ipv6, v6, 16u);

    uint8_t fam = 0u;
    if (xury_bytes_get(&c, &fam, 1u) != XURY_OK) {
        return XURY_ERR_BUFFER_TOO_SMALL;
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
 * Generate a random nonce.
 *
 * Uses the secure RNG. If the secure source is not available (e.g.
 * before the platform layer is linked), the fast generator is used.
 * Nonces are correlation tokens, not secrets; the fast generator is
 * acceptable here, and using it does not weaken the protocol.
 *
 * A nonce of 0 is valid, but we avoid it so that a zeroed packet is
 * unambiguously not a valid request.
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
 * INTERNAL — SOURCE ENDPOINT
 * ============================================================================
 */

/*
 * Fill an xury_endpoint_t from the RESPONSE observed_* fields.
 *
 * Returns true if the family is one of the two we understand and the
 * address converts to a string, false otherwise. On false, *out is
 * left with family UNSPEC.
 */
static bool endpoint_from_response(const xprb_packet_t *pkt,
                                   xury_endpoint_t *out)
{
    memset(out, 0, sizeof(*out));
    out->family = XURY_AF_UNSPEC;

    if (pkt->observed_family == XPRB_FAMILY_INET) {
        if (xury_format_ip(XURY_AF_INET,
                           pkt->observed_ipv4, 4u,
                           out->ip, sizeof(out->ip)) != XURY_OK) {
            return false;
        }
        out->family = XURY_AF_INET;
        out->port   = pkt->port;
        return true;
    }
    if (pkt->observed_family == XPRB_FAMILY_INET6) {
        if (xury_format_ip(XURY_AF_INET6,
                           pkt->observed_ipv6, 16u,
                           out->ip, sizeof(out->ip)) != XURY_OK) {
            return false;
        }
        out->family = XURY_AF_INET6;
        out->port   = pkt->port;
        return true;
    }
    return false;
}

/*
 * ============================================================================
 * INTERNAL — SOCKET
 * ============================================================================
 */

/*
 * Create and bind a UDP socket for probing.
 *
 * Family selection: we bind a single IPv4 socket. Probing over IPv6
 * would need a second socket; the current protocol and the current
 * result struct are family-agnostic, but the transport is IPv4 for
 * now. This keeps the first implementation small and honest; IPv6
 * probing is a future addition, not a silent half-measure.
 *
 * The socket is bound to an ephemeral local port. The chosen port is
 * reported through *out_local so the caller can fill local_ports[].
 */
static xury_err_t make_probe_socket(xury_sock_t *out_sock,
                                    xury_endpoint_t *out_local)
{
    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = xury_platform_sock_create(XURY_AF_INET,
                                              XURY_PLATFORM_SOCK_UDP,
                                              &s);
    if (rc != XURY_OK) {
        return rc;
    }

    xury_endpoint_t bind_ep;
    memset(&bind_ep, 0, sizeof(bind_ep));
    bind_ep.family = XURY_AF_INET;
    bind_ep.port   = 0u;
    /* Empty ip string means INADDR_ANY for the platform layer. */
    bind_ep.ip[0] = '\0';

    rc = xury_platform_sock_bind(s, &bind_ep);
    if (rc != XURY_OK) {
        (void)xury_platform_sock_close(s);
        return rc;
    }

    xury_endpoint_t local;
    memset(&local, 0, sizeof(local));
    rc = xury_platform_sock_local(s, &local);
    if (rc != XURY_OK) {
        (void)xury_platform_sock_close(s);
        return rc;
    }

    *out_sock = s;
    *out_local = local;
    return XURY_OK;
}

/*
 * Send a REQUEST and wait for a matching RESPONSE.
 *
 * timeout_ms is the deadline for this single exchange. On timeout,
 * XURY_ERR_TIMEOUT is returned. On malformed or mismatched packets,
 * the function keeps waiting until the deadline.
 *
 * On success, *out_pkt holds the decoded RESPONSE.
 */
static xury_err_t exchange_once(xury_sock_t s,
                                const xury_endpoint_t *peer,
                                uint64_t nonce,
                                uint16_t local_port,
                                uint32_t timeout_ms,
                                xprb_packet_t *out_pkt)
{
    uint8_t req[XPRB_REQUEST_SIZE];
    xury_err_t rc = xprb_encode_request(req, sizeof(req),
                                        nonce, local_port);
    if (rc != XURY_OK) {
        return rc;
    }

    size_t sent = 0u;
    rc = xury_platform_sock_sendto(s, req, sizeof(req),
                                   peer, &sent);
    if (rc != XURY_OK) {
        return rc;
    }
    if (sent != sizeof(req)) {
        return XURY_ERR_PARTIAL_WRITE;
    }

    uint64_t deadline = xury_platform_time_ms() + (uint64_t)timeout_ms;
    if (timeout_ms == 0u) {
        deadline = 0u;  /* no deadline */
    }

    for (;;) {
        uint32_t wait = 0u;
        if (deadline != 0u) {
            uint64_t now = xury_platform_time_ms();
            if (now >= deadline) {
                return XURY_ERR_TIMEOUT;
            }
            uint64_t remaining = deadline - now;
            if (remaining > 0xFFFFFFFFu) {
                remaining = 0xFFFFFFFFu;
            }
            wait = (uint32_t)remaining;
        } else {
            wait = 0u;
        }

        uint8_t buf[XPRB_RESPONSE_SIZE + 16u];
        xury_endpoint_t from;
        size_t recvd = 0u;

        rc = xury_platform_sock_recvfrom(s, buf, sizeof(buf),
                                         &from, &recvd, wait);
        if (rc == XURY_ERR_TIMEOUT) {
            /*
             * recvfrom with a short wait returning TIMEOUT is normal;
             * we loop until the outer deadline.
             */
            continue;
        }
        if (rc != XURY_OK) {
            /*
             * Any other recvfrom failure is not recoverable here.
             * The caller will record it.
             */
            return rc;
        }

        xprb_packet_t pkt;
        if (xprb_decode(buf, recvd, &pkt) != XURY_OK) {
            continue;   /* ignore malformed */
        }
        if (pkt.type != XPRB_TYPE_RESPONSE) {
            continue;
        }
        if (pkt.nonce != nonce) {
            continue;   /* not our response */
        }

        *out_pkt = pkt;
        return XURY_OK;
    }
}

/*
 * ============================================================================
 * INTERNAL — RTT
 * ============================================================================
 */

/*
 * Append an RTT sample to the result, capped at XURY_PROBE_RTT_SAMPLES.
 * Silently drops extra samples beyond the cap.
 */
static void record_rtt(xury_probing_result_t *out, uint32_t rtt_ms)
{
    if (out->rtt_count >= XURY_PROBE_RTT_SAMPLES) {
        return;
    }
    out->rtt_samples[out->rtt_count] = rtt_ms;
    out->rtt_count++;
}

/*
 * Recompute rtt_avg_ms from the current samples.
 */
static void recompute_rtt_avg(xury_probing_result_t *out)
{
    if (out->rtt_count == 0u) {
        out->rtt_avg_ms = 0u;
        return;
    }
    uint64_t sum = 0u;
    for (uint8_t i = 0; i < out->rtt_count; i++) {
        sum += out->rtt_samples[i];
    }
    out->rtt_avg_ms = (uint32_t)(sum / out->rtt_count);
}

/*
 * ============================================================================
 * INTERNAL — RESULT HELPERS
 * ============================================================================
 */

static void probing_clear(xury_probing_result_t *r)
{
    memset(r, 0, sizeof(*r));
    r->status = XURY_SCAN_SUB_SKIPPED;
}

static void record_local_port(xury_probing_result_t *out, uint16_t port)
{
    if (out->sample_count >= XURY_PROBE_PORT_SAMPLES) {
        return;
    }
    out->local_ports[out->sample_count] = port;
}

static void record_external_port(xury_probing_result_t *out, uint16_t port)
{
    if (out->sample_count >= XURY_PROBE_PORT_SAMPLES) {
        return;
    }
    out->external_ports[out->sample_count] = port;
    out->sample_count++;
    out->external_ports_known = true;
}

/*
 * ============================================================================
 * PUBLIC ENTRY POINT
 * ============================================================================
 */

xury_err_t xury_scan_probing(const xury_endpoint_t *peer_targets,
                             size_t peer_count,
                             uint32_t timeout_ms,
                             xury_probing_result_t *out)
{
    if (out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (peer_count == 0u) {
        return XURY_ERR_INVAL;
    }
    if (peer_targets == NULL) {
        return XURY_ERR_INVAL;
    }

    probing_clear(out);

    uint64_t t0 = xury_platform_time_ms();

    xury_sock_t s = XURY_SOCK_INVALID;
    xury_endpoint_t local;
    xury_err_t rc = make_probe_socket(&s, &local);
    if (rc != XURY_OK) {
        out->status = XURY_SCAN_SUB_FAILED;
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;
    }

    /*
     * ------------------------------------------------------------------
     * Phase 1: single probe to each peer
     * ------------------------------------------------------------------
     *
     * The first peer that answers a REQUEST becomes the collection
     * target for phase 2. Every answering peer contributes to
     * peer_reachable and, if the answer's observed family is IPv6,
     * to peer_supports_ipv6.
     *
     * We use a per-peer timeout derived from the total budget. The
     * division is deliberately conservative: even with many peers,
     * every peer gets a fair slice.
     */
    uint32_t per_peer_ms = timeout_ms;
    if (per_peer_ms != 0u && peer_count > 1u) {
        per_peer_ms = per_peer_ms / (uint32_t)peer_count;
        if (per_peer_ms == 0u) {
            per_peer_ms = 1u;
        }
    }

    size_t first_responder_index = (size_t)-1;
    bool any_responded = false;

    for (size_t i = 0; i < peer_count; i++) {
        uint64_t nonce = make_nonce();
        xprb_packet_t pkt;

        uint64_t send_time = xury_platform_time_ms();
        rc = exchange_once(s, &peer_targets[i], nonce,
                           local.port, per_peer_ms, &pkt);
        uint64_t recv_time = xury_platform_time_ms();

        if (rc == XURY_OK) {
            any_responded = true;
            out->peer_reachable = true;

            if (pkt.observed_family == XPRB_FAMILY_INET6) {
                out->peer_supports_ipv6 = true;
            }

            uint32_t rtt = (recv_time >= send_time)
                               ? (uint32_t)(recv_time - send_time)
                               : 0u;
            record_rtt(out, rtt);

            if (first_responder_index == (size_t)-1) {
                first_responder_index = i;
            }
        }
        /* Non-responding peers are simply not counted. */
    }

    if (!any_responded) {
        (void)xury_platform_sock_close(s);
        recompute_rtt_avg(out);
        out->status = XURY_SCAN_SUB_FAILED;
        out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
        return XURY_OK;
    }

    /*
     * ------------------------------------------------------------------
     * Phase 2: collect external port samples from the first responder
     * ------------------------------------------------------------------
     *
     * Each iteration sends one REQUEST with a fresh nonce and records
     * one observed external port. The local port used for the probe
     * is also recorded, in the same slot, so the two arrays stay
     * aligned.
     *
     * We do NOT assume these samples form a NAT allocation sequence.
     * They are observations, recorded in arrival order. F.3a/F.3b
     * decide later whether a pattern is present.
     */
    const xury_endpoint_t *target = &peer_targets[first_responder_index];

    /*
     * Account for the probe we already sent in phase 1: its observed
     * external port, if any, is the first sample. To keep the code
     * simple and the accounting honest, we re-derive it here by
     * probing again. The cost is one extra round trip; the benefit
     * is a single code path for sample collection.
     *
     * (A future optimization may reuse the phase-1 response. Until
     * then, correctness over cleverness.)
     */
    for (uint8_t i = 0; i < XURY_PROBE_PORT_SAMPLES; i++) {
        uint64_t nonce = make_nonce();
        xprb_packet_t pkt;

        rc = exchange_once(s, target, nonce, local.port,
                           per_peer_ms, &pkt);
        if (rc != XURY_OK) {
            /*
             * The target stopped answering. We keep whatever samples
             * we have and report PARTIAL below. A sample is an
             * observation; a missing sample is not filled in.
             */
            break;
        }

        record_local_port(out, local.port);
        record_external_port(out, pkt.port);
    }

    (void)xury_platform_sock_close(s);

    recompute_rtt_avg(out);

    /*
     * Status:
     *   - If we collected at least one external port, OK.
     *   - If not, PARTIAL: peers answered, but no external port was
     *     captured. That is still an honest partial result.
     *
     * TTL fields stay 0 by design (deferred, see probing.h).
     */
    if (out->sample_count > 0u) {
        out->status = XURY_SCAN_SUB_OK;
    } else {
        out->status = XURY_SCAN_SUB_PARTIAL;
    }

    out->elapsed_ms = (uint32_t)(xury_platform_time_ms() - t0);
    return XURY_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
