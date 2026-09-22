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

#ifndef XURY_SCAN_INTERNAL_PROBING_H
#define XURY_SCAN_INTERNAL_PROBING_H

/*
 * ============================================================================
 * XURY SCAN — PROBING (F.2)
 * ============================================================================
 *
 * Active measurements against caller-supplied peer endpoints.
 *
 * Probing sends a small Xury-defined probe packet (XPRB) to each peer
 * and, for the first peer that answers, collects a fixed number of
 * observed external endpoints. Those observations feed F.3a (math)
 * and F.3b (classification); probing itself does not interpret them.
 *
 * ----------------------------------------------------------------------------
 * No server, no STUN
 * ----------------------------------------------------------------------------
 *
 * Xury is a no-server P2P NAT traversal engine. Probing does not
 * contact any third-party service, and no address is embedded in the
 * library. The caller supplies every endpoint that will be probed.
 * Where the caller gets those endpoints from (a DHT, a bootstrap
 * exchange, an application-specific channel) is not Xury's concern.
 *
 * The probe protocol is a minimal Xury-defined exchange, not STUN.
 * It is intentionally not interoperable with STUN servers. A peer
 * that answers a probe must be running Xury-compatible code.
 *
 * ----------------------------------------------------------------------------
 * The XPRB protocol
 * ----------------------------------------------------------------------------
 *
 * Every probe packet begins with a 4-byte magic and a 1-byte type.
 *
 *   REQUEST (15 bytes):
 *
 *     offset  size  field
 *     ------  ----  -----
 *     0       4     magic       "XPRB"
 *     4       1     type        0x01
 *     5       8     nonce       random, big-endian
 *     13      2     local_port  sender's local port, big-endian
 *
 *   RESPONSE (36 bytes):
 *
 *     offset  size  field
 *     ------  ----  -----
 *     0       4     magic       "XPRB"
 *     4       1     type        0x02
 *     5       8     nonce       echoed from the request, big-endian
 *     13      2     observed_port   source port the responder saw
 *     15      4     observed_ipv4   source IPv4, big-endian (0 if v6)
 *     19      16    observed_ipv6   source IPv6 (0 if v4)
 *     35      1     observed_family 0 = UNSPEC, 4 = INET, 6 = INET6
 *
 * The nonce is an opaque correlation token. The requester verifies
 * that the nonce in the response matches the nonce in its request, so
 * a stray or spoofed packet cannot be mistaken for an answer.
 *
 * The observed_* fields describe the requester's source endpoint as
 * the responder saw it. This is the information the requester cannot
 * obtain locally: its own external mapping. The responder copies it
 * from the packet header, not from any external source.
 *
 * ----------------------------------------------------------------------------
 * What probing does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - Does not resolve the gateway MAC. (Deferred, as in F.1.)
 *
 *   - Does not measure TTL to the gateway or to the peer. TTL
 *     discovery requires raw-socket capability that is not portable
 *     across the platforms Xury targets. Both TTL fields stay at 0.
 *
 *   - Does not interpret the observed endpoints. It collects them.
 *     F.3a/F.3b analyze them later.
 *
 *   - Does not assume that a sequence of observed ports represents a
 *     NAT allocation sequence. It records observations in order; any
 *     pattern is a hypothesis for F.3b, not a fact here.
 *
 * ----------------------------------------------------------------------------
 * Selection rules
 * ----------------------------------------------------------------------------
 *
 * probe collection target: the first peer in peer_targets[] that
 * answers a REQUEST. Every other peer is probed once, to contribute
 * to peer_reachable and peer_supports_ipv6.
 *
 * For the selected peer, up to XURY_PROBE_PORT_SAMPLES REQUESTs are
 * sent, each with a fresh nonce, and each RESPONSE contributes one
 * observed external port to external_ports[].
 *
 * ----------------------------------------------------------------------------
 * Status semantics
 * ----------------------------------------------------------------------------
 *
 *   XURY_SCAN_SUB_SKIPPED   never produced by probing
 *   XURY_SCAN_SUB_OK        at least one peer answered; observed
 *                           samples may be fewer than the maximum
 *   XURY_SCAN_SUB_PARTIAL   some peers answered, some did not
 *   XURY_SCAN_SUB_FAILED    no peer answered, or peer_count == 0
 *
 * The function returns XURY_ERR_INVAL only for invalid arguments
 * (out == NULL, or peer_count == 0, or peer_targets == NULL with
 * peer_count > 0). Platform and peer-level failures are recorded in
 * the status field, not propagated, so the scan orchestrator can
 * decide how much to trust a partial result.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 * - src/platform/platform.h     (socket create/bind/sendto/recvfrom,
 *                                monotonic time)
 * - src/core/internal/bytes.h   (packet encode/decode, big-endian)
 * - src/core/internal/rand.h    (nonce generation)
 * - <xury/scan.h>               (xury_probing_result_t)
 *
 * No allocation, no I/O beyond the platform sockets, no global state.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/err.h>
#include <xury/scan.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * PUBLIC ENTRY POINT
 * ============================================================================
 */

/*
 * Probe a set of caller-supplied peer endpoints.
 *
 * Arguments:
 *   peer_targets  array of peer endpoints; must not be NULL if
 *                 peer_count > 0
 *   peer_count    number of entries in peer_targets[]
 *   timeout_ms    total budget for the probing sub-phase. 0 means
 *                 "no deadline" (the call will still return once all
 *                 peers have been tried or timed out individually).
 *   out           result; must not be NULL
 *
 * Returns:
 *   XURY_OK        out filled, possibly with status PARTIAL or
 *                  FAILED. The caller must inspect out->status.
 *   XURY_ERR_INVAL out is NULL, or peer_count == 0, or
 *                  peer_targets is NULL with peer_count > 0
 *
 * Never allocates. Sends only XPRB packets. Blocks until the budget
 * is exhausted or all peers have been tried.
 */
xury_err_t xury_scan_probing(const xury_endpoint_t *peer_targets,
                             size_t peer_count,
                             uint32_t timeout_ms,
                             xury_probing_result_t *out);

/*
 * ============================================================================
 * END OF XURY SCAN INTERNAL PROBING HEADER
 * ============================================================================
 */

#endif /* XURY_SCAN_INTERNAL_PROBING_H */
