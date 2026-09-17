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

#ifndef XURY_PEER_H
#define XURY_PEER_H

/*
 * ============================================================================
 * XURY PEER-ASSISTED NAT TRAVERSAL
 * ============================================================================
 *
 * Xury has no servers. Instead, peers help each other.
 *
 * Two peer-assisted mechanisms:
 *
 *   1. MIRROR
 *      A peer reflects our public endpoint back to us, like a mirror.
 *      Replaces the role of a STUN server — but the "server" is just
 *      another peer.
 *
 *      Flow:
 *        A sends a probe to B.
 *        B sees A's public ip:port from the packet header.
 *        B sends back a response with that ip:port.
 *        A now knows its public endpoint.
 *
 *   2. RELAY
 *      A peer forwards traffic between two peers that cannot reach
 *      each other directly. Replaces the role of a TURN server — but
 *      the "server" is just another peer.
 *
 *      Flow:
 *        A asks C to relay to B.
 *        C agrees (or refuses).
 *        A <-> C <-> B
 *
 *   3. UPGRADE
 *      When a relay path exists, attempt to replace it with a direct
 *      path. The relay connection is kept until the direct connection
 *      succeeds, then torn down.
 *
 *      Flow:
 *        A <-> C <-> B       (relay established)
 *        A and B coordinate a direct punch via C.
 *        A <-> B             (direct succeeds)
 *        A and C tear down relay.
 *
 * ============================================================================
 *
 * IMPORTANT — Scope boundary:
 *
 *   Peer discovery (finding peers, bootstrapping, DHT) is NOT Xury.
 *   The host product provides peers via xury_add_peer().
 *   Xury uses those peers only for NAT traversal.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/version.h>
#include <xury/types.h>
#include <xury/err.h>
#include <xury/engine.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * MIRROR
 * ============================================================================
 *
 * Ask a peer to reflect our public endpoint.
 *
 * This is the "no-STUN" replacement. The peer is a regular peer, not a
 * dedicated server. Any reachable peer can serve as a mirror.
 *
 * Requirements:
 *   - The peer must be reachable (its endpoint must be known).
 *   - The peer must implement Xury's mirror protocol (any host using
 *     this library does so automatically).
 *
 * Result:
 *   out_self receives the endpoint the peer saw for us.
 *   This is our public ip:port as observed from outside the NAT.
 *
 * Cost:
 *   One probe + one response. Small.
 *
 * Failure modes:
 *   XURY_ERR_MIRROR_FAIL          — no response
 *   XURY_ERR_MIRROR_BAD_RESPONSE  — response malformed or spoofed
 *   XURY_ERR_PEER_UNREACHABLE     — peer not reachable
 *   XURY_ERR_TIMEOUT              — no response in time
 */

xury_err_t xury_mirror_query(xury_engine_t *e,
                             const xury_endpoint_t *peer,
                             xury_endpoint_t *out_self,
                             uint32_t timeout_ms);

/*
 * Ask several peers in sequence, until one answers.
 *
 * Useful when some peers are behind NAT themselves and cannot
 * reflect for us. Skips peers that fail and tries the next.
 *
 * Arguments:
 *   peers        — array of peer endpoints
 *   peer_count   — number of entries in peers[]
 *   out_self     — receives the first consistent public endpoint
 *   timeout_ms   — total budget across all peers
 *
 * Returns:
 *   XURY_OK                      — at least one peer answered
 *   XURY_ERR_MIRROR_FAIL         — all peers failed
 *   XURY_ERR_INVAL               — e, peers or out_self is NULL,
 *                                   or peer_count == 0
 *   XURY_ERR_TIMEOUT             — budget exceeded
 *
 * Threading:
 *   Blocks the calling thread.
 */
xury_err_t xury_mirror_query_any(xury_engine_t *e,
                                 const xury_endpoint_t *peers,
                                 size_t peer_count,
                                 xury_endpoint_t *out_self,
                                 uint32_t timeout_ms);

/*
 * Classify our NAT by asking multiple peers.
 *
 * Uses the fact that a symmetric NAT will show DIFFERENT external
 * ports to different destinations, while a cone NAT shows the same
 * port regardless of destination.
 *
 * Algorithm:
 *   1. Ask peer A -> endpoint_a
 *   2. Ask peer B -> endpoint_b
 *   3. Ask peer C -> endpoint_c
 *   4. If all three IPs and ports match  -> full cone
 *      If all IPs match but ports differ -> symmetric
 *      If ports match but some IPs differ -> restricted cone
 *      Else -> unknown
 *
 * This is a heuristic. The result is a best-effort classification,
 * not an authoritative one.
 *
 * Arguments:
 *   peers        — at least 2 peer endpoints
 *   peer_count   — number of entries
 *   out_type     — receives the classification
 *   timeout_ms   — total budget
 *
 * Returns:
 *   XURY_OK                       — classification produced
 *   XURY_ERR_INVAL                — bad arguments
 *   XURY_ERR_MIRROR_FAIL          — too few peers answered
 *   XURY_ERR_TIMEOUT              — budget exceeded
 */
xury_err_t xury_mirror_classify(xury_engine_t *e,
                                const xury_endpoint_t *peers,
                                size_t peer_count,
                                xury_nat_type_t *out_type,
                                uint32_t timeout_ms);

/*
 * ============================================================================
 * RELAY
 * ============================================================================
 *
 * Ask a peer to forward traffic between us and a target peer.
 *
 * The relay peer is a regular peer, not a dedicated server.
 * Any reachable peer can serve as a relay if it consents.
 *
 * Requirements:
 *   - The relay peer must be reachable from both sides.
 *   - The relay peer must implement Xury's relay protocol.
 *
 * The relay is used when:
 *   - direct hole punch failed
 *   - symmetric NAT prevents punch
 *   - CGNAT blocks all outbound
 *
 * Cost:
 *   - All traffic goes through the relay peer.
 *   - Adds one hop of latency.
 *   - Consumes the relay peer's bandwidth.
 */

/*
 * Request a relay from the given helper peer to the given target peer.
 *
 * On success, the engine opens a relay path:
 *
 *   us <-> helper <-> target
 *
 * and xury_get_socket_fd() returns a socket that reads/writes through
 * the relay. The host does not need to be aware of the relay.
 *
 * Arguments:
 *   e             — engine handle
 *   helper        — endpoint of the relay peer
 *   target        — endpoint of the peer we want to reach
 *   timeout_ms    — budget
 *
 * Returns:
 *   XURY_OK                 — relay established
 *   XURY_ERR_INVAL          — bad arguments
 *   XURY_ERR_RELAY_REFUSED  — helper refused
 *   XURY_ERR_RELAY_FAIL     — relay setup failed
 *   XURY_ERR_PEER_UNREACHABLE — helper or target unreachable
 *   XURY_ERR_TIMEOUT        — budget exceeded
 *   XURY_ERR_BUSY           — another relay in progress
 *   XURY_ERR_NOT_READY      — engine not started
 *
 * Threading:
 *   Blocks the calling thread.
 */
xury_err_t xury_relay_request(xury_engine_t *e,
                              const xury_endpoint_t *helper,
                              const xury_endpoint_t *target,
                              uint32_t timeout_ms);

/*
 * Accept a relay request from another peer.
 *
 * If a host wants to act as a relay for others, it must enable this.
 * By default, Xury does NOT accept relay requests.
 *
 * When accepted, the engine opens a relay path between the requester
 * and the target and forwards traffic until either side closes.
 *
 * Arguments:
 *   e           — engine handle
 *   requester   — who is asking
 *   target      — who they want to reach
 *   timeout_ms  — how long to keep the relay open
 *
 * Returns:
 *   XURY_OK                  — relay accepted and running
 *   XURY_ERR_INVAL           — bad arguments
 *   XURY_ERR_NOT_SUPPORTED   — relaying disabled in config
 *   XURY_ERR_PEER_UNREACHABLE— target unreachable
 *   XURY_ERR_BUSY            — too many active relays
 *   XURY_ERR_TIMEOUT         — budget exceeded
 */
xury_err_t xury_relay_accept(xury_engine_t *e,
                             const xury_endpoint_t *requester,
                             const xury_endpoint_t *target,
                             uint32_t timeout_ms);

/*
 * Close the current relay.
 *
 * Safe to call when no relay is active.
 */
xury_err_t xury_relay_close(xury_engine_t *e);

/*
 * Return the number of peers currently using this engine as a relay.
 *
 * Only meaningful if xury_relay_accept() has been called.
 */
size_t xury_relay_active_count(const xury_engine_t *e);

/*
 * ============================================================================
 * UPGRADE — relay -> direct
 * ============================================================================
 *
 * When a relay is active, attempt to replace it with a direct path.
 *
 * Flow:
 *   1. Relay is active: us <-> helper <-> target.
 *   2. We ask the helper to coordinate a direct punch.
 *   3. Helper forwards our public endpoint to the target and vice versa.
 *   4. Both sides attempt simultaneous open.
 *   5. If direct succeeds, we close the relay and switch to direct.
 *   6. If direct fails within the budget, we keep the relay.
 *
 * This is an optimization. It is safe to skip. Hosts that need the
 * lowest possible latency can call it after xury_relay_request().
 *
 * Arguments:
 *   e           — engine handle
 *   timeout_ms  — total budget for the upgrade attempt
 *
 * Returns:
 *   XURY_OK                    — upgraded to direct
 *   XURY_ERR_INVAL             — e is NULL
 *   XURY_ERR_NOT_CONNECTED     — no relay is active
 *   XURY_ERR_UPGRADE_FAIL      — direct could not be established
 *   XURY_ERR_TIMEOUT           — budget exceeded
 *   XURY_ERR_NOT_SUPPORTED     — upgrade disabled in config
 *
 * On success:
 *   The relay is closed. xury_get_socket_fd() now returns the direct
 *   socket. The host does not need to do anything.
 *
 * On failure:
 *   The relay remains active. Nothing changes.
 */
xury_err_t xury_relay_upgrade(xury_engine_t *e, uint32_t timeout_ms);

/*
 * ============================================================================
 * MIRROR SERVER ROLE
 * ============================================================================
 *
 * A host may choose to act as a mirror for others.
 *
 * This is optional. If disabled (default), the engine will not respond
 * to mirror probes from other peers.
 *
 * Acting as a mirror costs almost nothing (one small response per
 * probe) and helps the peer network.
 */

/*
 * Enable or disable the mirror role for this engine.
 *
 * When enabled, the engine listens for mirror probes on its bound
 * port and responds with the observed source endpoint.
 *
 * Returns:
 *   XURY_OK           — setting applied
 *   XURY_ERR_INVAL    — e is NULL
 *   XURY_ERR_NOT_READY— engine not started
 */
xury_err_t xury_mirror_set_enabled(xury_engine_t *e, bool enabled);

/*
 * True if this engine currently answers mirror probes.
 */
bool xury_mirror_is_enabled(const xury_engine_t *e);

/*
 * Return the number of mirror probes answered so far.
 *
 * Useful for metrics and for verifying that the mirror role works.
 */
uint64_t xury_mirror_answered_count(const xury_engine_t *e);

/*
 * ============================================================================
 * STRING HELPERS
 * ============================================================================
 */

/*
 * Return a short tag for a NAT type ("full_cone", "symmetric", ...).
 * Never returns NULL.
 */
const char *xury_nat_type_tag(xury_nat_type_t t);

/*
 * Return a short tag for a CGNAT type ("simple", "hash", ...).
 * Never returns NULL.
 */
const char *xury_cgnat_type_tag(xury_cgnat_type_t t);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY PEER HEADER
 * ============================================================================
 */

#endif /* XURY_PEER_H */
