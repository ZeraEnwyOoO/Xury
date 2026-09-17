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

#ifndef XURY_API_INTERNAL_PEER_H
#define XURY_API_INTERNAL_PEER_H

/*
 * ============================================================================
 * XURY INTERNAL PEER HELPERS
 * ============================================================================
 *
 * Internal helpers used by src/api/peer.c, the mirror layer, the relay
 * layer, and the engine's peer registry.
 *
 * Public API (include/xury/peer.h) already exposes:
 *
 *   xury_mirror_query()
 *   xury_mirror_query_any()
 *   xury_mirror_classify()
 *   xury_mirror_set_enabled()
 *   xury_mirror_is_enabled()
 *   xury_mirror_answered_count()
 *   xury_relay_request()
 *   xury_relay_accept()
 *   xury_relay_close()
 *   xury_relay_active_count()
 *   xury_relay_upgrade()
 *   xury_nat_type_tag()
 *   xury_cgnat_type_tag()
 *
 * This header adds:
 *
 *   - the peer registry entry layout used by the engine
 *   - registry lookup / insert / remove primitives
 *   - "pick a helper" selection used by mirror and relay
 *   - capability bits per peer (mirror-capable, relay-capable)
 *   - mirror/relay session counters
 *
 * Rules:
 *   - Never expose these in include/xury/.
 *   - Never call them from public headers.
 *   - No allocation in query paths; the registry owns its storage.
 *   - No dependency on engine internals beyond an opaque forward decl.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/types.h>
#include <xury/err.h>
#include <xury/peer.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration: engine is opaque here. */
struct xury_engine;

/*
 * ============================================================================
 * PEER CAPABILITIES
 * ============================================================================
 *
 * Bitmask describing what a peer can do for us.
 *
 * The host supplies the base endpoint. Capabilities are learned over
 * time: when a peer answers a mirror probe, we mark it as MIRROR_OK;
 * when it agrees to relay, we mark it as RELAY_OK.
 *
 * They are advisory. Selection prefers capable peers but may fall back
 * to untested ones.
 */

typedef enum {
    XURY_PEER_CAP_NONE       = 0u,

    /* Peer answered a mirror probe at least once. */
    XURY_PEER_CAP_MIRROR_OK  = 1u << 0,

    /* Peer answered a mirror probe with a consistent endpoint. */
    XURY_PEER_CAP_MIRROR_STABLE = 1u << 1,

    /* Peer is reachable (responded to any probe). */
    XURY_PEER_CAP_REACHABLE  = 1u << 2,

    /* Peer agreed to act as a relay at least once. */
    XURY_PEER_CAP_RELAY_OK   = 1u << 3,

    /* Peer is likely public (no NAT in front of it). */
    XURY_PEER_CAP_PUBLIC     = 1u << 4,

    /* Peer has refused mirror or relay too many times. */
    XURY_PEER_CAP_BAD        = 1u << 5,
} xury_peer_cap_t;

/*
 * ============================================================================
 * PEER ENTRY
 * ============================================================================
 *
 * One slot in the engine's peer registry.
 *
 * Layout is chosen for a small open-addressed hash table keyed by the
 * 64-bit peer-id hash. Empty slots have id all-zero and in_use == false.
 *
 * Fields:
 *   id          — 32-byte peer id (opaque to Xury)
 *   endpoint    — last known reachable endpoint
 *   caps        — capability bitmask
 *   last_seen_ms— monotonic ms of last successful interaction
 *   failures    — consecutive failures since last success
 *   rtt_ms      — exponentially weighted moving average RTT
 *   in_use      — slot occupied
 */

typedef struct xury_peer_entry {
    xury_peer_id_t  id;
    xury_endpoint_t endpoint;
    uint32_t        caps;
    uint64_t        last_seen_ms;
    uint32_t        failures;
    uint32_t        rtt_ms;
    bool            in_use;
} xury_peer_entry_t;

/*
 * ============================================================================
 * REGISTRY CONFIGURATION
 * ============================================================================
 *
 * The registry starts small and grows by rehashing when the load
 * factor exceeds XURY_PEER_REGISTRY_LOAD_NUM / DEN.
 */

#define XURY_PEER_REGISTRY_INITIAL_CAP  16u
#define XURY_PEER_REGISTRY_LOAD_NUM      3u
#define XURY_PEER_REGISTRY_LOAD_DEN      4u

/*
 * ============================================================================
 * REGISTRY LIFECYCLE
 * ============================================================================
 */

/*
 * Allocate an empty peer registry inside the engine.
 *
 * Called by xury_engine_start().
 *
 * Returns:
 *   XURY_OK        — registry ready
 *   XURY_ERR_INVAL — e is NULL
 *   XURY_ERR_NOMEM — allocation failed
 */
xury_err_t xury_peer_registry_init(struct xury_engine *e);

/*
 * Free the registry and all entries.
 * Safe to call on an already-empty registry.
 */
void xury_peer_registry_free(struct xury_engine *e);

/*
 * Return the number of peers currently stored.
 */
size_t xury_peer_registry_count(const struct xury_engine *e);

/*
 * ============================================================================
 * REGISTRY OPERATIONS
 * ============================================================================
 *
 * These are the real implementations. Public xury_add_peer() /
 * xury_remove_peer() / xury_lookup_peer() / xury_clear_peers() call
 * them after validating arguments.
 */

/*
 * Insert or update a peer.
 *
 * If the peer id already exists, the endpoint and capabilities are
 * updated in place. Existing stats (rtt, failures, last_seen) are
 * preserved.
 *
 * Returns:
 *   XURY_OK         — inserted or updated
 *   XURY_ERR_INVAL  — e, id, or ep is NULL
 *   XURY_ERR_NOMEM  — grow failed
 */
xury_err_t xury_peer_registry_put(struct xury_engine *e,
                                  const xury_peer_id_t *id,
                                  const xury_endpoint_t *ep);

/*
 * Look up a peer by id.
 *
 * Returns:
 *   XURY_OK          — found, *out_entry filled
 *   XURY_ERR_INVAL   — e, id, or out_entry is NULL
 *   XURY_ERR_NO_PEER — not found
 *
 * The returned pointer is valid until the next registry mutation.
 */
xury_err_t xury_peer_registry_find(struct xury_engine *e,
                                   const xury_peer_id_t *id,
                                   xury_peer_entry_t **out_entry);

/*
 * Remove a peer by id.
 *
 * Returns XURY_OK even if the peer was absent.
 * Returns XURY_ERR_INVAL if e or id is NULL.
 */
xury_err_t xury_peer_registry_remove(struct xury_engine *e,
                                     const xury_peer_id_t *id);

/*
 * Remove all peers. Keeps the allocated capacity.
 */
void xury_peer_registry_clear(struct xury_engine *e);

/*
 * ============================================================================
 * STATISTICS AND CAPABILITIES
 * ============================================================================
 */

/*
 * Record a successful interaction with a peer.
 *
 * Updates last_seen_ms, resets failures, and folds rtt_ms into the
 * EWMA. Sets the given capability bits.
 *
 * Safe to call with an entry that is not in the registry (updates the
 * entry only).
 */
void xury_peer_record_success(xury_peer_entry_t *entry,
                              uint32_t rtt_ms,
                              uint32_t set_caps);

/*
 * Record a failed interaction.
 *
 * Increments failures. After XURY_PEER_FAIL_THRESHOLD consecutive
 * failures, sets XURY_PEER_CAP_BAD.
 */
void xury_peer_record_failure(xury_peer_entry_t *entry);

#define XURY_PEER_FAIL_THRESHOLD 5u

/*
 * True if the entry has the given capability bit.
 */
bool xury_peer_has_cap(const xury_peer_entry_t *entry, uint32_t cap);

/*
 * Clear the BAD capability so a peer can be retried.
 */
void xury_peer_forgive(xury_peer_entry_t *entry);

/*
 * ============================================================================
 * HELPER SELECTION
 * ============================================================================
 *
 * Choose the best peer for a given role. Used by the mirror and relay
 * layers.
 *
 * Selection policy (in order):
 *   1. Prefer peers with the required capability set.
 *   2. Prefer peers with low RTT.
 *   3. Skip peers marked BAD.
 *   4. Skip the peer we are trying to reach (self-exclusion).
 *
 * If no peer matches, returns XURY_ERR_NO_PEER.
 */

/*
 * Pick a peer to act as a mirror.
 *
 * exclude may be NULL or the endpoint to skip (usually the target
 * peer). On success, *out_endpoint receives the chosen peer's endpoint
 * and *out_id (optional) receives its id.
 */
xury_err_t xury_peer_pick_mirror(struct xury_engine *e,
                                 const xury_endpoint_t *exclude,
                                 xury_endpoint_t *out_endpoint,
                                 xury_peer_id_t *out_id);

/*
 * Pick a peer to act as a relay toward target.
 *
 * Prefers RELAY_OK peers. Falls back to PUBLIC peers if none.
 * exclude is the target (never chosen as its own relay).
 */
xury_err_t xury_peer_pick_relay(struct xury_engine *e,
                                const xury_endpoint_t *target,
                                xury_endpoint_t *out_endpoint,
                                xury_peer_id_t *out_id);

/*
 * Return a snapshot of up to max peers into the caller-supplied array.
 *
 * Returns the number of entries written.
 * The order is unspecified.
 */
size_t xury_peer_registry_snapshot(const struct xury_engine *e,
                                   xury_peer_entry_t *out,
                                   size_t max);

/*
 * ============================================================================
 * INTERNAL COUNTERS
 * ============================================================================
 *
 * Monotonic per-engine counters. Reported through xury_mirror_answered_count()
 * and xury_relay_active_count() (public) and used by tests.
 */

typedef struct {
    uint64_t mirror_probes_sent;
    uint64_t mirror_probes_answered;
    uint64_t mirror_probes_failed;

    uint64_t relay_requests_sent;
    uint64_t relay_requests_accepted;
    uint64_t relay_requests_refused;

    uint64_t relay_active_peak;
    uint64_t relay_active_now;
} xury_peer_counters_t;

/*
 * Return a pointer to the engine's peer counters.
 * Returns NULL if e is NULL.
 */
const xury_peer_counters_t *xury_peer_counters(const struct xury_engine *e);

/*
 * Mutable accessor for internal layers that record events.
 * Returns NULL if e is NULL.
 */
xury_peer_counters_t *xury_peer_counters_mut(struct xury_engine *e);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY INTERNAL PEER HEADER
 * ============================================================================
 */

#endif /* XURY_API_INTERNAL_PEER_H */
