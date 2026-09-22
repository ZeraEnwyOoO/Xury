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

#ifndef XURY_SMART_INTERNAL_CACHE_H
#define XURY_SMART_INTERNAL_CACHE_H

/*
 * ============================================================================
 * XURY SMART — CACHE
 * ============================================================================
 *
 * Persistent scan result cache.
 *
 * The cache stores the classification part of a previous scan so that
 * a repeat scan on the same network can short-circuit expensive
 * sub-phases. It is the "MEMORY" sub-phase of the scan pipeline
 * described in include/xury/scan.h.
 *
 * ----------------------------------------------------------------------------
 * What is cached
 * ----------------------------------------------------------------------------
 *
 * Only the fields that describe a stable network property:
 *
 *   nat_type
 *   nat_label
 *   cgnat_type
 *   successful weapons bitmap
 *   failed weapons bitmap
 *
 * These are the fields whose values depend on the network the host is
 * attached to, not on the peer being reached or on the current run.
 * Everything else is either recomputed cheaply (interface list) or
 * depends on the peer (probing samples).
 *
 * ----------------------------------------------------------------------------
 * What the caller supplies
 * ----------------------------------------------------------------------------
 *
 * Two things, both already part of the public config:
 *
 *   storage
 *     An xury_storage_iface_t from <xury/types.h>. The cache uses
 *     it to read and write a single opaque blob. Where that blob
 *     lives (a file, a key-value store, Android SharedPreferences)
 *     is the host's choice. Xury does not open files, does not
 *     touch the filesystem, and does not pick a path.
 *
 *   key
 *     A 64-bit network fingerprint. The cache does not compute it;
 *     the caller does. This is deliberate: the fingerprint has to
 *     combine the version prefix, the network identity, and the
 *     config fingerprint, and the network identity is a scan-layer
 *     concern (gateway, subnet) that the smart layer must not
 *     duplicate.
 *
 * If storage is NULL, or key is 0, the cache is inert: loads report
 * "not loaded" and stores succeed as no-ops. This is the intended
 * behavior for hosts that do not want caching. It is not an error.
 *
 * ----------------------------------------------------------------------------
 * TTL
 * ----------------------------------------------------------------------------
 *
 * The caller supplies a TTL in seconds. Entries older than the TTL
 * are treated as not loaded. A TTL of 0 means "never expire"; this
 * is allowed because the host may have its own invalidation policy.
 *
 * ----------------------------------------------------------------------------
 * Threading
 * ----------------------------------------------------------------------------
 *
 * The cache holds no state. Every call takes its storage and key as
 * arguments. Two engines with two different storage backends do not
 * interfere. Within one engine, the scan pipeline is single-threaded
 * by design (see include/xury/engine.h), so no locking is needed
 * here.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/types.h>
#include <xury/err.h>
#include <xury/scan.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * LOAD
 * ============================================================================
 */

/*
 * Attempt to load a cached scan result.
 *
 * Arguments:
 *   storage   storage interface, or NULL for "no cache"
 *   key       network fingerprint, or 0 for "no cache"
 *   ttl_sec   maximum age in seconds; 0 means "never expire"
 *   out       result to fill; must not be NULL
 *
 * On return, *out is always fully written:
 *
 *   - If storage is NULL, key is 0, or no entry exists for key:
 *       loaded  = false
 *       valid   = false
 *       status  = XURY_SCAN_SUB_SKIPPED
 *       other fields zeroed
 *
 *   - If an entry exists but is older than ttl_sec (and ttl_sec != 0):
 *       loaded  = true
 *       valid   = false
 *       status  = XURY_SCAN_SUB_SKIPPED
 *       cached_* fields filled from the entry (for diagnostics)
 *       age_sec filled with the observed age
 *
 *   - If an entry exists and is fresh:
 *       loaded  = true
 *       valid   = true
 *       status  = XURY_SCAN_SUB_OK
 *       cached_* fields filled
 *       age_sec filled
 *
 * The function never allocates. It reads at most
 * XURY_SMART_CACHE_BLOB_MAX bytes through the storage callback.
 *
 * Returns:
 *   XURY_OK        out filled (including the "not loaded" cases)
 *   XURY_ERR_INVAL out is NULL
 *
 * A failing storage->load is treated as "no entry": out->loaded is
 * false and status is SKIPPED. The cache is a hint, not a source of
 * truth; a broken storage backend must not fail the scan.
 */
xury_err_t xury_smart_cache_load(const xury_storage_iface_t *storage,
                                 uint64_t key,
                                 uint32_t ttl_sec,
                                 xury_memory_result_t *out);

/*
 * ============================================================================
 * STORE
 * ============================================================================
 */

/*
 * Store the classification part of a scan result.
 *
 * Arguments:
 *   storage   storage interface, or NULL for "no store"
 *   key       network fingerprint, or 0 for "no store"
 *   analysis  the classification to persist; must not be NULL
 *
 * Only the fields listed at the top of this header are written.
 * Everything else in the analysis struct is ignored.
 *
 * If storage is NULL or key is 0, the call is a successful no-op.
 *
 * The function never allocates. It writes at most
 * XURY_SMART_CACHE_BLOB_MAX bytes through the storage callback.
 *
 * Returns:
 *   XURY_OK          stored, or intentionally skipped
 *   XURY_ERR_INVAL   analysis is NULL
 *
 * A failing storage->save is reported as-is. Unlike load, a store
 * failure IS surfaced, because a host that asked for persistence and
 * did not get it should be able to notice.
 */
xury_err_t xury_smart_cache_store(const xury_storage_iface_t *storage,
                                  uint64_t key,
                                  const xury_analysis_result_t *analysis);

/*
 * ============================================================================
 * INVALIDATE
 * ============================================================================
 */

/*
 * Invalidate the cached entry for a key.
 *
 * Arguments:
 *   storage   storage interface, or NULL for "no cache"
 *   key       network fingerprint, or 0 for "no cache"
 *
 * The storage interface has no "delete" callback, so this writes a
 * zero-length blob, which both load and store treat as "no entry".
 *
 * Returns:
 *   XURY_OK          invalidated, or intentionally skipped
 *   XURY_ERR_INVAL   storage is non-NULL and key is 0 (misuse)
 *
 * A storage with no save callback is treated as "no cache"; the call
 * succeeds without doing anything.
 */
xury_err_t xury_smart_cache_invalidate(const xury_storage_iface_t *storage,
                                       uint64_t key);

/*
 * ============================================================================
 * BLOB SIZE
 * ============================================================================
 *
 * The on-disk format is Xury's own; the host is expected to treat it
 * as opaque. This constant exists so the smart layer, the storage
 * layer, and tests can agree on an upper bound without sharing a
 * struct definition. It is not part of the public ABI.
 *
 * The current format is versioned and self-describing; the size is
 * fixed because every field is fixed-width.
 */

#define XURY_SMART_CACHE_BLOB_MAX 64u

/*
 * ============================================================================
 * END OF XURY SMART INTERNAL CACHE HEADER
 * ============================================================================
 */

#endif /* XURY_SMART_INTERNAL_CACHE_H */
