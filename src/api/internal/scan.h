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

#ifndef XURY_API_INTERNAL_SCAN_H
#define XURY_API_INTERNAL_SCAN_H

/*
 * ============================================================================
 * XURY INTERNAL SCAN HELPERS
 * ============================================================================
 *
 * Internal helpers used by src/api/scan.c, the engine orchestrator, and
 * the analysis layer.
 *
 * Public API (include/xury/scan.h) already exposes:
 *
 *   xury_scan_result_t        (composite result)
 *   xury_sensing_result_t
 *   xury_probing_result_t
 *   xury_math_result_t
 *   xury_memory_result_t
 *   xury_analysis_result_t
 *   xury_scan_sub_status_t
 *
 *   xury_scan()
 *   xury_scan_quick()
 *   xury_scan_invalidate()
 *   xury_nat_type_str()
 *   xury_nat_label_str()
 *   xury_cgnat_type_str()
 *   xury_network_type_str()
 *   xury_scan_sub_status_str()
 *
 * This header adds:
 *
 *   - the internal entry point the engine calls (dispatch layer)
 *   - a result reset helper
 *   - a result-to-weapon-context adapter (feeds weapon applicability)
 *   - a result fingerprint (for cache keys)
 *   - a result comparison (for "did anything change?")
 *   - a result pretty-printer for logs
 *
 * Rules:
 *   - Never expose these in include/xury/.
 *   - Never call them from public headers.
 *   - No allocation: formatting writes into caller buffers.
 *   - No dependency on engine internals beyond an opaque forward decl.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/types.h>
#include <xury/err.h>
#include <xury/scan.h>
#include <xury/weapon.h>

#include "api/internal/weapon.h"   /* xury_weapon_context_t */

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration: engine is opaque here. */
struct xury_engine;

/*
 * ============================================================================
 * RESULT INIT / RESET
 * ============================================================================
 */

/*
 * Zero a scan result and set all sub-status fields to SKIPPED.
 *
 * Safe to call on a stack-allocated result before passing it to
 * xury_scan(). xury_scan() also calls this internally, so calling it
 * yourself is optional but harmless.
 */
void xury_scan_result_reset(xury_scan_result_t *r);

/*
 * True if the result has been fully populated and represents a
 * successful scan.
 */
bool xury_scan_result_is_complete(const xury_scan_result_t *r);

/*
 * ============================================================================
 * INTERNAL ENTRY POINT
 * ============================================================================
 *
 * The public xury_scan() in src/api/scan.c is a thin wrapper that
 * validates arguments and then calls this. The engine also calls this
 * from xury_connect() before the STRIKE phase.
 *
 * Behavior is identical to xury_scan() but without argument validation
 * against the public contract. Callers must pass non-NULL, valid
 * pointers.
 */
xury_err_t xury_scan_internal(struct xury_engine *e,
                              const xury_endpoint_t *peer,
                              xury_scan_result_t *out);

/*
 * Internal quick scan: sensing + cached memory only.
 *
 * Used by xury_scan_quick() and by the engine's fast path.
 */
xury_err_t xury_scan_internal_quick(struct xury_engine *e,
                                    xury_scan_result_t *out);

/*
 * ============================================================================
 * ADAPTERS
 * ============================================================================
 */

/*
 * Build a weapon applicability context from a scan result.
 *
 * This is the bridge between the scan layer (which produces results)
 * and the weapon layer (which consumes contexts).
 *
 * The mapping is:
 *
 *   ctx->ipv6_present     <- sensing.ipv6_global || sensing.local_ipv6 set
 *   ctx->ipv6_global      <- sensing.ipv6_global
 *   ctx->peer_has_ipv6    <- probing.peer_supports_ipv6
 *   ctx->peer_is_lan      <- analysis.lan_viable
 *   ctx->peer_reachable   <- probing.peer_reachable
 *   ctx->upnp_available   <- sensing.upnp_available (if set) else false
 *   ctx->natpmp_available <- sensing.natpmp_available
 *   ctx->pcp_available    <- sensing.pcp_available
 *   ctx->symmetric        <- analysis.nat_type == SYMMETRIC
 *   ctx->cgnat            <- analysis.nat_type == CGNAT
 *   ctx->port_predictable <- math.port_predictable
 *   ctx->helper_available <- engine has >= 1 peer in the registry
 *   ctx->allow_aggressive <- config.enable_sweet_aggressive
 *
 * Returns XURY_OK on success, XURY_ERR_INVAL if r or out is NULL.
 */
xury_err_t xury_scan_to_weapon_context(const struct xury_engine *e,
                                       const xury_scan_result_t *r,
                                       xury_weapon_context_t *out);

/*
 * ============================================================================
 * FINGERPRINT
 * ============================================================================
 *
 * A stable 64-bit hash of the parts of a scan result that affect
 * weapon selection.
 *
 * Used to:
 *   - key the cache
 *   - detect "same network, same result" fast paths
 *   - detect "network changed" and invalidate the cache
 *
 * Deterministic: same inputs -> same hash across runs and platforms.
 * Not cryptographic.
 */
uint64_t xury_scan_result_fingerprint(const xury_scan_result_t *r);

/*
 * Compare two scan results for "meaningful difference".
 *
 * Returns true if the two results would lead to different weapon
 * choices. Fields that are ignored:
 *   - all elapsed_ms fields
 *   - status fields
 *   - fast_path, early_terminated
 *   - memory.age_sec
 *
 * Fields that are compared:
 *   - analysis.nat_type, nat_label, cgnat_type
 *   - analysis.recommended_weapon
 *   - analysis.ipv6_viable, lan_viable, peer_reachable
 *   - math.port_predictable
 *   - sensing.ipv6_global
 *   - probing.peer_reachable, peer_supports_ipv6
 *
 * Returns:
 *   true  if the results differ in a way that matters
 *   false otherwise (including when either pointer is NULL)
 */
bool xury_scan_result_differs(const xury_scan_result_t *a,
                              const xury_scan_result_t *b);

/*
 * ============================================================================
 * LOGGING
 * ============================================================================
 */

/*
 * Format a short, one-line summary of a scan result into buf.
 *
 * Example:
 *
 *   "scan: nat=symmetric label=hard cgnat=random rec=relay \
 *    ipv6=no lan=no peer=yes t=412ms fast=no"
 *
 * Always NUL-terminates when buflen > 0.
 *
 * Returns the number of bytes that WOULD have been written, excluding
 * the NUL. Callers can detect truncation with (ret >= buflen).
 *
 * Recommended buffer size: 160 bytes.
 */
size_t xury_scan_result_format(const xury_scan_result_t *r,
                               char *buf,
                               size_t buflen);

/*
 * Format a single sub-phase status line.
 *
 * Example:
 *
 *   "sensing: ok 12ms"
 *
 * Returns bytes-would-have-written, excluding NUL.
 */
size_t xury_scan_sub_format(const char *name,
                            xury_scan_sub_status_t status,
                            uint32_t elapsed_ms,
                            char *buf,
                            size_t buflen);

/*
 * ============================================================================
 * VALIDATION
 * ============================================================================
 */

/*
 * Sanity-check a populated scan result. Used by tests and by the
 * internal assert path.
 *
 * Checks:
 *   - analysis.nat_type is in range
 *   - analysis.nat_label is in range
 *   - analysis.cgnat_type is in range
 *   - analysis.recommended_weapon is valid (or NONE)
 *   - analysis.recommended_confidence <= 100
 *   - probing.sample_count <= XURY_PROBE_PORT_SAMPLES
 *   - probing.rtt_count    <= XURY_PROBE_RTT_SAMPLES
 *   - if analysis.cgnat_type != UNKNOWN, analysis.nat_type == CGNAT
 *
 * Returns:
 *   XURY_OK        — consistent
 *   XURY_ERR_INVAL — inconsistent
 */
xury_err_t xury_scan_result_validate(const xury_scan_result_t *r);

/*
 * ============================================================================
 * CACHE KEY HELPERS
 * ============================================================================
 *
 * A cache entry is keyed by:
 *
 *   <version-prefix><network-fingerprint><config-fingerprint>
 *
 * The three parts are provided by:
 *   - xury_version_cache_prefix()  (api/internal/version.h)
 *   - xury_scan_result_fingerprint()  (this file, for the network part)
 *   - xury_config_fingerprint()    (api/internal/config.h)
 *
 * This file provides the network part only. The cache layer composes
 * the final key.
 */

/*
 * Compute the network part of a cache key.
 *
 * Unlike xury_scan_result_fingerprint(), this hash is stable across
 * scan runs on the same network even if the recommended weapon
 * changed, because it is keyed only on network identity:
 *
 *   - gateway MAC (if known)
 *   - gateway IP
 *   - local IPv4 subnet (first 24 bits)
 *   - local IPv6 prefix (first 64 bits, if any)
 *
 * Returns 0 if the network cannot be identified (caller must not cache
 * in that case).
 */
uint64_t xury_scan_network_fingerprint(const xury_scan_result_t *r);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY INTERNAL SCAN HEADER
 * ============================================================================
 */

#endif /* XURY_API_INTERNAL_SCAN_H */
