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

#ifndef XURY_SCAN_INTERNAL_SCAN_H
#define XURY_SCAN_INTERNAL_SCAN_H

/*
 * ============================================================================
 * XURY SCAN — INTERNAL
 * ============================================================================
 *
 * Scan context and internal entry points for the scan orchestrator.
 *
 * The orchestrator (src/scan/scan.c) drives the sub-phases:
 *
 *   sensing  -> probing -> math -> classify -> analysis
 *
 * and, when the smart layer is linked, consults:
 *
 *   memory   (cache load, cache store)
 *   early term (short-circuit on a strong signal)
 *
 * The context carries the inputs the orchestrator needs. It does NOT
 * own any of the sub-results; those live in the caller's
 * xury_scan_result_t.
 *
 * ----------------------------------------------------------------------------
 * Dependency rule
 * ----------------------------------------------------------------------------
 *
 * scan/ may include:
 *   - include/xury/*.h              (public contract)
 *   - src/core/internal/*.h         (foundation: time, bytes, ...)
 *   - src/platform/platform.h       (OS layer)
 *   - src/api/internal/*.h          (foundational api helpers, e.g.
 *                                    types, config, weapon; NOT the
 *                                    orchestration wrappers such as
 *                                    api/internal/scan.h once they
 *                                    exist, because those will wrap
 *                                    scan/ itself)
 *   - src/scan/internal/*.h         (siblings)
 *   - src/analysis/internal/*.h     (classify, score, analysis)
 *
 * scan/ must NOT include:
 *   - src/engine/...                (engine sits above scan)
 *   - src/api/scan.c                (wrapper around scan)
 *
 * ----------------------------------------------------------------------------
 * Design
 * ----------------------------------------------------------------------------
 *
 * xury_scan_ctx_t is a lightweight value struct, allocated by the
 * caller on the stack. It holds borrowed pointers and a small copy of
 * the configuration the orchestrator needs. It is not heap-allocated
 * and not retained beyond the call.
 *
 * The internal entry points take a context plus a result pointer.
 * The public xury_scan() is a thin wrapper that builds the context
 * from an engine and calls these.
 *
 * No allocation in this header. No allocation is implied by using it.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/types.h>
#include <xury/err.h>
#include <xury/config.h>
#include <xury/scan.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * SCAN CONTEXT
 * ============================================================================
 *
 * Borrowed pointers only. The caller owns the storage for every
 * pointer in this struct and must keep it valid for the duration of
 * the scan call.
 *
 * Fields:
 *
 *   cfg
 *     Resolved configuration. The orchestrator reads the enable_*
 *     flags and the timeout fields from here. It does not take
 *     ownership and does not copy.
 *
 *   log
 *     Optional logger. May be NULL, in which case the orchestrator
 *     emits nothing. The logger is owned by the engine.
 *
 *   alloc
 *     Optional allocator. May be NULL, in which case the orchestrator
 *     uses no dynamic allocation at all (it currently needs none).
 *     Present so future sub-phases can allocate through the same
 *     allocator without changing the context shape.
 *
 *   peer
 *     Optional peer hint. May be NULL. When non-NULL, it is the
 *     endpoint the caller wants to reach, and is the target passed
 *     to probing. When NULL, probing still runs but with no peer;
 *     the orchestrator treats that as "no probing target supplied"
 *     and records probing.status = XURY_SCAN_SUB_SKIPPED.
 *
 *   now_ms
 *     Monotonic start time, captured by the caller. The orchestrator
 *     uses it to compute total_elapsed_ms without calling the clock
 *     itself more than necessary.
 */
typedef struct {
    const xury_config_t *cfg;
    void                *log;       /* xury_logger_t *; opaque here */
    const void          *alloc;     /* xury_allocator_t *; opaque here */
    const xury_endpoint_t *peer;
    uint64_t             now_ms;
} xury_scan_ctx_t;

/*
 * ============================================================================
 * INTERNAL ENTRY POINTS
 * ============================================================================
 */

/*
 * Run the full scan pipeline.
 *
 * Pipeline:
 *   1. sensing        (always, unless config disables it)
 *   2. memory load    (if smart layer is linked and enabled)
 *   3. early term     (if smart layer is linked and enabled)
 *   4. probing        (skipped if early term fired, or if no peer)
 *   5. math           (over probing.external_ports)
 *   6. classify       (over probing.external_ports)
 *   7. analysis       (combines sensing, probing, classify)
 *   8. memory store   (if smart layer is linked and enabled)
 *
 * The result is filled in place. Sub-phase statuses record what ran
 * and what did not.
 *
 * Returns:
 *   XURY_OK          result filled (possibly partial)
 *   XURY_ERR_INVAL   ctx or out is NULL
 *
 * The function never allocates.
 */
xury_err_t xury_scan_run(const xury_scan_ctx_t *ctx,
                         xury_scan_result_t *out);

/*
 * Run the quick scan pipeline.
 *
 * Pipeline:
 *   1. sensing
 *   2. memory load (if smart layer is linked and enabled)
 *
 * Never sends packets. Never probes. Never analyzes.
 *
 * Returns:
 *   XURY_OK          result filled
 *   XURY_ERR_INVAL   ctx or out is NULL
 */
xury_err_t xury_scan_run_quick(const xury_scan_ctx_t *ctx,
                               xury_scan_result_t *out);

/*
 * ============================================================================
 * INTERNAL — STRING HELPERS
 * ============================================================================
 *
 * Implementations live in src/scan/scan.c. They are declared here
 * because other scan-adjacent layers (analysis, smart) need them but
 * must not link against the public scan API directly.
 */

const char *xury_nat_type_str(xury_nat_type_t t);
const char *xury_nat_label_str(xury_nat_label_t l);
const char *xury_cgnat_type_str(xury_cgnat_type_t t);
const char *xury_network_type_str(xury_network_type_t n);
const char *xury_scan_sub_status_str(xury_scan_sub_status_t s);

/*
 * ============================================================================
 * END OF XURY SCAN INTERNAL HEADER
 * ============================================================================
 */

#endif /* XURY_SCAN_INTERNAL_SCAN_H */
