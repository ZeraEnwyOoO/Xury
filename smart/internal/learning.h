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

#ifndef XURY_SMART_INTERNAL_LEARNING_H
#define XURY_SMART_INTERNAL_LEARNING_H

/*
 * ============================================================================
 * XURY SMART — LEARNING (Stage 1: data collection)
 * ============================================================================
 *
 * Records the outcome of weapon attempts, keyed by NAT type, so that
 * a future decision layer (adaptive.c, Stage 2) can prefer weapons
 * that have historically worked for the observed NAT context.
 *
 * ----------------------------------------------------------------------------
 * Scope: NAT traversal only
 * ----------------------------------------------------------------------------
 *
 * This module answers exactly one question:
 *
 *     "For this NAT type, which weapon has actually worked?"
 *
 * It is NOT a general-purpose ML or analytics module. It does not
 * model latency, cost, bandwidth, peer behavior, or anything outside
 * the (nat_type, weapon) -> {success, fail} count.
 *
 * See docs/AI_CONTEXT.md for the project-wide scope reminder.
 *
 * ----------------------------------------------------------------------------
 * Stage 1 vs Stage 2
 * ----------------------------------------------------------------------------
 *
 * Stage 1 (this file, now):
 *
 *   Record raw success/fail counts. Pure data collection. No
 *   decisions, no thresholds, no ordering. Stage 1 has no
 *   dependency on Phase H: a caller can record a synthetic outcome
 *   (nat=SYMMETRIC, weapon=IPV6, success=true) even before any
 *   weapon implementation exists.
 *
 * Stage 2 (adaptive.c, later, after Phase H):
 *
 *   Turn the recorded counts into a weapon ordering. Stage 2 needs
 *   real Phase H execution data before it can decide anything, and
 *   its thresholds are a research question (see docs/RESEARCH.md).
 *   Until then, Stage 2 returns XURY_ERR_NOT_CALIBRATED.
 *
 * Splitting the two is deliberate: Stage 1 is honest and testable
 * today; Stage 2 would require inventing constants, which Xury does
 * not do.
 *
 * ----------------------------------------------------------------------------
 * Storage
 * ----------------------------------------------------------------------------
 *
 * Fixed-size, in-memory, no allocation:
 *
 *   - one uint32_t success counter per (nat_type, weapon)
 *   - one uint32_t fail    counter per (nat_type, weapon)
 *
 * The struct is therefore XURY_NAT_COUNT * XURY_WEAPON_COUNT * 2
 * counters. At the time of writing that is 7 * 12 * 2 = 168
 * counters, or 672 bytes. The caller owns the struct; the module
 * never allocates.
 *
 * Persistence is not part of Stage 1. When Stage 2 wants to persist
 * counts, it will reuse the storage interface already defined for
 * cache.c (xury_storage_iface_t) rather than inventing file I/O.
 *
 * ----------------------------------------------------------------------------
 * Threading
 * ----------------------------------------------------------------------------
 *
 * The struct is not internally synchronized. It is intended to be
 * owned by a single engine and used from that engine's thread,
 * matching the one-engine-one-thread rule in include/xury/engine.h.
 *
 * ----------------------------------------------------------------------------
 * Overflow
 * ----------------------------------------------------------------------------
 *
 * Counters are uint32_t. At one attempt per second, a counter would
 * take over 136 years to wrap. The module does not saturate; a
 * wrapped counter is a bug in the host, not in the module.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 * - <xury/types.h>     (xury_nat_type_t, xury_weapon_t,
 *                       XURY_NAT_COUNT, XURY_WEAPON_COUNT)
 * - <xury/err.h>       (xury_err_t)
 *
 * No allocation, no I/O, no platform, no global state.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/types.h>
#include <xury/err.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * LEARNING STATE
 * ============================================================================
 *
 * Fixed-size counters, indexed by [nat_type][weapon].
 *
 * Index 0 of each dimension is the sentinel (XURY_NAT_UNKNOWN,
 * XURY_WEAPON_NONE). Recording against a sentinel is allowed and
 * counted like any other; callers that never record against the
 * sentinel simply leave those rows/columns at zero.
 *
 * The struct is deliberately concrete (not opaque) so the host can
 * embed it in the engine by value, and so tests can inspect counts
 * directly without accessor calls.
 */

typedef struct {
    /*
     * success[nat_type][weapon] — number of attempts that succeeded.
     * fail[nat_type][weapon]    — number of attempts that failed.
     */
    uint32_t success[XURY_NAT_COUNT][XURY_WEAPON_COUNT];
    uint32_t fail[XURY_NAT_COUNT][XURY_WEAPON_COUNT];
} xury_smart_learning_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Zero all counters.
 *
 * Safe to call on a stack-allocated struct before first use, and
 * safe to call again to reset. Does nothing if l is NULL.
 */
void xury_smart_learning_init(xury_smart_learning_t *l);

/*
 * ============================================================================
 * RECORD
 * ============================================================================
 *
 * Record one weapon attempt outcome for a NAT type.
 *
 * Arguments:
 *   l          learning state; must not be NULL
 *   nat_type   the NAT type observed for this attempt
 *   weapon     the weapon that was attempted
 *   success    true if the weapon succeeded, false if it failed
 *
 * Returns:
 *   XURY_OK          recorded
 *   XURY_ERR_INVAL   l is NULL, or nat_type or weapon is out of range
 *
 * "Out of range" means:
 *   nat_type < 0 || nat_type >= XURY_NAT_COUNT
 *   weapon   < 0 || weapon   >= XURY_WEAPON_COUNT
 *
 * The sentinel values (XURY_NAT_UNKNOWN, XURY_WEAPON_NONE) are
 * considered valid inputs and are recorded like any other.
 *
 * The function does not allocate, does not log, and does not make
 * any decision based on the outcome.
 */
xury_err_t xury_smart_learning_record(xury_smart_learning_t *l,
                                      xury_nat_type_t nat_type,
                                      xury_weapon_t weapon,
                                      bool success);

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

/*
 * Read the raw counters for one (nat_type, weapon) pair.
 *
 * Arguments:
 *   l             learning state; must not be NULL
 *   nat_type      the NAT type to query
 *   weapon        the weapon to query
 *   out_success   receives the success count; may be NULL
 *   out_fail      receives the fail count;    may be NULL
 *
 * Returns:
 *   XURY_OK          counts written (where requested)
 *   XURY_ERR_INVAL   l is NULL, or nat_type or weapon is out of range
 *
 * At least one of out_success / out_fail should be non-NULL for the
 * call to be useful, but passing NULL for both is legal and simply
 * validates the arguments.
 */
xury_err_t xury_smart_learning_get(const xury_smart_learning_t *l,
                                   xury_nat_type_t nat_type,
                                   xury_weapon_t weapon,
                                   uint32_t *out_success,
                                   uint32_t *out_fail);

/*
 * ============================================================================
 * WHAT IS NOT HERE
 * ============================================================================
 *
 * Deliberately absent from Stage 1:
 *
 *   - preferred_weapon(nat_type) — a decision function. Belongs to
 *     Stage 2, and needs a calibrated threshold that does not exist
 *     yet. Will return XURY_ERR_NOT_CALIBRATED until then.
 *
 *   - weapon ordering — same reason.
 *
 *   - persistence — Stage 1 is in-memory. Stage 2 will reuse the
 *     storage interface from cache.c when persistence is needed.
 *
 *   - decay, smoothing, confidence — all require constants chosen
 *     from real measurement. Not yet.
 *
 * If a future change wants any of these, it belongs in Stage 2
 * (adaptive.c), not here.
 * ============================================================================
 */

/*
 * ============================================================================
 * END OF XURY SMART INTERNAL LEARNING HEADER
 * ============================================================================
 */

#endif /* XURY_SMART_INTERNAL_LEARNING_H */
