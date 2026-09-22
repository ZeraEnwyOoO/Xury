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

#ifndef XURY_SMART_INTERNAL_EARLY_TERM_H
#define XURY_SMART_INTERNAL_EARLY_TERM_H

/*
 * ============================================================================
 * XURY SMART — EARLY TERMINATION
 * ============================================================================
 *
 * Short-circuits the scan pipeline when a strong signal makes further
 * measurement unnecessary.
 *
 * The scan pipeline in include/xury/scan.h is documented as being
 * skippable when:
 *
 *   - a cached result is fresh and matches the current network
 *   - a global IPv6 address is detected (IPv6 needs no NAT traversal)
 *
 * This module is the second of those. It is a policy layer: it looks
 * at the results collected so far and decides whether the remaining
 * sub-phases should run.
 *
 * ----------------------------------------------------------------------------
 * What early termination is NOT
 * ----------------------------------------------------------------------------
 *
 * It is not a heuristic guess. Each rule it applies corresponds to a
 * documented, checkable condition:
 *
 *   IPv6_GLOBAL
 *     A global IPv6 address is present AND the peer answered on
 *     IPv6. In that case a direct IPv6 path exists and no NAT
 *     traversal is required. This is a fact, not a prediction.
 *
 *   CACHED_FRESH
 *     A valid, fresh cache entry exists for the current network. The
 *     previous scan already answered the question this scan would
 *     ask. Using it is not guessing; it is reusing a measurement.
 *
 *   CACHED_IPV6
 *     The cache says the network was IPv6-viable the last time it
 *     was seen, and the local sensing still reports global IPv6.
 *     The peer's IPv6 support is not yet known, so this rule fires
 *     only when the caller has already established it.
 *
 * No other rules exist. If a future change wants to short-circuit on
 * something else, it must add a new xury_early_term_reason_t value
 * here and a matching branch in early_term.c, with a comment that
 * names the observation the rule depends on. There is no
 * "probably true" rule, and no numeric threshold.
 *
 * ----------------------------------------------------------------------------
 * Ordering
 * ----------------------------------------------------------------------------
 *
 * The checks are evaluated in a fixed order, and the first that
 * fires wins:
 *
 *   1. IPv6_GLOBAL   -- strongest: no NAT at all
 *   2. CACHED_FRESH  -- second: a complete previous answer
 *   3. CACHED_IPV6   -- third: a partial previous answer
 *
 * The order is part of the contract. A caller that wants a different
 * precedence must not reorder these checks; it must add a new reason
 * with an explicit position.
 *
 * ----------------------------------------------------------------------------
 * Status semantics
 * ----------------------------------------------------------------------------
 *
 * The result struct returned by a decision function always has a
 * well-defined value:
 *
 *   terminate = true
 *     reason is one of the two or three non-NONE values.
 *     The scan pipeline should stop after the current sub-phase.
 *
 *   terminate = false
 *     reason is XURY_EARLY_TERM_NONE.
 *     The scan pipeline should continue normally.
 *
 * There is no "I don't know" state. Either a rule fired or none did.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 * - <xury/scan.h>     (the sub-results the decision is based on)
 *
 * No allocation, no I/O, no platform, no global state.
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
 * REASON
 * ============================================================================
 *
 * Why the pipeline was (or was not) terminated early.
 *
 * NONE is the identity value for "not terminated". It must be 0 so
 * that a zero-initialized result struct reads as "no decision".
 */

typedef enum {
    XURY_EARLY_TERM_NONE        = 0,
    XURY_EARLY_TERM_IPV6_GLOBAL = 1,
    XURY_EARLY_TERM_CACHED_FRESH = 2,
    XURY_EARLY_TERM_CACHED_IPV6  = 3,
} xury_early_term_reason_t;

/*
 * ============================================================================
 * DECISION
 * ============================================================================
 */

typedef struct {
    bool                     terminate;
    xury_early_term_reason_t reason;
} xury_early_term_decision_t;

/*
 * ============================================================================
 * PUBLIC ENTRY POINT
 * ============================================================================
 */

/*
 * Decide whether the scan pipeline should stop early.
 *
 * Arguments:
 *   sensing   the sensing sub-result; must not be NULL
 *   memory    the cache sub-result; must not be NULL
 *   probing   the probing sub-result, or NULL if probing has not run
 *             yet. Passing NULL means "peer IPv6 support is not
 *             known", which disables the rules that need it.
 *   out       the decision; must not be NULL
 *
 * Returns:
 *   XURY_OK        out filled
 *   XURY_ERR_INVAL sensing, memory, or out is NULL
 *
 * The function never allocates, never reads the peer endpoint
 * directly (it only looks at the probing result), and never guesses.
 */
xury_err_t xury_early_term_decide(const xury_sensing_result_t *sensing,
                                  const xury_memory_result_t *memory,
                                  const xury_probing_result_t *probing,
                                  xury_early_term_decision_t *out);

/*
 * ============================================================================
 * STRING HELPERS
 * ============================================================================
 */

/*
 * Stable, human-readable name for a reason.
 * Never returns NULL.
 */
const char *xury_early_term_reason_name(xury_early_term_reason_t r);

/*
 * ============================================================================
 * END OF XURY SMART INTERNAL EARLY TERMINATION HEADER
 * ============================================================================
 */

#endif /* XURY_SMART_INTERNAL_EARLY_TERM_H */
