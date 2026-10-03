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

#ifndef XURY_BLITZ_INTERNAL_BLITZ_H
#define XURY_BLITZ_INTERNAL_BLITZ_H

/*
 * ============================================================================
 * XURY BLITZ — SHARED TYPES (Phase L)
 * ============================================================================
 *
 * BLITZ is the commander. Given a peer and a context, it selects a
 * strategy, executes weapons in order, observes results, and — when
 * the strategy is exhausted — decides whether to adapt, retry, or
 * stop.
 *
 * BLITZ is NOT a loop runner. It is a state-aware decision maker.
 * It may consult an optional advisor, but it owns the final
 * decision. It does not depend on the advisor or on any learning
 * module existing.
 *
 * ----------------------------------------------------------------------------
 * Semantic model (locked)
 * ----------------------------------------------------------------------------
 *
 *   STRATEGY        = decision structure (V1: linear sequence)
 *   PATH            = actual route taken through current strategy
 *   TRANSITION      = how BLITZ moved to the next attempt
 *   EXECUTION STATE = (strategy_id, step_index, weapon)
 *   REVISIT         = execution state already appeared in history
 *   LOOP            = revisit that V1 cannot justify
 *   HISTORY         = bounded, append-only attempt records
 *
 * V1 has no justification mechanism for revisit. Therefore, in V1,
 * a revisit is a loop and BLITZ stops. V2 may add justification
 * rules (context change, explicit retry with evidence) without
 * changing the meaning of the fields below.
 *
 * ----------------------------------------------------------------------------
 * Commander, not advisor
 * ----------------------------------------------------------------------------
 *
 * The advisor (optional, may be NULL) suggests. BLITZ decides. A
 * future adaptive.c may implement an advisor; this header does not
 * depend on it. BLITZ runs correctly with advisor == NULL.
 *
 * The learning state (optional, may be NULL) is accumulated
 * evidence. BLITZ may pass it to the advisor; it does not read it
 * directly.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 * This header includes only:
 *   <xury/types.h>                  public types
 *   <xury/err.h>                    error codes
 *   api/internal/weapon.h           xury_weapon_context_t
 *   weapons/internal/weapon_ops.h   xury_weapon_attempt_result_t
 *
 * It deliberately does NOT include any core/, platform/, or peer/
 * header. Those belong to the .c files.
 *
 * No allocation, no global state.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/types.h>
#include <xury/err.h>

#include "api/internal/weapon.h"
#include "weapons/internal/weapon_ops.h"
#include "smart/internal/learning.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * STRATEGY IDENTITY
 * ============================================================================
 *
 * A stable identity for each named strategy. The display name
 * (a string) is separate and may change; the enum does not.
 *
 * History records the enum, not the string, so that a strategy
 * rename does not invalidate old history.
 *
 * V1 catalog is:
 *   PRIORITY_ORDER  — weapons in api/weapon.c priority order,
 *                     filtered by applicability. Evidence-derived.
 *   TRAVERSAL_ONLY  — HOLE, PREDICT. Valid composition.
 *
 * DIRECT_FIRST is not in the V1 catalog. It is a proposed strategy
 * whose ordering is a design choice, not evidence-derived. It may
 * be added later, alongside real measurement.
 */
typedef enum {
    XURY_BLITZ_STRATEGY_NONE           = 0,
    XURY_BLITZ_STRATEGY_PRIORITY_ORDER = 1,
    XURY_BLITZ_STRATEGY_TRAVERSAL_ONLY = 2,
} xury_blitz_strategy_id_t;

/*
 * ============================================================================
 * TRANSITION
 * ============================================================================
 *
 * How BLITZ arrived at the current attempt. Recorded per attempt,
 * for debugging and for the loop detector.
 *
 * STRATEGY_NEXT — implicit: the next step in the current strategy.
 * RETRY         — explicit: BLITZ asked for the same weapon again,
 *                 within the current strategy.
 * ADAPT         — explicit: BLITZ changed strategy.
 * DIRECT        — explicit: BLITZ chose a weapon not from the
 *                 strategy sequence.
 */
typedef enum {
    XURY_BLITZ_TRANS_STRATEGY_NEXT = 0,
    XURY_BLITZ_TRANS_RETRY         = 1,
    XURY_BLITZ_TRANS_ADAPT         = 2,
    XURY_BLITZ_TRANS_DIRECT        = 3,
} xury_blitz_transition_t;

/*
 * ============================================================================
 * STOP REASON
 * ============================================================================
 *
 * Why BLITZ returned. Every return path sets exactly one of these
 * in the result struct. No duplicate flags.
 */
typedef enum {
    /* A weapon reported success. Winner is set. */
    XURY_BLITZ_STOP_SUCCESS = 0,

    /* The caller's timeout_ms budget was exhausted. */
    XURY_BLITZ_STOP_BUDGET = 1,

    /* The current strategy produced no valid next step, and no
     * adaptation is available. */
    XURY_BLITZ_STOP_NO_TRANSITION = 2,

    /* The loop detector saw a revisit that V1 cannot justify. */
    XURY_BLITZ_STOP_LOOP_DETECTED = 3,

    /* The history array is full. Appending another attempt would
     * lose evidence. V1 does not overwrite. */
    XURY_BLITZ_STOP_HISTORY_FULL = 4,

    /* All applicable strategies have been tried, and none
     * succeeded. */
    XURY_BLITZ_STOP_ALL_EXHAUSTED = 5,
} xury_blitz_stop_t;

/*
 * ============================================================================
 * STRATEGY (V1)
 * ============================================================================
 *
 * V1 strategies are linear sequences. The semantics allow future
 * representations to add conditional branching (graph) without
 * changing the meaning of "strategy".
 *
 * The sequence is immutable once constructed; the runtime path is
 * recorded separately in the history.
 *
 * XURY_BLITZ_MAX_STEPS bounds the compile-time size. It is a
 * storage bound, not a claim about how many steps a strategy
 * "should" have. 11 is one more than XURY_WEAPON_COUNT, which is
 * the largest meaningful sequence today.
 */
#define XURY_BLITZ_MAX_STEPS 12u

typedef struct {
    xury_blitz_strategy_id_t id;
    const char              *display_name;   /* for logs; may change */
    xury_weapon_t            steps[XURY_BLITZ_MAX_STEPS];
    uint8_t                  step_count;
} xury_blitz_strategy_t;

/*
 * ============================================================================
 * HISTORY (V1)
 * ============================================================================
 *
 * Bounded, fixed-size, append-only. No heap allocation. When the
 * array is full, BLITZ stops with STOP_HISTORY_FULL; it never
 * silently overwrites evidence.
 *
 * The size is an implementation limit, not a semantic claim. 64 is
 * chosen to comfortably exceed the number of attempts any V1
 * strategy can produce, so the limit is only hit when something
 * unexpected is happening.
 *
 * Each record carries:
 *   - execution-state identity: (strategy_id, step_index, weapon)
 *   - transition metadata:      (transition, from_strategy,
 *                                retry_of_index)
 *   - result:                    (success, elapsed_ms, error)
 *   - timing:                    (started_ms)
 *
 * The loop detector uses the execution-state identity. The
 * transition metadata is for debugging and for future justification
 * rules (V2).
 */
#define XURY_BLITZ_MAX_ATTEMPTS 64u

#define XURY_BLITZ_NO_ATTEMPT 0xFFFFu

typedef struct {
    /* Execution-state identity */
    xury_blitz_strategy_id_t strategy_id;
    uint8_t                  step_index;
    xury_weapon_t            weapon;

    /* Transition metadata */
    xury_blitz_transition_t  transition;
    xury_blitz_strategy_id_t from_strategy;   /* only for ADAPT */
    uint16_t                 retry_of_index;  /* only for RETRY */

    /* Result */
    bool                             success;
    uint32_t                         elapsed_ms;
    xury_err_t                       error;    /* XURY_OK on success/fail */

    /* Timing */
    uint64_t                         started_ms;
} xury_blitz_attempt_record_t;

typedef struct {
    xury_blitz_attempt_record_t records[XURY_BLITZ_MAX_ATTEMPTS];
    uint16_t                    count;
} xury_blitz_history_t;

/*
 * ============================================================================
 * ADVISOR (optional)
 * ============================================================================
 *
 * An advisor MAY suggest a strategy. BLITZ decides. An advisor is
 * not required; BLITZ runs correctly when the advisor pointer is
 * NULL.
 *
 * The recommendation type is intentionally small in V1. It returns
 * a strategy id and writes an optional display name. A future
 * revision may extend the recommendation (next weapon, retry hint,
 * abandon hint) without changing the call site, by adding fields to
 * the recommendation struct.
 *
 * The advisor MUST NOT call into BLITZ. The dependency direction is
 * one-way: BLITZ may consult the advisor; the advisor does not know
 * BLITZ exists.
 */
typedef struct {
    xury_blitz_strategy_id_t strategy_id;
    const char              *display_name;   /* may be NULL */
} xury_blitz_recommendation_t;

typedef struct {
    /*
     * Ask the advisor for a recommendation.
     *
     * May be NULL. If NULL, BLITZ uses its own default strategy
     * selection.
     *
     * Returns XURY_OK and fills *out on success.
     * Returns an error (the recommendation is ignored) on failure.
     */
    xury_err_t (*recommend)(
        const struct xury_blitz_state_s *state,
        xury_blitz_recommendation_t     *out,
        void                            *userdata);

    void *userdata;
} xury_blitz_advisor_t;

/*
 * ============================================================================
 * STATE (input to xury_blitz_race)
 * ============================================================================
 *
 * Everything BLITZ needs to run one attempt. The caller owns the
 * struct and is responsible for keeping it valid for the duration
 * of the call.
 *
 * The applicability context is treated as immutable for the duration
 * of one xury_blitz_race() call. To re-scan and re-run, the caller
 * creates a new state.
 *
 * local_port and predicted_peer_port are forwarded to weapons
 * unchanged. Weapons that do not use them ignore them. See the
 * notes in weapon_ops.h.
 */
typedef struct xury_blitz_state_s {
    /* Target peer (caller-supplied, never hardcoded) */
    xury_endpoint_t        peer;

    /* Applicability context from scan/analysis */
    xury_weapon_context_t  ctx;

    /* NAT type from scan (for future advisor use) */
    xury_nat_type_t        nat_type;

    /* Ports forwarded to weapons that use them */
    uint16_t               local_port;
    uint16_t               predicted_peer_port;

    /* Total budget for the entire BLITZ attempt */
    uint32_t               timeout_ms;

    /* Optional advisor. NULL means "no advisor". */
    const xury_blitz_advisor_t *advisor;

    /* Optional learning state. NULL means "no accumulated evidence". */
    const xury_smart_learning_t *learning;
} xury_blitz_state_t;

/*
 * ============================================================================
 * RESULT (output of xury_blitz_race)
 * ============================================================================
 *
 * On XURY_OK:
 *   - stop_reason is one of the STOP_* values.
 *   - winner is XURY_WEAPON_NONE unless stop_reason is SUCCESS.
 *   - result is valid only when winner != NONE.
 *   - attempts_count is the number of records in history.
 *   - elapsed_ms is the wall-clock duration of the whole call.
 *
 * On XURY_ERR_INVAL (programming error), out is left untouched.
 */
typedef struct {
    xury_blitz_stop_t                stop_reason;
    xury_weapon_t                    winner;
    xury_weapon_attempt_result_t     result;
    uint16_t                         attempts_count;
    uint32_t                         elapsed_ms;
} xury_blitz_result_t;

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY BLITZ SHARED TYPES
 * ============================================================================
 */

#endif /* XURY_BLITZ_INTERNAL_BLITZ_H */
