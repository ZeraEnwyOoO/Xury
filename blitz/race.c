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
 * XURY BLITZ — RACE IMPLEMENTATION (Phase L)
 * ============================================================================
 *
 * Real implementation of blitz/internal/race.h.
 *
 * Sequential weapon execution in priority order, with a bounded
 * history, a strict revisit loop detector, and honest termination.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No concurrent racing. V2 concern, needs engine.
 *   - No relay, upgrade, or birthday. Those weapons do not exist.
 *   - No persistence. History is local to one call.
 *   - No engine integration. No socket ownership, no lifecycle.
 *   - No advisor implementation. An advisor may be supplied by the
 *     caller; race.c only calls it, it does not define one.
 *   - No learning. The learning state may be supplied by the caller
 *     for the advisor to read; race.c does not read it directly.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * V1 selects its initial strategy as:
 *
 *   - If state->advisor is non-NULL, ask it once for a
 *     recommendation. If the recommendation names a known V1
 *     strategy, use it. Otherwise, fall back to priority_order.
 *
 *   - If the advisor is NULL or its recommendation is unusable,
 *     use priority_order.
 *
 * The initial strategy is not changed mid-run in V1 except through
 * the NO_TRANSITION stop. Adaptation (mid-run strategy change) is
 * a V2 concern; the fields for it exist in blitz.h so that the
 * data model does not need to change later, but race.c does not
 * exercise them in V1.
 *
 * Why: V1's contract is "try weapons in priority order, return the
 * first success, or report total failure". That is enough to make
 * the library usable. Adaptive strategy selection without real
 * measurement data would be a design choice, not evidence, and
 * would violate the same principle that deferred adaptive.c.
 *
 * The history array exists in V1 for two reasons:
 *
 *   1. Loop detection needs it, even for a linear strategy:
 *      a strategy may legitimately repeat a weapon (e.g. HOLE
 *      at step 0 and again at step 4), and we must detect the
 *      case where the same (strategy, step, weapon) triple is
 *      reached twice.
 *   2. Debugging and future justification rules need the
 *      transition metadata. V1 does not act on it, but recording
 *      it costs nothing and lets a caller inspect what happened
 *      if the race fails.
 *
 * ----------------------------------------------------------------------------
 * Loop detection (V1: strict revisit)
 * ----------------------------------------------------------------------------
 *
 * V1 has no justification mechanism for revisiting an execution
 * state. Therefore, in V1:
 *
 *     revisit = loop
 *
 * The detector scans the history for an exact match of
 * (strategy_id, step_index, weapon). If found, BLITZ stops with
 * STOP_LOOP_DETECTED rather than appending a duplicate.
 *
 * This is stricter than necessary for a linear strategy, which
 * cannot revisit by construction, but it is the correct V1
 * behaviour for the data model in blitz.h and it will still be
 * correct if V2 adds adaptation that can revisit.
 *
 * ----------------------------------------------------------------------------
 * Return-code convention
 * ----------------------------------------------------------------------------
 *
 * See race.h. The short form:
 *
 *   XURY_ERR_INVAL  — programming error: NULL state or out, bad
 *                     peer, or zero timeout_ms.
 *   XURY_OK         — the race ran. Inspect out->stop_reason.
 *   other errors    — genuine platform failure; out is untouched.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   blitz/internal/blitz.h          shared types
 *   blitz/internal/race.h           this file's contract
 *   weapons/internal/weapon_ops.h   xury_weapon_attempt_ctx_t
 *   weapons/internal/ipv6.h         xury_weapon_ipv6_try
 *   weapons/internal/upnp.h         xury_weapon_upnp_try
 *   weapons/internal/natpmp.h       xury_weapon_natpmp_try
 *   weapons/internal/pcp.h          xury_weapon_pcp_try
 *   weapons/internal/hole.h         xury_weapon_hole_try
 *   weapons/internal/predict.h      xury_weapon_predict_try
 *   api/internal/weapon.h           xury_weapon_applicable_mask
 *                                   xury_weapon_mask_next
 *   platform/platform.h             monotonic time
 *   xury/types.h, xury/err.h        public types
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

#include "platform/platform.h"
#include "api/internal/weapon.h"
#include "weapons/internal/weapon_ops.h"
#include "weapons/internal/ipv6.h"
#include "weapons/internal/upnp.h"
#include "weapons/internal/natpmp.h"
#include "weapons/internal/pcp.h"
#include "weapons/internal/hole.h"
#include "weapons/internal/predict.h"
#include "blitz/internal/blitz.h"
#include "blitz/internal/race.h"

/*
 * ============================================================================
 * INTERNAL — STRATEGY CATALOG
 * ============================================================================
 *
 * V1 strategy catalog. Two strategies, both evidence-derived or
 * semantically justified:
 *
 *   priority_order  — the api/weapon.c priority table, filtered
 *                     by applicability. Evidence-derived: the
 *                     priority table is locked and tested in
 *                     test_weapon.c.
 *
 *   traversal_only  — HOLE, PREDICT. A valid composition: these
 *                     two weapons are the traversal category in
 *                     weapon.h. No performance claim is made.
 *
 * The catalog is static. Adding a strategy is a deliberate act,
 * not a runtime decision.
 *
 * Steps are listed in execution order. Steps whose weapons are not
 * applicable in the current context are skipped at runtime (see
 * the run loop). This keeps the catalog simple and lets the
 * applicability rules stay in one place (api/weapon.c).
 */

static const xury_blitz_strategy_t g_strategy_priority_order = {
    .id           = XURY_BLITZ_STRATEGY_PRIORITY_ORDER,
    .display_name = "priority_order",
    .steps        = {
        XURY_WEAPON_IPV6,
        XURY_WEAPON_LAN,
        XURY_WEAPON_UPNP,
        XURY_WEAPON_NATPMP,
        XURY_WEAPON_PCP,
        XURY_WEAPON_HOLE,
        XURY_WEAPON_PREDICT,
        XURY_WEAPON_MIRROR,
        XURY_WEAPON_RELAY,
        XURY_WEAPON_UPGRADE,
        XURY_WEAPON_BIRTHDAY,
    },
    .step_count   = 11u,
};

static const xury_blitz_strategy_t g_strategy_traversal_only = {
    .id           = XURY_BLITZ_STRATEGY_TRAVERSAL_ONLY,
    .display_name = "traversal_only",
    .steps        = {
        XURY_WEAPON_HOLE,
        XURY_WEAPON_PREDICT,
    },
    .step_count   = 2u,
};

/*
 * Look up a strategy by identity. Returns NULL if the id is not
 * one of the V1 catalog entries.
 */
static const xury_blitz_strategy_t *strategy_by_id(
    xury_blitz_strategy_id_t id)
{
    switch (id) {
    case XURY_BLITZ_STRATEGY_PRIORITY_ORDER:
        return &g_strategy_priority_order;
    case XURY_BLITZ_STRATEGY_TRAVERSAL_ONLY:
        return &g_strategy_traversal_only;
    default:
        return NULL;
    }
}

/*
 * ============================================================================
 * INTERNAL — HISTORY
 * ============================================================================
 */

static void history_init(xury_blitz_history_t *h)
{
    memset(h, 0, sizeof(*h));
}

/*
 * Append an attempt. Returns XURY_OK on success, or
 * XURY_ERR_BUFFER_TOO_SMALL if the array is full. Callers must
 * treat a full history as a stop condition, never as a silent
 * overwrite.
 */
static xury_err_t history_append(xury_blitz_history_t *h,
                                 const xury_blitz_attempt_record_t *rec)
{
    if (h->count >= XURY_BLITZ_MAX_ATTEMPTS) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    h->records[h->count] = *rec;
    h->count++;
    return XURY_OK;
}

/*
 * True if the same (strategy_id, step_index, weapon) triple
 * already appears in the history. See the file header for why this
 * is the V1 loop definition.
 */
static bool history_contains_state(
    const xury_blitz_history_t *h,
    xury_blitz_strategy_id_t strategy_id,
    uint8_t step_index,
    xury_weapon_t weapon)
{
    for (uint16_t i = 0; i < h->count; i++) {
        const xury_blitz_attempt_record_t *r = &h->records[i];
        if (r->strategy_id == strategy_id &&
            r->step_index  == step_index  &&
            r->weapon      == weapon) {
            return true;
        }
    }
    return false;
}

/*
 * ============================================================================
 * INTERNAL — DISPATCH
 * ============================================================================
 *
 * Call the weapon function named by w, with the given attempt
 * context. Unknown or unimplemented weapons return
 * XURY_ERR_NOT_IMPLEMENTED, which the run loop treats as a
 * platform-level skip (the weapon exists in the catalog but has
 * no implementation yet).
 */
static xury_err_t call_weapon(xury_weapon_t w,
                              const xury_weapon_attempt_ctx_t *ctx,
                              xury_weapon_attempt_result_t *out)
{
    switch (w) {
    case XURY_WEAPON_IPV6:
        return xury_weapon_ipv6_try(ctx, out);
    case XURY_WEAPON_UPNP:
        return xury_weapon_upnp_try(ctx, out);
    case XURY_WEAPON_NATPMP:
        return xury_weapon_natpmp_try(ctx, out);
    case XURY_WEAPON_PCP:
        return xury_weapon_pcp_try(ctx, out);
    case XURY_WEAPON_HOLE:
        return xury_weapon_hole_try(ctx, out);
    case XURY_WEAPON_PREDICT:
        return xury_weapon_predict_try(ctx, out);

    case XURY_WEAPON_LAN:
    case XURY_WEAPON_MIRROR:
    case XURY_WEAPON_RELAY:
    case XURY_WEAPON_UPGRADE:
    case XURY_WEAPON_BIRTHDAY:
        /*
         * Catalog entries with no implementation in Phase H.
         *
         * LAN is detection logic, not a Phase H weapon.
         * MIRROR, RELAY, UPGRADE, BIRTHDAY are Phase I or future.
         *
         * Reporting XURY_ERR_NOT_IMPLEMENTED here is honest: the
         * weapon is in the priority table, but this build cannot
         * execute it. The run loop treats it as a skip.
         */
        return XURY_ERR_NOT_IMPLEMENTED;

    default:
        return XURY_ERR_NOT_IMPLEMENTED;
    }
}

/*
 * ============================================================================
 * INTERNAL — INITIAL STRATEGY SELECTION
 * ============================================================================
 *
 * Ask the advisor (if any) once for a recommendation. If the
 * recommendation names a known V1 strategy, use it. Otherwise,
 * fall back to priority_order.
 *
 * The advisor is a suggestion, not a command. BLITZ decides.
 */

static const xury_blitz_strategy_t *select_initial_strategy(
    const xury_blitz_state_t *state)
{
    if (state->advisor != NULL &&
        state->advisor->recommend != NULL) {

        xury_blitz_recommendation_t rec;
        memset(&rec, 0, sizeof(rec));

        xury_err_t rc = state->advisor->recommend(
            state, &rec, state->advisor->userdata);

        if (rc == XURY_OK) {
            const xury_blitz_strategy_t *s =
                strategy_by_id(rec.strategy_id);
            if (s != NULL) {
                return s;
            }
            /* Recommendation unknown; fall through to default. */
        }
        /* Advisor failed; fall through to default. */
    }

    return &g_strategy_priority_order;
}

/*
 * ============================================================================
 * PUBLIC ENTRY POINT
 * ============================================================================
 */

xury_err_t xury_blitz_race(const xury_blitz_state_t *state,
                           xury_blitz_result_t *out)
{
    /*
     * ------------------------------------------------------------------
     * Argument validation
     * ------------------------------------------------------------------
     */
    if (state == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }

    /*
     * A usable peer is required. This mirrors the weapon contract:
     * the peer is caller-supplied, and a malformed one is a
     * programming error.
     */
    if (state->peer.family != XURY_AF_INET &&
        state->peer.family != XURY_AF_INET6) {
        return XURY_ERR_INVAL;
    }
    if (state->peer.ip[0] == '\0' || state->peer.port == 0u) {
        return XURY_ERR_INVAL;
    }

    /*
     * A zero deadline would mean "wait forever", which for a race
     * with a bounded history is a hang. Require a real budget.
     */
    if (state->timeout_ms == 0u) {
        return XURY_ERR_INVAL;
    }

    memset(out, 0, sizeof(*out));

    uint64_t t0 = xury_platform_time_ms();
    uint64_t deadline_ms = t0 + (uint64_t)state->timeout_ms;

    /*
     * ------------------------------------------------------------------
     * Initialize history
     * ------------------------------------------------------------------
     */
    xury_blitz_history_t history;
    history_init(&history);

    /*
     * ------------------------------------------------------------------
     * Select initial strategy
     * ------------------------------------------------------------------
     *
     * V1 uses one strategy per call. Adaptation (mid-run strategy
     * change) is a V2 concern; the fields exist in blitz.h but
     * race.c does not exercise them yet.
     */
    const xury_blitz_strategy_t *strategy =
        select_initial_strategy(state);

    /*
     * ------------------------------------------------------------------
     * Precompute the applicable-weapon mask for this context.
     * ------------------------------------------------------------------
     *
     * This is the same mask api/weapon.c uses for its selection
     * layer. A step whose weapon is not in the mask is skipped:
     * the context says it cannot work.
     */
    uint32_t applicable_mask =
        xury_weapon_applicable_mask(&state->ctx);

    /*
     * ------------------------------------------------------------------
     * Run loop
     * ------------------------------------------------------------------
     *
     * For each step in the strategy:
     *   1. If the budget is exhausted, stop with STOP_BUDGET.
     *   2. If the weapon is not applicable, skip.
     *   3. If the same execution state was already visited, stop
     *      with STOP_LOOP_DETECTED.
     *   4. Call the weapon with a per-attempt context built from
     *      the state.
     *   5. Record the attempt in history.
     *   6. If the weapon succeeded, stop with STOP_SUCCESS.
     *
     * If the loop finishes without success, stop with
     * STOP_ALL_EXHAUSTED.
     */
    for (uint8_t step = 0u; step < strategy->step_count; step++) {
        xury_weapon_t w = strategy->steps[step];

        if (!xury_weapon_is_valid(w)) {
            continue;
        }

        /* Budget check. */
        uint64_t now = xury_platform_time_ms();
        if (now >= deadline_ms) {
            out->stop_reason = XURY_BLITZ_STOP_BUDGET;
            goto done;
        }

        /* Applicability check. */
        if ((applicable_mask & XURY_WEAPON_BIT(w)) == 0u) {
            continue;
        }

        /* Loop detector (V1: strict revisit). */
        if (history_contains_state(&history, strategy->id,
                                   step, w)) {
            out->stop_reason = XURY_BLITZ_STOP_LOOP_DETECTED;
            goto done;
        }

        /* Build the per-attempt context. */
        xury_weapon_attempt_ctx_t actx;
        memset(&actx, 0, sizeof(actx));
        actx.peer              = state->peer;
        actx.applicability_ctx = state->ctx;
        actx.local_port        = state->local_port;
        actx.predicted_peer_port = state->predicted_peer_port;

        /*
         * Per-attempt budget: the smaller of the remaining total
         * budget and the caller's overall timeout. This keeps the
         * race inside its promise without giving every weapon the
         * full budget and blowing the deadline.
         */
        uint64_t remaining_ms = deadline_ms - now;
        if (remaining_ms > 0xFFFFFFFFu) {
            remaining_ms = 0xFFFFFFFFu;
        }
        actx.timeout_ms = (uint32_t)remaining_ms;

        /* Call the weapon. */
        xury_weapon_attempt_result_t wres;
        memset(&wres, 0, sizeof(wres));
        xury_err_t wrc = call_weapon(w, &actx, &wres);

        /*
         * Record the attempt. The transition is STRATEGY_NEXT
         * because V1 only moves forward through the sequence.
         * from_strategy and retry_of_index are NONE / NO_ATTEMPT.
         */
        xury_blitz_attempt_record_t rec;
        memset(&rec, 0, sizeof(rec));
        rec.strategy_id     = strategy->id;
        rec.step_index      = step;
        rec.weapon          = w;
        rec.transition      = XURY_BLITZ_TRANS_STRATEGY_NEXT;
        rec.from_strategy   = XURY_BLITZ_STRATEGY_NONE;
        rec.retry_of_index  = XURY_BLITZ_NO_ATTEMPT;
        rec.success         = wres.success;
        rec.elapsed_ms      = wres.elapsed_ms;
        rec.error           = wrc;
        rec.started_ms      = now;

        if (history_append(&history, &rec) != XURY_OK) {
            out->stop_reason = XURY_BLITZ_STOP_HISTORY_FULL;
            goto done;
        }

        /*
         * Interpretation:
         *   - XURY_OK with success  -> winner.
         *   - XURY_OK without success -> weapon ran and reported a
         *     real-world failure. Continue.
         *   - XURY_ERR_NOT_IMPLEMENTED -> weapon has no
         *     implementation. Continue.
         *   - Any other error -> a genuine platform failure. We do
         *     not abort the whole race on one weapon's platform
         *     problem; the next weapon might work. Record and
         *     continue.
         *
         * V1 deliberately does not escalate a single weapon's
         * platform error into a race failure. The caller reads the
         * stop reason and the history; if every weapon failed with
         * a platform error, the stop reason will be ALL_EXHAUSTED,
         * and the history will show the errors.
         */
        if (wrc == XURY_OK && wres.success) {
            out->stop_reason = XURY_BLITZ_STOP_SUCCESS;
            out->winner      = w;
            out->result      = wres;
            goto done;
        }
    }

    /*
     * The strategy finished without success.
     */
    out->stop_reason = XURY_BLITZ_STOP_ALL_EXHAUSTED;

done:
    out->attempts_count = history.count;
    out->elapsed_ms     = (uint32_t)(xury_platform_time_ms() - t0);
    return XURY_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
