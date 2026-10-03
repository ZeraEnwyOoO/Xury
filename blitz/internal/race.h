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

#ifndef XURY_BLITZ_INTERNAL_RACE_H
#define XURY_BLITZ_INTERNAL_RACE_H

/*
 * ============================================================================
 * XURY BLITZ — RACE (Phase L)
 * ============================================================================
 *
 * Declares xury_blitz_race(), the V1 BLITZ entry point.
 *
 * BLITZ is the commander. Given a state (peer, context, ports,
 * budget) and an optional advisor, xury_blitz_race() selects a
 * strategy, executes weapons in sequence, observes results, and
 * decides whether to adapt, retry, or stop.
 *
 * ----------------------------------------------------------------------------
 * Peer not parent: the advisor is optional
 * ----------------------------------------------------------------------------
 *
 * BLITZ and any future ADAPTIVE (Phase J Stage 2) are PEERS, not a
 * parent-child pair. BLITZ must be able to run completely without
 * ADAPTIVE — the advisor pointer in xury_blitz_state_t may be NULL,
 * and the learning pointer may be NULL. In that case, BLITZ uses
 * its own default strategy selection (the api/weapon.c priority
 * table, filtered by applicability) directly. It does NOT call
 * into smart/adaptive.c at all.
 *
 * When the advisor IS provided, BLITZ MAY consult it as one input
 * to its decision, but the final decision remains BLITZ's. The
 * advisor suggests; BLITZ decides. This is the same one-way
 * dependency direction used elsewhere in Xury:
 *
 *   BLITZ → (optional) → advisor
 *   advisor does NOT call into BLITZ
 *
 * Testability is a direct consequence: the BLITZ test suite
 * exercises xury_blitz_race() with advisor == NULL and
 * learning == NULL, proving there is no hard dependency on
 * adaptive.c existing or being correct.
 *
 * ----------------------------------------------------------------------------
 * Scope of V1
 * ----------------------------------------------------------------------------
 *
 *   - Sequential. One weapon at a time. V2 will add concurrent
 *     racing, which requires engine-level lifecycle and
 *     cancellation design (see engine/, Phase M).
 *
 *   - Single strategy per invocation. BLITZ may adapt mid-run
 *     (change strategy), but it does not run two strategies in
 *     parallel.
 *
 *   - No relay, no upgrade, no birthday. Those weapons are not
 *     implemented yet. Strategies that would use them are not in
 *     the V1 catalog.
 *
 *   - No persistence. History is a local, bounded array inside
 *     the call. When BLITZ returns, the history is gone.
 *
 *   - No engine integration. BLITZ does not own sockets, does not
 *     manage a lifecycle, and does not call xury_get_socket_fd().
 *     That integration is Phase M.
 *
 * ----------------------------------------------------------------------------
 * Return-code convention (matches weapon_ops.h)
 * ----------------------------------------------------------------------------
 *
 *   XURY_OK         — the race ran. Whether it succeeded is in
 *                     out->stop_reason and out->winner. A
 *                     timeout, an exhausted strategy, a detected
 *                     loop, or a full history are real-world
 *                     outcomes, not errors.
 *
 *   XURY_ERR_INVAL  — programming error: state or out is NULL, or
 *                     state->peer is unusable, or state->timeout_ms
 *                     is zero (a race with no deadline would
 *                     hang; the caller made a mistake).
 *
 *   other errors    — a genuine platform failure prevented the
 *                     race from running at all. Out is untouched.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   blitz/internal/blitz.h          xury_blitz_state_t,
 *                                   xury_blitz_result_t
 *   xury/types.h, xury/err.h        public types
 *
 * The .c file additionally includes the weapon headers it calls,
 * plus core/ and platform/ for timing. Those are not needed by
 * this declaration.
 *
 * No allocation, no global state.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/types.h>
#include <xury/err.h>

#include "blitz/internal/blitz.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * ENTRY POINT
 * ============================================================================
 */

/*
 * Run one BLITZ attempt.
 *
 * Given a state, BLITZ:
 *   1. Selects an initial strategy. If state->advisor is non-NULL,
 *      it asks the advisor for a recommendation. Otherwise, it
 *      uses the api/weapon.c priority order filtered by
 *      applicability.
 *   2. Executes the strategy's weapons in sequence, calling each
 *      weapon's xury_weapon_<name>_try() with a per-attempt
 *      context built from the state.
 *   3. Records each attempt in a bounded history.
 *   4. On success, stops with XURY_BLITZ_STOP_SUCCESS and sets
 *      out->winner to the weapon that succeeded.
 *   5. On failure, decides whether to continue, adapt, retry, or
 *      stop. The decision rules are documented in blitz.h and are
 *      bounded by the loop detector and the caller's budget.
 *   6. Returns XURY_OK with a stop reason and, on success, the
 *      winning weapon and its result.
 *
 * Arguments:
 *   state   input state; must not be NULL. state->peer must be a
 *           usable endpoint. state->timeout_ms must be non-zero
 *           (a race with no deadline would hang).
 *   out     result; must not be NULL.
 *
 * Returns:
 *   XURY_OK         out filled. Inspect out->stop_reason and
 *                   out->winner.
 *   XURY_ERR_INVAL  state or out is NULL, state->peer is unusable,
 *                   or state->timeout_ms is zero.
 *   other           genuine platform failure; out is untouched.
 *
 * On XURY_OK, out->stop_reason is always one of the
 * XURY_BLITZ_STOP_* values. If stop_reason is SUCCESS, out->winner
 * is a valid weapon (not XURY_WEAPON_NONE) and out->result is the
 * winning weapon's result. For any other stop reason, out->winner
 * is XURY_WEAPON_NONE and out->result is zeroed.
 *
 * Blocks the calling thread for at most state->timeout_ms, plus a
 * small bounded overhead for the last attempt.
 */
xury_err_t xury_blitz_race(const xury_blitz_state_t *state,
                           xury_blitz_result_t *out);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY BLITZ RACE HEADER
 * ============================================================================
 */

#endif /* XURY_BLITZ_INTERNAL_RACE_H */
