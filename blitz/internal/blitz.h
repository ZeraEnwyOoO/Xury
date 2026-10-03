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
 * (Same header comment as before — omitted here for brevity.)
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
 * FORWARD DECLARATIONS
 * ============================================================================
 *
 * xury_blitz_state_t and xury_blitz_advisor_t reference each other:
 *
 *   - the state holds an optional pointer to an advisor;
 *   - the advisor's recommend callback takes a pointer to the state.
 *
 * Both are declared as incomplete struct types here, then defined
 * in full below. This lets each type's definition mention the
 * other without a circular include.
 */
typedef struct xury_blitz_state_s   xury_blitz_state_t;
typedef struct xury_blitz_advisor_s xury_blitz_advisor_t;

/*
 * ============================================================================
 * STRATEGY IDENTITY
 * ============================================================================
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
 */

typedef enum {
    XURY_BLITZ_STOP_SUCCESS        = 0,
    XURY_BLITZ_STOP_BUDGET         = 1,
    XURY_BLITZ_STOP_NO_TRANSITION  = 2,
    XURY_BLITZ_STOP_LOOP_DETECTED  = 3,
    XURY_BLITZ_STOP_HISTORY_FULL   = 4,
    XURY_BLITZ_STOP_ALL_EXHAUSTED  = 5,
} xury_blitz_stop_t;

/*
 * ============================================================================
 * STRATEGY (V1)
 * ============================================================================
 */

#define XURY_BLITZ_MAX_STEPS 12u

typedef struct {
    xury_blitz_strategy_id_t id;
    const char              *display_name;
    xury_weapon_t            steps[XURY_BLITZ_MAX_STEPS];
    uint8_t                  step_count;
} xury_blitz_strategy_t;

/*
 * ============================================================================
 * HISTORY (V1)
 * ============================================================================
 */

#define XURY_BLITZ_MAX_ATTEMPTS 64u
#define XURY_BLITZ_NO_ATTEMPT   0xFFFFu

typedef struct {
    xury_blitz_strategy_id_t strategy_id;
    uint8_t                  step_index;
    xury_weapon_t            weapon;

    xury_blitz_transition_t  transition;
    xury_blitz_strategy_id_t from_strategy;
    uint16_t                 retry_of_index;

    bool                             success;
    uint32_t                         elapsed_ms;
    xury_err_t                       error;

    uint64_t                         started_ms;
} xury_blitz_attempt_record_t;

typedef struct {
    xury_blitz_attempt_record_t records[XURY_BLITZ_MAX_ATTEMPTS];
    uint16_t                    count;
} xury_blitz_history_t;

/*
 * ============================================================================
 * RECOMMENDATION
 * ============================================================================
 *
 * A recommendation from an advisor. Small in V1; extended in later
 * revisions by adding fields, not by changing the call site.
 */

typedef struct {
    xury_blitz_strategy_id_t strategy_id;
    const char              *display_name;
} xury_blitz_recommendation_t;

/*
 * ============================================================================
 * STATE (full definition)
 * ============================================================================
 */

struct xury_blitz_state_s {
    xury_endpoint_t        peer;
    xury_weapon_context_t  ctx;
    xury_nat_type_t        nat_type;

    uint16_t               local_port;
    uint16_t               predicted_peer_port;

    uint32_t               timeout_ms;

    const xury_blitz_advisor_t  *advisor;
    const xury_smart_learning_t *learning;
};

/*
 * ============================================================================
 * ADVISOR (full definition)
 * ============================================================================
 */

struct xury_blitz_advisor_s {
    xury_err_t (*recommend)(
        const xury_blitz_state_t *state,
        xury_blitz_recommendation_t *out,
        void *userdata);

    void *userdata;
};

/*
 * ============================================================================
 * RESULT
 * ============================================================================
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
