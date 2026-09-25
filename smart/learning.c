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
 * XURY SMART — LEARNING IMPLEMENTATION (Stage 1: data collection)
 * ============================================================================
 *
 * Real implementation of src/smart/internal/learning.h.
 *
 * Records raw (nat_type, weapon) -> {success, fail} counts. No
 * decisions, no thresholds, no ordering. See the header for the full
 * contract and for the scope reminder (NAT traversal only, not
 * general-purpose ML).
 *
 * ----------------------------------------------------------------------------
 * What this file is NOT
 * ----------------------------------------------------------------------------
 *
 *   - Not a decision layer. There is no "which weapon should we try
 *     next?" function here. That belongs to Stage 2 (adaptive.c) and
 *     requires calibration that does not exist yet.
 *
 *   - Not persistent. Counts live in the struct the caller owns.
 *     Stage 2 will reuse the cache.c storage interface when
 *     persistence is needed.
 *
 *   - Not synchronized. One engine, one thread, by design.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 * - src/smart/internal/learning.h
 * - <xury/types.h>, <xury/err.h>
 * - <string.h>          (for memset in init)
 *
 * No allocation, no I/O, no platform, no global state.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/types.h>
#include <xury/err.h>

#include "smart/internal/learning.h"

/*
 * ============================================================================
 * INTERNAL HELPERS
 * ============================================================================
 */

/*
 * True if the NAT type is a valid index into the counters.
 *
 * The sentinels (XURY_NAT_UNKNOWN) are valid inputs: they index row
 * 0 of the array. Callers that never record against a sentinel
 * simply leave that row at zero.
 */
static bool nat_type_in_range(xury_nat_type_t nat_type)
{
    int v = (int)nat_type;
    return v >= 0 && v < (int)XURY_NAT_COUNT;
}

/*
 * True if the weapon is a valid index into the counters.
 *
 * The sentinel (XURY_WEAPON_NONE) is a valid input: it indexes
 * column 0 of the array.
 */
static bool weapon_in_range(xury_weapon_t weapon)
{
    int v = (int)weapon;
    return v >= 0 && v < (int)XURY_WEAPON_COUNT;
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

void xury_smart_learning_init(xury_smart_learning_t *l)
{
    if (l == NULL) {
        return;
    }
    memset(l, 0, sizeof(*l));
}

/*
 * ============================================================================
 * RECORD
 * ============================================================================
 */

xury_err_t xury_smart_learning_record(xury_smart_learning_t *l,
                                      xury_nat_type_t nat_type,
                                      xury_weapon_t weapon,
                                      bool success)
{
    if (l == NULL) {
        return XURY_ERR_INVAL;
    }
    if (!nat_type_in_range(nat_type)) {
        return XURY_ERR_INVAL;
    }
    if (!weapon_in_range(weapon)) {
        return XURY_ERR_INVAL;
    }

    /*
     * Increment the appropriate counter. The two arrays are
     * independent; a counter never saturates (a uint32_t at one
     * increment per second would take over 136 years to wrap).
     */
    uint32_t *cell = success
        ? &l->success[(size_t)nat_type][(size_t)weapon]
        : &l->fail   [(size_t)nat_type][(size_t)weapon];

    (*cell)++;

    return XURY_OK;
}

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

xury_err_t xury_smart_learning_get(const xury_smart_learning_t *l,
                                   xury_nat_type_t nat_type,
                                   xury_weapon_t weapon,
                                   uint32_t *out_success,
                                   uint32_t *out_fail)
{
    if (l == NULL) {
        return XURY_ERR_INVAL;
    }
    if (!nat_type_in_range(nat_type)) {
        return XURY_ERR_INVAL;
    }
    if (!weapon_in_range(weapon)) {
        return XURY_ERR_INVAL;
    }

    /*
     * out_success and out_fail are optional. The argument validation
     * above is the whole point of allowing both to be NULL: a caller
     * that only wants to validate an index pair can pass NULL, NULL.
     */
    if (out_success != NULL) {
        *out_success = l->success[(size_t)nat_type][(size_t)weapon];
    }
    if (out_fail != NULL) {
        *out_fail = l->fail[(size_t)nat_type][(size_t)weapon];
    }

    return XURY_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
