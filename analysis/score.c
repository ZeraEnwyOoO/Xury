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
 * XURY ANALYSIS — SCORE IMPLEMENTATION (F.3c)
 * ============================================================================
 *
 * Honest stub. Every function returns XURY_ERR_NOT_CALIBRATED.
 *
 * See src/analysis/internal/score.h for the full rationale, and
 * docs/RESEARCH.md §2 F.3c and §4 for why no formula is written yet.
 *
 * ----------------------------------------------------------------------------
 * What this file must NOT do
 * ----------------------------------------------------------------------------
 *
 *   - Must NOT invent probability values.
 *   - Must NOT contain hidden heuristics.
 *   - Must NOT use the scan result, even to "sanity check".
 *   - Must NOT set *out on error.
 *
 * Any of those would turn an honest "I don't know" into a silent
 * lie, and would defeat the purpose of the RESEARCH.md contract.
 *
 * ----------------------------------------------------------------------------
 * The 11 functions are deliberately separate
 * ----------------------------------------------------------------------------
 *
 * A single dispatcher would be shorter. The separate form is chosen
 * so that when calibration data arrives, each weapon gets its own
 * body in place, with its own features and its own prior, without
 * rewriting a generic function into eleven special cases later.
 *
 * For now, all eleven bodies are identical and return
 * XURY_ERR_NOT_CALIBRATED.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/err.h>
#include <xury/scan.h>

#include "analysis/internal/score.h"

/*
 * ============================================================================
 * INTERNAL — SHARED BODY
 * ============================================================================
 *
 * One helper implements the current behavior for every weapon. The
 * public functions below call it with their own name, so a future
 * change that makes one weapon different from the others is a local
 * edit, not a refactor.
 *
 * On *out == NULL, XURY_ERR_INVAL is returned.
 * On success (not yet reachable), this helper would write *out. The
 * parameter is kept so the signatures do not change when calibration
 * lands.
 *
 * The scan result parameter is intentionally unused. It is part of
 * the signature because the calibrated bodies will need it, and
 * because a caller passing NULL should not be a special error path
 * here: F.3c does not read the observation.
 */

static xury_err_t score_not_calibrated(const xury_scan_result_t *r,
                                       double *out)
{
    (void)r;

    if (out == NULL) {
        return XURY_ERR_INVAL;
    }

    /*
     * Do NOT write to *out. The caller must not read it. Returning
     * XURY_ERR_NOT_CALIBRATED is the entire point of this layer
     * until docs/RESEARCH.md §4 is resolved.
     */
    return XURY_ERR_NOT_CALIBRATED;
}

/*
 * ============================================================================
 * PUBLIC — 11 WEAPON PROBABILITY FUNCTIONS
 * ============================================================================
 *
 * Order matches xury_weapon_t in <xury/types.h> (after NONE):
 *
 *   1  IPV6
 *   2  LAN
 *   3  UPNP
 *   4  NATPMP
 *   5  PCP
 *   6  HOLE
 *   7  PREDICT
 *   8  BIRTHDAY
 *   9  MIRROR
 *  10  RELAY
 *  11  UPGRADE
 */

xury_err_t xury_analysis_p_ipv6(const xury_scan_result_t *r, double *out)
{
    return score_not_calibrated(r, out);
}

xury_err_t xury_analysis_p_lan(const xury_scan_result_t *r, double *out)
{
    return score_not_calibrated(r, out);
}

xury_err_t xury_analysis_p_upnp(const xury_scan_result_t *r, double *out)
{
    return score_not_calibrated(r, out);
}

xury_err_t xury_analysis_p_natpmp(const xury_scan_result_t *r, double *out)
{
    return score_not_calibrated(r, out);
}

xury_err_t xury_analysis_p_pcp(const xury_scan_result_t *r, double *out)
{
    return score_not_calibrated(r, out);
}

xury_err_t xury_analysis_p_hole(const xury_scan_result_t *r, double *out)
{
    return score_not_calibrated(r, out);
}

xury_err_t xury_analysis_p_predict(const xury_scan_result_t *r, double *out)
{
    return score_not_calibrated(r, out);
}

xury_err_t xury_analysis_p_birthday(const xury_scan_result_t *r, double *out)
{
    return score_not_calibrated(r, out);
}

xury_err_t xury_analysis_p_mirror(const xury_scan_result_t *r, double *out)
{
    return score_not_calibrated(r, out);
}

xury_err_t xury_analysis_p_relay(const xury_scan_result_t *r, double *out)
{
    return score_not_calibrated(r, out);
}

xury_err_t xury_analysis_p_upgrade(const xury_scan_result_t *r, double *out)
{
    return score_not_calibrated(r, out);
}

/*
 * ============================================================================
 * PUBLIC — CALIBRATION STATUS
 * ============================================================================
 *
 * Always false until docs/RESEARCH.md §4 is resolved. When real
 * calibration lands, this becomes true and the caller can switch
 * from xury_weapon_base_strength() priors to the probabilities
 * above in one place.
 */

bool xury_analysis_score_calibrated(void)
{
    return false;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
