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

#ifndef XURY_ANALYSIS_INTERNAL_SCORE_H
#define XURY_ANALYSIS_INTERNAL_SCORE_H

/*
 * ============================================================================
 * XURY ANALYSIS — SCORE (F.3c)
 * ============================================================================
 *
 * Weapon effectiveness probabilities.
 *
 * This is F.3c in the three-layer split documented in docs/RESEARCH.md:
 *
 *   F.3a  Pure math           deterministic, no NAT knowledge   (done)
 *   F.3b  Classification      heuristic, documented thresholds  (done)
 *   F.3c  Scoring             requires empirical calibration    (this file)
 *
 * ----------------------------------------------------------------------------
 * STATUS: NOT CALIBRATED
 * ----------------------------------------------------------------------------
 *
 * Every function declared here answers the question:
 *
 *     "Given what we observed, how likely is weapon X to succeed?"
 *
 * That answer depends on real success/fail rates across real NAT
 * devices, ISPs, router firmware, and mobile carriers. Xury does not
 * have that data yet. Per docs/RESEARCH.md §2 F.3c and §4, no formula
 * can be written honestly without it.
 *
 * Consequently:
 *
 *   - Every function in this file returns XURY_ERR_NOT_CALIBRATED.
 *   - No probability value is ever written to *out on error.
 *   - No magic constants, no heuristics, no "reasonable defaults".
 *
 * XURY_ERR_NOT_CALIBRATED is distinct from XURY_ERR_NOT_IMPLEMENTED
 * on purpose. The code path exists and is reachable; what is missing
 * is evidence, not code. Anyone auditing the codebase later should be
 * able to tell the difference immediately.
 *
 * ----------------------------------------------------------------------------
 * Why an explicit per-weapon function instead of a table
 * ----------------------------------------------------------------------------
 *
 * A table of 11 function pointers would be compact, but it would make
 * each entry anonymous. When calibration data arrives, each weapon
 * will get its own formula (different features, different priors,
 * different failure modes). Giving each weapon its own named function
 * now means the calibration work later edits eleven small functions
 * in place, instead of rewriting a generic dispatcher.
 *
 * ----------------------------------------------------------------------------
 * Output contract
 * ----------------------------------------------------------------------------
 *
 * On success (not possible yet, but defined for the calibrated future):
 *
 *   *out receives a probability in [0.0, 1.0].
 *   The function returns XURY_OK.
 *
 * On XURY_ERR_NOT_CALIBRATED:
 *
 *   *out is untouched. Callers must not read it.
 *
 * On XURY_ERR_INVAL:
 *
 *   out is NULL. Nothing to write.
 *
 * Callers that need a starting point before calibration lands should
 * use xury_weapon_base_strength() from <xury/weapon.h>, which returns
 * a documented prior on a 0..100 scale. That prior is not a
 * probability and is not a substitute for F.3c; it is simply the
 * best available guess in the absence of measurement.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 * - <xury/err.h>     for xury_err_t
 * - <xury/scan.h>    for xury_scan_result_t
 *
 * No engine, no platform, no allocation, no I/O, no global state.
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
 * PER-WEAPON PROBABILITY FUNCTIONS
 * ============================================================================
 *
 * Each function takes the scan result (the observation) and writes a
 * probability to *out on success.
 *
 * Until calibration data exists, every one of them returns
 * XURY_ERR_NOT_CALIBRATED and leaves *out untouched.
 *
 * The signatures are stable. When calibration arrives, only the
 * bodies change.
 */

xury_err_t xury_analysis_p_ipv6   (const xury_scan_result_t *r, double *out);
xury_err_t xury_analysis_p_lan    (const xury_scan_result_t *r, double *out);
xury_err_t xury_analysis_p_upnp   (const xury_scan_result_t *r, double *out);
xury_err_t xury_analysis_p_natpmp (const xury_scan_result_t *r, double *out);
xury_err_t xury_analysis_p_pcp    (const xury_scan_result_t *r, double *out);
xury_err_t xury_analysis_p_hole   (const xury_scan_result_t *r, double *out);
xury_err_t xury_analysis_p_predict(const xury_scan_result_t *r, double *out);
xury_err_t xury_analysis_p_birthday(const xury_scan_result_t *r, double *out);
xury_err_t xury_analysis_p_mirror (const xury_scan_result_t *r, double *out);
xury_err_t xury_analysis_p_relay  (const xury_scan_result_t *r, double *out);
xury_err_t xury_analysis_p_upgrade(const xury_scan_result_t *r, double *out);

/*
 * ============================================================================
 * CALIBRATION STATUS
 * ============================================================================
 *
 * A single predicate the caller can use to decide whether to attempt
 * any of the functions above. Today it always returns false.
 *
 * It exists so that callers do not have to probe one function and
 * infer the state of the rest. When calibration lands, this returns
 * true and the caller switches from priors to probabilities in one
 * place.
 */

bool xury_analysis_score_calibrated(void);

/*
 * ============================================================================
 * END OF XURY ANALYSIS INTERNAL SCORE HEADER
 * ============================================================================
 */

#endif /* XURY_ANALYSIS_INTERNAL_SCORE_H */
