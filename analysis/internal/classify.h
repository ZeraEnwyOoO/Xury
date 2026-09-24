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

#ifndef XURY_ANALYSIS_INTERNAL_CLASSIFY_H
#define XURY_ANALYSIS_INTERNAL_CLASSIFY_H

/*
 * ============================================================================
 * XURY ANALYSIS — CLASSIFY (F.3b)
 * ============================================================================
 *
 * Pattern classification for observed port sequences.
 *
 * This is F.3b in the three-layer split documented in docs/RESEARCH.md:
 *
 *   F.3a  Pure math           deterministic, no NAT knowledge
 *   F.3b  Classification      heuristic, documented thresholds
 *   F.3c  Scoring             requires empirical calibration
 *
 * F.3b sits directly on top of F.3a. It calls the pure math helpers
 * (variance, median) and turns their numeric output into a labeled
 * pattern with a confidence level.
 *
 * ----------------------------------------------------------------------------
 * What this layer does NOT do
 * ----------------------------------------------------------------------------
 *
 * F.3b makes NO claim about weapon effectiveness. It does not decide
 * which traversal method to try. It does not assign probabilities.
 * Those are F.3c, which requires real-world calibration and is not
 * implemented yet (see docs/RESEARCH.md §2 and §4).
 *
 * F.3b also does NOT invent thresholds. Every numeric cutoff it uses
 * is supplied by the caller through xury_classify_cfg_t. The caller
 * (the scan orchestrator, eventually) is responsible for choosing
 * values that have been calibrated or, failing that, documented as
 * provisional. F.3b itself stays honest by refusing to hide a magic
 * number.
 *
 * ----------------------------------------------------------------------------
 * Output vocabulary
 * ----------------------------------------------------------------------------
 *
 *   INSUFFICIENT_DATA  not enough samples to say anything
 *   SEQUENTIAL_LIKE    step is near 1, delta variance is low
 *   FIXED_STEP_LIKE    step is a near-constant integer greater than 1
 *   RANDOM_LIKE        no consistent step
 *
 * These labels are hypotheses, not facts. Confidence expresses how
 * strong the evidence is:
 *
 *   LOW      fewer than 2 * min_samples
 *   MEDIUM   fewer than 4 * min_samples
 *   HIGH     at least 4 * min_samples
 *
 * ----------------------------------------------------------------------------
 * Two design decisions (see docs/RESEARCH_addendum_variance_decision.md)
 * ----------------------------------------------------------------------------
 *
 * 1. Variance is DELTA variance, not value variance.
 *
 *    {5,6,7,8} and {50000,50001,50002,50003} have identical step
 *    patterns and must classify identically. Value variance made
 *    classification depend on absolute port magnitude, which is
 *    unrelated to predictability.
 *
 * 2. The step estimate is the MEDIAN of the deltas, not the
 *    least-squares slope.
 *
 *    The variance gate already verifies consistency; the step
 *    estimator only needs to report the typical step. The median is
 *    the standard robust-statistics choice for that: a single
 *    outlier delta (e.g. one repeated port, producing delta = 0)
 *    collapses the least-squares slope but does not move the median.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 * - src/scan/internal/math.h   (F.3a, completed)
 * - <xury/err.h>               (xury_err_t)
 * - <xury/scan.h>              (public scan types are part of the
 *                               layer's vocabulary)
 * - <stdint.h>, <stddef.h>, <stdbool.h>
 *
 * No engine, no platform, no allocation, no I/O. Pure logic.
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
 * PATTERN
 * ============================================================================
 */

typedef enum {
    /*
     * Not enough samples, or the caller passed a NULL/empty array.
     * This is a first-class answer, not an error.
     */
    XURY_PATTERN_INSUFFICIENT_DATA = 0,

    /*
     * Step is near 1 and delta variance is low. The classic "router
     * increments the port by one" case.
     */
    XURY_PATTERN_SEQUENTIAL_LIKE   = 1,

    /*
     * Step is a near-constant integer greater than 1. Some routers
     * advance by a fixed batch size rather than one.
     */
    XURY_PATTERN_FIXED_STEP_LIKE   = 2,

    /*
     * No consistent step. Delta variance is above threshold, or the
     * step estimate is not near an integer.
     */
    XURY_PATTERN_RANDOM_LIKE       = 3,
} xury_port_pattern_t;

/*
 * ============================================================================
 * CONFIDENCE
 * ============================================================================
 */

typedef enum {
    XURY_CONFIDENCE_LOW    = 0,
    XURY_CONFIDENCE_MEDIUM = 1,
    XURY_CONFIDENCE_HIGH   = 2,
} xury_confidence_t;

/*
 * ============================================================================
 * CONFIGURATION
 * ============================================================================
 *
 * All thresholds used by the classifier. There are no hidden constants
 * in classify.c; every numeric cutoff comes from here.
 *
 * Fields:
 *
 *   min_samples
 *     Minimum number of observations required before any pattern
 *     other than INSUFFICIENT_DATA can be reported.
 *
 *     This value is an open research question (docs/RESEARCH.md §3).
 *     It must be chosen by the caller. There is no library default.
 *
 *   variance_threshold
 *     Maximum variance of consecutive deltas (steps) between ports
 *     for the sequence to be considered "consistent". Above this
 *     value, the pattern is RANDOM_LIKE regardless of the step
 *     estimate.
 *
 *     Deltas, not raw ports: this makes the check independent of
 *     absolute port magnitude. A sequence starting at 5 and a
 *     sequence starting at 50000 with the same step pattern classify
 *     identically. See docs/RESEARCH_addendum_variance_decision.md.
 *
 *     This value is an open research question (docs/RESEARCH.md §4).
 *     It must be chosen by the caller. There is no library default.
 *
 *   slope_tolerance
 *     Maximum absolute difference between the step estimate and the
 *     nearest integer for the step to be considered "near-integer".
 *
 *     The step estimate is the MEDIAN of the consecutive deltas
 *     between ports, not the least-squares slope over the raw ports.
 *     The field name is historical; the value applies to the median
 *     step. See docs/RESEARCH_addendum_variance_decision.md.
 *
 *     This value is an open research question (docs/RESEARCH.md §4).
 *     It must be chosen by the caller. There is no library default.
 *
 * A caller with no calibration data yet should still supply values,
 * but must document them as provisional. F.3b cannot detect whether a
 * value is calibrated; it can only refuse to invent one.
 *
 * A NULL cfg pointer is treated as "misuse": the function returns
 * XURY_ERR_INVAL and does not write to *out. This is the one case
 * where F.3b reports an error rather than a pattern.
 */

typedef struct {
    size_t min_samples;
    double variance_threshold;
    double slope_tolerance;
} xury_classify_cfg_t;

/*
 * ============================================================================
 * RESULT
 * ============================================================================
 */

typedef struct {
    /*
     * The labeled pattern. Never left uninitialized on success.
     */
    xury_port_pattern_t pattern;

    /*
     * How strong the evidence is. For INSUFFICIENT_DATA, this is
     * always LOW.
     */
    xury_confidence_t   confidence;

    /*
     * The predicted next value, computed as
     * last_port + round(median_step), clamped to [1, 65535].
     *
     * Meaningful only when pattern is SEQUENTIAL_LIKE or
     * FIXED_STEP_LIKE. When pattern is INSUFFICIENT_DATA or
     * RANDOM_LIKE, the field is set to 0 and must not be used.
     */
    uint16_t            predicted_next;
} xury_port_classification_t;

/*
 * ============================================================================
 * PUBLIC ENTRY POINT
 * ============================================================================
 */

/*
 * Classify a sequence of observed port values.
 *
 * Arguments:
 *   ports   observed ports, in order
 *   n       number of entries in ports
 *   cfg     thresholds; must not be NULL
 *   out     result; must not be NULL
 *
 * Returns:
 *   XURY_OK          out filled
 *   XURY_ERR_INVAL   cfg or out is NULL
 *
 * Behavior:
 *   - If cfg or out is NULL -> XURY_ERR_INVAL, *out untouched.
 *   - If ports is NULL or n < cfg->min_samples ->
 *       pattern = INSUFFICIENT_DATA
 *       confidence = LOW
 *       predicted_next = 0
 *       returns XURY_OK
 *   - Otherwise runs the classification rule and fills out.
 *
 * The function never allocates and never fails for any other reason.
 */
xury_err_t xury_classify_port_pattern(
    const uint16_t *ports,
    size_t n,
    const xury_classify_cfg_t *cfg,
    xury_port_classification_t *out);

/*
 * ============================================================================
 * STRING HELPERS
 * ============================================================================
 *
 * Stable, human-readable names for logs and tests. Never return NULL.
 */

const char *xury_port_pattern_name(xury_port_pattern_t p);
const char *xury_confidence_name(xury_confidence_t c);

/*
 * ============================================================================
 * END OF XURY ANALYSIS INTERNAL CLASSIFY HEADER
 * ============================================================================
 */

#endif /* XURY_ANALYSIS_INTERNAL_CLASSIFY_H */
 
