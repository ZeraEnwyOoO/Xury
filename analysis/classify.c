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
 * XURY ANALYSIS — CLASSIFY IMPLEMENTATION (F.3b)
 * ============================================================================
 *
 * Real implementation of src/analysis/internal/classify.h.
 *
 * F.3b sits directly on top of F.3a. It calls:
 *
 *     xury_math_variance()      (variance of consecutive deltas)
 *     xury_math_median()        (robust step estimate)
 *
 * and turns their numeric output into a labeled pattern plus a
 * confidence level.
 *
 * ----------------------------------------------------------------------------
 * Two design decisions
 * ----------------------------------------------------------------------------
 *
 * Both are recorded in docs/RESEARCH_addendum_variance_decision.md.
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
 * No hidden thresholds
 * ----------------------------------------------------------------------------
 *
 * Every numeric cutoff used here comes from the caller through
 * xury_classify_cfg_t. This file contains no magic numbers that
 * decide SEQUENTIAL_LIKE vs FIXED_STEP_LIKE vs RANDOM_LIKE.
 *
 * The only numeric literal in the classification path is 1.0, which
 * is not a threshold but the definition of "sequential" (step of
 * exactly one). It is not subject to calibration.
 *
 * If a future change needs another cutoff, it must be added to the
 * config struct, not hardcoded here. See docs/RESEARCH.md §5.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 * - src/scan/internal/math.h        (F.3a, completed)
 * - src/analysis/internal/classify.h
 * - <math.h>                        (for round())
 *
 * No allocation. No I/O. No platform. No global state.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <math.h>

#include "scan/internal/math.h"
#include "analysis/internal/classify.h"

/*
 * ============================================================================
 * INTERNAL HELPERS
 * ============================================================================
 */

/*
 * Return the nearest integer to v as a double.
 *
 * Wraps round() so the intent is named at the call site and so a
 * future port to a freestanding target has one place to change.
 */
static double nearest_integer(double v)
{
    return round(v);
}

/*
 * True if a step estimate is within tolerance of the nearest integer.
 *
 * Tolerance comes from cfg. A tolerance of 0 means "exact integer
 * only"; a negative tolerance is treated as 0 by the caller path
 * that validates cfg, so this function can assume >= 0.
 *
 * The name still says "slope" for historical reasons: the threshold
 * field is cfg->slope_tolerance, and it used to be applied to a
 * least-squares slope. It is now applied to the median delta. See
 * docs/RESEARCH_addendum_variance_decision.md.
 */
static bool slope_is_near_integer(double step,
                                  double tolerance)
{
    double nearest = nearest_integer(step);
    double d = step - nearest;
    if (d < 0.0) {
        d = -d;
    }
    return d <= tolerance;
}

/*
 * Compute the confidence level from the sample count.
 *
 * Buckets (from docs/RESEARCH.md §2 F.3b and the project decision):
 *
 *     n <  2 * min_samples   -> LOW
 *     n <  4 * min_samples   -> MEDIUM
 *     otherwise              -> HIGH
 *
 * min_samples is guaranteed > 0 by the caller path that validates
 * cfg, so the multiplications do not overflow for any realistic
 * value of n.
 */
static xury_confidence_t confidence_from_n(size_t n,
                                           size_t min_samples)
{
    /*
     * The comparison is written so that the multiplications cannot
     * overflow even if min_samples were absurdly large: we divide
     * n by min_samples instead of multiplying min_samples by 2 or 4.
     *
     * n / min_samples is integer division; the buckets are:
     *
     *     ratio < 2  -> LOW
     *     ratio < 4  -> MEDIUM
     *     otherwise  -> HIGH
     *
     * This is equivalent to the multiplication form for all n and
     * min_samples > 0, and cannot overflow.
     */
    size_t ratio = n / min_samples;
    if (ratio < 2u) {
        return XURY_CONFIDENCE_LOW;
    }
    if (ratio < 4u) {
        return XURY_CONFIDENCE_MEDIUM;
    }
    return XURY_CONFIDENCE_HIGH;
}

/*
 * ============================================================================
 * DELTA ARRAY
 * ============================================================================
 *
 * Compute the array of consecutive deltas, in magnitude form.
 *
 * deltas[i] = |ports[i+1] - ports[i]|, for i in [0, n-1).
 *
 * The magnitude form is used because the variance gate and the median
 * step estimator both care about the size of the step, not its
 * direction. A decreasing sequence with a constant step still has a
 * constant step; direction is not part of the pattern vocabulary in
 * this layer.
 *
 * The caller supplies a stack buffer. It must have room for at least
 * n - 1 entries.
 *
 * Returns the number of deltas written (n - 1), or 0 if the inputs
 * are unusable.
 */
static size_t compute_deltas(const uint16_t *ports,
                             size_t n,
                             uint16_t *deltas,
                             size_t cap)
{
    if (ports == NULL || deltas == NULL || n < 2u) {
        return 0u;
    }
    if (cap < n - 1u) {
        return 0u;
    }

    for (size_t i = 0; i + 1u < n; i++) {
        int32_t d = (int32_t)ports[i + 1u] - (int32_t)ports[i];
        if (d < 0) {
            d = -d;
        }
        deltas[i] = (uint16_t)d;
    }
    return n - 1u;
}

/*
 * ============================================================================
 * CLASSIFICATION RULE
 * ============================================================================
 *
 * Given enough samples, decide the pattern.
 *
 * Order of checks:
 *
 *   1. Delta variance must be below cfg->variance_threshold. If not,
 *      the sequence is RANDOM_LIKE regardless of the step estimate.
 *
 *   2. The step is estimated as the MEDIAN of the deltas. It must be
 *      near an integer within cfg->slope_tolerance. If not, the
 *      sequence is RANDOM_LIKE.
 *
 *   3. If the rounded step is 1, the pattern is SEQUENTIAL_LIKE.
 *
 *   4. Otherwise (rounded step != 1, but near-integer), the pattern
 *      is FIXED_STEP_LIKE.
 *
 * A step of 0 (constant sequence) falls through to FIXED_STEP_LIKE,
 * which is the honest answer: the step is constant, but it is not the
 * canonical +1 case.
 *
 * The caller is responsible for choosing thresholds that make this
 * rule meaningful. F.3b does not second-guess them.
 *
 * ----------------------------------------------------------------------------
 * Buffer bound
 * ----------------------------------------------------------------------------
 *
 * The delta array lives on the stack. Its size is bounded by
 * XURY_CLASSIFY_MAX_SAMPLES - 1, which is comfortably larger than
 * the probe sample cap (XURY_PROBE_PORT_SAMPLES) that the scan layer
 * enforces at the call site. If a caller ever passes more, the
 * function falls back to RANDOM_LIKE without reading past the array.
 */

#define XURY_CLASSIFY_MAX_SAMPLES 64u

static xury_port_pattern_t classify_rule(const uint16_t *ports,
                                         size_t n,
                                         const xury_classify_cfg_t *cfg)
{
    if (n < 2u || n > XURY_CLASSIFY_MAX_SAMPLES) {
        return XURY_PATTERN_RANDOM_LIKE;
    }

    uint16_t deltas[XURY_CLASSIFY_MAX_SAMPLES - 1u];
    size_t delta_count = compute_deltas(ports, n,
                                        deltas, sizeof(deltas) / sizeof(deltas[0]));
    if (delta_count == 0u) {
        return XURY_PATTERN_RANDOM_LIKE;
    }

    /*
     * Step 1: delta variance.
     */
    double delta_variance = xury_math_variance(deltas, delta_count);
    if (delta_variance > cfg->variance_threshold) {
        return XURY_PATTERN_RANDOM_LIKE;
    }

    /*
     * Step 2: median step estimate, near-integer check.
     */
    double step = xury_math_median(deltas, delta_count);
    if (!slope_is_near_integer(step, cfg->slope_tolerance)) {
        return XURY_PATTERN_RANDOM_LIKE;
    }

    /*
     * Steps 3 and 4: classify by the rounded step.
     */
    double rounded = nearest_integer(step);
    if (rounded == 1.0) {
        return XURY_PATTERN_SEQUENTIAL_LIKE;
    }
    return XURY_PATTERN_FIXED_STEP_LIKE;
}

/*
 * ============================================================================
 * PREDICTION
 * ============================================================================
 *
 * Predict the next port value from the median delta.
 *
 * The result is last_port + round(median_step), clamped to [1, 65535].
 * Port 0 is not a legal destination and is never returned.
 *
 * This is intentionally NOT xury_math_predict_next(): that function
 * predicts from the least-squares slope, which is not robust to a
 * single outlier delta. Classification uses the median for the same
 * reason, and the prediction must be consistent with the
 * classification.
 */
static uint16_t predict_from_median(const uint16_t *ports,
                                    size_t n,
                                    const uint16_t *deltas,
                                    size_t delta_count)
{
    double step = xury_math_median(deltas, delta_count);
    double last = (double)ports[n - 1u];
    double predicted = last + nearest_integer(step);

    if (predicted < 1.0) {
        return 1u;
    }
    if (predicted > 65535.0) {
        return 65535u;
    }
    return (uint16_t)predicted;
}

/*
 * ============================================================================
 * PUBLIC ENTRY POINT
 * ============================================================================
 */

xury_err_t xury_classify_port_pattern(
    const uint16_t *ports,
    size_t n,
    const xury_classify_cfg_t *cfg,
    xury_port_classification_t *out)
{
    if (cfg == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }

    /*
     * Not enough samples. This is a valid, first-class answer, not an
     * error. We fill *out completely so the caller can use it
     * unconditionally.
     */
    if (ports == NULL || n < cfg->min_samples) {
        out->pattern        = XURY_PATTERN_INSUFFICIENT_DATA;
        out->confidence     = XURY_CONFIDENCE_LOW;
        out->predicted_next = 0u;
        return XURY_OK;
    }

    xury_port_pattern_t pattern = classify_rule(ports, n, cfg);

    out->pattern    = pattern;
    out->confidence = confidence_from_n(n, cfg->min_samples);

    if (pattern == XURY_PATTERN_SEQUENTIAL_LIKE ||
        pattern == XURY_PATTERN_FIXED_STEP_LIKE) {
        /*
         * Recompute the deltas once more for the prediction. The
         * classify_rule() call above did the same work; the two are
         * deliberately not merged because the prediction is only
         * needed on the success path, and classify_rule() is called
         * on every path.
         *
         * The cost is a few dozen uint16 stores on success, which is
         * negligible next to the classification work itself.
         */
        if (n >= 2u && n <= XURY_CLASSIFY_MAX_SAMPLES) {
            uint16_t deltas[XURY_CLASSIFY_MAX_SAMPLES - 1u];
            size_t dc = compute_deltas(ports, n,
                                       deltas,
                                       sizeof(deltas) / sizeof(deltas[0]));
            if (dc > 0u) {
                out->predicted_next = predict_from_median(ports, n,
                                                          deltas, dc);
            } else {
                out->predicted_next = 0u;
            }
        } else {
            out->predicted_next = 0u;
        }
    } else {
        out->predicted_next = 0u;
    }

    return XURY_OK;
}

/*
 * ============================================================================
 * STRING HELPERS
 * ============================================================================
 */

const char *xury_port_pattern_name(xury_port_pattern_t p)
{
    switch (p) {
    case XURY_PATTERN_INSUFFICIENT_DATA: return "insufficient_data";
    case XURY_PATTERN_SEQUENTIAL_LIKE:   return "sequential_like";
    case XURY_PATTERN_FIXED_STEP_LIKE:   return "fixed_step_like";
    case XURY_PATTERN_RANDOM_LIKE:       return "random_like";
    default:                             return "unknown";
    }
}

const char *xury_confidence_name(xury_confidence_t c)
{
    switch (c) {
    case XURY_CONFIDENCE_LOW:    return "low";
    case XURY_CONFIDENCE_MEDIUM: return "medium";
    case XURY_CONFIDENCE_HIGH:   return "high";
    default:                     return "unknown";
    }
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
