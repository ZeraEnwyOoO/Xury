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
 *     xury_math_slope()         (least-squares step over raw ports)
 *     xury_math_predict_next()  (next port, already clamped)
 *
 * and turns their numeric output into a labeled pattern plus a
 * confidence level.
 *
 * ----------------------------------------------------------------------------
 * Variance is delta variance
 * ----------------------------------------------------------------------------
 *
 * The variance gate is applied to the array of consecutive deltas
 * between ports, not to the raw port values. See
 * docs/RESEARCH_addendum_variance_decision.md for the decision.
 *
 * In short: {5,6,7,8} and {50000,50001,50002,50003} have identical
 * step patterns and must classify identically. Value variance made
 * classification depend on absolute port magnitude, which is
 * unrelated to predictability.
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
 * True if slope is within tolerance of the nearest integer.
 *
 * Tolerance comes from cfg. A tolerance of 0 means "exact integer
 * only"; a negative tolerance is treated as 0 by the caller path
 * that validates cfg, so this function can assume >= 0.
 */
static bool slope_is_near_integer(double slope,
                                  double tolerance)
{
    double nearest = nearest_integer(slope);
    double d = slope - nearest;
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
 * CLASSIFICATION RULE
 * ============================================================================
 *
 * Given enough samples, decide the pattern.
 *
 * Order of checks:
 *
 *   1. Delta variance must be below cfg->variance_threshold. If not,
 *      the sequence is RANDOM_LIKE regardless of slope.
 *
 *      Variance is measured over consecutive deltas, not raw ports.
 *      This makes the check independent of absolute port magnitude:
 *      {5,6,7,8} and {50000,50001,50002,50003} have identical step
 *      patterns and therefore identical delta variance, so they
 *      classify the same way.
 *
 *   2. Slope (least-squares, over the raw port values against the
 *      sample index) must be near an integer within
 *      cfg->slope_tolerance. If not, the sequence is RANDOM_LIKE.
 *
 *   3. If the nearest integer to the slope is 1, the pattern is
 *      SEQUENTIAL_LIKE.
 *
 *   4. Otherwise (nearest integer != 1, but near-integer), the
 *      pattern is FIXED_STEP_LIKE.
 *
 * A slope of 0 or a negative slope can still be "near an integer".
 * They fall through to FIXED_STEP_LIKE, which is the honest answer:
 * the step is constant, but it is not the canonical +1 case.
 *
 * The caller is responsible for choosing thresholds that make this
 * rule meaningful. F.3b does not second-guess them.
 *
 * ----------------------------------------------------------------------------
 * Delta array
 * ----------------------------------------------------------------------------
 *
 * deltas has length n - 1. The caller-supplied ports array has at
 * least min_samples entries (checked before this function is called),
 * and min_samples >= 2 is assumed by the caller's contract, so n >= 2
 * here and deltas has at least one entry.
 *
 * A fixed-size stack buffer is used. XURY_CLASSIFY_MAX_SAMPLES bounds
 * the input length at the call site (probing produces at most that
 * many samples), and this function is never called with more.
 */

#define XURY_CLASSIFY_MAX_SAMPLES 64u

static xury_port_pattern_t classify_rule(const uint16_t *ports,
                                         size_t n,
                                         const xury_classify_cfg_t *cfg)
{
    /*
     * Step 1: delta variance.
     *
     * Compute the deltas into a stack buffer. If n is larger than the
     * buffer, fall back to RANDOM_LIKE without reading past the array
     * (this should never happen given the call-site bound, but the
     * check is cheap and avoids undefined behavior if it ever does).
     */
    if (n < 2u || n > XURY_CLASSIFY_MAX_SAMPLES) {
        return XURY_PATTERN_RANDOM_LIKE;
    }

    uint16_t deltas[XURY_CLASSIFY_MAX_SAMPLES - 1u];
    for (size_t i = 0; i + 1u < n; i++) {
        /*
         * Ports are uint16_t; a negative delta (ports decreasing)
         * would wrap. We care about the magnitude of the step, so
         * use a signed difference and store the absolute value.
         *
         * A decreasing sequence with constant negative step is still
         * a fixed step; the slope check below distinguishes direction.
         */
        int32_t d = (int32_t)ports[i + 1u] - (int32_t)ports[i];
        if (d < 0) {
            d = -d;
        }
        deltas[i] = (uint16_t)d;
    }

    double delta_variance = xury_math_variance(deltas, n - 1u);
    if (delta_variance > cfg->variance_threshold) {
        return XURY_PATTERN_RANDOM_LIKE;
    }

    /*
     * Step 2: slope over the raw ports, against the sample index.
     */
    double slope = xury_math_slope(ports, n);
    if (!slope_is_near_integer(slope, cfg->slope_tolerance)) {
        return XURY_PATTERN_RANDOM_LIKE;
    }

    /*
     * Steps 3 and 4: classify by the rounded slope.
     */
    double step = nearest_integer(slope);
    if (step == 1.0) {
        return XURY_PATTERN_SEQUENTIAL_LIKE;
    }
    return XURY_PATTERN_FIXED_STEP_LIKE;
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
        out->predicted_next = xury_math_predict_next(ports, n);
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
