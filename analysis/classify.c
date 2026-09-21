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
 *     xury_math_variance()      (spread of the observed ports)
 *     xury_math_slope()         (least-squares step)
 *     xury_math_predict_next()  (next port, already clamped)
 *
 * and turns their numeric output into a labeled pattern plus a
 * confidence level.
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
 *   1. Variance must be below cfg->variance_threshold. If not, the
 *      sequence is RANDOM_LIKE regardless of slope.
 *
 *   2. Slope must be near an integer within cfg->slope_tolerance.
 *      If not, the sequence is RANDOM_LIKE.
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
 */
static xury_port_pattern_t classify_rule(const uint16_t *ports,
                                         size_t n,
                                         const xury_classify_cfg_t *cfg)
{
    double variance = xury_math_variance(ports, n);
    if (variance > cfg->variance_threshold) {
        return XURY_PATTERN_RANDOM_LIKE;
    }

    double slope = xury_math_slope(ports, n);
    if (!slope_is_near_integer(slope, cfg->slope_tolerance)) {
        return XURY_PATTERN_RANDOM_LIKE;
    }

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
