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
 * Design decisions
 * ----------------------------------------------------------------------------
 *
 * Recorded in docs/RESEARCH_addendum_variance_decision.md:
 *
 * 1. Variance is DELTA variance, not value variance.
 *
 * 2. The step magnitude estimate is the MEDIAN of the absolute
 *    deltas, not the least-squares slope.
 *
 * 3. Pattern classification (SEQUENTIAL_LIKE / FIXED_STEP_LIKE /
 *    RANDOM_LIKE) uses the step MAGNITUDE only. Direction does not
 *    affect the pattern: {50,49,48,47} and {47,48,49,50} are equally
 *    predictable, so both classify as SEQUENTIAL_LIKE.
 *
 * 4. predicted_next still needs direction. It uses a majority vote
 *    of the signed deltas: the sign that occurs more often wins.
 *    Zero deltas (repeats) count toward neither side. A tie
 *    defaults to +1 (arbitrary but documented; ties only matter for
 *    RANDOM_LIKE patterns, where predicted_next is set to 0 anyway).
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
 */
static double nearest_integer(double v)
{
    return round(v);
}

/*
 * True if a step estimate is within tolerance of the nearest integer.
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
 * Buckets:
 *
 *     n <  2 * min_samples   -> LOW
 *     n <  4 * min_samples   -> MEDIUM
 *     otherwise              -> HIGH
 *
 * Uses division rather than multiplication to avoid any overflow
 * concern for absurd min_samples values.
 */
static xury_confidence_t confidence_from_n(size_t n,
                                           size_t min_samples)
{
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
 * DELTA ARRAY (magnitude)
 * ============================================================================
 *
 * Compute the array of consecutive deltas in magnitude form:
 *
 *     deltas[i] = |ports[i+1] - ports[i]|
 *
 * The magnitude form is used for the variance gate and the median
 * step estimator, both of which care about the size of the step, not
 * its direction.
 *
 * Returns the number of deltas written (n - 1), or 0 on bad input.
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
 * DELTA DIRECTION (majority vote)
 * ============================================================================
 *
 * Return +1 or -1, whichever sign of the signed deltas occurs more
 * often across the sequence.
 *
 * Rules (see docs/RESEARCH_addendum_variance_decision.md):
 *
 *   - A positive delta (ports[i+1] > ports[i]) votes +1.
 *   - A negative delta (ports[i+1] < ports[i]) votes -1.
 *   - A zero delta (ports[i+1] == ports[i]) votes neither. The
 *     repeat case is a perturbation of magnitude only; it does not
 *     carry a direction.
 *   - A tie (pos == neg) defaults to +1. This is arbitrary but
 *     documented. Ties in practice mean genuinely mixed direction,
 *     which implies RANDOM_LIKE, for which predicted_next is 0 and
 *     the direction value is therefore unused.
 *
 * Direction is only meaningful for SEQUENTIAL_LIKE and
 * FIXED_STEP_LIKE patterns, where the signed deltas are expected to
 * agree.
 *
 * Returns +1 or -1. Never returns 0.
 */
static int delta_direction(const uint16_t *ports, size_t n)
{
    if (ports == NULL || n < 2u) {
        return +1;
    }

    size_t pos = 0u;
    size_t neg = 0u;

    for (size_t i = 0; i + 1u < n; i++) {
        if (ports[i + 1u] > ports[i]) {
            pos++;
        } else if (ports[i + 1u] < ports[i]) {
            neg++;
        }
        /* Equal: vote neither. */
    }

    if (neg > pos) {
        return -1;
    }
    return +1;
}

/*
 * ============================================================================
 * CLASSIFICATION RULE
 * ============================================================================
 *
 * Order of checks:
 *
 *   1. Delta variance must be below cfg->variance_threshold.
 *
 *   2. The step magnitude is the MEDIAN of the absolute deltas. It
 *      must be near an integer within cfg->slope_tolerance.
 *
 *   3. Rounded step == 1 -> SEQUENTIAL_LIKE.
 *
 *   4. Rounded step != 1, near-integer -> FIXED_STEP_LIKE.
 *
 * Direction is not part of the pattern; see the design note above.
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
                                        deltas,
                                        sizeof(deltas) / sizeof(deltas[0]));
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
     * Step 2: median step magnitude, near-integer check.
     */
    double step = xury_math_median(deltas, delta_count);
    if (!slope_is_near_integer(step, cfg->slope_tolerance)) {
        return XURY_PATTERN_RANDOM_LIKE;
    }

    /*
     * Steps 3 and 4: classify by the rounded step magnitude.
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
 * Predict the next port value:
 *
 *     predicted = last_port + direction * round(median_step)
 *
 * where direction is the majority vote of the signed deltas (+1 or
 * -1), and median_step is the median of the absolute deltas.
 *
 * The result is clamped to [1, 65535]. Port 0 is not a legal
 * destination and is never returned.
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
    int    dir  = delta_direction(ports, n);

    double last = (double)ports[n - 1u];
    double predicted = last + (double)dir * nearest_integer(step);

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
         * Recompute the deltas for the prediction. The two are
         * deliberately not merged because the prediction is only
         * needed on the success path, and classify_rule() is called
         * on every path.
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
