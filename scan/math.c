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
 * XURY SCAN — MATH IMPLEMENTATION (F.3a)
 * ============================================================================
 *
 * Real implementation of src/scan/internal/math.h.
 *
 * Pure statistics over a uint16_t sequence. No NAT knowledge, no
 * thresholds, no decisions. The interpretation of these numbers is
 * F.3b (src/analysis/classify.c) and beyond.
 *
 * All accumulators are double. With n up to a few dozen samples and
 * values up to 65535, the sums stay far inside double's exact integer
 * range (2^53), so there is no precision loss and no overflow.
 *
 * No allocation. No I/O. No platform dependency. No global state.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <math.h>

#include "scan/internal/math.h"

/*
 * ============================================================================
 * CENTRAL TENDENCY
 * ============================================================================
 */

double xury_math_mean(const uint16_t *v, size_t n)
{
    if (v == NULL || n == 0u) {
        return 0.0;
    }

    double sum = 0.0;
    for (size_t i = 0; i < n; i++) {
        sum += (double)v[i];
    }
    return sum / (double)n;
}

double xury_math_variance(const uint16_t *v, size_t n)
{
    if (v == NULL || n == 0u || n == 1u) {
        return 0.0;
    }

    /*
     * Two-pass: compute the mean first, then the sum of squared
     * deviations. One-pass (Welford) would be more numerically
     * robust for huge n, but n here is bounded by the probe sample
     * count (small), so two-pass is simpler and exact enough.
     */
    double mean = xury_math_mean(v, n);

    double acc = 0.0;
    for (size_t i = 0; i < n; i++) {
        double d = (double)v[i] - mean;
        acc += d * d;
    }
    return acc / (double)n;
}

/*
 * ============================================================================
 * MEDIAN
 * ============================================================================
 *
 * Population-style median: sort the values, then take the middle
 * element for odd n, or the average of the two middle elements for
 * even n.
 *
 * The input array is not modified; we copy into a fixed-size stack
 * buffer and sort that.
 *
 * The stack buffer is bounded by XURY_MATH_MEDIAN_MAX. Inputs larger
 * than that are truncated to the first XURY_MATH_MEDIAN_MAX elements:
 * the median of a truncated sample is still a useful estimate, and
 * refusing to compute would be worse for a diagnostic aid. Callers
 * that care about the exact bound should ensure n <= the cap.
 *
 * Insertion sort is used: n is small (bounded by the probe sample
 * count, at most a few dozen), and insertion sort has no allocation,
 * no recursion, and predictable behavior.
 *
 * See docs/RESEARCH_addendum_variance_decision.md for why F.3b uses
 * this instead of the least-squares slope for step estimation.
 */

#define XURY_MATH_MEDIAN_MAX 64u

double xury_math_median(const uint16_t *v, size_t n)
{
    if (v == NULL || n == 0u) {
        return 0.0;
    }

    size_t m = (n > XURY_MATH_MEDIAN_MAX) ? XURY_MATH_MEDIAN_MAX : n;

    uint16_t sorted[XURY_MATH_MEDIAN_MAX];
    for (size_t i = 0; i < m; i++) {
        sorted[i] = v[i];
    }

    /* Insertion sort. Stable, in-place, no allocation. */
    for (size_t i = 1u; i < m; i++) {
        uint16_t key = sorted[i];
        size_t j = i;
        while (j > 0u && sorted[j - 1u] > key) {
            sorted[j] = sorted[j - 1u];
            j--;
        }
        sorted[j] = key;
    }

    if ((m & 1u) != 0u) {
        return (double)sorted[m / 2u];
    }

    double a = (double)sorted[m / 2u - 1u];
    double b = (double)sorted[m / 2u];
    return (a + b) / 2.0;
}

/*
 * ============================================================================
 * SLOPE
 * ============================================================================
 *
 * Least-squares slope of v[i] against i.
 *
 *     slope = Sxy / Sxx
 *
 * where:
 *
 *     xbar = mean of i           = (n - 1) / 2
 *     ybar = mean of v[i]        = xury_math_mean(v, n)
 *     Sxy  = sum((i - xbar) * (v[i] - ybar))
 *     Sxx  = sum((i - xbar)^2)
 *
 * xbar is computed in closed form to avoid a second pass over the
 * indices.
 *
 * This is a general-purpose primitive. It is no longer called by
 * F.3b's classification (which uses xury_math_median instead, for
 * outlier robustness), but it remains valid and may be used by other
 * layers.
 */

double xury_math_slope(const uint16_t *v, size_t n)
{
    if (v == NULL || n < 2u) {
        return 0.0;
    }

    const double xbar = ((double)n - 1.0) / 2.0;
    const double ybar = xury_math_mean(v, n);

    double sxy = 0.0;
    double sxx = 0.0;
    for (size_t i = 0; i < n; i++) {
        double dx = (double)i - xbar;
        double dy = (double)v[i] - ybar;
        sxy += dx * dy;
        sxx += dx * dx;
    }

    if (sxx == 0.0) {
        /* Cannot happen for n >= 2, but keep the guard. */
        return 0.0;
    }
    return sxy / sxx;
}

/*
 * ============================================================================
 * SEQUENCE SHAPE
 * ============================================================================
 */

bool xury_math_is_monotonic(const uint16_t *v, size_t n)
{
    if (v == NULL || n < 2u) {
        /* Vacuously true: nothing to violate monotonicity. */
        return true;
    }

    for (size_t i = 0; i + 1u < n; i++) {
        if (v[i] > v[i + 1u]) {
            return false;
        }
    }
    return true;
}

uint16_t xury_math_predict_next(const uint16_t *v, size_t n)
{
    if (v == NULL || n == 0u) {
        return 0u;
    }

    /*
     * next = last + round(slope)
     *
     * The step is rounded to the nearest integer because the observed
     * step size between consecutive ports is an integer; the slope is
     * a real-valued estimate of that step.
     *
     * This is a math-layer default, not a claim about NAT behavior.
     *
     * This is a general-purpose primitive. F.3b no longer uses it for
     * classification; classify.c computes its prediction directly
     * from the median delta, for outlier robustness.
     */
    const double slope = xury_math_slope(v, n);
    const double last  = (double)v[n - 1u];

    double predicted = last + round(slope);

    /*
     * Clamp to the valid uint16 port range [1, 65535].
     * Port 0 is not a legal destination and is never returned.
     */
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
 * END OF FILE
 * ============================================================================
 */
