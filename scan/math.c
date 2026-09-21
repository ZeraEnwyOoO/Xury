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

double xury_math_slope(const uint16_t *v, size_t n)
{
    if (v == NULL || n < 2u) {
        return 0.0;
    }

    /*
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
     * xbar is computed in closed form to avoid a second pass over
     * the indices.
     */
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
