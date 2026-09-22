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

#ifndef XURY_SCAN_INTERNAL_MATH_H
#define XURY_SCAN_INTERNAL_MATH_H

/*
 * ============================================================================
 * XURY SCAN — MATH (F.3a)
 * ============================================================================
 *
 * Pure statistical helpers used by the scan layer.
 *
 * This is F.3a in the three-layer split documented in docs/RESEARCH.md:
 *
 *   F.3a  Pure math           deterministic, no NAT knowledge
 *   F.3b  Classification      heuristic, documented thresholds
 *   F.3c  Scoring             requires empirical calibration
 *
 * F.3a makes NO claims about NAT behavior. It computes numbers from
 * numbers. Every function here is:
 *
 *   - pure (no side effects, no I/O, no allocation)
 *   - deterministic (same inputs -> same outputs)
 *   - independent of the engine, platform, and config
 *
 * Nothing in this file knows what a port is, what a NAT is, or what a
 * "predictable" sequence means. That interpretation lives in F.3b
 * (src/analysis/classify.c).
 *
 * ----------------------------------------------------------------------------
 * The sequence model
 * ----------------------------------------------------------------------------
 *
 * Every function takes a sequence of uint16_t values as:
 *
 *     const uint16_t *v, size_t n
 *
 * The implicit x-axis is the sample index: x_i = i, for i in [0, n).
 * The y-axis is v[i].
 *
 * This matches how port samples are collected: a sequence of observed
 * external ports, in the order they were observed.
 *
 * ----------------------------------------------------------------------------
 * Edge case policy
 * ----------------------------------------------------------------------------
 *
 * All functions are total. They never fail, never return NaN, and
 * never read past the array. On degenerate input they return 0:
 *
 *   v == NULL        -> 0
 *   n == 0           -> 0
 *   variance, n == 1 -> 0        (single sample has no spread)
 *   slope,    n <  2 -> 0        (line needs two points)
 *   is_monotonic, n < 2 -> true  (vacuously monotone)
 *   predict_next, n == 0 -> 0
 *
 * Callers that need to distinguish "0 because empty" from "0 because
 * the math really is 0" must check n themselves. The math layer does
 * not carry that distinction.
 *
 * ----------------------------------------------------------------------------
 * Implementation notes
 * ----------------------------------------------------------------------------
 *
 * - All accumulators are double. With n up to a few dozen samples and
 *   values up to 65535, the sums stay far inside double's exact
 *   integer range, so no overflow or precision loss is a concern.
 *
 * - predict_next uses round(slope) and clamps the result to [1, 65535].
 *   The clamp is a math-layer default, not a NAT-behavior claim.
 *
 * This header depends only on <stdint.h> and <stddef.h>. It must
 * remain so.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * CENTRAL TENDENCY
 * ============================================================================
 */

/*
 * Arithmetic mean of the sequence.
 *
 * Returns 0 when v == NULL or n == 0.
 */
double xury_math_mean(const uint16_t *v, size_t n);

/*
 * Population variance:
 *
 *     variance = sum((v[i] - mean)^2) / n
 *
 * Divides by n, not n - 1. This measures the spread of the observed
 * samples themselves, not an estimate of an underlying distribution.
 *
 * Returns 0 when v == NULL, n == 0, or n == 1.
 */
double xury_math_variance(const uint16_t *v, size_t n);

/*
 * Least-squares slope of v[i] against i.
 *
 *     slope = sum((i - xbar) * (v[i] - ybar))
 *           / sum((i - xbar)^2)
 *
 * where xbar is the mean of the indices and ybar is the mean of v.
 *
 * Returns 0 when v == NULL or n < 2.
 */
double xury_math_slope(const uint16_t *v, size_t n);

/*
 * ============================================================================
 * SEQUENCE SHAPE
 * ============================================================================
 */

/*
 * True if the sequence is non-strictly increasing:
 *
 *     v[i] <= v[i + 1]   for all i in [0, n - 1)
 *
 * Non-strict because some NAT implementations reuse a port, producing
 * a repeat rather than a strict increase.
 *
 * Returns true when v == NULL or n < 2 (vacuously monotone).
 */
bool xury_math_is_monotonic(const uint16_t *v, size_t n);

/*
 * Predict the next value in the sequence.
 *
 * Formula:
 *
 *     next = last + round(slope)
 *
 * where slope is xury_math_slope(v, n) and last is v[n - 1].
 *
 * The result is clamped to the valid uint16 port range [1, 65535].
 * Port 0 is not a legal destination port and is never returned.
 *
 * Returns 0 when v == NULL or n == 0.
 */
uint16_t xury_math_predict_next(const uint16_t *v, size_t n);

/*
 * ============================================================================
 * END OF XURY SCAN INTERNAL MATH HEADER
 * ============================================================================
 */

#endif /* XURY_SCAN_INTERNAL_MATH_H */
