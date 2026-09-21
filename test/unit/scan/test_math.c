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
 * TESTS — src/scan/math.c (F.3a)
 * ============================================================================
 *
 * Exercise the pure math helpers:
 *
 *   xury_math_mean()
 *   xury_math_variance()
 *   xury_math_slope()
 *   xury_math_is_monotonic()
 *   xury_math_predict_next()
 *
 * No mocks, no fakes. Every value is computed by the library from
 * synthetic inputs chosen so the expected result is known exactly.
 *
 * The tolerance used for floating-point comparisons is 1e-9, which
 * is far tighter than any real-world signal we care about but loose
 * enough to absorb the last bit or two of double rounding on the
 * simple arithmetic these functions do.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "scan/internal/math.h"
#include "test/test.h"

#define EPS 1e-9

/*
 * ============================================================================
 * MEAN
 * ============================================================================
 */

static void test_mean_null(void)
{
    TEST_ASSERT_NEAR(xury_math_mean(NULL, 5), 0.0, EPS);
}

static void test_mean_zero_n(void)
{
    const uint16_t v[1] = { 42u };
    TEST_ASSERT_NEAR(xury_math_mean(v, 0), 0.0, EPS);
}

static void test_mean_single(void)
{
    const uint16_t v[1] = { 1234u };
    TEST_ASSERT_NEAR(xury_math_mean(v, 1), 1234.0, EPS);
}

static void test_mean_two(void)
{
    const uint16_t v[2] = { 10u, 20u };
    TEST_ASSERT_NEAR(xury_math_mean(v, 2), 15.0, EPS);
}

static void test_mean_even_count(void)
{
    const uint16_t v[4] = { 1u, 2u, 3u, 4u };
    TEST_ASSERT_NEAR(xury_math_mean(v, 4), 2.5, EPS);
}

static void test_mean_odd_count(void)
{
    const uint16_t v[5] = { 2u, 4u, 6u, 8u, 10u };
    TEST_ASSERT_NEAR(xury_math_mean(v, 5), 6.0, EPS);
}

static void test_mean_all_same(void)
{
    const uint16_t v[4] = { 500u, 500u, 500u, 500u };
    TEST_ASSERT_NEAR(xury_math_mean(v, 4), 500.0, EPS);
}

static void test_mean_large_values(void)
{
    /* Near the top of uint16 range. */
    const uint16_t v[3] = { 60000u, 65000u, 65535u };
    double expected = (60000.0 + 65000.0 + 65535.0) / 3.0;
    TEST_ASSERT_NEAR(xury_math_mean(v, 3), expected, EPS);
}

/*
 * ============================================================================
 * VARIANCE
 * ============================================================================
 */

static void test_variance_null(void)
{
    TEST_ASSERT_NEAR(xury_math_variance(NULL, 5), 0.0, EPS);
}

static void test_variance_zero_n(void)
{
    const uint16_t v[1] = { 42u };
    TEST_ASSERT_NEAR(xury_math_variance(v, 0), 0.0, EPS);
}

static void test_variance_single(void)
{
    const uint16_t v[1] = { 42u };
    TEST_ASSERT_NEAR(xury_math_variance(v, 1), 0.0, EPS);
}

static void test_variance_all_same(void)
{
    const uint16_t v[5] = { 7u, 7u, 7u, 7u, 7u };
    TEST_ASSERT_NEAR(xury_math_variance(v, 5), 0.0, EPS);
}

static void test_variance_two_points(void)
{
    /*
     * v = {10, 20}
     * mean = 15
     * deviations: -5, +5
     * squared: 25, 25
     * sum = 50
     * population variance = 50 / 2 = 25
     */
    const uint16_t v[2] = { 10u, 20u };
    TEST_ASSERT_NEAR(xury_math_variance(v, 2), 25.0, EPS);
}

static void test_variance_known_sequence(void)
{
    /*
     * v = {2, 4, 4, 4, 5, 5, 7, 9}
     * mean = 5
     * squared deviations: 9, 1, 1, 1, 0, 0, 4, 16
     * sum = 32
     * population variance = 32 / 8 = 4
     */
    const uint16_t v[8] = { 2u, 4u, 4u, 4u, 5u, 5u, 7u, 9u };
    TEST_ASSERT_NEAR(xury_math_variance(v, 8), 4.0, EPS);
}

static void test_variance_population_not_sample(void)
{
    /*
     * This pins the population-vs-sample choice.
     *
     * v = {1, 2, 3, 4, 5}
     * mean = 3
     * squared deviations: 4, 1, 0, 1, 4
     * sum = 10
     * population variance = 10 / 5 = 2.0
     * sample variance     = 10 / 4 = 2.5
     *
     * The library returns 2.0.
     */
    const uint16_t v[5] = { 1u, 2u, 3u, 4u, 5u };
    TEST_ASSERT_NEAR(xury_math_variance(v, 5), 2.0, EPS);
}

/*
 * ============================================================================
 * SLOPE
 * ============================================================================
 */

static void test_slope_null(void)
{
    TEST_ASSERT_NEAR(xury_math_slope(NULL, 5), 0.0, EPS);
}

static void test_slope_zero_n(void)
{
    const uint16_t v[1] = { 1u };
    TEST_ASSERT_NEAR(xury_math_slope(v, 0), 0.0, EPS);
}

static void test_slope_single(void)
{
    const uint16_t v[1] = { 1u };
    TEST_ASSERT_NEAR(xury_math_slope(v, 1), 0.0, EPS);
}

static void test_slope_flat(void)
{
    const uint16_t v[5] = { 100u, 100u, 100u, 100u, 100u };
    TEST_ASSERT_NEAR(xury_math_slope(v, 5), 0.0, EPS);
}

static void test_slope_step_one(void)
{
    /*
     * Perfectly linear with step 1.
     * v = {10, 11, 12, 13, 14}
     * slope = 1.0
     */
    const uint16_t v[5] = { 10u, 11u, 12u, 13u, 14u };
    TEST_ASSERT_NEAR(xury_math_slope(v, 5), 1.0, EPS);
}

static void test_slope_step_two(void)
{
    /*
     * Perfectly linear with step 2.
     * v = {10, 12, 14, 16, 18}
     * slope = 2.0
     */
    const uint16_t v[5] = { 10u, 12u, 14u, 16u, 18u };
    TEST_ASSERT_NEAR(xury_math_slope(v, 5), 2.0, EPS);
}

static void test_slope_negative(void)
{
    /*
     * Perfectly linear, decreasing.
     * v = {20, 15, 10, 5}
     * slope = -5.0
     */
    const uint16_t v[4] = { 20u, 15u, 10u, 5u };
    TEST_ASSERT_NEAR(xury_math_slope(v, 4), -5.0, EPS);
}

static void test_slope_known_two_points(void)
{
    /*
     * Two points is always a perfect line.
     * v = {100, 200}
     * slope = (200 - 100) / (1 - 0) = 100.0
     */
    const uint16_t v[2] = { 100u, 200u };
    TEST_ASSERT_NEAR(xury_math_slope(v, 2), 100.0, EPS);
}

static void test_slope_known_nonperfect(void)
{
    /*
     * Hand-computed least-squares slope.
     *
     * x = {0, 1, 2, 3}
     * y = {1, 3, 2, 5}
     *
     * xbar = 1.5, ybar = 2.75
     * Sxy = (-1.5)(-1.75) + (-0.5)(0.25)
     *     + ( 0.5)(-0.75) + ( 1.5)( 2.25)
     *     = 2.625 - 0.125 - 0.375 + 3.375
     *     = 5.5
     * Sxx = 2.25 + 0.25 + 0.25 + 2.25 = 5.0
     * slope = 5.5 / 5.0 = 1.1
     */
    const uint16_t v[4] = { 1u, 3u, 2u, 5u };
    TEST_ASSERT_NEAR(xury_math_slope(v, 4), 1.1, EPS);
}

/*
 * ============================================================================
 * MONOTONIC
 * ============================================================================
 */

static void test_monotonic_null(void)
{
    /* Vacuously true. */
    TEST_ASSERT(xury_math_is_monotonic(NULL, 5));
}

static void test_monotonic_zero_n(void)
{
    const uint16_t v[1] = { 1u };
    TEST_ASSERT(xury_math_is_monotonic(v, 0));
}

static void test_monotonic_single(void)
{
    const uint16_t v[1] = { 1u };
    TEST_ASSERT(xury_math_is_monotonic(v, 1));
}

static void test_monotonic_strictly_increasing(void)
{
    const uint16_t v[5] = { 1u, 2u, 3u, 4u, 5u };
    TEST_ASSERT(xury_math_is_monotonic(v, 5));
}

static void test_monotonic_non_strictly_increasing(void)
{
    /*
     * Repeats are allowed: non-strict.
     */
    const uint16_t v[5] = { 1u, 2u, 2u, 3u, 3u };
    TEST_ASSERT(xury_math_is_monotonic(v, 5));
}

static void test_monotonic_all_same(void)
{
    const uint16_t v[4] = { 42u, 42u, 42u, 42u };
    TEST_ASSERT(xury_math_is_monotonic(v, 4));
}

static void test_monotonic_decreasing(void)
{
    const uint16_t v[4] = { 5u, 4u, 3u, 2u };
    TEST_ASSERT(!xury_math_is_monotonic(v, 4));
}

static void test_monotonic_one_drop(void)
{
    const uint16_t v[5] = { 1u, 2u, 3u, 2u, 5u };
    TEST_ASSERT(!xury_math_is_monotonic(v, 5));
}

static void test_monotonic_only_at_end(void)
{
    const uint16_t v[5] = { 1u, 2u, 3u, 4u, 3u };
    TEST_ASSERT(!xury_math_is_monotonic(v, 5));
}

/*
 * ============================================================================
 * PREDICT_NEXT
 * ============================================================================
 */

static void test_predict_null(void)
{
    TEST_ASSERT_EQ(xury_math_predict_next(NULL, 5), 0u);
}

static void test_predict_zero_n(void)
{
    const uint16_t v[1] = { 1u };
    TEST_ASSERT_EQ(xury_math_predict_next(v, 0), 0u);
}

static void test_predict_single(void)
{
    /*
     * One sample. Slope is 0 by convention (n < 2). So the prediction
     * is last + 0 = last.
     */
    const uint16_t v[1] = { 4000u };
    TEST_ASSERT_EQ(xury_math_predict_next(v, 1), 4000u);
}

static void test_predict_step_one(void)
{
    /*
     * v = {10, 11, 12, 13, 14}
     * slope = 1
     * last  = 14
     * next  = 14 + 1 = 15
     */
    const uint16_t v[5] = { 10u, 11u, 12u, 13u, 14u };
    TEST_ASSERT_EQ(xury_math_predict_next(v, 5), 15u);
}

static void test_predict_step_two(void)
{
    /*
     * v = {10, 12, 14, 16, 18}
     * slope = 2
     * last  = 18
     * next  = 18 + 2 = 20
     */
    const uint16_t v[5] = { 10u, 12u, 14u, 16u, 18u };
    TEST_ASSERT_EQ(xury_math_predict_next(v, 5), 20u);
}

static void test_predict_flat(void)
{
    /*
     * v = {500, 500, 500}
     * slope = 0
     * last  = 500
     * next  = 500 + 0 = 500
     */
    const uint16_t v[3] = { 500u, 500u, 500u };
    TEST_ASSERT_EQ(xury_math_predict_next(v, 3), 500u);
}

static void test_predict_rounds_slope(void)
{
    /*
     * Fractional slope must be rounded to nearest integer.
     *
     * v = {10, 12, 13}
     * xbar = 1, ybar = 35/3
     * Sxy = (-1)(10 - 35/3) + 0 + (1)(13 - 35/3)
     *     = (-1)(-5/3) + (1)(4/3)
     *     = 5/3 + 4/3 = 3
     * Sxx = 1 + 0 + 1 = 2
     * slope = 1.5
     * round(1.5) = 2  (round half away from zero)
     * last = 13
     * next = 15
     */
    const uint16_t v[3] = { 10u, 12u, 13u };
    TEST_ASSERT_EQ(xury_math_predict_next(v, 3), 15u);
}

static void test_predict_clamp_low(void)
{
    /*
     * Decreasing sequence near zero must not underflow the port
     * range. The clamp floor is 1.
     *
     * v = {5, 4, 3, 2, 1}
     * slope = -1
     * last  = 1
     * raw   = 0  -> clamped to 1
     */
    const uint16_t v[5] = { 5u, 4u, 3u, 2u, 1u };
    TEST_ASSERT_EQ(xury_math_predict_next(v, 5), 1u);
}

static void test_predict_clamp_high(void)
{
    /*
     * Increasing sequence near the top must not overflow uint16.
     *
     * v = {65530, 65532, 65534}
     * slope = 2
     * last  = 65534
     * raw   = 65536 -> clamped to 65535
     */
    const uint16_t v[3] = { 65530u, 65532u, 65534u };
    TEST_ASSERT_EQ(xury_math_predict_next(v, 3), 65535u);
}

static void test_predict_never_zero_port(void)
{
    /*
     * Port 0 is not a legal destination. The function must never
     * return it, even for pathological input.
     */
    const uint16_t v[3] = { 2u, 1u, 0u };
    uint16_t p = xury_math_predict_next(v, 3);
    TEST_ASSERT(p >= 1u);
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    /* Mean */
    TEST_RUN(test_mean_null);
    TEST_RUN(test_mean_zero_n);
    TEST_RUN(test_mean_single);
    TEST_RUN(test_mean_two);
    TEST_RUN(test_mean_even_count);
    TEST_RUN(test_mean_odd_count);
    TEST_RUN(test_mean_all_same);
    TEST_RUN(test_mean_large_values);

    /* Variance */
    TEST_RUN(test_variance_null);
    TEST_RUN(test_variance_zero_n);
    TEST_RUN(test_variance_single);
    TEST_RUN(test_variance_all_same);
    TEST_RUN(test_variance_two_points);
    TEST_RUN(test_variance_known_sequence);
    TEST_RUN(test_variance_population_not_sample);

    /* Slope */
    TEST_RUN(test_slope_null);
    TEST_RUN(test_slope_zero_n);
    TEST_RUN(test_slope_single);
    TEST_RUN(test_slope_flat);
    TEST_RUN(test_slope_step_one);
    TEST_RUN(test_slope_step_two);
    TEST_RUN(test_slope_negative);
    TEST_RUN(test_slope_known_two_points);
    TEST_RUN(test_slope_known_nonperfect);

    /* Monotonic */
    TEST_RUN(test_monotonic_null);
    TEST_RUN(test_monotonic_zero_n);
    TEST_RUN(test_monotonic_single);
    TEST_RUN(test_monotonic_strictly_increasing);
    TEST_RUN(test_monotonic_non_strictly_increasing);
    TEST_RUN(test_monotonic_all_same);
    TEST_RUN(test_monotonic_decreasing);
    TEST_RUN(test_monotonic_one_drop);
    TEST_RUN(test_monotonic_only_at_end);

    /* Predict_next */
    TEST_RUN(test_predict_null);
    TEST_RUN(test_predict_zero_n);
    TEST_RUN(test_predict_single);
    TEST_RUN(test_predict_step_one);
    TEST_RUN(test_predict_step_two);
    TEST_RUN(test_predict_flat);
    TEST_RUN(test_predict_rounds_slope);
    TEST_RUN(test_predict_clamp_low);
    TEST_RUN(test_predict_clamp_high);
    TEST_RUN(test_predict_never_zero_port);
}

TEST_MAIN()
