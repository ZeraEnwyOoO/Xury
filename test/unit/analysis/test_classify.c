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
 * TESTS — src/analysis/classify.c (F.3b)
 * ============================================================================
 *
 * Exercise the pattern classifier:
 *
 *   xury_classify_port_pattern()
 *   xury_port_pattern_name()
 *   xury_confidence_name()
 *
 * No mocks, no fakes. Every value comes from the library, driven by
 * synthetic port sequences and explicit config structs.
 *
 * The thresholds used in these tests are chosen so the expected
 * pattern is unambiguous. They are test fixtures, not library
 * defaults. The library has no defaults; every threshold is supplied
 * by the caller.
 *
 * ----------------------------------------------------------------------------
 * Test design notes
 * ----------------------------------------------------------------------------
 *
 * The classifier uses two design decisions that shape these tests:
 *
 *   1. Variance is measured over consecutive DELTAS, not raw port
 *      values. See docs/RESEARCH_addendum_variance_decision.md.
 *
 *   2. The step MAGNITUDE is the median of the absolute deltas, not
 *      the least-squares slope. Direction is not part of the pattern;
 *      it only affects predicted_next.
 *
 * Tests that pin specific behaviors are named after what they
 * actually verify, not after the old slope-based design.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "analysis/internal/classify.h"
#include "test/test.h"

/*
 * ============================================================================
 * FIXTURES
 * ============================================================================
 *
 * A small, permissive config that makes the intent of each test easy
 * to read. Values are deliberately loose; the point is to exercise
 * the classification rule, not to pin calibration.
 */

#define MIN_SAMPLES 4u

static xury_classify_cfg_t cfg_default(void)
{
    xury_classify_cfg_t cfg;
    cfg.min_samples        = MIN_SAMPLES;
    cfg.variance_threshold = 2.0;
    cfg.slope_tolerance    = 0.1;
    return cfg;
}

/*
 * ============================================================================
 * ARGUMENT VALIDATION
 * ============================================================================
 */

static void test_null_cfg(void)
{
    const uint16_t ports[4] = { 1u, 2u, 3u, 4u };
    xury_port_classification_t out;
    memset(&out, 0xAA, sizeof(out));

    xury_err_t rc = xury_classify_port_pattern(ports, 4, NULL, &out);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);

    /* out must be untouched. */
    unsigned char *p = (unsigned char *)&out;
    for (size_t i = 0; i < sizeof(out); i++) {
        TEST_ASSERT_EQ(p[i], 0xAA);
    }
}

static void test_null_out(void)
{
    const uint16_t ports[4] = { 1u, 2u, 3u, 4u };
    xury_classify_cfg_t cfg = cfg_default();

    xury_err_t rc = xury_classify_port_pattern(ports, 4, &cfg, NULL);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_null_both(void)
{
    xury_err_t rc = xury_classify_port_pattern(NULL, 0, NULL, NULL);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

/*
 * ============================================================================
 * INSUFFICIENT_DATA
 * ============================================================================
 */

static void test_insufficient_null_ports(void)
{
    xury_classify_cfg_t cfg = cfg_default();
    xury_port_classification_t out;

    xury_err_t rc = xury_classify_port_pattern(NULL, 10, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.pattern, XURY_PATTERN_INSUFFICIENT_DATA);
    TEST_ASSERT_EQ(out.confidence, XURY_CONFIDENCE_LOW);
    TEST_ASSERT_EQ(out.predicted_next, 0u);
}

static void test_insufficient_zero_n(void)
{
    const uint16_t ports[1] = { 100u };
    xury_classify_cfg_t cfg = cfg_default();
    xury_port_classification_t out;

    xury_err_t rc = xury_classify_port_pattern(ports, 0, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.pattern, XURY_PATTERN_INSUFFICIENT_DATA);
    TEST_ASSERT_EQ(out.confidence, XURY_CONFIDENCE_LOW);
    TEST_ASSERT_EQ(out.predicted_next, 0u);
}

static void test_insufficient_below_min(void)
{
    const uint16_t ports[3] = { 100u, 101u, 102u };
    xury_classify_cfg_t cfg = cfg_default();  /* min_samples = 4 */

    xury_port_classification_t out;
    xury_err_t rc = xury_classify_port_pattern(ports, 3, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.pattern, XURY_PATTERN_INSUFFICIENT_DATA);
    TEST_ASSERT_EQ(out.confidence, XURY_CONFIDENCE_LOW);
    TEST_ASSERT_EQ(out.predicted_next, 0u);
}

static void test_exactly_min_is_sufficient(void)
{
    /*
     * n == min_samples is enough; the boundary is "less than", not
     * "less than or equal".
     */
    const uint16_t ports[4] = { 100u, 101u, 102u, 103u };
    xury_classify_cfg_t cfg = cfg_default();

    xury_port_classification_t out;
    xury_err_t rc = xury_classify_port_pattern(ports, 4, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT(out.pattern != XURY_PATTERN_INSUFFICIENT_DATA);
}

/*
 * ============================================================================
 * SEQUENTIAL_LIKE
 * ============================================================================
 */

static void test_sequential_step_one(void)
{
    /*
     * Classic +1 sequence with zero variance around the step.
     */
    const uint16_t ports[5] = { 100u, 101u, 102u, 103u, 104u };
    xury_classify_cfg_t cfg = cfg_default();
    xury_port_classification_t out;

    xury_err_t rc = xury_classify_port_pattern(ports, 5, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.pattern, XURY_PATTERN_SEQUENTIAL_LIKE);
    TEST_ASSERT_EQ(out.predicted_next, 105u);
}

static void test_sequential_step_one_longer(void)
{
    const uint16_t ports[8] = {
        1000u, 1001u, 1002u, 1003u, 1004u, 1005u, 1006u, 1007u
    };
    xury_classify_cfg_t cfg = cfg_default();
    xury_port_classification_t out;

    xury_err_t rc = xury_classify_port_pattern(ports, 8, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.pattern, XURY_PATTERN_SEQUENTIAL_LIKE);
    TEST_ASSERT_EQ(out.predicted_next, 1008u);
}

static void test_sequential_predicted_is_not_zero(void)
{
    /*
     * Predicted ports must never be 0; the clamp floor is 1.
     */
    const uint16_t ports[4] = { 10u, 11u, 12u, 13u };
    xury_classify_cfg_t cfg = cfg_default();
    xury_port_classification_t out;

    xury_err_t rc = xury_classify_port_pattern(ports, 4, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.pattern, XURY_PATTERN_SEQUENTIAL_LIKE);
    TEST_ASSERT(out.predicted_next >= 1u);
}

static void test_sequential_negative_direction(void)
{
    /*
     * Decreasing sequence with constant magnitude step 1.
     *
     * Direction does not affect pattern classification: {50,49,48,47}
     * and {47,48,49,50} are equally predictable, so both classify as
     * SEQUENTIAL_LIKE (step magnitude = 1).
     *
     * Direction is preserved for predicted_next, however; see
     * test_predict_decreasing_direction below.
     */
    const uint16_t ports[4] = { 50u, 49u, 48u, 47u };
    xury_classify_cfg_t cfg = cfg_default();
    xury_port_classification_t out;

    xury_err_t rc = xury_classify_port_pattern(ports, 4, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.pattern, XURY_PATTERN_SEQUENTIAL_LIKE);
}

static void test_sequential_with_single_repeat(void)
{
    /*
     * A single repeat in an otherwise sequential sequence.
     *
     * The classifier uses MEDIAN delta, not least-squares slope, so a
     * single outlier delta (the 0 from the repeated port) does not
     * move the step estimate. The deltas are {1, 0, 1, 1}; sorted
     * {0, 1, 1, 1}; median = 1.0. Delta variance = 0.1875, well
     * below 2.0.
     *
     * Result: SEQUENTIAL_LIKE. The old slope-based design collapsed
     * the slope to 0.7 and misclassified this as RANDOM_LIKE; see
     * docs/RESEARCH_addendum_variance_decision.md.
     */
    const uint16_t ports[5] = { 100u, 101u, 101u, 102u, 103u };
    xury_classify_cfg_t cfg = cfg_default();
    xury_port_classification_t out;

    xury_err_t rc = xury_classify_port_pattern(ports, 5, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.pattern, XURY_PATTERN_SEQUENTIAL_LIKE);
}

/*
 * ============================================================================
 * FIXED_STEP_LIKE
 * ============================================================================
 */

static void test_fixed_step_two(void)
{
    /*
     * Step of 2. Deltas are {2,2,2,2}; median 2.0; variance 0.0.
     */
    const uint16_t ports[5] = { 100u, 102u, 104u, 106u, 108u };
    xury_classify_cfg_t cfg = cfg_default();
    xury_port_classification_t out;

    xury_err_t rc = xury_classify_port_pattern(ports, 5, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.pattern, XURY_PATTERN_FIXED_STEP_LIKE);
    TEST_ASSERT_EQ(out.predicted_next, 110u);
}

static void test_fixed_step_ten(void)
{
    const uint16_t ports[4] = { 200u, 210u, 220u, 230u };
    xury_classify_cfg_t cfg = cfg_default();
    xury_port_classification_t out;

    xury_err_t rc = xury_classify_port_pattern(ports, 4, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.pattern, XURY_PATTERN_FIXED_STEP_LIKE);
    TEST_ASSERT_EQ(out.predicted_next, 240u);
}

static void test_fixed_step_zero(void)
{
    /*
     * Constant sequence. Deltas are {0,0,0}; median 0.0; variance 0.0.
     * Nearest integer to 0 is 0, not 1, so FIXED_STEP_LIKE. This is
     * the honest label: the step is constant, but it is not the +1
     * case.
     */
    const uint16_t ports[4] = { 500u, 500u, 500u, 500u };
    xury_classify_cfg_t cfg = cfg_default();
    xury_port_classification_t out;

    xury_err_t rc = xury_classify_port_pattern(ports, 4, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.pattern, XURY_PATTERN_FIXED_STEP_LIKE);
    TEST_ASSERT_EQ(out.predicted_next, 500u);
}

/*
 * ============================================================================
 * RANDOM_LIKE
 * ============================================================================
 */

static void test_random_high_variance(void)
{
    /*
     * Variance is far above 2.0. Even though the median may be
     * near-integer by coincidence, the variance gate fires first.
     */
    const uint16_t ports[6] = {
        100u, 5000u, 200u, 4000u, 300u, 3000u
    };
    xury_classify_cfg_t cfg = cfg_default();
    xury_port_classification_t out;

    xury_err_t rc = xury_classify_port_pattern(ports, 6, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.pattern, XURY_PATTERN_RANDOM_LIKE);
    TEST_ASSERT_EQ(out.predicted_next, 0u);
}

static void test_random_median_step_not_near_integer(void)
{
    /*
     * Under the median-delta design, this sequence is NOT random.
     *
     * Sequence: {100, 103, 105, 108, 110, 113}
     * Deltas:   {3, 2, 3, 2, 3}
     * Delta variance: 0.24  (< 2.0 threshold -> consistent)
     * Median delta:   3.0   (near-integer -> step magnitude 3)
     *
     * Under the old slope-based design, this classified as RANDOM
     * because the least-squares slope (2.5) was not near-integer.
     * Under the median design, the representative step is 3 and the
     * variance gate confirms consistency, so FIXED_STEP_LIKE is the
     * correct answer.
     */
    const uint16_t ports[6] = { 100u, 103u, 105u, 108u, 110u, 113u };
    xury_classify_cfg_t cfg = cfg_default();
    xury_port_classification_t out;

    xury_err_t rc = xury_classify_port_pattern(ports, 6, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.pattern, XURY_PATTERN_FIXED_STEP_LIKE);
}

static void test_random_predicted_is_zero(void)
{
    /*
     * For RANDOM_LIKE, predicted_next must be 0.
     */
    const uint16_t ports[5] = { 1u, 60000u, 2u, 50000u, 3u };
    xury_classify_cfg_t cfg = cfg_default();
    xury_port_classification_t out;

    xury_err_t rc = xury_classify_port_pattern(ports, 5, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.pattern, XURY_PATTERN_RANDOM_LIKE);
    TEST_ASSERT_EQ(out.predicted_next, 0u);
}

/*
 * ============================================================================
 * CONFIDENCE
 * ============================================================================
 */

static void test_confidence_low_at_min(void)
{
    /*
     * n == min_samples -> ratio 1 -> LOW.
     */
    const uint16_t ports[4] = { 100u, 101u, 102u, 103u };
    xury_classify_cfg_t cfg = cfg_default();  /* min_samples = 4 */

    xury_port_classification_t out;
    xury_err_t rc = xury_classify_port_pattern(ports, 4, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.confidence, XURY_CONFIDENCE_LOW);
}

static void test_confidence_medium(void)
{
    /*
     * n = 8, min_samples = 4 -> ratio 2 -> MEDIUM.
     */
    const uint16_t ports[8] = {
        100u, 101u, 102u, 103u, 104u, 105u, 106u, 107u
    };
    xury_classify_cfg_t cfg = cfg_default();

    xury_port_classification_t out;
    xury_err_t rc = xury_classify_port_pattern(ports, 8, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.confidence, XURY_CONFIDENCE_MEDIUM);
}

static void test_confidence_high(void)
{
    /*
     * n = 16, min_samples = 4 -> ratio 4 -> HIGH.
     */
    const uint16_t ports[16] = {
        100u, 101u, 102u, 103u, 104u, 105u, 106u, 107u,
        108u, 109u, 110u, 111u, 112u, 113u, 114u, 115u
    };
    xury_classify_cfg_t cfg = cfg_default();

    xury_port_classification_t out;
    xury_err_t rc = xury_classify_port_pattern(ports, 16, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.confidence, XURY_CONFIDENCE_HIGH);
}

static void test_confidence_high_well_above(void)
{
    const uint16_t ports[32] = {
        100u, 101u, 102u, 103u, 104u, 105u, 106u, 107u,
        108u, 109u, 110u, 111u, 112u, 113u, 114u, 115u,
        116u, 117u, 118u, 119u, 120u, 121u, 122u, 123u,
        124u, 125u, 126u, 127u, 128u, 129u, 130u, 131u
    };
    xury_classify_cfg_t cfg = cfg_default();

    xury_port_classification_t out;
    xury_err_t rc = xury_classify_port_pattern(ports, 32, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.confidence, XURY_CONFIDENCE_HIGH);
}

static void test_confidence_medium_also_for_random(void)
{
    /*
     * Confidence is about sample count, not pattern. A RANDOM_LIKE
     * answer with many samples is still MEDIUM or HIGH. This is
     * deliberate: the caller can distinguish "I don't know because
     * I haven't seen enough" from "I've seen plenty and it's noise".
     */
    const uint16_t ports[8] = {
        10u, 60000u, 20u, 50000u, 30u, 40000u, 40u, 30000u
    };
    xury_classify_cfg_t cfg = cfg_default();

    xury_port_classification_t out;
    xury_err_t rc = xury_classify_port_pattern(ports, 8, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.pattern, XURY_PATTERN_RANDOM_LIKE);
    TEST_ASSERT_EQ(out.confidence, XURY_CONFIDENCE_MEDIUM);
}

/*
 * ============================================================================
 * PREDICTION DIRECTION
 * ============================================================================
 *
 * Pattern classification ignores direction, but predicted_next must
 * preserve it. These tests verify the majority-vote direction helper
 * is actually used on the prediction path.
 */

static void test_predict_decreasing_direction(void)
{
    /*
     * {50, 49, 48, 47} is a decreasing sequential sequence. The
     * predicted next port is 47 - 1 = 46, NOT 47 + 1 = 48.
     */
    const uint16_t ports[4] = { 50u, 49u, 48u, 47u };
    xury_classify_cfg_t cfg = cfg_default();
    xury_port_classification_t out;

    xury_err_t rc = xury_classify_port_pattern(ports, 4, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.pattern, XURY_PATTERN_SEQUENTIAL_LIKE);
    TEST_ASSERT_EQ(out.predicted_next, 46u);
}

static void test_predict_increasing_direction(void)
{
    /*
     * Mirror of the above: increasing sequence predicts last + 1.
     */
    const uint16_t ports[4] = { 47u, 48u, 49u, 50u };
    xury_classify_cfg_t cfg = cfg_default();
    xury_port_classification_t out;

    xury_err_t rc = xury_classify_port_pattern(ports, 4, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.pattern, XURY_PATTERN_SEQUENTIAL_LIKE);
    TEST_ASSERT_EQ(out.predicted_next, 51u);
}

static void test_predict_decreasing_fixed_step(void)
{
    /*
     * Decreasing fixed-step sequence. Predicted next is
     * last - 10 = 170, not last + 10 = 190.
     */
    const uint16_t ports[4] = { 200u, 190u, 180u, 170u };
    xury_classify_cfg_t cfg = cfg_default();
    xury_port_classification_t out;

    xury_err_t rc = xury_classify_port_pattern(ports, 4, &cfg, &out);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(out.pattern, XURY_PATTERN_FIXED_STEP_LIKE);
    TEST_ASSERT_EQ(out.predicted_next, 160u);
}

/*
 * ============================================================================
 * STRING HELPERS
 * ============================================================================
 */

static void test_pattern_name(void)
{
    TEST_ASSERT_STREQ(
        xury_port_pattern_name(XURY_PATTERN_INSUFFICIENT_DATA),
        "insufficient_data");
    TEST_ASSERT_STREQ(
        xury_port_pattern_name(XURY_PATTERN_SEQUENTIAL_LIKE),
        "sequential_like");
    TEST_ASSERT_STREQ(
        xury_port_pattern_name(XURY_PATTERN_FIXED_STEP_LIKE),
        "fixed_step_like");
    TEST_ASSERT_STREQ(
        xury_port_pattern_name(XURY_PATTERN_RANDOM_LIKE),
        "random_like");
    TEST_ASSERT_STREQ(
        xury_port_pattern_name((xury_port_pattern_t)999),
        "unknown");
}

static void test_confidence_name(void)
{
    TEST_ASSERT_STREQ(xury_confidence_name(XURY_CONFIDENCE_LOW),
                      "low");
    TEST_ASSERT_STREQ(xury_confidence_name(XURY_CONFIDENCE_MEDIUM),
                      "medium");
    TEST_ASSERT_STREQ(xury_confidence_name(XURY_CONFIDENCE_HIGH),
                      "high");
    TEST_ASSERT_STREQ(xury_confidence_name((xury_confidence_t)999),
                      "unknown");
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    /* Argument validation */
    TEST_RUN(test_null_cfg);
    TEST_RUN(test_null_out);
    TEST_RUN(test_null_both);

    /* Insufficient data */
    TEST_RUN(test_insufficient_null_ports);
    TEST_RUN(test_insufficient_zero_n);
    TEST_RUN(test_insufficient_below_min);
    TEST_RUN(test_exactly_min_is_sufficient);

    /* Sequential-like */
    TEST_RUN(test_sequential_step_one);
    TEST_RUN(test_sequential_step_one_longer);
    TEST_RUN(test_sequential_predicted_is_not_zero);
    TEST_RUN(test_sequential_negative_direction);
    TEST_RUN(test_sequential_with_single_repeat);

    /* Fixed-step-like */
    TEST_RUN(test_fixed_step_two);
    TEST_RUN(test_fixed_step_ten);
    TEST_RUN(test_fixed_step_zero);

    /* Random-like */
    TEST_RUN(test_random_high_variance);
    TEST_RUN(test_random_median_step_not_near_integer);
    TEST_RUN(test_random_predicted_is_zero);

    /* Confidence */
    TEST_RUN(test_confidence_low_at_min);
    TEST_RUN(test_confidence_medium);
    TEST_RUN(test_confidence_high);
    TEST_RUN(test_confidence_high_well_above);
    TEST_RUN(test_confidence_medium_also_for_random);

    /* Prediction direction */
    TEST_RUN(test_predict_decreasing_direction);
    TEST_RUN(test_predict_increasing_direction);
    TEST_RUN(test_predict_decreasing_fixed_step);

    /* String helpers */
    TEST_RUN(test_pattern_name);
    TEST_RUN(test_confidence_name);
}

TEST_MAIN()
