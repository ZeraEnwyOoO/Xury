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

#ifndef XURY_TESTS_TEST_H
#define XURY_TESTS_TEST_H

/*
 * ============================================================================
 * XURY TEST FRAMEWORK
 * ============================================================================
 *
 * A minimal, dependency-free test framework for Xury.
 *
 * Design goals:
 *   - No external dependency (no Unity, no CMocka).
 *   - No allocation.
 *   - Deterministic exit codes.
 *   - Useful output on failure without a debugger.
 *
 * Usage:
 *
 *   #include <xury/xury.h>
 *   #include "tests/test.h"
 *
 *   static void test_one(void) {
 *       TEST_ASSERT(1 + 1 == 2);
 *   }
 *
 *   static void test_two(void) {
 *       TEST_ASSERT_EQ(2 * 2, 4);
 *   }
 *
 *   static void run_all_tests(void) {
 *       TEST_RUN(test_one);
 *       TEST_RUN(test_two);
 *   }
 *
 *   TEST_MAIN()
 *
 * Exit code:
 *   0  all tests passed
 *   1  at least one test failed
 *
 * The framework never calls exit() except from TEST_MAIN().
 * A failing TEST_ASSERT returns from the current test function; it
 * does NOT abort the whole process.
 *
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>

/*
 * ----------------------------------------------------------------------------
 * Global counters
 * ----------------------------------------------------------------------------
 * Each test binary is a separate process, so a single set of globals
 * is fine. Tests run sequentially within a binary.
 */
static int g_test_total   = 0;
static int g_test_failed  = 0;
static int g_assert_total = 0;

/*
 * ----------------------------------------------------------------------------
 * Failure reporting
 * ----------------------------------------------------------------------------
 */
static void test_report_failure(const char *file,
                                int line,
                                const char *expr,
                                const char *detail)
{
    fprintf(stderr, "  FAIL %s:%d\n", file, line);
    if (expr != NULL) {
        fprintf(stderr, "    expected: %s\n", expr);
    }
    if (detail != NULL) {
        fprintf(stderr, "    detail  : %s\n", detail);
    }
    g_test_failed++;
}

/*
 * ----------------------------------------------------------------------------
 * Assertion macros
 * ----------------------------------------------------------------------------
 *
 * All assertion macros return from the test function on failure. This
 * keeps subsequent asserts from cascading after a broken precondition.
 */

#define TEST_ASSERT(cond)                                              \
    do {                                                               \
        g_assert_total++;                                              \
        if (!(cond)) {                                                 \
            test_report_failure(__FILE__, __LINE__, #cond, NULL);      \
            return;                                                    \
        }                                                              \
    } while (0)

#define TEST_ASSERT_MSG(cond, msg)                                     \
    do {                                                               \
        g_assert_total++;                                              \
        if (!(cond)) {                                                 \
            test_report_failure(__FILE__, __LINE__, #cond, (msg));     \
            return;                                                    \
        }                                                              \
    } while (0)

/*
 * Equality for signed and unsigned 64-bit. We deliberately use a
 * generic macro and cast both sides to int64_t so that mixed-signed
 * comparisons produce a single, obvious result.
 */
#define TEST_ASSERT_EQ(a, b)                                           \
    do {                                                               \
        g_assert_total++;                                              \
        int64_t _a = (int64_t)(a);                                     \
        int64_t _b = (int64_t)(b);                                     \
        if (_a != _b) {                                                \
            char _buf[128];                                            \
            snprintf(_buf, sizeof(_buf),                               \
                     "%s=%lld, %s=%lld",                               \
                     #a, (long long)_a, #b, (long long)_b);            \
            test_report_failure(__FILE__, __LINE__, #a " == " #b,      \
                                _buf);                                 \
            return;                                                    \
        }                                                              \
    } while (0)

#define TEST_ASSERT_NE(a, b)                                           \
    do {                                                               \
        g_assert_total++;                                              \
        int64_t _a = (int64_t)(a);                                     \
        int64_t _b = (int64_t)(b);                                     \
        if (_a == _b) {                                                \
            char _buf[128];                                            \
            snprintf(_buf, sizeof(_buf),                               \
                     "%s=%lld, %s=%lld",                               \
                     #a, (long long)_a, #b, (long long)_b);            \
            test_report_failure(__FILE__, __LINE__, #a " != " #b,      \
                                _buf);                                 \
            return;                                                    \
        }                                                              \
    } while (0)

/*
 * Floating-point equality with absolute tolerance.
 *
 * Compares two double values. The comparison passes when
 * |a - b| <= eps. NaN on either side is a failure, because NaN != NaN
 * and any test that produces NaN is broken.
 *
 * The tolerance is absolute, not relative. Callers that need a
 * relative comparison should compute the ratio themselves and use
 * TEST_ASSERT_NEAR on that.
 */
#define TEST_ASSERT_NEAR(a, b, eps)                                    \
    do {                                                               \
        g_assert_total++;                                              \
        double _a   = (double)(a);                                     \
        double _b   = (double)(b);                                     \
        double _eps = (double)(eps);                                   \
        double _d   = _a - _b;                                         \
        if (_d < 0.0) {                                                \
            _d = -_d;                                                  \
        }                                                              \
        if (!(_d <= _eps)) {                                           \
            char _buf[192];                                            \
            snprintf(_buf, sizeof(_buf),                               \
                     "%s=%g, %s=%g, diff=%g, eps=%g",                  \
                     #a, _a, #b, _b, _d, _eps);                        \
            test_report_failure(__FILE__, __LINE__,                    \
                                #a " ~= " #b, _buf);                   \
            return;                                                    \
        }                                                              \
    } while (0)

/*
 * String equality. Both arguments must be NUL-terminated or NULL.
 * Two NULLs are considered equal.
 */
#define TEST_ASSERT_STREQ(a, b)                                        \
    do {                                                               \
        g_assert_total++;                                              \
        const char *_a = (a);                                          \
        const char *_b = (b);                                          \
        bool _eq = (_a == _b) ||                                       \
                   (_a != NULL && _b != NULL &&                        \
                    strcmp(_a, _b) == 0);                              \
        if (!_eq) {                                                    \
            char _buf[256];                                            \
            snprintf(_buf, sizeof(_buf),                               \
                     "\"%s\" vs \"%s\"",                               \
                     _a ? _a : "(null)",                               \
                     _b ? _b : "(null)");                              \
            test_report_failure(__FILE__, __LINE__, #a " == " #b,      \
                                _buf);                                 \
            return;                                                    \
        }                                                              \
    } while (0)

/*
 * Pointer non-NULL.
 */
#define TEST_ASSERT_NOT_NULL(p)                                        \
    do {                                                               \
        g_assert_total++;                                              \
        if ((p) == NULL) {                                             \
            test_report_failure(__FILE__, __LINE__, #p " != NULL",     \
                                NULL);                                 \
            return;                                                    \
        }                                                              \
    } while (0)

/*
 * Pointer NULL.
 */
#define TEST_ASSERT_NULL(p)                                            \
    do {                                                               \
        g_assert_total++;                                              \
        if ((p) != NULL) {                                             \
            test_report_failure(__FILE__, __LINE__, #p " == NULL",     \
                                NULL);                                 \
            return;                                                    \
        }                                                              \
    } while (0)

/*
 * ----------------------------------------------------------------------------
 * Test runner
 * ----------------------------------------------------------------------------
 */

#define TEST_RUN(fn)                                                   \
    do {                                                               \
        g_test_total++;                                                \
        int _failed_before = g_test_failed;                            \
        printf("  running %s\n", #fn);                                 \
        fn();                                                          \
        if (g_test_failed != _failed_before) {                         \
            printf("    %s FAILED\n", #fn);                            \
        }                                                              \
    } while (0)

/*
 * ----------------------------------------------------------------------------
 * Main
 * ----------------------------------------------------------------------------
 * The test file defines run_all_tests() and then uses TEST_MAIN() to
 * provide main(). The macro prints a summary and returns the right
 * exit code.
 */
#define TEST_MAIN()                                                    \
    int main(void) {                                                   \
        printf("=== %s ===\n", __FILE__);                              \
        run_all_tests();                                               \
        printf("--- %d/%d tests, %d assertions, %d failed ---\n",      \
               g_test_total - g_test_failed,                           \
               g_test_total,                                           \
               g_assert_total,                                         \
               g_test_failed);                                         \
        return (g_test_failed > 0) ? 1 : 0;                            \
    }

#endif /* XURY_TESTS_TEST_H */
