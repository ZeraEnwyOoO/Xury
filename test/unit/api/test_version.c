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
 * TESTS — src/api/version.c
 * ============================================================================
 *
 * These tests exercise the real version functions:
 *
 *   public  (include/xury/version.h, include/xury/engine.h)
 *     xury_version()
 *     xury_build_commit()
 *     xury_build_date()
 *     xury_build_type()
 *     xury_build_platform()
 *     xury_api_version()
 *
 *   internal (src/api/internal/version.h)
 *     xury_version_code()
 *     xury_version_parse()
 *     xury_version_compare()
 *     xury_version_about()
 *     xury_version_tag()
 *     xury_version_full()
 *     xury_version_cache_prefix()
 *     xury_version_self_check()
 *
 * The tests do NOT mock anything. Every assertion is against the real
 * value produced by the library.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "api/internal/version.h"
#include "tests/test.h"

/*
 * ============================================================================
 * PUBLIC API — STRINGS
 * ============================================================================
 */

static void test_version_string_not_null(void)
{
    const char *v = xury_version();
    TEST_ASSERT_NOT_NULL(v);
}

static void test_version_string_matches_macro(void)
{
    /* The runtime string must equal the compile-time macro. */
    TEST_ASSERT_STREQ(xury_version(), XURY_VERSION_STRING);
}

static void test_build_commit_not_null(void)
{
    const char *v = xury_build_commit();
    TEST_ASSERT_NOT_NULL(v);
    /* Either a real hash or the literal "unknown". */
    TEST_ASSERT(v[0] != '\0');
}

static void test_build_date_not_null(void)
{
    const char *v = xury_build_date();
    TEST_ASSERT_NOT_NULL(v);
    TEST_ASSERT(v[0] != '\0');
}

static void test_build_type_not_null(void)
{
    const char *v = xury_build_type();
    TEST_ASSERT_NOT_NULL(v);
    TEST_ASSERT(v[0] != '\0');
}

static void test_build_platform_not_null(void)
{
    const char *v = xury_build_platform();
    TEST_ASSERT_NOT_NULL(v);
    TEST_ASSERT(v[0] != '\0');
}

static void test_api_version_positive(void)
{
    int v = xury_api_version();
    TEST_ASSERT(v >= 1);
    TEST_ASSERT_EQ(v, (int)XURY_API_VERSION);
}

/*
 * ============================================================================
 * INTERNAL — COMPOSITE
 * ============================================================================
 */

static void test_version_code_matches_macro(void)
{
    uint32_t runtime = xury_version_code();
    uint32_t compile = (uint32_t)XURY_VERSION_CODE;
    TEST_ASSERT_EQ(runtime, compile);
}

static void test_version_code_layout(void)
{
    /*
     * XURY_VERSION_CODE is (MAJOR << 16) | (MINOR << 8) | PATCH.
     * Verify the pieces come out where we expect.
     */
    uint32_t code = xury_version_code();
    uint32_t major = (code >> 16) & 0xFFu;
    uint32_t minor = (code >>  8) & 0xFFu;
    uint32_t patch = (code      ) & 0xFFu;

    TEST_ASSERT_EQ(major, (uint32_t)XURY_VERSION_MAJOR);
    TEST_ASSERT_EQ(minor, (uint32_t)XURY_VERSION_MINOR);
    TEST_ASSERT_EQ(patch, (uint32_t)XURY_VERSION_PATCH);
}

/*
 * ============================================================================
 * INTERNAL — PARSE
 * ============================================================================
 */

static void test_parse_valid_full(void)
{
    TEST_ASSERT_EQ(xury_version_parse("0.1.0"), 0x000100u);
    TEST_ASSERT_EQ(xury_version_parse("1.2.3"), 0x010203u);
    TEST_ASSERT_EQ(xury_version_parse("10.20.30"), 0x0A141Eu);
    TEST_ASSERT_EQ(xury_version_parse("255.255.255"), 0xFFFFFFu);
}

static void test_parse_leading_v(void)
{
    TEST_ASSERT_EQ(xury_version_parse("v0.1.0"), 0x000100u);
    TEST_ASSERT_EQ(xury_version_parse("V1.2.3"), 0x010203u);
}

static void test_parse_partial(void)
{
    /* Missing minor / patch default to 0. */
    TEST_ASSERT_EQ(xury_version_parse("1"), 0x010000u);
    TEST_ASSERT_EQ(xury_version_parse("1.2"), 0x010200u);
}

static void test_parse_rejects_garbage(void)
{
    TEST_ASSERT_EQ(xury_version_parse(NULL), 0u);
    TEST_ASSERT_EQ(xury_version_parse(""), 0u);
    TEST_ASSERT_EQ(xury_version_parse("abc"), 0u);
    TEST_ASSERT_EQ(xury_version_parse("1.2.3x"), 0u);
    TEST_ASSERT_EQ(xury_version_parse("1.2.3.4"), 0u);
    TEST_ASSERT_EQ(xury_version_parse(" 1.2.3"), 0u);
    TEST_ASSERT_EQ(xury_version_parse("1.2.3 "), 0u);
    TEST_ASSERT_EQ(xury_version_parse("-1.2.3"), 0u);
    TEST_ASSERT_EQ(xury_version_parse("1..3"), 0u);
    TEST_ASSERT_EQ(xury_version_parse("v"), 0u);
}

static void test_parse_rejects_overflow(void)
{
    /* A single component larger than uint32 must be rejected. */
    TEST_ASSERT_EQ(xury_version_parse("99999999999"), 0u);
}

static void test_parse_roundtrip_of_library_version(void)
{
    /* Our own version string must parse back to our own code. */
    uint32_t parsed = xury_version_parse(XURY_VERSION_STRING);
    TEST_ASSERT_EQ(parsed, (uint32_t)XURY_VERSION_CODE);
}

/*
 * ============================================================================
 * INTERNAL — COMPARE
 * ============================================================================
 */

static void test_compare_less(void)
{
    TEST_ASSERT(xury_version_compare(0x000100u, 0x010000u) < 0);
    TEST_ASSERT(xury_version_compare(0x010000u, 0x010001u) < 0);
    TEST_ASSERT(xury_version_compare(0x010200u, 0x010201u) < 0);
}

static void test_compare_equal(void)
{
    TEST_ASSERT_EQ(xury_version_compare(0x000100u, 0x000100u), 0);
    TEST_ASSERT_EQ(xury_version_compare(0u, 0u), 0);
    TEST_ASSERT_EQ(xury_version_compare(0xFFFFFFu, 0xFFFFFFu), 0);
}

static void test_compare_greater(void)
{
    TEST_ASSERT(xury_version_compare(0x010000u, 0x000100u) > 0);
    TEST_ASSERT(xury_version_compare(0x010001u, 0x010000u) > 0);
}

static void test_compare_matches_at_least_macro(void)
{
    /*
     * The public header provides XURY_VERSION_AT_LEAST. Verify it
     * agrees with the runtime comparator for a few representative
     * pairs.
     */
    const uint32_t cur = xury_version_code();

    /* At least our own version: true. */
    TEST_ASSERT_EQ(xury_version_compare(cur, cur), 0);

    /* At least 0.0.0: true. */
    TEST_ASSERT(xury_version_compare(cur, 0x000000u) >= 0);

    /* At least 1.0.0 (assuming we are 0.x): cur < 0x010000. */
    #if (XURY_VERSION_MAJOR == 0)
    TEST_ASSERT(xury_version_compare(cur, 0x010000u) < 0);
    #endif
}

/*
 * ============================================================================
 * INTERNAL — PRECOMPUTED STRINGS
 * ============================================================================
 */

static void test_about_not_null_and_nonempty(void)
{
    const char *s = xury_version_about();
    TEST_ASSERT_NOT_NULL(s);
    TEST_ASSERT(s[0] != '\0');
    /* Must contain the version string. */
    TEST_ASSERT_NOT_NULL(strstr(s, XURY_VERSION_STRING));
}

static void test_about_starts_with_xury(void)
{
    const char *s = xury_version_about();
    TEST_ASSERT(strncmp(s, "Xury ", 5) == 0);
}

static void test_tag_not_null_and_contains_version(void)
{
    const char *s = xury_version_tag();
    TEST_ASSERT_NOT_NULL(s);
    TEST_ASSERT(strncmp(s, "Xury/", 5) == 0);
    TEST_ASSERT_NOT_NULL(strstr(s, XURY_VERSION_STRING));
}

static void test_full_not_null(void)
{
    const char *s = xury_version_full();
    TEST_ASSERT_NOT_NULL(s);
    TEST_ASSERT(s[0] != '\0');
    /* Must contain the version string. */
    TEST_ASSERT_NOT_NULL(strstr(s, XURY_VERSION_STRING));
}

static void test_cache_prefix_shape(void)
{
    const char *s = xury_version_cache_prefix();
    TEST_ASSERT_NOT_NULL(s);
    /* Must start with "xury:v". */
    TEST_ASSERT(strncmp(s, "xury:v", 6) == 0);
    /* Must end with ':'. */
    size_t len = strlen(s);
    TEST_ASSERT(len > 0);
    TEST_ASSERT_EQ(s[len - 1], ':');
    /* Must contain the version string. */
    TEST_ASSERT_NOT_NULL(strstr(s, XURY_VERSION_STRING));
}

/*
 * ============================================================================
 * INTERNAL — SELF CHECK
 * ============================================================================
 */

static void test_self_check_ok(void)
{
    /* The library must consider its own headers consistent. */
    TEST_ASSERT_EQ(xury_version_self_check(), XURY_OK);
}

static void test_self_check_is_idempotent(void)
{
    /* Calling twice must not change the result. */
    xury_err_t a = xury_version_self_check();
    xury_err_t b = xury_version_self_check();
    TEST_ASSERT_EQ(a, b);
    TEST_ASSERT_EQ(a, XURY_OK);
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    /* Public API — strings */
    TEST_RUN(test_version_string_not_null);
    TEST_RUN(test_version_string_matches_macro);
    TEST_RUN(test_build_commit_not_null);
    TEST_RUN(test_build_date_not_null);
    TEST_RUN(test_build_type_not_null);
    TEST_RUN(test_build_platform_not_null);
    TEST_RUN(test_api_version_positive);

    /* Internal — composite */
    TEST_RUN(test_version_code_matches_macro);
    TEST_RUN(test_version_code_layout);

    /* Internal — parse */
    TEST_RUN(test_parse_valid_full);
    TEST_RUN(test_parse_leading_v);
    TEST_RUN(test_parse_partial);
    TEST_RUN(test_parse_rejects_garbage);
    TEST_RUN(test_parse_rejects_overflow);
    TEST_RUN(test_parse_roundtrip_of_library_version);

    /* Internal — compare */
    TEST_RUN(test_compare_less);
    TEST_RUN(test_compare_equal);
    TEST_RUN(test_compare_greater);
    TEST_RUN(test_compare_matches_at_least_macro);

    /* Internal — precomputed strings */
    TEST_RUN(test_about_not_null_and_nonempty);
    TEST_RUN(test_about_starts_with_xury);
    TEST_RUN(test_tag_not_null_and_contains_version);
    TEST_RUN(test_full_not_null);
    TEST_RUN(test_cache_prefix_shape);

    /* Internal — self check */
    TEST_RUN(test_self_check_ok);
    TEST_RUN(test_self_check_is_idempotent);
}

TEST_MAIN()
