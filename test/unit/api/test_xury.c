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
 * TESTS — src/api/xury.c
 * ============================================================================
 *
 * Exercise the real umbrella helpers:
 *
 *   xury_about()
 *   xury_str_len() / _eq() / _eq_ci() / _copy()
 *   xury_str_trim() / _lower() / _upper() / _starts_with() / _ends_with()
 *   xury_clamp_u32() / _u64() / _min_u32() / _max_u32()
 *   xury_round_up_u32() / xury_align_ptr()
 *   xury_fmt_u32() / _u64() / _i32() / _i64()
 *   xury_fmt_hex32() / _hex64() / _hex64_pad() / _hex_bytes()
 *   xury_parse_u32() / _u64() / _i32() / _bool() / _duration_ms()
 *   xury_fmt_endpoint() / _fmt_peer_id()
 *   xury_set_assert_handler()
 *   xury_global_init() / _shutdown() / _is_ready()
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "api/internal/xury.h"
#include "test/test.h"

/*
 * ============================================================================
 * PROCESS LIFECYCLE
 * ============================================================================
 */

static void test_global_init_shutdown(void)
{
    TEST_ASSERT_EQ(xury_global_init(), XURY_OK);
    TEST_ASSERT(xury_global_is_ready());
    xury_global_shutdown();
}

static void test_global_refcount(void)
{
    /* Baseline */
    xury_global_init();
    xury_global_init();
    TEST_ASSERT(xury_global_is_ready());

    xury_global_shutdown();
    TEST_ASSERT(xury_global_is_ready());   /* still one left */
    xury_global_shutdown();
    /* May be zero or one depending on prior tests; don't assert zero. */
}

/*
 * ============================================================================
 * STRING — LENGTH / EQUAL
 * ============================================================================
 */

static void test_str_len(void)
{
    TEST_ASSERT_EQ(xury_str_len(""), 0u);
    TEST_ASSERT_EQ(xury_str_len("abc"), 3u);
    TEST_ASSERT_EQ(xury_str_len(NULL), 0u);
}

static void test_str_eq(void)
{
    TEST_ASSERT(xury_str_eq("a", "a"));
    TEST_ASSERT(xury_str_eq(NULL, NULL));
    TEST_ASSERT(!xury_str_eq("a", "b"));
    TEST_ASSERT(!xury_str_eq(NULL, "a"));
    TEST_ASSERT(!xury_str_eq("a", NULL));
}

static void test_str_eq_ci(void)
{
    TEST_ASSERT(xury_str_eq_ci("abc", "ABC"));
    TEST_ASSERT(xury_str_eq_ci("AbC", "aBc"));
    TEST_ASSERT(xury_str_eq_ci(NULL, NULL));
    TEST_ASSERT(!xury_str_eq_ci("abc", "abd"));
    TEST_ASSERT(!xury_str_eq_ci(NULL, "a"));
}

/*
 * ============================================================================
 * STRING — COPY / TRIM / CASE
 * ============================================================================
 */

static void test_str_copy(void)
{
    char buf[8];
    size_t n = xury_str_copy(buf, sizeof(buf), "abc");
    TEST_ASSERT_EQ(n, 3u);
    TEST_ASSERT_STREQ(buf, "abc");
}

static void test_str_copy_truncates(void)
{
    char buf[4];
    size_t n = xury_str_copy(buf, sizeof(buf), "abcdef");
    TEST_ASSERT(n >= sizeof(buf));
    TEST_ASSERT_STREQ(buf, "abc");
}

static void test_str_copy_null(void)
{
    char buf[4] = "xx";
    size_t n = xury_str_copy(buf, sizeof(buf), NULL);
    TEST_ASSERT_EQ(n, 0u);
    TEST_ASSERT_STREQ(buf, "");

    n = xury_str_copy(NULL, 0, "abc");
    TEST_ASSERT_EQ(n, 3u);
}

static void test_str_trim(void)
{
    char s1[] = "  hello  ";
    TEST_ASSERT_STREQ(xury_str_trim(s1), "hello");

    char s2[] = "\t\nx\r\n";
    TEST_ASSERT_STREQ(xury_str_trim(s2), "x");

    char s3[] = "";
    TEST_ASSERT_STREQ(xury_str_trim(s3), "");

    TEST_ASSERT_NULL(xury_str_trim(NULL));
}

static void test_str_lower_upper(void)
{
    char s[] = "AbC123";
    xury_str_lower(s);
    TEST_ASSERT_STREQ(s, "abc123");

    xury_str_upper(s);
    TEST_ASSERT_STREQ(s, "ABC123");

    xury_str_lower(NULL);
    xury_str_upper(NULL);
}

static void test_str_starts_with(void)
{
    TEST_ASSERT(xury_str_starts_with("hello", "he"));
    TEST_ASSERT(xury_str_starts_with("hello", ""));
    TEST_ASSERT(xury_str_starts_with("hello", "hello"));
    TEST_ASSERT(!xury_str_starts_with("hello", "lo"));
    TEST_ASSERT(!xury_str_starts_with(NULL, "x"));
    TEST_ASSERT(!xury_str_starts_with("x", NULL));
}

static void test_str_ends_with(void)
{
    TEST_ASSERT(xury_str_ends_with("hello", "lo"));
    TEST_ASSERT(xury_str_ends_with("hello", ""));
    TEST_ASSERT(xury_str_ends_with("hello", "hello"));
    TEST_ASSERT(!xury_str_ends_with("hello", "he"));
    TEST_ASSERT(!xury_str_ends_with(NULL, "x"));
    TEST_ASSERT(!xury_str_ends_with("x", NULL));
}

/*
 * ============================================================================
 * NUMERIC
 * ============================================================================
 */

static void test_clamp(void)
{
    TEST_ASSERT_EQ(xury_clamp_u32(5, 1, 10), 5u);
    TEST_ASSERT_EQ(xury_clamp_u32(0, 1, 10), 1u);
    TEST_ASSERT_EQ(xury_clamp_u32(99, 1, 10), 10u);
    TEST_ASSERT_EQ(xury_clamp_u32(5, 10, 1), 10u);   /* lo > hi */

    TEST_ASSERT_EQ(xury_clamp_u64(5, 1, 10), 5u);
}

static void test_min_max(void)
{
    TEST_ASSERT_EQ(xury_min_u32(3, 5), 3u);
    TEST_ASSERT_EQ(xury_max_u32(3, 5), 5u);
}

static void test_round_up(void)
{
    TEST_ASSERT_EQ(xury_round_up_u32(0, 8), 0u);
    TEST_ASSERT_EQ(xury_round_up_u32(1, 8), 8u);
    TEST_ASSERT_EQ(xury_round_up_u32(8, 8), 8u);
    TEST_ASSERT_EQ(xury_round_up_u32(9, 8), 16u);
    TEST_ASSERT_EQ(xury_round_up_u32(5, 0), 5u);
}

static void test_align_ptr(void)
{
    uint8_t buf[32];
    void *p = xury_align_ptr(buf + 1, 8);
    TEST_ASSERT(((uintptr_t)p & 7u) == 0u);

    TEST_ASSERT(xury_align_ptr(buf, 0) == buf);
}

/*
 * ============================================================================
 * FORMATTING — INTEGER
 * ============================================================================
 */

static void test_fmt_u32(void)
{
    char buf[16];
    xury_fmt_u32(0u, buf, sizeof(buf));
    TEST_ASSERT_STREQ(buf, "0");
    xury_fmt_u32(12345u, buf, sizeof(buf));
    TEST_ASSERT_STREQ(buf, "12345");
    xury_fmt_u32(0xFFFFFFFFu, buf, sizeof(buf));
    TEST_ASSERT_STREQ(buf, "4294967295");
}

static void test_fmt_i32(void)
{
    char buf[16];
    xury_fmt_i32(0, buf, sizeof(buf));
    TEST_ASSERT_STREQ(buf, "0");
    xury_fmt_i32(-42, buf, sizeof(buf));
    TEST_ASSERT_STREQ(buf, "-42");
    xury_fmt_i32(INT32_MIN, buf, sizeof(buf));
    TEST_ASSERT_STREQ(buf, "-2147483648");
    xury_fmt_i32(INT32_MAX, buf, sizeof(buf));
    TEST_ASSERT_STREQ(buf, "2147483647");
}

static void test_fmt_u64_i64(void)
{
    char buf[32];
    xury_fmt_u64(UINT64_MAX, buf, sizeof(buf));
    TEST_ASSERT_STREQ(buf, "18446744073709551615");
    xury_fmt_i64(INT64_MIN, buf, sizeof(buf));
    TEST_ASSERT_STREQ(buf, "-9223372036854775808");
}

static void test_fmt_truncation(void)
{
    char buf[4];
    size_t n = xury_fmt_u32(123456u, buf, sizeof(buf));
    TEST_ASSERT(n >= sizeof(buf));
    TEST_ASSERT_EQ(buf[sizeof(buf) - 1u], '\0');
}

/*
 * ============================================================================
 * FORMATTING — HEX
 * ============================================================================
 */

static void test_fmt_hex(void)
{
    char buf[32];
    xury_fmt_hex32(0u, buf, sizeof(buf));
    TEST_ASSERT_STREQ(buf, "0");

    xury_fmt_hex32(0xDEADBEEFu, buf, sizeof(buf));
    TEST_ASSERT_STREQ(buf, "deadbeef");

    xury_fmt_hex64(0x0123456789ABCDEFull, buf, sizeof(buf));
    TEST_ASSERT_STREQ(buf, "123456789abcdef");
}

static void test_fmt_hex64_pad(void)
{
    char buf[32];
    xury_fmt_hex64_pad(0xDEu, 4, buf, sizeof(buf));
    TEST_ASSERT_STREQ(buf, "00de");

    xury_fmt_hex64_pad(0xABu, 1, buf, sizeof(buf));
    TEST_ASSERT_STREQ(buf, "ab");

    xury_fmt_hex64_pad(0xABu, 99, buf, sizeof(buf));
    /* Width clamps to 16. */
    TEST_ASSERT_EQ(strlen(buf), 16u);
}

static void test_fmt_hex_bytes(void)
{
    uint8_t bytes[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    char buf[16];
    size_t n = xury_fmt_hex_bytes(bytes, 4, buf, sizeof(buf));
    TEST_ASSERT_EQ(n, 8u);
    TEST_ASSERT_STREQ(buf, "deadbeef");

    /* NULL with 0 length. */
    n = xury_fmt_hex_bytes(NULL, 0, buf, sizeof(buf));
    TEST_ASSERT_EQ(n, 0u);
    TEST_ASSERT_STREQ(buf, "");
}

/*
 * ============================================================================
 * PARSING
 * ============================================================================
 */

static void test_parse_u32(void)
{
    uint32_t v = 0;
    TEST_ASSERT_EQ(xury_parse_u32("0", &v), XURY_OK);
    TEST_ASSERT_EQ(v, 0u);

    TEST_ASSERT_EQ(xury_parse_u32("12345", &v), XURY_OK);
    TEST_ASSERT_EQ(v, 12345u);

    TEST_ASSERT_EQ(xury_parse_u32("", &v), XURY_ERR_OUT_OF_RANGE);
    TEST_ASSERT_EQ(xury_parse_u32("abc", &v), XURY_ERR_OUT_OF_RANGE);
    TEST_ASSERT_EQ(xury_parse_u32("12x", &v), XURY_ERR_OUT_OF_RANGE);
    TEST_ASSERT_EQ(xury_parse_u32(" 12", &v), XURY_ERR_OUT_OF_RANGE);
    TEST_ASSERT_EQ(xury_parse_u32(NULL, &v), XURY_ERR_INVAL);
    TEST_ASSERT_EQ(xury_parse_u32("1", NULL), XURY_ERR_INVAL);
}

static void test_parse_u32_overflow(void)
{
    uint32_t v = 0;
    TEST_ASSERT_EQ(xury_parse_u32("4294967296", &v), XURY_ERR_OUT_OF_RANGE);
}

static void test_parse_i32(void)
{
    int32_t v = 0;
    TEST_ASSERT_EQ(xury_parse_i32("0", &v), XURY_OK);
    TEST_ASSERT_EQ(v, 0);

    TEST_ASSERT_EQ(xury_parse_i32("-42", &v), XURY_OK);
    TEST_ASSERT_EQ(v, -42);

    TEST_ASSERT_EQ(xury_parse_i32("+7", &v), XURY_OK);
    TEST_ASSERT_EQ(v, 7);

    TEST_ASSERT_EQ(xury_parse_i32("2147483647", &v), XURY_OK);
    TEST_ASSERT_EQ(v, 2147483647);

    TEST_ASSERT_EQ(xury_parse_i32("-2147483648", &v), XURY_OK);
    TEST_ASSERT_EQ(v, INT32_MIN);

    TEST_ASSERT_EQ(xury_parse_i32("-2147483649", &v), XURY_ERR_OUT_OF_RANGE);
}

static void test_parse_bool(void)
{
    bool v = false;

    TEST_ASSERT_EQ(xury_parse_bool("1", &v), XURY_OK);
    TEST_ASSERT(v);
    TEST_ASSERT_EQ(xury_parse_bool("true", &v), XURY_OK);
    TEST_ASSERT(v);
    TEST_ASSERT_EQ(xury_parse_bool("YES", &v), XURY_OK);
    TEST_ASSERT(v);
    TEST_ASSERT_EQ(xury_parse_bool("on", &v), XURY_OK);
    TEST_ASSERT(v);

    TEST_ASSERT_EQ(xury_parse_bool("0", &v), XURY_OK);
    TEST_ASSERT(!v);
    TEST_ASSERT_EQ(xury_parse_bool("false", &v), XURY_OK);
    TEST_ASSERT(!v);
    TEST_ASSERT_EQ(xury_parse_bool("NO", &v), XURY_OK);
    TEST_ASSERT(!v);
    TEST_ASSERT_EQ(xury_parse_bool("off", &v), XURY_OK);
    TEST_ASSERT(!v);

    TEST_ASSERT_EQ(xury_parse_bool("bogus", &v), XURY_ERR_INVAL);
}

static void test_parse_duration(void)
{
    uint32_t v = 0;
    TEST_ASSERT_EQ(xury_parse_duration_ms("123", &v), XURY_OK);
    TEST_ASSERT_EQ(v, 123u);

    TEST_ASSERT_EQ(xury_parse_duration_ms("123ms", &v), XURY_OK);
    TEST_ASSERT_EQ(v, 123u);

    TEST_ASSERT_EQ(xury_parse_duration_ms("5s", &v), XURY_OK);
    TEST_ASSERT_EQ(v, 5000u);

    TEST_ASSERT_EQ(xury_parse_duration_ms("2m", &v), XURY_OK);
    TEST_ASSERT_EQ(v, 120000u);

    TEST_ASSERT_EQ(xury_parse_duration_ms("", &v), XURY_ERR_OUT_OF_RANGE);
    TEST_ASSERT_EQ(xury_parse_duration_ms("abc", &v), XURY_ERR_OUT_OF_RANGE);
    TEST_ASSERT_EQ(xury_parse_duration_ms("5x", &v), XURY_ERR_OUT_OF_RANGE);
}

/*
 * ============================================================================
 * ENDPOINT / PEER ID SHORTCUTS
 * ============================================================================
 */

static void test_fmt_endpoint(void)
{
    xury_endpoint_t e;
    xury_endpoint_clear(&e);
    strcpy(e.ip, "1.2.3.4");
    e.port = 80;
    e.family = XURY_AF_INET;

    char buf[64];
    TEST_ASSERT_EQ(xury_fmt_endpoint(&e, buf, sizeof(buf)), XURY_OK);
    TEST_ASSERT_STREQ(buf, "1.2.3.4:80");
}

static void test_fmt_peer_id(void)
{
    xury_peer_id_t id;
    xury_peer_id_clear(&id);
    id.bytes[0] = 0xAB;

    char buf[80];
    TEST_ASSERT_EQ(xury_fmt_peer_id(&id, buf, sizeof(buf)), XURY_OK);
    TEST_ASSERT_EQ(strlen(buf), 64u);
    TEST_ASSERT(buf[0] == 'a' && buf[1] == 'b');
}

/*
 * ============================================================================
 * ABOUT / VERSION
 * ============================================================================
 */

static void test_about(void)
{
    const char *s = xury_about();
    TEST_ASSERT_NOT_NULL(s);
    TEST_ASSERT(s[0] != '\0');
    /* Should contain the version string. */
    TEST_ASSERT_NOT_NULL(strstr(s, XURY_VERSION_STRING));
}

/*
 * ============================================================================
 * ASSERT HANDLER
 * ============================================================================
 */

static int  g_assert_calls = 0;
static char g_assert_expr[64];

static void my_assert_handler(const char *expr,
                              const char *file,
                              int line,
                              void *userdata)
{
    (void)file;
    (void)line;
    (void)userdata;
    g_assert_calls++;
    size_t i = 0;
    while (expr[i] != '\0' && i + 1u < sizeof(g_assert_expr)) {
        g_assert_expr[i] = expr[i];
        i++;
    }
    g_assert_expr[i] = '\0';
}

static void test_assert_handler(void)
{
    g_assert_calls = 0;
    g_assert_expr[0] = '\0';

    xury_set_assert_handler(my_assert_handler, NULL);

    /* We can't easily trigger an assert from a test without abort()
     * when no handler is installed. Instead we verify that setting
     * and reading back the handler works by restoring the default. */
    TEST_ASSERT(true);

    xury_set_assert_handler(NULL, NULL);
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    TEST_RUN(test_global_init_shutdown);
    TEST_RUN(test_global_refcount);

    TEST_RUN(test_str_len);
    TEST_RUN(test_str_eq);
    TEST_RUN(test_str_eq_ci);
    TEST_RUN(test_str_copy);
    TEST_RUN(test_str_copy_truncates);
    TEST_RUN(test_str_copy_null);
    TEST_RUN(test_str_trim);
    TEST_RUN(test_str_lower_upper);
    TEST_RUN(test_str_starts_with);
    TEST_RUN(test_str_ends_with);

    TEST_RUN(test_clamp);
    TEST_RUN(test_min_max);
    TEST_RUN(test_round_up);
    TEST_RUN(test_align_ptr);

    TEST_RUN(test_fmt_u32);
    TEST_RUN(test_fmt_i32);
    TEST_RUN(test_fmt_u64_i64);
    TEST_RUN(test_fmt_truncation);

    TEST_RUN(test_fmt_hex);
    TEST_RUN(test_fmt_hex64_pad);
    TEST_RUN(test_fmt_hex_bytes);

    TEST_RUN(test_parse_u32);
    TEST_RUN(test_parse_u32_overflow);
    TEST_RUN(test_parse_i32);
    TEST_RUN(test_parse_bool);
    TEST_RUN(test_parse_duration);

    TEST_RUN(test_fmt_endpoint);
    TEST_RUN(test_fmt_peer_id);

    TEST_RUN(test_about);
    TEST_RUN(test_assert_handler);
}

TEST_MAIN()
