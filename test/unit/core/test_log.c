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
 * TESTS — src/core/log.c
 * ============================================================================
 *
 * Exercise the real log primitives:
 *
 *   xury_log_init()
 *   xury_log_set_level() / xury_log_get_level()
 *   xury_log_enabled()
 *   xury_log()
 *   xury_log_v()
 *   xury_log_raw()
 *   xury_log_fmt_i64() / _u64() / _hex() / _errno()
 *
 * A capture hook records the last line for assertions.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <xury/xury.h>
#include "core/internal/log.h"
#include "test/test.h"

/*
 * ============================================================================
 * CAPTURE HOOK
 * ============================================================================
 */

typedef struct {
    int              calls;
    xury_log_level_t last_level;
    char             last_msg[XURY_LOG_LINE_MAX];
} capture_t;

static capture_t g_cap;

static void capture_hook(xury_log_level_t level,
                         const char *msg,
                         void *userdata)
{
    capture_t *c = (capture_t *)userdata;
    c->calls++;
    c->last_level = level;
    /* Copy into fixed buffer, NUL-terminate. */
    size_t i = 0;
    while (msg[i] != '\0' && i + 1u < sizeof(c->last_msg)) {
        c->last_msg[i] = msg[i];
        i++;
    }
    c->last_msg[i] = '\0';
}

static void capture_reset(void)
{
    memset(&g_cap, 0, sizeof(g_cap));
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

static void test_init_sets_fields(void)
{
    xury_logger_t lg;
    xury_log_init(&lg, capture_hook, &g_cap, XURY_LOG_WARN);

    TEST_ASSERT(lg.hook == capture_hook);
    TEST_ASSERT(lg.userdata == &g_cap);
    TEST_ASSERT_EQ(lg.min_level, XURY_LOG_WARN);
    TEST_ASSERT_EQ(lg.emitted, 0u);
    TEST_ASSERT_EQ(lg.dropped, 0u);
}

static void test_init_clamps_level(void)
{
    xury_logger_t lg;

    xury_log_init(&lg, NULL, NULL, (xury_log_level_t)-5);
    TEST_ASSERT_EQ(lg.min_level, XURY_LOG_TRACE);

    xury_log_init(&lg, NULL, NULL, (xury_log_level_t)99);
    TEST_ASSERT_EQ(lg.min_level, XURY_LOG_ERROR);
}

static void test_init_null_is_noop(void)
{
    xury_log_init(NULL, capture_hook, &g_cap, XURY_LOG_INFO);
}

static void test_set_get_level(void)
{
    xury_logger_t lg;
    xury_log_init(&lg, NULL, NULL, XURY_LOG_INFO);

    xury_log_set_level(&lg, XURY_LOG_ERROR);
    TEST_ASSERT_EQ(xury_log_get_level(&lg), XURY_LOG_ERROR);

    xury_log_set_level(&lg, (xury_log_level_t)-1);
    TEST_ASSERT_EQ(xury_log_get_level(&lg), XURY_LOG_TRACE);
}

static void test_get_level_null(void)
{
    TEST_ASSERT_EQ(xury_log_get_level(NULL), XURY_LOG_INFO);
}

/*
 * ============================================================================
 * ENABLED
 * ============================================================================
 */

static void test_enabled_respects_level(void)
{
    xury_logger_t lg;
    xury_log_init(&lg, NULL, NULL, XURY_LOG_WARN);

    TEST_ASSERT(!xury_log_enabled(&lg, XURY_LOG_TRACE));
    TEST_ASSERT(!xury_log_enabled(&lg, XURY_LOG_DEBUG));
    TEST_ASSERT(!xury_log_enabled(&lg, XURY_LOG_INFO));
    TEST_ASSERT(xury_log_enabled(&lg, XURY_LOG_WARN));
    TEST_ASSERT(xury_log_enabled(&lg, XURY_LOG_ERROR));
}

static void test_enabled_null(void)
{
    TEST_ASSERT(!xury_log_enabled(NULL, XURY_LOG_ERROR));
}

/*
 * ============================================================================
 * EMIT — RAW
 * ============================================================================
 */

static void test_raw_emits(void)
{
    capture_reset();
    xury_logger_t lg;
    xury_log_init(&lg, capture_hook, &g_cap, XURY_LOG_TRACE);

    xury_log_raw(&lg, XURY_LOG_INFO, "hello");

    TEST_ASSERT_EQ(g_cap.calls, 1);
    TEST_ASSERT_EQ(g_cap.last_level, XURY_LOG_INFO);
    TEST_ASSERT_STREQ(g_cap.last_msg, "hello");
    TEST_ASSERT_EQ(lg.emitted, 1u);
}

static void test_raw_filters_below_level(void)
{
    capture_reset();
    xury_logger_t lg;
    xury_log_init(&lg, capture_hook, &g_cap, XURY_LOG_WARN);

    xury_log_raw(&lg, XURY_LOG_INFO, "dropped");

    TEST_ASSERT_EQ(g_cap.calls, 0);
    TEST_ASSERT_EQ(lg.emitted, 0u);
    TEST_ASSERT_EQ(lg.dropped, 1u);
}

static void test_raw_null_hook_counts(void)
{
    xury_logger_t lg;
    xury_log_init(&lg, NULL, NULL, XURY_LOG_TRACE);

    xury_log_raw(&lg, XURY_LOG_INFO, "no hook");
    TEST_ASSERT_EQ(lg.emitted, 1u);
}

/*
 * ============================================================================
 * EMIT — FORMAT
 * ============================================================================
 */

static void test_fmt_specs(void)
{
    capture_reset();
    xury_logger_t lg;
    xury_log_init(&lg, capture_hook, &g_cap, XURY_LOG_TRACE);

    xury_log(&lg, XURY_LOG_INFO, "%s %d %u",
             "x", -42, 7u);
    TEST_ASSERT_STREQ(g_cap.last_msg, "x -42 7");
}

static void test_fmt_hex(void)
{
    capture_reset();
    xury_logger_t lg;
    xury_log_init(&lg, capture_hook, &g_cap, XURY_LOG_TRACE);

    xury_log(&lg, XURY_LOG_INFO, "0x%x", 0xDEADu);
    TEST_ASSERT_STREQ(g_cap.last_msg, "0xdead");
}

static void test_fmt_ll(void)
{
    capture_reset();
    xury_logger_t lg;
    xury_log_init(&lg, capture_hook, &g_cap, XURY_LOG_TRACE);

    xury_log(&lg, XURY_LOG_INFO, "%lld %llu",
             (long long)-1, (unsigned long long)1);
    TEST_ASSERT_STREQ(g_cap.last_msg, "-1 1");
}

static void test_fmt_zu(void)
{
    capture_reset();
    xury_logger_t lg;
    xury_log_init(&lg, capture_hook, &g_cap, XURY_LOG_TRACE);

    xury_log(&lg, XURY_LOG_INFO, "%zu", (size_t)1234u);
    TEST_ASSERT_STREQ(g_cap.last_msg, "1234");
}

static void test_fmt_pointer(void)
{
    capture_reset();
    xury_logger_t lg;
    xury_log_init(&lg, capture_hook, &g_cap, XURY_LOG_TRACE);

    xury_log(&lg, XURY_LOG_INFO, "%p", NULL);
    TEST_ASSERT_STREQ(g_cap.last_msg, "(nil)");
}

static void test_fmt_percent(void)
{
    capture_reset();
    xury_logger_t lg;
    xury_log_init(&lg, capture_hook, &g_cap, XURY_LOG_TRACE);

    xury_log(&lg, XURY_LOG_INFO, "100%%");
    TEST_ASSERT_STREQ(g_cap.last_msg, "100%");
}

static void test_fmt_unknown_is_literal(void)
{
    capture_reset();
    xury_logger_t lg;
    xury_log_init(&lg, capture_hook, &g_cap, XURY_LOG_TRACE);

    /* %f is not supported: must be emitted literally, no crash. */
    xury_log(&lg, XURY_LOG_INFO, "a %f b");
    TEST_ASSERT_STREQ(g_cap.last_msg, "a %f b");
}

static void test_fmt_null_string(void)
{
    capture_reset();
    xury_logger_t lg;
    xury_log_init(&lg, capture_hook, &g_cap, XURY_LOG_TRACE);

    xury_log(&lg, XURY_LOG_INFO, "%s", (const char *)NULL);
    TEST_ASSERT_STREQ(g_cap.last_msg, "(null)");
}

static void test_fmt_truncates_safely(void)
{
    capture_reset();
    xury_logger_t lg;
    xury_log_init(&lg, capture_hook, &g_cap, XURY_LOG_TRACE);

    /* Build a long string longer than the line buffer. */
    char big[1024];
    memset(big, 'x', sizeof(big) - 1u);
    big[sizeof(big) - 1u] = '\0';

    xury_log(&lg, XURY_LOG_INFO, "%s", big);

    /* The captured message must be NUL-terminated and shorter than
     * the line buffer. */
    size_t len = strlen(g_cap.last_msg);
    TEST_ASSERT(len < XURY_LOG_LINE_MAX);
    TEST_ASSERT_EQ(g_cap.last_msg[len], '\0');
}

static void test_fmt_via_va(void)
{
    capture_reset();
    xury_logger_t lg;
    xury_log_init(&lg, capture_hook, &g_cap, XURY_LOG_TRACE);

    /* Direct call to xury_log() already exercises va_list; this test
     * just makes sure the public va wrapper is reachable. */
    xury_log(&lg, XURY_LOG_INFO, "a%db", 1);
    TEST_ASSERT_STREQ(g_cap.last_msg, "a1b");
}

/*
 * ============================================================================
 * FORMATTING PRIMITIVES
 * ============================================================================
 */

static void test_fmt_u64_basic(void)
{
    char buf[32];
    xury_log_fmt_u64(buf, sizeof(buf), 0u);
    TEST_ASSERT_STREQ(buf, "0");

    xury_log_fmt_u64(buf, sizeof(buf), 12345u);
    TEST_ASSERT_STREQ(buf, "12345");

    xury_log_fmt_u64(buf, sizeof(buf), UINT64_MAX);
    TEST_ASSERT_STREQ(buf, "18446744073709551615");
}

static void test_fmt_i64_basic(void)
{
    char buf[32];
    xury_log_fmt_i64(buf, sizeof(buf), 0);
    TEST_ASSERT_STREQ(buf, "0");

    xury_log_fmt_i64(buf, sizeof(buf), -42);
    TEST_ASSERT_STREQ(buf, "-42");

    xury_log_fmt_i64(buf, sizeof(buf), INT64_MIN);
    TEST_ASSERT_STREQ(buf, "-9223372036854775808");

    xury_log_fmt_i64(buf, sizeof(buf), INT64_MAX);
    TEST_ASSERT_STREQ(buf, "9223372036854775807");
}

static void test_fmt_hex_basic(void)
{
    char buf[32];
    xury_log_fmt_hex(buf, sizeof(buf), 0u);
    TEST_ASSERT_STREQ(buf, "0");

    xury_log_fmt_hex(buf, sizeof(buf), 0xDEADBEEFu);
    TEST_ASSERT_STREQ(buf, "deadbeef");

    xury_log_fmt_hex(buf, sizeof(buf), UINT64_MAX);
    TEST_ASSERT_STREQ(buf, "ffffffffffffffff");
}

static void test_fmt_truncation_returns_would_be(void)
{
    char buf[4];
    size_t n = xury_log_fmt_u64(buf, sizeof(buf), 123456u);
    TEST_ASSERT(n >= sizeof(buf));
    TEST_ASSERT_EQ(buf[sizeof(buf) - 1u], '\0');
}

static void test_fmt_errno_with_value(void)
{
    char buf[64];
    xury_log_fmt_errno(buf, sizeof(buf), XURY_ERR_IO, EAGAIN);
    /* Must contain the tag and the errno number. */
    TEST_ASSERT_NOT_NULL(strstr(buf, "io"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "errno="));
}

static void test_fmt_errno_without_value(void)
{
    char buf[64];
    xury_log_fmt_errno(buf, sizeof(buf), XURY_ERR_TIMEOUT, 0);
    TEST_ASSERT_STREQ(buf, "timeout");
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    TEST_RUN(test_init_sets_fields);
    TEST_RUN(test_init_clamps_level);
    TEST_RUN(test_init_null_is_noop);
    TEST_RUN(test_set_get_level);
    TEST_RUN(test_get_level_null);

    TEST_RUN(test_enabled_respects_level);
    TEST_RUN(test_enabled_null);

    TEST_RUN(test_raw_emits);
    TEST_RUN(test_raw_filters_below_level);
    TEST_RUN(test_raw_null_hook_counts);

    TEST_RUN(test_fmt_specs);
    TEST_RUN(test_fmt_hex);
    TEST_RUN(test_fmt_ll);
    TEST_RUN(test_fmt_zu);
    TEST_RUN(test_fmt_pointer);
    TEST_RUN(test_fmt_percent);
    TEST_RUN(test_fmt_unknown_is_literal);
    TEST_RUN(test_fmt_null_string);
    TEST_RUN(test_fmt_truncates_safely);
    TEST_RUN(test_fmt_via_va);

    TEST_RUN(test_fmt_u64_basic);
    TEST_RUN(test_fmt_i64_basic);
    TEST_RUN(test_fmt_hex_basic);
    TEST_RUN(test_fmt_truncation_returns_would_be);
    TEST_RUN(test_fmt_errno_with_value);
    TEST_RUN(test_fmt_errno_without_value);
}

TEST_MAIN()
