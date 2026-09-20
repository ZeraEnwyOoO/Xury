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
 * TESTS — src/api/err.c
 * ============================================================================
 *
 * Exercise the real error helpers:
 *
 *   public (include/xury/err.h)
 *     xury_strerror()
 *     xury_err_tag()
 *     xury_err_class()
 *     xury_err_class_name()
 *     xury_err_from_errno()
 *     xury_err_is_ok()      (inline)
 *     xury_err_is_error()   (inline)
 *
 *   internal (src/api/internal/err.h)
 *     xury_err_info()
 *     xury_err_table_size()
 *     xury_err_table_at()
 *     xury_err_by_symbol()
 *     xury_err_to_errno()
 *     xury_err_from_errno_ctx()
 *     xury_err_is_retryable()
 *     xury_err_is_fatal()
 *     xury_err_is_benign()
 *     xury_err_set_last_errno()
 *     xury_err_get_last_errno()
 *     xury_err_clear_last_errno()
 *     xury_err_push_context()
 *     xury_err_pop_context()
 *     xury_err_clear_context()
 *     xury_err_context_depth()
 *     xury_err_context_at()
 *     xury_err_context_format()
 *
 * No mocks, no fakes. Every value comes from the library.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <xury/xury.h>
#include "api/internal/err.h"
#include "test/test.h"

/*
 * ============================================================================
 * PUBLIC — STRINGS
 * ============================================================================
 */

static void test_strerror_ok(void)
{
    const char *s = xury_strerror(XURY_OK);
    TEST_ASSERT_NOT_NULL(s);
    TEST_ASSERT_STREQ(s, "success");
}

static void test_strerror_timeout(void)
{
    const char *s = xury_strerror(XURY_ERR_TIMEOUT);
    TEST_ASSERT_NOT_NULL(s);
    TEST_ASSERT_STREQ(s, "operation timed out");
}

static void test_strerror_never_null(void)
{
    /* Even for a value that is not in the table. */
    const char *s = xury_strerror((xury_err_t)-9999);
    TEST_ASSERT_NOT_NULL(s);
    TEST_ASSERT(s[0] != '\0');
}

static void test_err_tag(void)
{
    TEST_ASSERT_STREQ(xury_err_tag(XURY_OK), "ok");
    TEST_ASSERT_STREQ(xury_err_tag(XURY_ERR_TIMEOUT), "timeout");
    TEST_ASSERT_STREQ(xury_err_tag(XURY_ERR_PUNCH_FAIL), "punch_fail");
    TEST_ASSERT_STREQ(xury_err_tag(XURY_ERR_NOMEM), "nomem");
    TEST_ASSERT_STREQ(xury_err_tag((xury_err_t)-9999), "unknown");
}

static void test_err_is_ok_inline(void)
{
    TEST_ASSERT(xury_err_is_ok(XURY_OK));
    TEST_ASSERT(!xury_err_is_ok(XURY_ERR_TIMEOUT));
}

static void test_err_is_error_inline(void)
{
    TEST_ASSERT(!xury_err_is_error(XURY_OK));
    TEST_ASSERT(xury_err_is_error(XURY_ERR_TIMEOUT));
    TEST_ASSERT(xury_err_is_error((xury_err_t)-9999));
}

/*
 * ============================================================================
 * PUBLIC — CLASSES
 * ============================================================================
 */

static void test_err_class(void)
{
    TEST_ASSERT_EQ(xury_err_class(XURY_OK), XURY_ERR_CLASS_OK);
    TEST_ASSERT_EQ(xury_err_class(XURY_ERR_INVAL),
                   XURY_ERR_CLASS_ARGUMENT);
    TEST_ASSERT_EQ(xury_err_class(XURY_ERR_NOMEM),
                   XURY_ERR_CLASS_MEMORY);
    TEST_ASSERT_EQ(xury_err_class(XURY_ERR_TIMEOUT),
                   XURY_ERR_CLASS_NETWORK);
    TEST_ASSERT_EQ(xury_err_class(XURY_ERR_PUNCH_FAIL),
                   XURY_ERR_CLASS_NAT);
    TEST_ASSERT_EQ(xury_err_class(XURY_ERR_CGNAT_STRICT),
                   XURY_ERR_CLASS_CGNAT);
    TEST_ASSERT_EQ(xury_err_class(XURY_ERR_NO_PEER),
                   XURY_ERR_CLASS_PEER);
    TEST_ASSERT_EQ(xury_err_class(XURY_ERR_PLATFORM_INIT),
                   XURY_ERR_CLASS_PLATFORM);
    TEST_ASSERT_EQ(xury_err_class(XURY_ERR_NOT_READY),
                   XURY_ERR_CLASS_STATE);
    TEST_ASSERT_EQ(xury_err_class(XURY_ERR_NOT_CALIBRATED),
                   XURY_ERR_CLASS_RESEARCH);
    TEST_ASSERT_EQ(xury_err_class((xury_err_t)-9999),
                   XURY_ERR_CLASS_UNKNOWN);
}

static void test_err_class_name(void)
{
    TEST_ASSERT_STREQ(xury_err_class_name(XURY_ERR_CLASS_OK), "ok");
    TEST_ASSERT_STREQ(xury_err_class_name(XURY_ERR_CLASS_ARGUMENT),
                      "argument");
    TEST_ASSERT_STREQ(xury_err_class_name(XURY_ERR_CLASS_MEMORY),
                      "memory");
    TEST_ASSERT_STREQ(xury_err_class_name(XURY_ERR_CLASS_NETWORK),
                      "network");
    TEST_ASSERT_STREQ(xury_err_class_name(XURY_ERR_CLASS_NAT), "nat");
    TEST_ASSERT_STREQ(xury_err_class_name(XURY_ERR_CLASS_CGNAT), "cgnat");
    TEST_ASSERT_STREQ(xury_err_class_name(XURY_ERR_CLASS_PEER), "peer");
    TEST_ASSERT_STREQ(xury_err_class_name(XURY_ERR_CLASS_PLATFORM),
                      "platform");
    TEST_ASSERT_STREQ(xury_err_class_name(XURY_ERR_CLASS_STATE), "state");
    TEST_ASSERT_STREQ(xury_err_class_name(XURY_ERR_CLASS_RESEARCH),
                      "research");
    TEST_ASSERT_STREQ(xury_err_class_name(XURY_ERR_CLASS_UNKNOWN),
                      "unknown");
    TEST_ASSERT_STREQ(xury_err_class_name((xury_err_class_t)999),
                      "unknown");
}

/*
 * ============================================================================
 * INTERNAL — TABLE
 * ============================================================================
 */

static void test_table_size_positive(void)
{
    size_t n = xury_err_table_size();
    /* Must have at least XURY_OK. */
    TEST_ASSERT(n >= 1u);
}

static void test_table_at_out_of_range(void)
{
    size_t n = xury_err_table_size();
    TEST_ASSERT_NULL(xury_err_table_at(n));
    TEST_ASSERT_NULL(xury_err_table_at(n + 100u));
}

static void test_table_at_valid(void)
{
    size_t n = xury_err_table_size();
    for (size_t i = 0; i < n; i++) {
        const xury_err_info_t *info = xury_err_table_at(i);
        TEST_ASSERT_NOT_NULL(info);
        TEST_ASSERT_NOT_NULL(info->symbol);
        TEST_ASSERT_NOT_NULL(info->tag);
        TEST_ASSERT_NOT_NULL(info->message);
        TEST_ASSERT(info->symbol[0] != '\0');
        TEST_ASSERT(info->tag[0] != '\0');
        TEST_ASSERT(info->message[0] != '\0');
    }
}

static void test_table_contains_ok_first(void)
{
    const xury_err_info_t *info = xury_err_table_at(0);
    TEST_ASSERT_NOT_NULL(info);
    TEST_ASSERT_EQ(info->code, XURY_OK);
    TEST_ASSERT_STREQ(info->symbol, "XURY_OK");
}

static void test_table_symbols_unique(void)
{
    /*
     * Every symbol must be unique. This catches accidental copy-paste
     * when adding entries.
     */
    size_t n = xury_err_table_size();
    for (size_t i = 0; i < n; i++) {
        const xury_err_info_t *a = xury_err_table_at(i);
        for (size_t j = i + 1u; j < n; j++) {
            const xury_err_info_t *b = xury_err_table_at(j);
            TEST_ASSERT(strcmp(a->symbol, b->symbol) != 0);
        }
    }
}

static void test_table_codes_unique(void)
{
    /* Every code must appear exactly once. */
    size_t n = xury_err_table_size();
    for (size_t i = 0; i < n; i++) {
        const xury_err_info_t *a = xury_err_table_at(i);
        for (size_t j = i + 1u; j < n; j++) {
            const xury_err_info_t *b = xury_err_table_at(j);
            TEST_ASSERT_NE(a->code, b->code);
        }
    }
}

static void test_by_symbol(void)
{
    TEST_ASSERT_NOT_NULL(xury_err_by_symbol("XURY_OK"));
    TEST_ASSERT_NOT_NULL(xury_err_by_symbol("XURY_ERR_TIMEOUT"));
    TEST_ASSERT_NOT_NULL(xury_err_by_symbol("XURY_ERR_PUNCH_FAIL"));
    TEST_ASSERT_NULL(xury_err_by_symbol(NULL));
    TEST_ASSERT_NULL(xury_err_by_symbol("NOT_A_REAL_SYMBOL"));
}

static void test_by_symbol_returns_same_as_info(void)
{
    const xury_err_info_t *a = xury_err_by_symbol("XURY_ERR_TIMEOUT");
    const xury_err_info_t *b = xury_err_info(XURY_ERR_TIMEOUT);
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_NOT_NULL(b);
    TEST_ASSERT(a == b);
}

/*
 * ============================================================================
 * INTERNAL — INFO
 * ============================================================================
 */

static void test_info_known(void)
{
    const xury_err_info_t *info = xury_err_info(XURY_ERR_TIMEOUT);
    TEST_ASSERT_NOT_NULL(info);
    TEST_ASSERT_EQ(info->code, XURY_ERR_TIMEOUT);
    TEST_ASSERT_STREQ(info->symbol, "XURY_ERR_TIMEOUT");
    TEST_ASSERT_STREQ(info->tag, "timeout");
    TEST_ASSERT_STREQ(info->message, "operation timed out");
    TEST_ASSERT_EQ(info->class_id, XURY_ERR_CLASS_NETWORK);
    TEST_ASSERT(info->retryable);
    TEST_ASSERT(!info->fatal);
}

static void test_info_unknown(void)
{
    const xury_err_info_t *info = xury_err_info((xury_err_t)-9999);
    TEST_ASSERT_NULL(info);
}

static void test_not_calibrated_exists(void)
{
    const xury_err_info_t *info = xury_err_info(XURY_ERR_NOT_CALIBRATED);
    TEST_ASSERT_NOT_NULL(info);
    TEST_ASSERT_EQ(info->code, XURY_ERR_NOT_CALIBRATED);
    TEST_ASSERT_STREQ(info->symbol, "XURY_ERR_NOT_CALIBRATED");
    TEST_ASSERT_STREQ(info->tag, "not_calibrated");
    TEST_ASSERT_STREQ(info->message, "requires empirical calibration");
    TEST_ASSERT_EQ(info->class_id, XURY_ERR_CLASS_RESEARCH);
    TEST_ASSERT(!info->retryable);
    TEST_ASSERT(!info->fatal);
    TEST_ASSERT(!xury_err_is_benign(XURY_ERR_NOT_CALIBRATED));
}

static void test_not_calibrated_strerror(void)
{
    const char *s = xury_strerror(XURY_ERR_NOT_CALIBRATED);
    TEST_ASSERT_NOT_NULL(s);
    TEST_ASSERT(s[0] != '\0');
    /* Must not be the generic "unknown error" fallback. */
    TEST_ASSERT(strcmp(s, "unknown error") != 0);
}

static void test_not_calibrated_class(void)
{
    TEST_ASSERT_EQ(xury_err_class(XURY_ERR_NOT_CALIBRATED),
                   XURY_ERR_CLASS_RESEARCH);
    TEST_ASSERT_STREQ(xury_err_class_name(XURY_ERR_CLASS_RESEARCH),
                      "research");
}

static void test_research_class_distinct(void)
{
    /*
     * RESEARCH must be a distinct class value from every other class.
     * This catches accidental aliasing when adding a new class.
     */
    TEST_ASSERT(XURY_ERR_CLASS_RESEARCH != XURY_ERR_CLASS_OK);
    TEST_ASSERT(XURY_ERR_CLASS_RESEARCH != XURY_ERR_CLASS_GENERAL);
    TEST_ASSERT(XURY_ERR_CLASS_RESEARCH != XURY_ERR_CLASS_ARGUMENT);
    TEST_ASSERT(XURY_ERR_CLASS_RESEARCH != XURY_ERR_CLASS_MEMORY);
    TEST_ASSERT(XURY_ERR_CLASS_RESEARCH != XURY_ERR_CLASS_NETWORK);
    TEST_ASSERT(XURY_ERR_CLASS_RESEARCH != XURY_ERR_CLASS_NAT);
    TEST_ASSERT(XURY_ERR_CLASS_RESEARCH != XURY_ERR_CLASS_CGNAT);
    TEST_ASSERT(XURY_ERR_CLASS_RESEARCH != XURY_ERR_CLASS_PEER);
    TEST_ASSERT(XURY_ERR_CLASS_RESEARCH != XURY_ERR_CLASS_PLATFORM);
    TEST_ASSERT(XURY_ERR_CLASS_RESEARCH != XURY_ERR_CLASS_STATE);
    TEST_ASSERT(XURY_ERR_CLASS_RESEARCH != XURY_ERR_CLASS_UNKNOWN);
}

 /* ---- continued from part 1/2 ---- */

/*
 * ============================================================================
 * ERRNO MAPPING
 * ============================================================================
 */

static void test_from_errno_zero_is_ok(void)
{
    TEST_ASSERT_EQ(xury_err_from_errno(0), XURY_OK);
}

static void test_from_errno_common(void)
{
    TEST_ASSERT_EQ(xury_err_from_errno(EINVAL), XURY_ERR_INVAL);
    TEST_ASSERT_EQ(xury_err_from_errno(ENOMEM), XURY_ERR_NOMEM);
    TEST_ASSERT_EQ(xury_err_from_errno(ETIMEDOUT), XURY_ERR_TIMEOUT);
    TEST_ASSERT_EQ(xury_err_from_errno(ECONNREFUSED),
                   XURY_ERR_CONNECTION_REFUSED);
    TEST_ASSERT_EQ(xury_err_from_errno(ECONNRESET),
                   XURY_ERR_CONNECTION_RESET);
    TEST_ASSERT_EQ(xury_err_from_errno(EHOSTUNREACH),
                   XURY_ERR_HOST_UNREACHABLE);
    TEST_ASSERT_EQ(xury_err_from_errno(ENETUNREACH),
                   XURY_ERR_NET_UNREACHABLE);
    TEST_ASSERT_EQ(xury_err_from_errno(EADDRINUSE),
                   XURY_ERR_ADDR_IN_USE);
    TEST_ASSERT_EQ(xury_err_from_errno(EADDRNOTAVAIL),
                   XURY_ERR_ADDR_NOT_AVAILABLE);
    TEST_ASSERT_EQ(xury_err_from_errno(EACCES), XURY_ERR_PERMISSION);
    TEST_ASSERT_EQ(xury_err_from_errno(EPERM), XURY_ERR_PERMISSION);
    TEST_ASSERT_EQ(xury_err_from_errno(EAGAIN), XURY_ERR_WOULD_BLOCK);
}

static void test_from_errno_unknown_falls_back_to_io(void)
{
    /* An errno we never map explicitly. Use a large, unlikely value. */
    TEST_ASSERT_EQ(xury_err_from_errno(99999), XURY_ERR_IO);
}

static void test_from_errno_ctx_matches_plain(void)
{
    /* The context variant must return the same value. */
    TEST_ASSERT_EQ(xury_err_from_errno_ctx(EINVAL, "test"),
                   xury_err_from_errno(EINVAL));
    TEST_ASSERT_EQ(xury_err_from_errno_ctx(0, "test"), XURY_OK);
    TEST_ASSERT_EQ(xury_err_from_errno_ctx(EINVAL, NULL),
                   XURY_ERR_INVAL);
}

static void test_to_errno_ok(void)
{
    TEST_ASSERT_EQ(xury_err_to_errno(XURY_OK), 0);
}

static void test_to_errno_common(void)
{
    TEST_ASSERT_EQ(xury_err_to_errno(XURY_ERR_INVAL), EINVAL);
    TEST_ASSERT_EQ(xury_err_to_errno(XURY_ERR_NOMEM), ENOMEM);
    TEST_ASSERT_EQ(xury_err_to_errno(XURY_ERR_TIMEOUT), ETIMEDOUT);
    TEST_ASSERT_EQ(xury_err_to_errno(XURY_ERR_CONNECTION_REFUSED),
                   ECONNREFUSED);
    TEST_ASSERT_EQ(xury_err_to_errno(XURY_ERR_CONNECTION_RESET),
                   ECONNRESET);
    TEST_ASSERT_EQ(xury_err_to_errno(XURY_ERR_ADDR_IN_USE),
                   EADDRINUSE);
    TEST_ASSERT_EQ(xury_err_to_errno(XURY_ERR_PERMISSION), EACCES);
    TEST_ASSERT_EQ(xury_err_to_errno(XURY_ERR_WOULD_BLOCK), EAGAIN);
}

static void test_to_errno_unknown_falls_back_to_eio(void)
{
    /* Anything we do not reverse maps to EIO. */
    TEST_ASSERT_EQ(xury_err_to_errno(XURY_ERR_PUNCH_FAIL), EIO);
    TEST_ASSERT_EQ(xury_err_to_errno((xury_err_t)-9999), EIO);
}

static void test_to_errno_not_calibrated_is_eio(void)
{
    /*
     * NOT_CALIBRATED is not a "function not implemented" condition;
     * it is a pending-experiment condition. The project convention is
     * to map unmapped codes to EIO, and this test pins that choice so
     * a future change cannot silently introduce a different mapping.
     */
    TEST_ASSERT_EQ(xury_err_to_errno(XURY_ERR_NOT_CALIBRATED), EIO);
}

static void test_errno_roundtrip_for_known_pairs(void)
{
    /*
     * For a few pairs that we map both ways, the round-trip must be
     * stable at the xury_err_t level.
     */
    struct pair {
        int        errno_value;
        xury_err_t xury_value;
    } pairs[] = {
        { EINVAL,       XURY_ERR_INVAL },
        { ENOMEM,       XURY_ERR_NOMEM },
        { ETIMEDOUT,    XURY_ERR_TIMEOUT },
        { ECONNREFUSED, XURY_ERR_CONNECTION_REFUSED },
        { EADDRINUSE,   XURY_ERR_ADDR_IN_USE },
        { EAGAIN,       XURY_ERR_WOULD_BLOCK },
    };

    for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
        xury_err_t x = xury_err_from_errno(pairs[i].errno_value);
        TEST_ASSERT_EQ(x, pairs[i].xury_value);

        int e = xury_err_to_errno(pairs[i].xury_value);
        xury_err_t y = xury_err_from_errno(e);
        TEST_ASSERT_EQ(y, pairs[i].xury_value);
    }
}

/*
 * ============================================================================
 * CLASSIFICATION
 * ============================================================================
 */

static void test_is_retryable(void)
{
    TEST_ASSERT(xury_err_is_retryable(XURY_ERR_TIMEOUT));
    TEST_ASSERT(xury_err_is_retryable(XURY_ERR_WOULD_BLOCK));
    TEST_ASSERT(xury_err_is_retryable(XURY_ERR_BUSY));
    TEST_ASSERT(xury_err_is_retryable(XURY_ERR_ADDR_IN_USE));
    TEST_ASSERT(xury_err_is_retryable(XURY_ERR_NOMEM));

    TEST_ASSERT(!xury_err_is_retryable(XURY_OK));
    TEST_ASSERT(!xury_err_is_retryable(XURY_ERR_INVAL));
    TEST_ASSERT(!xury_err_is_retryable(XURY_ERR_NULL_PTR));
    TEST_ASSERT(!xury_err_is_retryable((xury_err_t)-9999));
}

static void test_is_fatal(void)
{
    TEST_ASSERT(xury_err_is_fatal(XURY_ERR_INTERNAL));
    TEST_ASSERT(xury_err_is_fatal(XURY_ERR_PLATFORM_INIT));
    TEST_ASSERT(xury_err_is_fatal(XURY_ERR_PLATFORM_NOT_READY));
    TEST_ASSERT(xury_err_is_fatal(XURY_ERR_PLATFORM_UNSUPPORTED));

    TEST_ASSERT(!xury_err_is_fatal(XURY_OK));
    TEST_ASSERT(!xury_err_is_fatal(XURY_ERR_TIMEOUT));
    TEST_ASSERT(!xury_err_is_fatal(XURY_ERR_PUNCH_FAIL));
    TEST_ASSERT(!xury_err_is_fatal((xury_err_t)-9999));
}

static void test_is_benign(void)
{
    TEST_ASSERT(xury_err_is_benign(XURY_ERR_TIMEOUT));
    TEST_ASSERT(xury_err_is_benign(XURY_ERR_PUNCH_FAIL));
    TEST_ASSERT(xury_err_is_benign(XURY_ERR_PREDICT_FAIL));
    TEST_ASSERT(xury_err_is_benign(XURY_ERR_NO_MAPPING));
    TEST_ASSERT(xury_err_is_benign(XURY_ERR_CANCELLED));
    TEST_ASSERT(xury_err_is_benign(XURY_ERR_WOULD_BLOCK));

    TEST_ASSERT(!xury_err_is_benign(XURY_OK));
    TEST_ASSERT(!xury_err_is_benign(XURY_ERR_INVAL));
    TEST_ASSERT(!xury_err_is_benign(XURY_ERR_NOMEM));
    TEST_ASSERT(!xury_err_is_benign(XURY_ERR_INTERNAL));
    TEST_ASSERT(!xury_err_is_benign(XURY_ERR_NOT_CALIBRATED));
}

static void test_classification_mutually_consistent(void)
{
    /*
     * OK is never retryable, never fatal, never benign.
     * Fatal errors are not retryable and not benign.
     */
    TEST_ASSERT(!xury_err_is_retryable(XURY_OK));
    TEST_ASSERT(!xury_err_is_fatal(XURY_OK));
    TEST_ASSERT(!xury_err_is_benign(XURY_OK));

    TEST_ASSERT(!xury_err_is_retryable(XURY_ERR_INTERNAL));
    TEST_ASSERT(xury_err_is_fatal(XURY_ERR_INTERNAL));
    TEST_ASSERT(!xury_err_is_benign(XURY_ERR_INTERNAL));

    /* TIMEOUT is retryable and benign, but not fatal. */
    TEST_ASSERT(xury_err_is_retryable(XURY_ERR_TIMEOUT));
    TEST_ASSERT(!xury_err_is_fatal(XURY_ERR_TIMEOUT));
    TEST_ASSERT(xury_err_is_benign(XURY_ERR_TIMEOUT));

    /* NOT_CALIBRATED is none of the three. */
    TEST_ASSERT(!xury_err_is_retryable(XURY_ERR_NOT_CALIBRATED));
    TEST_ASSERT(!xury_err_is_fatal(XURY_ERR_NOT_CALIBRATED));
    TEST_ASSERT(!xury_err_is_benign(XURY_ERR_NOT_CALIBRATED));
}

/*
 * ============================================================================
 * LAST ERRNO (THREAD-LOCAL)
 * ============================================================================
 */

static void test_last_errno_starts_clear(void)
{
    xury_err_clear_last_errno();
    TEST_ASSERT_EQ(xury_err_get_last_errno(), 0);
}

static void test_last_errno_set_get(void)
{
    xury_err_set_last_errno(13);   /* EACCES */
    TEST_ASSERT_EQ(xury_err_get_last_errno(), 13);

    xury_err_clear_last_errno();
    TEST_ASSERT_EQ(xury_err_get_last_errno(), 0);
}

static void test_last_errno_overwrites(void)
{
    xury_err_set_last_errno(1);
    xury_err_set_last_errno(2);
    TEST_ASSERT_EQ(xury_err_get_last_errno(), 2);
    xury_err_clear_last_errno();
}

/*
 * ============================================================================
 * CONTEXT STACK (THREAD-LOCAL)
 * ============================================================================
 */

static void test_context_starts_empty(void)
{
    xury_err_clear_context();
    TEST_ASSERT_EQ(xury_err_context_depth(), 0u);
    TEST_ASSERT_NULL(xury_err_context_at(0));
}

static void test_context_push_pop(void)
{
    xury_err_clear_context();

    xury_err_push_context("scan");
    TEST_ASSERT_EQ(xury_err_context_depth(), 1u);
    TEST_ASSERT_STREQ(xury_err_context_at(0), "scan");

    xury_err_push_context("sensing");
    TEST_ASSERT_EQ(xury_err_context_depth(), 2u);
    TEST_ASSERT_STREQ(xury_err_context_at(0), "scan");
    TEST_ASSERT_STREQ(xury_err_context_at(1), "sensing");

    xury_err_pop_context();
    TEST_ASSERT_EQ(xury_err_context_depth(), 1u);
    TEST_ASSERT_STREQ(xury_err_context_at(0), "scan");

    xury_err_pop_context();
    TEST_ASSERT_EQ(xury_err_context_depth(), 0u);

    /* Pop on empty must not crash. */
    xury_err_pop_context();
    TEST_ASSERT_EQ(xury_err_context_depth(), 0u);
}

static void test_context_push_null_is_noop(void)
{
    xury_err_clear_context();
    xury_err_push_context(NULL);
    TEST_ASSERT_EQ(xury_err_context_depth(), 0u);
}

static void test_context_push_truncates_label(void)
{
    xury_err_clear_context();

    /* A label longer than the buffer. */
    char big[XURY_ERR_CONTEXT_MAX_LEN * 4];
    for (size_t i = 0; i < sizeof(big) - 1u; i++) {
        big[i] = 'x';
    }
    big[sizeof(big) - 1u] = '\0';

    xury_err_push_context(big);

    const char *stored = xury_err_context_at(0);
    TEST_ASSERT_NOT_NULL(stored);
    size_t len = strlen(stored);
    TEST_ASSERT(len < XURY_ERR_CONTEXT_MAX_LEN);
    TEST_ASSERT(len > 0u);
}

static void test_context_push_bounded(void)
{
    xury_err_clear_context();

    /*
     * Push more than MAX_DEPTH. The depth must stay bounded and the
     * oldest entries must be dropped.
     */
    for (int i = 0; i < (int)XURY_ERR_CONTEXT_MAX_DEPTH + 4; i++) {
        char label[16];
        snprintf(label, sizeof(label), "L%d", i);
        xury_err_push_context(label);
    }

    TEST_ASSERT_EQ(xury_err_context_depth(), XURY_ERR_CONTEXT_MAX_DEPTH);

    /* The most recent label must be present. */
    const char *last = xury_err_context_at(XURY_ERR_CONTEXT_MAX_DEPTH - 1u);
    TEST_ASSERT_NOT_NULL(last);

    xury_err_clear_context();
}

static void test_context_format_empty(void)
{
    xury_err_clear_context();
    char buf[64];
    size_t n = xury_err_context_format(buf, sizeof(buf));
    TEST_ASSERT_EQ(n, 0u);
    TEST_ASSERT_STREQ(buf, "");
}

static void test_context_format_chain(void)
{
    xury_err_clear_context();

    xury_err_push_context("scan");
    xury_err_push_context("sensing");
    xury_err_push_context("getifaddrs");

    char buf[128];
    size_t n = xury_err_context_format(buf, sizeof(buf));

    TEST_ASSERT_STREQ(buf, "scan -> sensing -> getifaddrs");
    TEST_ASSERT_EQ(n, strlen(buf));

    xury_err_clear_context();
}

static void test_context_format_truncation(void)
{
    xury_err_clear_context();

    xury_err_push_context("aaaa");
    xury_err_push_context("bbbb");
    xury_err_push_context("cccc");

    char buf[8];
    size_t need = xury_err_context_format(buf, sizeof(buf));

    /* need is the would-be length, which is longer than the buffer. */
    TEST_ASSERT(need >= sizeof(buf));
    /* Buffer must be NUL-terminated within its bounds. */
    TEST_ASSERT_EQ(buf[sizeof(buf) - 1u], '\0');
}

static void test_context_at_out_of_range(void)
{
    xury_err_clear_context();
    xury_err_push_context("one");
    TEST_ASSERT_NULL(xury_err_context_at(1u));
    TEST_ASSERT_NULL(xury_err_context_at(100u));
    xury_err_clear_context();
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    /* Public strings */
    TEST_RUN(test_strerror_ok);
    TEST_RUN(test_strerror_timeout);
    TEST_RUN(test_strerror_never_null);
    TEST_RUN(test_err_tag);
    TEST_RUN(test_err_is_ok_inline);
    TEST_RUN(test_err_is_error_inline);

    /* Public classes */
    TEST_RUN(test_err_class);
    TEST_RUN(test_err_class_name);

    /* Internal table */
    TEST_RUN(test_table_size_positive);
    TEST_RUN(test_table_at_out_of_range);
    TEST_RUN(test_table_at_valid);
    TEST_RUN(test_table_contains_ok_first);
    TEST_RUN(test_table_symbols_unique);
    TEST_RUN(test_table_codes_unique);
    TEST_RUN(test_by_symbol);
    TEST_RUN(test_by_symbol_returns_same_as_info);

    /* Internal info */
    TEST_RUN(test_info_known);
    TEST_RUN(test_info_unknown);
    TEST_RUN(test_not_calibrated_exists);
    TEST_RUN(test_not_calibrated_strerror);
    TEST_RUN(test_not_calibrated_class);
    TEST_RUN(test_research_class_distinct);

    /* errno mapping */
    TEST_RUN(test_from_errno_zero_is_ok);
    TEST_RUN(test_from_errno_common);
    TEST_RUN(test_from_errno_unknown_falls_back_to_io);
    TEST_RUN(test_from_errno_ctx_matches_plain);
    TEST_RUN(test_to_errno_ok);
    TEST_RUN(test_to_errno_common);
    TEST_RUN(test_to_errno_unknown_falls_back_to_eio);
    TEST_RUN(test_to_errno_not_calibrated_is_eio);
    TEST_RUN(test_errno_roundtrip_for_known_pairs);

    /* Classification */
    TEST_RUN(test_is_retryable);
    TEST_RUN(test_is_fatal);
    TEST_RUN(test_is_benign);
    TEST_RUN(test_classification_mutually_consistent);

    /* Last errno */
    TEST_RUN(test_last_errno_starts_clear);
    TEST_RUN(test_last_errno_set_get);
    TEST_RUN(test_last_errno_overwrites);

    /* Context stack */
    TEST_RUN(test_context_starts_empty);
    TEST_RUN(test_context_push_pop);
    TEST_RUN(test_context_push_null_is_noop);
    TEST_RUN(test_context_push_truncates_label);
    TEST_RUN(test_context_push_bounded);
    TEST_RUN(test_context_format_empty);
    TEST_RUN(test_context_format_chain);
    TEST_RUN(test_context_format_truncation);
    TEST_RUN(test_context_at_out_of_range);
}

TEST_MAIN()
