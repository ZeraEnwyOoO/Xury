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
 * TESTS — src/core/mem.c
 * ============================================================================
 *
 * Exercise the real memory primitives:
 *
 *   xury_mem_alloc()
 *   xury_mem_alloc_zero()
 *   xury_mem_realloc()
 *   xury_mem_free()
 *
 *   xury_mem_size_mul()
 *   xury_mem_size_add()
 *   xury_mem_size_add_mul()
 *   xury_mem_alloc_array()
 *   xury_mem_alloc_array_zero()
 *
 *   xury_mem_zero()
 *   xury_mem_copy()
 *   xury_mem_move()
 *   xury_mem_compare()
 *   xury_mem_is_zero()
 *
 *   xury_mem_get_stats()
 *   xury_mem_reset_stats()
 *
 * No mocks, no fakes. Every value comes from the library.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "core/internal/mem.h"
#include "tests/test.h"

/*
 * ============================================================================
 * CUSTOM ALLOCATOR FOR TESTING
 * ============================================================================
 *
 * A counting allocator that wraps malloc/realloc/free. It lets us
 * verify that the custom allocator path is actually used.
 */

typedef struct {
    int    alloc_calls;
    int    realloc_calls;
    int    free_calls;
    size_t live_bytes;
} counting_alloc_t;

static counting_alloc_t g_counting;

static void *counting_malloc(size_t n)
{
    g_counting.alloc_calls++;
    g_counting.live_bytes += n;
    return malloc(n);
}

static void *counting_realloc(void *p, size_t n)
{
    g_counting.realloc_calls++;
    return realloc(p, n);
}

static void counting_free(void *p)
{
    g_counting.free_calls++;
    free(p);
}

static xury_allocator_t make_counting_allocator(void)
{
    xury_allocator_t a;
    a.malloc_fn  = counting_malloc;
    a.realloc_fn = counting_realloc;
    a.free_fn    = counting_free;
    return a;
}

static void counting_reset(void)
{
    memset(&g_counting, 0, sizeof(g_counting));
}

/*
 * ============================================================================
 * ALLOCATION — SYSTEM
 * ============================================================================
 */

static void test_alloc_zero_returns_null(void)
{
    void *p = xury_mem_alloc(NULL, 0);
    TEST_ASSERT_NULL(p);
}

static void test_alloc_basic(void)
{
    void *p = xury_mem_alloc(NULL, 64);
    TEST_ASSERT_NOT_NULL(p);
    xury_mem_free(NULL, p);
}

static void test_alloc_zero_fills(void)
{
    uint8_t *p = (uint8_t *)xury_mem_alloc_zero(NULL, 32);
    TEST_ASSERT_NOT_NULL(p);
    for (int i = 0; i < 32; i++) {
        TEST_ASSERT_EQ(p[i], 0u);
    }
    xury_mem_free(NULL, p);
}

static void test_realloc_null_is_alloc(void)
{
    void *p = xury_mem_realloc(NULL, NULL, 64);
    TEST_ASSERT_NOT_NULL(p);
    xury_mem_free(NULL, p);
}

static void test_realloc_zero_frees(void)
{
    void *p = xury_mem_alloc(NULL, 64);
    TEST_ASSERT_NOT_NULL(p);
    void *q = xury_mem_realloc(NULL, p, 0);
    TEST_ASSERT_NULL(q);
}

static void test_free_null_is_noop(void)
{
    xury_mem_free(NULL, NULL);
}

/*
 * ============================================================================
 * ALLOCATION — CUSTOM
 * ============================================================================
 */

static void test_custom_allocator_is_used(void)
{
    counting_reset();
    xury_allocator_t a = make_counting_allocator();

    void *p = xury_mem_alloc(&a, 128);
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQ(g_counting.alloc_calls, 1);

    xury_mem_free(&a, p);
    TEST_ASSERT_EQ(g_counting.free_calls, 1);
}

static void test_custom_allocator_fallback_when_incomplete(void)
{
    counting_reset();

    /* Only malloc set: must fall back to system allocator. */
    xury_allocator_t a;
    memset(&a, 0, sizeof(a));
    a.malloc_fn = counting_malloc;

    void *p = xury_mem_alloc(&a, 64);
    TEST_ASSERT_NOT_NULL(p);
    /* Counting allocator was NOT used. */
    TEST_ASSERT_EQ(g_counting.alloc_calls, 0);

    xury_mem_free(&a, p);
}

/*
 * ============================================================================
 * SIZE ARITHMETIC
 * ============================================================================
 */

static void test_size_mul_ok(void)
{
    size_t out = 0;
    TEST_ASSERT_EQ(xury_mem_size_mul(4, 8, &out), XURY_OK);
    TEST_ASSERT_EQ(out, 32u);
}

static void test_size_mul_zero(void)
{
    size_t out = 1;
    TEST_ASSERT_EQ(xury_mem_size_mul(0, 100, &out), XURY_OK);
    TEST_ASSERT_EQ(out, 0u);
}

static void test_size_mul_overflow(void)
{
    size_t out = 0;
    size_t big = (SIZE_MAX / 2) + 1;
    TEST_ASSERT_EQ(xury_mem_size_mul(big, 2, &out),
                   XURY_ERR_OVERFLOW);
}

static void test_size_mul_null_out(void)
{
    TEST_ASSERT_EQ(xury_mem_size_mul(4, 8, NULL), XURY_ERR_INVAL);
}

static void test_size_add_ok(void)
{
    size_t out = 0;
    TEST_ASSERT_EQ(xury_mem_size_add(10, 20, &out), XURY_OK);
    TEST_ASSERT_EQ(out, 30u);
}

static void test_size_add_overflow(void)
{
    size_t out = 0;
    TEST_ASSERT_EQ(xury_mem_size_add(SIZE_MAX, 1, &out),
                   XURY_ERR_OVERFLOW);
}

static void test_size_add_mul_ok(void)
{
    size_t out = 0;
    TEST_ASSERT_EQ(xury_mem_size_add_mul(10, 4, 8, &out), XURY_OK);
    TEST_ASSERT_EQ(out, 42u);
}

static void test_size_add_mul_overflow_mul(void)
{
    size_t out = 0;
    size_t big = (SIZE_MAX / 2) + 1;
    TEST_ASSERT_EQ(xury_mem_size_add_mul(0, big, 2, &out),
                   XURY_ERR_OVERFLOW);
}

static void test_size_add_mul_overflow_add(void)
{
    size_t out = 0;
    TEST_ASSERT_EQ(xury_mem_size_add_mul(SIZE_MAX, 2, 2, &out),
                   XURY_ERR_OVERFLOW);
}

/*
 * ============================================================================
 * ARRAY ALLOCATION
 * ============================================================================
 */

static void test_alloc_array_ok(void)
{
    xury_err_t err = XURY_OK;
    void *p = xury_mem_alloc_array(NULL, 16, 8, &err);
    TEST_ASSERT_EQ(err, XURY_OK);
    TEST_ASSERT_NOT_NULL(p);
    xury_mem_free(NULL, p);
}

static void test_alloc_array_overflow(void)
{
    xury_err_t err = XURY_OK;
    size_t big = (SIZE_MAX / 2) + 1;
    void *p = xury_mem_alloc_array(NULL, big, 2, &err);
    TEST_ASSERT_EQ(err, XURY_ERR_OVERFLOW);
    TEST_ASSERT_NULL(p);
}

static void test_alloc_array_zero_ok(void)
{
    xury_err_t err = XURY_OK;
    uint8_t *p = (uint8_t *)xury_mem_alloc_array_zero(NULL, 8, 4, &err);
    TEST_ASSERT_EQ(err, XURY_OK);
    TEST_ASSERT_NOT_NULL(p);
    for (int i = 0; i < 32; i++) {
        TEST_ASSERT_EQ(p[i], 0u);
    }
    xury_mem_free(NULL, p);
}

/*
 * ============================================================================
 * BLOCK OPERATIONS
 * ============================================================================
 */

static void test_zero(void)
{
    uint8_t buf[16];
    memset(buf, 0xFF, sizeof(buf));
    xury_mem_zero(buf, sizeof(buf));
    for (int i = 0; i < 16; i++) {
        TEST_ASSERT_EQ(buf[i], 0u);
    }
}

static void test_zero_null_is_noop(void)
{
    xury_mem_zero(NULL, 16);
}

static void test_copy(void)
{
    uint8_t src[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t dst[8] = {0};
    xury_mem_copy(dst, src, sizeof(src));
    TEST_ASSERT_EQ(memcmp(dst, src, sizeof(src)), 0);
}

static void test_copy_null_is_noop(void)
{
    uint8_t buf[8] = {0};
    xury_mem_copy(NULL, buf, 8);
    xury_mem_copy(buf, NULL, 8);
}

static void test_move_overlap_forward(void)
{
    uint8_t buf[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    /* Move [0..3] to [2..5] with overlap. */
    xury_mem_move(buf + 2, buf, 4);
    TEST_ASSERT_EQ(buf[2], 1u);
    TEST_ASSERT_EQ(buf[3], 2u);
    TEST_ASSERT_EQ(buf[4], 3u);
    TEST_ASSERT_EQ(buf[5], 4u);
}

static void test_move_overlap_backward(void)
{
    uint8_t buf[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    /* Move [2..5] to [0..3] with overlap. */
    xury_mem_move(buf, buf + 2, 4);
    TEST_ASSERT_EQ(buf[0], 3u);
    TEST_ASSERT_EQ(buf[1], 4u);
    TEST_ASSERT_EQ(buf[2], 5u);
    TEST_ASSERT_EQ(buf[3], 6u);
}

static void test_compare(void)
{
    uint8_t a[4] = {1, 2, 3, 4};
    uint8_t b[4] = {1, 2, 3, 4};
    uint8_t c[4] = {1, 2, 3, 5};

    TEST_ASSERT_EQ(xury_mem_compare(a, b, 4), 0);
    TEST_ASSERT(xury_mem_compare(a, c, 4) < 0);
    TEST_ASSERT(xury_mem_compare(c, a, 4) > 0);
}

static void test_compare_zero_len(void)
{
    TEST_ASSERT_EQ(xury_mem_compare(NULL, NULL, 0), 0);
    uint8_t a[1] = {1};
    TEST_ASSERT_EQ(xury_mem_compare(&a, NULL, 0), 0);
}

static void test_compare_null(void)
{
    uint8_t a[1] = {1};
    TEST_ASSERT(xury_mem_compare(NULL, a, 1) < 0);
    TEST_ASSERT(xury_mem_compare(a, NULL, 1) > 0);
    TEST_ASSERT_EQ(xury_mem_compare(NULL, NULL, 1), 0);
}

static void test_is_zero(void)
{
    uint8_t a[4] = {0, 0, 0, 0};
    uint8_t b[4] = {0, 0, 0, 1};

    TEST_ASSERT(xury_mem_is_zero(a, 4));
    TEST_ASSERT(!xury_mem_is_zero(b, 4));
    TEST_ASSERT(xury_mem_is_zero(NULL, 0));
    TEST_ASSERT(!xury_mem_is_zero(NULL, 4));
}

/*
 * ============================================================================
 * DIAGNOSTICS
 * ============================================================================
 */

static void test_stats_reset(void)
{
    xury_mem_reset_stats();
    xury_mem_stats_t s;
    xury_mem_get_stats(&s);
    TEST_ASSERT_EQ(s.alloc_calls, 0u);
    TEST_ASSERT_EQ(s.realloc_calls, 0u);
    TEST_ASSERT_EQ(s.free_calls, 0u);
    TEST_ASSERT_EQ(s.live_bytes, 0u);
    TEST_ASSERT_EQ(s.peak_bytes, 0u);
}

static void test_stats_alloc_increments(void)
{
    xury_mem_reset_stats();
    void *p = xury_mem_alloc(NULL, 128);
    TEST_ASSERT_NOT_NULL(p);

    xury_mem_stats_t s;
    xury_mem_get_stats(&s);
    TEST_ASSERT_EQ(s.alloc_calls, 1u);
    TEST_ASSERT(s.live_bytes >= 128u);
    TEST_ASSERT(s.peak_bytes >= 128u);

    xury_mem_free(NULL, p);
}

static void test_stats_get_null_is_noop(void)
{
    xury_mem_get_stats(NULL);
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    /* Allocation — system */
    TEST_RUN(test_alloc_zero_returns_null);
    TEST_RUN(test_alloc_basic);
    TEST_RUN(test_alloc_zero_fills);
    TEST_RUN(test_realloc_null_is_alloc);
    TEST_RUN(test_realloc_zero_frees);
    TEST_RUN(test_free_null_is_noop);

    /* Allocation — custom */
    TEST_RUN(test_custom_allocator_is_used);
    TEST_RUN(test_custom_allocator_fallback_when_incomplete);

    /* Size arithmetic */
    TEST_RUN(test_size_mul_ok);
    TEST_RUN(test_size_mul_zero);
    TEST_RUN(test_size_mul_overflow);
    TEST_RUN(test_size_mul_null_out);
    TEST_RUN(test_size_add_ok);
    TEST_RUN(test_size_add_overflow);
    TEST_RUN(test_size_add_mul_ok);
    TEST_RUN(test_size_add_mul_overflow_mul);
    TEST_RUN(test_size_add_mul_overflow_add);

    /* Array allocation */
    TEST_RUN(test_alloc_array_ok);
    TEST_RUN(test_alloc_array_overflow);
    TEST_RUN(test_alloc_array_zero_ok);

    /* Block ops */
    TEST_RUN(test_zero);
    TEST_RUN(test_zero_null_is_noop);
    TEST_RUN(test_copy);
    TEST_RUN(test_copy_null_is_noop);
    TEST_RUN(test_move_overlap_forward);
    TEST_RUN(test_move_overlap_backward);
    TEST_RUN(test_compare);
    TEST_RUN(test_compare_zero_len);
    TEST_RUN(test_compare_null);
    TEST_RUN(test_is_zero);

    /* Diagnostics */
    TEST_RUN(test_stats_reset);
    TEST_RUN(test_stats_alloc_increments);
    TEST_RUN(test_stats_get_null_is_noop);
}

TEST_MAIN()
