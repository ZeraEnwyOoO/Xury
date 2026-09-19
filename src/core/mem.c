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
 * XURY CORE — MEMORY IMPLEMENTATION
 * ============================================================================
 *
 * Real implementation of src/core/internal/mem.h.
 *
 * Every allocation goes through one of the two helper functions below,
 * which pick the user's allocator if present or the system allocator
 * otherwise. Counters are updated on success.
 *
 * No stubs. No fakes. No simulation.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include <xury/types.h>
#include <xury/err.h>

#include "core/internal/mem.h"

/*
 * ============================================================================
 * INTERNAL HELPERS
 * ============================================================================
 */

static void *mem_sys_alloc(size_t n)
{
    return malloc(n);
}

static void *mem_sys_realloc(void *ptr, size_t n)
{
    return realloc(ptr, n);
}

static void mem_sys_free(void *ptr)
{
    free(ptr);
}

/*
 * Resolve the allocation callbacks.
 *
 * If alloc is NULL or any of its callbacks is NULL, the system
 * allocator is used. (Validation elsewhere guarantees all-or-nothing,
 * but we keep this defensive.)
 */
static void mem_resolve(const xury_allocator_t *alloc,
                        void *(**out_alloc)(size_t),
                        void *(**out_realloc)(void *, size_t),
                        void  (**out_free)(void *))
{
    if (alloc != NULL &&
        alloc->malloc_fn  != NULL &&
        alloc->realloc_fn != NULL &&
        alloc->free_fn    != NULL) {
        *out_alloc   = alloc->malloc_fn;
        *out_realloc = alloc->realloc_fn;
        *out_free    = alloc->free_fn;
    } else {
        *out_alloc   = mem_sys_alloc;
        *out_realloc = mem_sys_realloc;
        *out_free    = mem_sys_free;
    }
}

/*
 * ============================================================================
 * GLOBAL STATS
 * ============================================================================
 */

static xury_mem_stats_t g_mem_stats;

/*
 * Track a successful allocation of n bytes.
 */
static void mem_stats_on_alloc(size_t n)
{
    g_mem_stats.alloc_calls++;
    g_mem_stats.live_bytes += (uint64_t)n;
    if (g_mem_stats.live_bytes > g_mem_stats.peak_bytes) {
        g_mem_stats.peak_bytes = g_mem_stats.live_bytes;
    }
}

/*
 * ============================================================================
 * PUBLIC — ALLOCATION
 * ============================================================================
 */

void *xury_mem_alloc(const xury_allocator_t *alloc, size_t n)
{
    if (n == 0) {
        return NULL;
    }

    void *(*fn)(size_t);
    void *(*rf)(void *, size_t);
    void  (*ff)(void *);
    mem_resolve(alloc, &fn, &rf, &ff);
    (void)rf;
    (void)ff;

    void *p = fn(n);
    if (p != NULL) {
        mem_stats_on_alloc(n);
    }
    return p;
}

void *xury_mem_alloc_zero(const xury_allocator_t *alloc, size_t n)
{
    void *p = xury_mem_alloc(alloc, n);
    if (p != NULL) {
        memset(p, 0, n);
    }
    return p;
}

void *xury_mem_realloc(const xury_allocator_t *alloc, void *ptr, size_t n)
{
    if (ptr == NULL) {
        return xury_mem_alloc(alloc, n);
    }
    if (n == 0) {
        xury_mem_free(alloc, ptr);
        return NULL;
    }

    void *(*fn)(size_t);
    void *(*rf)(void *, size_t);
    void  (*ff)(void *);
    mem_resolve(alloc, &fn, &rf, &ff);
    (void)fn;
    (void)ff;

    void *p = rf(ptr, n);
    if (p != NULL) {
        g_mem_stats.realloc_calls++;
        /* We do not know the old size here; leave live_bytes as-is. */
    }
    return p;
}

void xury_mem_free(const xury_allocator_t *alloc, void *ptr)
{
    if (ptr == NULL) {
        g_mem_stats.free_calls++;
        return;
    }

    void *(*fn)(size_t);
    void *(*rf)(void *, size_t);
    void  (*ff)(void *);
    mem_resolve(alloc, &fn, &rf, &ff);
    (void)fn;
    (void)rf;

    ff(ptr);
    g_mem_stats.free_calls++;
    /* Cannot adjust live_bytes without the original size. */
}

/*
 * ============================================================================
 * PUBLIC — SIZE ARITHMETIC
 * ============================================================================
 */

xury_err_t xury_mem_size_mul(size_t a, size_t b, size_t *out)
{
    if (out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (a != 0 && b > (SIZE_MAX / a)) {
        return XURY_ERR_OVERFLOW;
    }
    *out = a * b;
    return XURY_OK;
}

xury_err_t xury_mem_size_add(size_t a, size_t b, size_t *out)
{
    if (out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (b > (SIZE_MAX - a)) {
        return XURY_ERR_OVERFLOW;
    }
    *out = a + b;
    return XURY_OK;
}

xury_err_t xury_mem_size_add_mul(size_t a, size_t b, size_t c, size_t *out)
{
    if (out == NULL) {
        return XURY_ERR_INVAL;
    }

    size_t prod;
    xury_err_t rc = xury_mem_size_mul(b, c, &prod);
    if (rc != XURY_OK) {
        return rc;
    }
    return xury_mem_size_add(a, prod, out);
}

/*
 * ============================================================================
 * PUBLIC — ARRAY ALLOCATION
 * ============================================================================
 */

void *xury_mem_alloc_array(const xury_allocator_t *alloc,
                           size_t count,
                           size_t elem_size,
                           xury_err_t *out_err)
{
    if (out_err != NULL) {
        *out_err = XURY_OK;
    }

    size_t total;
    xury_err_t rc = xury_mem_size_mul(count, elem_size, &total);
    if (rc != XURY_OK) {
        if (out_err != NULL) {
            *out_err = rc;
        }
        return NULL;
    }

    void *p = xury_mem_alloc(alloc, total);
    if (p == NULL && total > 0) {
        if (out_err != NULL) {
            *out_err = XURY_ERR_NOMEM;
        }
    }
    return p;
}

void *xury_mem_alloc_array_zero(const xury_allocator_t *alloc,
                                size_t count,
                                size_t elem_size,
                                xury_err_t *out_err)
{
    if (out_err != NULL) {
        *out_err = XURY_OK;
    }

    size_t total;
    xury_err_t rc = xury_mem_size_mul(count, elem_size, &total);
    if (rc != XURY_OK) {
        if (out_err != NULL) {
            *out_err = rc;
        }
        return NULL;
    }

    void *p = xury_mem_alloc_zero(alloc, total);
    if (p == NULL && total > 0) {
        if (out_err != NULL) {
            *out_err = XURY_ERR_NOMEM;
        }
    }
    return p;
}

/*
 * ============================================================================
 * PUBLIC — BLOCK OPERATIONS
 * ============================================================================
 */

void xury_mem_zero(void *ptr, size_t n)
{
    if (ptr == NULL || n == 0) {
        return;
    }
    memset(ptr, 0, n);
}

void xury_mem_copy(void *dst, const void *src, size_t n)
{
    if (dst == NULL || src == NULL || n == 0) {
        return;
    }
    memcpy(dst, src, n);
}

void xury_mem_move(void *dst, const void *src, size_t n)
{
    if (dst == NULL || src == NULL || n == 0) {
        return;
    }
    memmove(dst, src, n);
}

int xury_mem_compare(const void *a, const void *b, size_t n)
{
    if (n == 0) {
        return 0;
    }
    if (a == NULL && b == NULL) {
        return 0;
    }
    if (a == NULL) {
        return -1;
    }
    if (b == NULL) {
        return 1;
    }
    return memcmp(a, b, n);
}

bool xury_mem_is_zero(const void *ptr, size_t n)
{
    if (n == 0) {
        return true;
    }
    if (ptr == NULL) {
        return false;
    }

    const uint8_t *p = (const uint8_t *)ptr;
    for (size_t i = 0; i < n; i++) {
        if (p[i] != 0u) {
            return false;
        }
    }
    return true;
}

/*
 * ============================================================================
 * PUBLIC — DIAGNOSTICS
 * ============================================================================
 */

void xury_mem_get_stats(xury_mem_stats_t *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_mem_stats;
}

void xury_mem_reset_stats(void)
{
    g_mem_stats.alloc_calls   = 0u;
    g_mem_stats.realloc_calls = 0u;
    g_mem_stats.free_calls    = 0u;
    g_mem_stats.live_bytes    = 0u;
    g_mem_stats.peak_bytes    = 0u;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
