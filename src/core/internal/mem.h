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

#ifndef XURY_CORE_INTERNAL_MEM_H
#define XURY_CORE_INTERNAL_MEM_H

/*
 * ============================================================================
 * XURY CORE — MEMORY
 * ============================================================================
 *
 * Internal memory primitives.
 *
 * This is the lowest layer of Xury that performs allocation. Every
 * other layer allocates through these functions, never through malloc
 * directly. This gives the engine two properties it needs:
 *
 *   1. A single place to hook a custom allocator (xury_allocator_t).
 *   2. A single place to count allocations for diagnostics and tests.
 *
 * Scope:
 *   - allocate, reallocate, free
 *   - zero, copy, compare, move
 *   - overflow-checked size arithmetic
 *
 * Non-scope:
 *   - pools, arenas, slabs (not needed by Xury)
 *   - alignment beyond the allocator's default (add later if needed)
 *
 * Design rules:
 *   - Every allocator call receives the engine's allocator, if any.
 *     When the allocator is NULL, the system allocator is used.
 *   - All size arithmetic is overflow-checked. On overflow, the
 *     operation fails with XURY_ERR_OVERFLOW instead of wrapping.
 *   - Zero-size allocations return NULL, not a pointer.
 *   - Freeing NULL is a no-op, like the C standard.
 *
 * This header has no dependency on any other Xury header except
 * <xury/types.h> and <xury/err.h>. It must remain so.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/types.h>
#include <xury/err.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * ALLOCATION
 * ============================================================================
 *
 * These are the only allocation entry points in Xury.
 *
 * The allocator parameter is optional: pass NULL to use the system
 * allocator. If non-NULL, all three callbacks must be set (validated
 * by xury_config_validate() at create time).
 */

/*
 * Allocate n bytes.
 *
 * Returns NULL on failure or when n == 0.
 * The returned memory is NOT zeroed.
 */
void *xury_mem_alloc(const xury_allocator_t *alloc, size_t n);

/*
 * Allocate n bytes, zeroed.
 *
 * Returns NULL on failure or when n == 0.
 */
void *xury_mem_alloc_zero(const xury_allocator_t *alloc, size_t n);

/*
 * Resize a previous allocation.
 *
 * - ptr == NULL  -> behaves like xury_mem_alloc(alloc, n)
 * - n == 0       -> frees ptr and returns NULL
 *
 * On failure, the original pointer is unchanged and still valid.
 */
void *xury_mem_realloc(const xury_allocator_t *alloc, void *ptr, size_t n);

/*
 * Free a previous allocation.
 *
 * ptr == NULL is a no-op.
 * Safe to call with the same pointer as the allocator that produced it.
 */
void xury_mem_free(const xury_allocator_t *alloc, void *ptr);

/*
 * ============================================================================
 * SIZE ARITHMETIC
 * ============================================================================
 *
 * Overflow-checked helpers. These never wrap; they report failure.
 *
 * Usage:
 *   size_t total;
 *   if (xury_mem_size_mul(count, elem_size, &total) != XURY_OK) {
 *       return XURY_ERR_OVERFLOW;
 *   }
 */

/*
 * Compute a * b. Returns XURY_ERR_OVERFLOW if the product does not fit
 * in size_t. On success, *out is set.
 */
xury_err_t xury_mem_size_mul(size_t a, size_t b, size_t *out);

/*
 * Compute a + b. Returns XURY_ERR_OVERFLOW if the sum does not fit.
 */
xury_err_t xury_mem_size_add(size_t a, size_t b, size_t *out);

/*
 * Compute a + b * c. Returns XURY_ERR_OVERFLOW on any overflow.
 */
xury_err_t xury_mem_size_add_mul(size_t a, size_t b, size_t c, size_t *out);

/*
 * Allocate an array of count elements, each of size elem_size bytes,
 * with the product checked for overflow. Not zeroed.
 */
void *xury_mem_alloc_array(const xury_allocator_t *alloc,
                           size_t count,
                           size_t elem_size,
                           xury_err_t *out_err);

/*
 * Like xury_mem_alloc_array, but zeroed.
 */
void *xury_mem_alloc_array_zero(const xury_allocator_t *alloc,
                                size_t count,
                                size_t elem_size,
                                xury_err_t *out_err);

/*
 * ============================================================================
 * BLOCK OPERATIONS
 * ============================================================================
 *
 * These mirror <string.h> but are part of the Xury surface so that
 * every layer uses the same names and so that we can later add
 * instrumentation without touching call sites.
 */

/*
 * Zero n bytes at ptr.
 * ptr == NULL is a no-op.
 */
void xury_mem_zero(void *ptr, size_t n);

/*
 * Copy n bytes from src to dst.
 *
 * dst and src must not overlap. Use xury_mem_move() for overlap.
 * dst == NULL or src == NULL or n == 0: no-op.
 */
void xury_mem_copy(void *dst, const void *src, size_t n);

/*
 * Copy n bytes from src to dst, allowing overlap.
 */
void xury_mem_move(void *dst, const void *src, size_t n);

/*
 * Compare n bytes.
 *
 * Returns:
 *   < 0 if a < b
 *   = 0 if a == b
 *   > 0 if a > b
 *
 * n == 0: returns 0, even if pointers are NULL.
 * a == NULL or b == NULL (and n > 0): returns a deterministic non-zero.
 */
int xury_mem_compare(const void *a, const void *b, size_t n);

/*
 * True if the n bytes at ptr are all zero.
 *
 * ptr == NULL and n == 0: returns true.
 * ptr == NULL and n > 0 : returns false.
 */
bool xury_mem_is_zero(const void *ptr, size_t n);

/*
 * ============================================================================
 * DIAGNOSTICS
 * ============================================================================
 *
 * Global allocation counters.
 *
 * These are process-wide, not per engine. They exist for tests and for
 * a debug build that wants to assert "no leaks". They are not exposed
 * to the public API.
 *
 * The counters are monotonic; xury_mem_reset_stats() only makes sense
 * in a test process.
 */

typedef struct {
    uint64_t alloc_calls;    /* successful xury_mem_alloc* calls */
    uint64_t realloc_calls;  /* successful xury_mem_realloc calls */
    uint64_t free_calls;     /* xury_mem_free calls (incl. NULL) */
    uint64_t live_bytes;     /* sum of live allocation sizes */
    uint64_t peak_bytes;     /* high-water mark of live_bytes */
} xury_mem_stats_t;

/*
 * Copy the current counters into *out.
 * out == NULL is a no-op.
 */
void xury_mem_get_stats(xury_mem_stats_t *out);

/*
 * Reset the counters to zero.
 *
 * Intended for test processes only. In a running engine this would
 * corrupt the peak/live bookkeeping.
 */
void xury_mem_reset_stats(void);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY CORE INTERNAL MEMORY HEADER
 * ============================================================================
 */

#endif /* XURY_CORE_INTERNAL_MEM_H */
