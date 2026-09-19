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
 * XURY CORE — RANDOM IMPLEMENTATION
 * ============================================================================
 *
 * Real implementation of src/core/internal/rand.h.
 *
 * Two sources:
 *
 *   Secure:    forwarded to the platform layer (Phase D). Until then
 *              the secure functions return XURY_ERR_NOT_IMPLEMENTED.
 *              This is intentional: Xury must never silently swap in
 *              weak randomness for strong.
 *
 *   Fast:      a small xorshift64* generator, one per thread, seeded
 *              from the secure source when available.
 *
 * No allocation. No locks (fast state is thread-local).
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/types.h>
#include <xury/err.h>

#include "core/internal/rand.h"

/*
 * ----------------------------------------------------------------------------
 * Platform hook (provided by Phase D).
 * ----------------------------------------------------------------------------
 * Declared here so this file links cleanly before Phase D exists.
 * Phase D will provide the definition. Until then the weak-symbol
 * trick below makes the linker accept it and the secure functions
 * return XURY_ERR_NOT_IMPLEMENTED at runtime.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
xury_err_t xury_platform_rand_secure(void *buf, size_t n);
#endif

/*
 * ============================================================================
 * MIXER — SplitMix64 finalizer
 * ============================================================================
 *
 * A well-known 64-bit mixing function. Not cryptographic; used to
 * expand a seed and to spread low-entropy inputs.
 */

uint64_t xury_rand_mix64(uint64_t v)
{
    v ^= v >> 30;
    v *= 0xBF58476D1CE4E5B9ull;
    v ^= v >> 27;
    v *= 0x94D049BB133111EBull;
    v ^= v >> 31;
    return v;
}

/*
 * ============================================================================
 * FAST GENERATOR — xorshift64*
 * ============================================================================
 *
 * State is thread-local. Seed must be non-zero; we substitute a fixed
 * non-zero constant if the caller passes 0.
 *
 * The generator is seeded lazily on first use so that a thread that
 * never calls a rand function never touches the state.
 */

static _Thread_local uint64_t g_fast_state = 0u;
static _Thread_local bool     g_fast_seeded = false;

/*
 * Produce the next 64-bit value. Assumes state is already non-zero.
 */
static uint64_t fast_next_u64(void)
{
    uint64_t x = g_fast_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    g_fast_state = x;
    return x * 0x2545F4914F6CDD1Dull;
}

/*
 * Low-quality fallback seed. Only used when the secure source is not
 * available. Mixes the address of a stack variable with a constant
 * so the same fallback on two runs is unlikely to collide by luck.
 */
static uint64_t fallback_seed(void)
{
    uintptr_t here = (uintptr_t)&g_fast_state;
    uint64_t  v    = (uint64_t)here;
    return xury_rand_mix64(v ^ 0x9E3779B97F4A7C15ull);
}

void xury_rand_fast_seed(uint64_t seed)
{
    if (seed == 0u) {
        seed = 0x9E3779B97F4A7C15ull;
    }
    /* Mix once so the first output is not the seed itself. */
    g_fast_state  = xury_rand_mix64(seed);
    if (g_fast_state == 0u) {
        g_fast_state = 0x9E3779B97F4A7C15ull;
    }
    g_fast_seeded = true;
}

xury_err_t xury_rand_fast_seed_secure(void)
{
    uint64_t seed = 0u;

    xury_err_t rc = xury_rand_secure_u64(&seed);
    if (rc == XURY_OK && seed != 0u) {
        xury_rand_fast_seed(seed);
        return XURY_OK;
    }

    /*
     * Secure source not available: use the documented fallback.
     * Fast randomness is not security-sensitive, so this is safe.
     */
    xury_rand_fast_seed(fallback_seed());
    return rc;   /* propagate the secure error to the caller */
}

/*
 * Lazily seed on first use so callers do not have to remember.
 */
static void fast_ensure_seeded(void)
{
    if (!g_fast_seeded) {
        (void)xury_rand_fast_seed_secure();
    }
}

uint64_t xury_rand_fast_u64(void)
{
    fast_ensure_seeded();
    return fast_next_u64();
}

uint32_t xury_rand_fast_u32(void)
{
    return (uint32_t)(xury_rand_fast_u64() >> 32);
}

/*
 * Uniform value in [0, bound) with rejection sampling to avoid
 * modulo bias.
 */
uint32_t xury_rand_fast_below(uint32_t bound)
{
    if (bound == 0u) {
        return 0u;
    }

    /*
     * Largest multiple of bound that fits in uint32.
     * Reject values >= limit to keep the distribution uniform.
     */
    uint32_t limit = 0xFFFFFFFFu - (0xFFFFFFFFu % bound);

    for (;;) {
        uint32_t v = xury_rand_fast_u32();
        if (v < limit) {
            return v % bound;
        }
    }
}

void xury_rand_fast_bytes(void *buf, size_t n)
{
    if (buf == NULL || n == 0u) {
        return;
    }
    uint8_t *p = (uint8_t *)buf;
    size_t   i = 0u;
    while (i < n) {
        uint64_t v = fast_next_u64();
        for (int b = 0; b < 8 && i < n; b++) {
            p[i++] = (uint8_t)(v & 0xFFu);
            v >>= 8;
        }
    }
}

/* ---- continued from part 1/2 ---- */

/*
 * ============================================================================
 * SECURE RANDOM — DISPATCH TO PLATFORM
 * ============================================================================
 *
 * The secure source is provided by the platform layer (Phase D).
 *
 * Until Phase D lands, the platform symbol is a weak reference and
 * the wrapper returns XURY_ERR_NOT_IMPLEMENTED. This is deliberate:
 * Xury must never silently substitute weak randomness for strong.
 *
 * Once Phase D provides a real xury_platform_rand_secure(), the same
 * wrapper will use it with no change here.
 */

/*
 * If the platform hook is not linked, calling it would be undefined
 * behavior. Guard on its presence.
 */
#if defined(__GNUC__) || defined(__clang__)
static bool platform_rand_present(void)
{
    return xury_platform_rand_secure != NULL;
}
#else
static bool platform_rand_present(void)
{
    /* Non-GNU toolchains: assume the symbol is provided at link time. */
    return true;
}
#endif

xury_err_t xury_rand_secure(void *buf, size_t n)
{
    if (n == 0u) {
        return XURY_OK;
    }
    if (buf == NULL) {
        return XURY_ERR_INVAL;
    }

#if defined(__GNUC__) || defined(__clang__)
    if (!platform_rand_present()) {
        return XURY_ERR_NOT_IMPLEMENTED;
    }
#endif

    /*
     * Delegate to the platform implementation. Phase D guarantees:
     *   - all n bytes are written on success
     *   - no partial fills
     *   - thread-safe
     */
    extern xury_err_t xury_platform_rand_secure(void *, size_t);
    return xury_platform_rand_secure(buf, n);
}

xury_err_t xury_rand_secure_u32(uint32_t *out)
{
    if (out == NULL) {
        return XURY_ERR_INVAL;
    }
    uint32_t v = 0u;
    xury_err_t rc = xury_rand_secure(&v, sizeof(v));
    if (rc != XURY_OK) {
        return rc;
    }
    *out = v;
    return XURY_OK;
}

xury_err_t xury_rand_secure_u64(uint64_t *out)
{
    if (out == NULL) {
        return XURY_ERR_INVAL;
    }
    uint64_t v = 0u;
    xury_err_t rc = xury_rand_secure(&v, sizeof(v));
    if (rc != XURY_OK) {
        return rc;
    }
    *out = v;
    return XURY_OK;
}

/*
 * Uniform value in [0, bound) using the secure source and rejection
 * sampling to avoid modulo bias.
 *
 * Bounds are small in every Xury use (ports, peer index). We cap the
 * number of retries so a broken platform RNG cannot loop forever.
 */
#define XURY_RAND_REJECT_LIMIT 64

xury_err_t xury_rand_secure_below(uint32_t bound, uint32_t *out)
{
    if (out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (bound == 0u) {
        return XURY_ERR_INVAL;
    }

    /*
     * Largest multiple of bound that fits in uint32. Values at or
     * above this limit are rejected so the remaining range is an
     * exact multiple of bound and v % bound is uniform.
     */
    uint32_t limit = 0xFFFFFFFFu - (0xFFFFFFFFu % bound);

    for (int attempt = 0; attempt < XURY_RAND_REJECT_LIMIT; attempt++) {
        uint32_t v = 0u;
        xury_err_t rc = xury_rand_secure_u32(&v);
        if (rc != XURY_OK) {
            return rc;
        }
        if (v < limit) {
            *out = v % bound;
            return XURY_OK;
        }
    }

    /*
     * 64 consecutive rejections means the platform source is not
     * behaving like a uniform RNG. Report it rather than loop.
     */
    return XURY_ERR_IO;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
