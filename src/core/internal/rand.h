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

#ifndef XURY_CORE_INTERNAL_RAND_H
#define XURY_CORE_INTERNAL_RAND_H

/*
 * ============================================================================
 * XURY CORE — RANDOM
 * ============================================================================
 *
 * Random number generation.
 *
 * Xury needs two kinds of randomness:
 *
 *   SECURE  — tokens, peer ids, transaction ids, nonces. Must be
 *             unpredictable even to an attacker who sees previous
 *             outputs. Sourced from the platform: /dev/urandom on
 *             Linux, getrandom(2), arc4random on BSD/macOS, and the
 *             Java SecureRandom bridge on Android.
 *
 *   FAST    — port picking during a birthday-paradox spray, jitter
 *             for retry backoff, choosing which helper peer to try
 *             first. Does not need to be unpredictable; it needs to
 *             be fast and well-distributed within one run.
 *
 * Both are exposed here. The secure source is provided by the
 * platform layer (Phase D). Until Phase D exists, the secure
 * functions return XURY_ERR_NOT_IMPLEMENTED — and this is deliberate:
 * Xury must never silently substitute weak randomness for strong.
 *
 * The fast source is implemented here, in the core. It is a small
 * xorshift64* generator seeded from the secure source when available,
 * or from a low-quality mix of time and pointer values if not.
 *
 * Properties:
 *   - No allocation
 *   - Thread-local state for the fast source (no locks)
 *   - Secure functions never fall back to the fast source
 *
 * This header depends on <xury/types.h> and <xury/err.h>. It must
 * remain so.
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
 * SECURE RANDOM
 * ============================================================================
 *
 * Backed by the platform. On Linux and Android the implementation
 * will use getrandom(2) where available and /dev/urandom otherwise.
 *
 * Contract:
 *   - Every call either fills the buffer completely or returns an
 *     error. There is no partial fill.
 *   - The output is suitable for cryptographic use.
 *   - The function is thread-safe.
 *
 * Errors:
 *   XURY_ERR_NOT_IMPLEMENTED  — platform source not yet wired (Phase D)
 *   XURY_ERR_INVAL            — buf is NULL and n > 0
 *   XURY_ERR_IO               — the platform source failed
 */

/*
 * Fill buf with n cryptographically strong random bytes.
 *
 * n == 0 is a no-op returning XURY_OK.
 * buf == NULL and n > 0 returns XURY_ERR_INVAL.
 */
xury_err_t xury_rand_secure(void *buf, size_t n);

/*
 * Return a single 32-bit value from the secure source.
 */
xury_err_t xury_rand_secure_u32(uint32_t *out);

/*
 * Return a single 64-bit value from the secure source.
 */
xury_err_t xury_rand_secure_u64(uint64_t *out);

/*
 * Return a uniformly distributed value in [0, bound).
 *
 * bound == 0 returns XURY_ERR_INVAL.
 * The implementation must be free of modulo bias.
 */
xury_err_t xury_rand_secure_below(uint32_t bound, uint32_t *out);

/*
 * ============================================================================
 * FAST RANDOM (thread-local)
 * ============================================================================
 *
 * A small xorshift64* generator, one per thread. Seed it once per
 * thread. It is not cryptographic and must never be used for tokens
 * or identifiers that an attacker could predict.
 *
 * The generator's state lives in thread-local storage, so no locking
 * is required and two threads cannot affect each other.
 */

/*
 * Seed the current thread's fast generator.
 *
 * The seed should come from the secure source. If seed == 0 the
 * generator substitutes a fixed non-zero constant so it still works.
 */
void xury_rand_fast_seed(uint64_t seed);

/*
 * Seed the current thread's fast generator from the secure source.
 *
 * If the secure source is not yet available (Phase D), this falls
 * back to a low-quality seed derived from the address of a stack
 * variable and the current time. That fallback is fine for the fast
 * generator and is documented here so the choice is explicit.
 */
xury_err_t xury_rand_fast_seed_secure(void);

/*
 * Return the next 32-bit value from the fast generator.
 *
 * The generator is seeded lazily on first use.
 */
uint32_t xury_rand_fast_u32(void);

/*
 * Return the next 64-bit value from the fast generator.
 */
uint64_t xury_rand_fast_u64(void);

/*
 * Return a uniformly distributed value in [0, bound) from the fast
 * generator.
 *
 * bound == 0 returns 0.
 */
uint32_t xury_rand_fast_below(uint32_t bound);

/*
 * Fill buf with n bytes from the fast generator.
 * Not cryptographic.
 */
void xury_rand_fast_bytes(void *buf, size_t n);

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

/*
 * A 64-bit mixing function, useful as a seed expander and as a hash
 * finalizer. Based on the SplitMix64 finalizer; not cryptographic,
 * but well-distributed.
 */
uint64_t xury_rand_mix64(uint64_t v);

/*
 * ============================================================================
 * END OF XURY CORE INTERNAL RAND HEADER
 * ============================================================================
 */

#endif /* XURY_CORE_INTERNAL_RAND_H */
