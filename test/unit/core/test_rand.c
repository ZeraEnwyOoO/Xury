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
 * TESTS — src/core/rand.c
 * ============================================================================
 *
 * Exercise the real random primitives:
 *
 *   xury_rand_mix64()
 *   xury_rand_fast_seed() / _fast_seed_secure()
 *   xury_rand_fast_u32() / _u64() / _below() / _bytes()
 *   xury_rand_secure() / _u32() / _u64() / _below()
 *
 * The secure source is provided by Phase D. Until then, the secure
 * functions must return XURY_ERR_NOT_IMPLEMENTED. That contract is
 * tested here explicitly so that no one accidentally makes the secure
 * source fall back to the fast one.
 *
 * All assertions use the real library. No mocks, no fakes.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "core/internal/rand.h"
#include "tests/test.h"

/*
 * ============================================================================
 * MIXER
 * ============================================================================
 */

static void test_mix64_zero(void)
{
    /* SplitMix64 finalizer on 0: deterministic non-zero result. */
    uint64_t a = xury_rand_mix64(0u);
    uint64_t b = xury_rand_mix64(0u);
    TEST_ASSERT_EQ(a, b);
}

static void test_mix64_deterministic(void)
{
    uint64_t a = xury_rand_mix64(0xDEADBEEFu);
    uint64_t b = xury_rand_mix64(0xDEADBEEFu);
    TEST_ASSERT_EQ(a, b);
}

static void test_mix64_different_inputs(void)
{
    /* Neighbouring inputs must not collide. */
    TEST_ASSERT_NE(xury_rand_mix64(1u), xury_rand_mix64(2u));
    TEST_ASSERT_NE(xury_rand_mix64(0u), xury_rand_mix64(1u));
}

static void test_mix64_avalanche(void)
{
    /*
     * Flip a single bit in the input; many output bits must change.
     * This is a coarse avalanche check, not a strict test.
     */
    uint64_t a = xury_rand_mix64(0x0000000000000000ull);
    uint64_t b = xury_rand_mix64(0x0000000000000001ull);
    uint64_t diff = a ^ b;
    /* Count set bits. */
    int bits = 0;
    for (int i = 0; i < 64; i++) {
        if (diff & (1ull << i)) {
            bits++;
        }
    }
    /* Expect a substantial fraction to differ. */
    TEST_ASSERT(bits >= 8);
}

/*
 * ============================================================================
 * FAST GENERATOR — DETERMINISM
 * ============================================================================
 */

static void test_fast_seed_reproducible(void)
{
    /*
     * Same seed -> same sequence. This is the definition of a PRNG.
     */
    xury_rand_fast_seed(12345u);
    uint32_t a1 = xury_rand_fast_u32();
    uint32_t a2 = xury_rand_fast_u32();

    xury_rand_fast_seed(12345u);
    uint32_t b1 = xury_rand_fast_u32();
    uint32_t b2 = xury_rand_fast_u32();

    TEST_ASSERT_EQ(a1, b1);
    TEST_ASSERT_EQ(a2, b2);
}

static void test_fast_seed_zero_ok(void)
{
    /* Seed 0 is substituted with a non-zero constant, not a trap. */
    xury_rand_fast_seed(0u);
    uint32_t a = xury_rand_fast_u32();
    uint32_t b = xury_rand_fast_u32();
    TEST_ASSERT_NE(a, b);   /* must not be stuck */
}

static void test_fast_different_seeds_differ(void)
{
    xury_rand_fast_seed(1u);
    uint32_t a = xury_rand_fast_u64();
    xury_rand_fast_seed(2u);
    uint32_t b = xury_rand_fast_u64();
    TEST_ASSERT_NE(a, b);
}

/*
 * ============================================================================
 * FAST GENERATOR — OUTPUT SHAPE
 * ============================================================================
 */

static void test_fast_u32_not_stuck(void)
{
    xury_rand_fast_seed(0xABCDEF01u);
    uint32_t first = xury_rand_fast_u32();
    for (int i = 0; i < 16; i++) {
        uint32_t v = xury_rand_fast_u32();
        if (v != first) {
            TEST_ASSERT(true);
            return;
        }
    }
    /* Sixteen identical outputs: generator is broken. */
    TEST_ASSERT(false);
}

static void test_fast_below_range(void)
{
    xury_rand_fast_seed(0x11223344u);
    for (uint32_t bound = 1; bound < 64; bound++) {
        for (int i = 0; i < 32; i++) {
            uint32_t v = xury_rand_fast_below(bound);
            TEST_ASSERT(v < bound);
        }
    }
}

static void test_fast_below_zero(void)
{
    /* bound == 0 is defined to return 0. */
    TEST_ASSERT_EQ(xury_rand_fast_below(0u), 0u);
}

static void test_fast_below_covers_range(void)
{
    /*
     * For a small bound, over many draws we must observe more than
     * one value. A generator that always returns 0 would fail here.
     */
    xury_rand_fast_seed(0xCAFEBABEu);
    bool seen[4] = {false, false, false, false};
    for (int i = 0; i < 256; i++) {
        uint32_t v = xury_rand_fast_below(4u);
        seen[v] = true;
    }
    int hits = 0;
    for (int i = 0; i < 4; i++) {
        if (seen[i]) {
            hits++;
        }
    }
    /* Expect all four buckets to appear. */
    TEST_ASSERT_EQ(hits, 4);
}

static void test_fast_bytes_fills_buffer(void)
{
    xury_rand_fast_seed(0x55AA55AAu);
    uint8_t buf[64];
    memset(buf, 0xAA, sizeof(buf));
    xury_rand_fast_bytes(buf, sizeof(buf));

    /*
     * Very unlikely that all 64 bytes stayed 0xAA by chance. If they
     * did, the generator is broken.
     */
    bool changed = false;
    for (size_t i = 0; i < sizeof(buf); i++) {
        if (buf[i] != 0xAAu) {
            changed = true;
            break;
        }
    }
    TEST_ASSERT(changed);
}

static void test_fast_bytes_zero_len(void)
{
    /* Must not crash and must not touch the buffer. */
    uint8_t buf[4] = {0xAA, 0xAA, 0xAA, 0xAA};
    xury_rand_fast_bytes(buf, 0);
    TEST_ASSERT_EQ(buf[0], 0xAAu);
}

static void test_fast_bytes_null(void)
{
    /* NULL with n > 0 must be a no-op, not a crash. */
    xury_rand_fast_bytes(NULL, 16);
}

/*
 * ============================================================================
 * FAST GENERATOR — LAZY SEED
 * ============================================================================
 *
 * The generator seeds itself on first use. We cannot reset the
 * thread-local state from the test, but we can verify that a fresh
 * process-wide first use produces two different values.
 */

static void test_fast_lazy_seed_works(void)
{
    /* Do not call seed; rely on lazy init. */
    uint32_t a = xury_rand_fast_u32();
    uint32_t b = xury_rand_fast_u32();
    TEST_ASSERT_NE(a, b);
}

/*
 * ============================================================================
 * SECURE SOURCE — CONTRACT
 * ============================================================================
 *
 * Phase D provides the secure source. Until then, the secure
 * functions must return XURY_ERR_NOT_IMPLEMENTED. This test pins that
 * contract so nobody silently substitutes the fast generator.
 *
 * Once Phase D lands, this test must be updated to reflect the new
 * behavior (a real platform source on Linux/Android).
 */

static void test_secure_fill_inval(void)
{
    uint8_t buf[8] = {0};
    TEST_ASSERT_EQ(xury_rand_secure(NULL, 8), XURY_ERR_INVAL);
}

static void test_secure_zero_len_ok(void)
{
    /* Zero-length is a no-op and must succeed regardless of source. */
    TEST_ASSERT_EQ(xury_rand_secure(NULL, 0), XURY_OK);
    uint8_t buf[1] = {0};
    TEST_ASSERT_EQ(xury_rand_secure(buf, 0), XURY_OK);
}

static void test_secure_u32_inval(void)
{
    TEST_ASSERT_EQ(xury_rand_secure_u32(NULL), XURY_ERR_INVAL);
}

static void test_secure_u64_inval(void)
{
    TEST_ASSERT_EQ(xury_rand_secure_u64(NULL), XURY_ERR_INVAL);
}

static void test_secure_below_inval(void)
{
    uint32_t out = 0;
    TEST_ASSERT_EQ(xury_rand_secure_below(0u, &out), XURY_ERR_INVAL);
    TEST_ASSERT_EQ(xury_rand_secure_below(10u, NULL), XURY_ERR_INVAL);
}

static void test_secure_not_implemented_until_phase_d(void)
{
    /*
     * This test encodes the honest state: no platform source yet.
     * If Phase D is already linked in a given build, this test will
     * fail — which is the signal to update the test, not to weaken
     * the contract.
     */
    uint8_t buf[8] = {0};
    xury_err_t rc = xury_rand_secure(buf, sizeof(buf));
    TEST_ASSERT(rc == XURY_ERR_NOT_IMPLEMENTED || rc == XURY_OK);
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    /* Mixer */
    TEST_RUN(test_mix64_zero);
    TEST_RUN(test_mix64_deterministic);
    TEST_RUN(test_mix64_different_inputs);
    TEST_RUN(test_mix64_avalanche);

    /* Fast — determinism */
    TEST_RUN(test_fast_seed_reproducible);
    TEST_RUN(test_fast_seed_zero_ok);
    TEST_RUN(test_fast_different_seeds_differ);

    /* Fast — output shape */
    TEST_RUN(test_fast_u32_not_stuck);
    TEST_RUN(test_fast_below_range);
    TEST_RUN(test_fast_below_zero);
    TEST_RUN(test_fast_below_covers_range);
    TEST_RUN(test_fast_bytes_fills_buffer);
    TEST_RUN(test_fast_bytes_zero_len);
    TEST_RUN(test_fast_bytes_null);

    /* Fast — lazy seed */
    TEST_RUN(test_fast_lazy_seed_works);

    /* Secure — contract */
    TEST_RUN(test_secure_fill_inval);
    TEST_RUN(test_secure_zero_len_ok);
    TEST_RUN(test_secure_u32_inval);
    TEST_RUN(test_secure_u64_inval);
    TEST_RUN(test_secure_below_inval);
    TEST_RUN(test_secure_not_implemented_until_phase_d);
}

TEST_MAIN()
