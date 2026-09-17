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
 * TESTS — src/api/config.c
 * ============================================================================
 *
 * Exercise the internal config helpers:
 *
 *   xury_config_validate()
 *   xury_config_apply_defaults()
 *   xury_config_normalize()
 *   xury_config_weapon_enabled()
 *   xury_config_effective_connect_timeout()
 *   xury_config_fingerprint()
 *
 * The tests build configs from scratch, mutate a single field, and
 * assert the exact behavior. No mocks, no fakes.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "api/internal/config.h"
#include "tests/test.h"

/*
 * ----------------------------------------------------------------------------
 * Helper: a fully zeroed config.
 * ----------------------------------------------------------------------------
 * Zero means "use defaults" for every field, which is exactly the
 * contract we want to verify.
 */
static xury_config_t zero_cfg(void)
{
    xury_config_t c;
    memset(&c, 0, sizeof(c));
    return c;
}

/*
 * Helper: a config with an explicit struct_version so it is NOT
 * treated as "all zero".
 */
static xury_config_t explicit_cfg(void)
{
    xury_config_t c;
    memset(&c, 0, sizeof(c));
    c.struct_version = XURY_CONFIG_VERSION;
    return c;
}

/*
 * ============================================================================
 * VALIDATE
 * ============================================================================
 */

static void test_validate_null(void)
{
    TEST_ASSERT_EQ(xury_config_validate(NULL), XURY_ERR_INVAL);
}

static void test_validate_zero_ok(void)
{
    /* All-zero is explicitly allowed: it means "all defaults". */
    xury_config_t c = zero_cfg();
    TEST_ASSERT_EQ(xury_config_validate(&c), XURY_OK);
}

static void test_validate_explicit_version_ok(void)
{
    xury_config_t c = explicit_cfg();
    TEST_ASSERT_EQ(xury_config_validate(&c), XURY_OK);
}

static void test_validate_bad_struct_version(void)
{
    xury_config_t c = zero_cfg();
    c.struct_version = 999u;
    TEST_ASSERT_EQ(xury_config_validate(&c), XURY_ERR_INVAL);
}

static void test_validate_bad_strategy(void)
{
    xury_config_t c = zero_cfg();
    c.force_strategy = (xury_strategy_t)9999;
    TEST_ASSERT_EQ(xury_config_validate(&c), XURY_ERR_INVAL);
}

static void test_validate_weapon_mask_unknown_bit(void)
{
    xury_config_t c = zero_cfg();
    /* Set a bit far above XURY_WEAPON_COUNT. */
    c.enable_weapons = 1u << 31;
    TEST_ASSERT_EQ(xury_config_validate(&c), XURY_ERR_INVAL);
}

static void test_validate_weapon_mask_none_bit(void)
{
    xury_config_t c = zero_cfg();
    /* Bit 0 is XURY_WEAPON_NONE, which must never be set. */
    c.enable_weapons = 1u << 0;
    TEST_ASSERT_EQ(xury_config_validate(&c), XURY_ERR_INVAL);
}

static void test_validate_weapon_mask_ok(void)
{
    xury_config_t c = zero_cfg();
    c.enable_weapons = XURY_WEAPON_BIT(XURY_WEAPON_IPV6) |
                       XURY_WEAPON_BIT(XURY_WEAPON_HOLE);
    TEST_ASSERT_EQ(xury_config_validate(&c), XURY_OK);
}

static void test_validate_timeout_too_small(void)
{
    xury_config_t c = zero_cfg();
    c.scan_timeout_ms = 1u;   /* below MIN_SCAN_MS */
    TEST_ASSERT_EQ(xury_config_validate(&c), XURY_ERR_INVAL);
}

static void test_validate_timeout_too_large(void)
{
    xury_config_t c = zero_cfg();
    c.connect_timeout_ms = 0xFFFFFFFFu;   /* above MAX */
    TEST_ASSERT_EQ(xury_config_validate(&c), XURY_ERR_INVAL);
}

static void test_validate_timeout_ok(void)
{
    xury_config_t c = zero_cfg();
    c.scan_timeout_ms    = XURY_CONFIG_MIN_SCAN_MS;
    c.connect_timeout_ms = XURY_CONFIG_MAX_TIMEOUT_MS;
    TEST_ASSERT_EQ(xury_config_validate(&c), XURY_OK);
}

static void test_validate_max_parallel_out_of_range(void)
{
    xury_config_t c = zero_cfg();
    c.max_parallel = XURY_CONFIG_MAX_PARALLEL + 1u;
    TEST_ASSERT_EQ(xury_config_validate(&c), XURY_ERR_INVAL);
}

static void test_validate_interface_not_terminated(void)
{
    xury_config_t c = zero_cfg();
    /* Fill with non-NUL bytes. */
    for (size_t i = 0; i < sizeof(c.local_interface); i++) {
        c.local_interface[i] = 'x';
    }
    TEST_ASSERT_EQ(xury_config_validate(&c), XURY_ERR_INVAL);
}

static void test_validate_allocator_partial(void)
{
    xury_config_t c = zero_cfg();
    xury_allocator_t a;
    memset(&a, 0, sizeof(a));
    /* Only malloc set: must be rejected. */
    a.malloc_fn = (void *(*)(size_t))0x1;
    c.allocator = &a;
    TEST_ASSERT_EQ(xury_config_validate(&c), XURY_ERR_INVAL);
}

static void test_validate_allocator_all_set(void)
{
    xury_config_t c = zero_cfg();
    xury_allocator_t a;
    memset(&a, 0, sizeof(a));
    a.malloc_fn  = (void *(*)(size_t))0x1;
    a.realloc_fn = (void *(*)(void *, size_t))0x1;
    a.free_fn    = (void (*)(void *))0x1;
    c.allocator = &a;
    TEST_ASSERT_EQ(xury_config_validate(&c), XURY_OK);
}

static void test_validate_storage_partial(void)
{
    xury_config_t c = zero_cfg();
    xury_storage_iface_t s;
    memset(&s, 0, sizeof(s));
    /* Only load set: must be rejected. */
    s.load = (int (*)(void *, uint8_t *, size_t *))0x1;
    c.storage = &s;
    TEST_ASSERT_EQ(xury_config_validate(&c), XURY_ERR_INVAL);
}

static void test_validate_storage_both_set(void)
{
    xury_config_t c = zero_cfg();
    xury_storage_iface_t s;
    memset(&s, 0, sizeof(s));
    s.load = (int (*)(void *, uint8_t *, size_t *))0x1;
    s.save = (int (*)(void *, const uint8_t *, size_t))0x1;
    c.storage = &s;
    TEST_ASSERT_EQ(xury_config_validate(&c), XURY_OK);
}

/*
 * ============================================================================
 * APPLY DEFAULTS
 * ============================================================================
 */

static void test_defaults_null_args(void)
{
    xury_config_t c = zero_cfg();
    TEST_ASSERT_EQ(xury_config_apply_defaults(NULL, &c), XURY_ERR_INVAL);
    TEST_ASSERT_EQ(xury_config_apply_defaults(&c, NULL), XURY_ERR_INVAL);
}

static void test_defaults_zero_fills_everything(void)
{
    xury_config_t in  = zero_cfg();
    xury_config_t out = zero_cfg();

    TEST_ASSERT_EQ(xury_config_apply_defaults(&in, &out), XURY_OK);

    /* struct_version filled in. */
    TEST_ASSERT_EQ(out.struct_version, XURY_CONFIG_VERSION);

    /* Weapons defaulted. */
    TEST_ASSERT_EQ(out.enable_weapons, XURY_DEFAULT_WEAPONS);

    /* Timeouts defaulted. */
    TEST_ASSERT_EQ(out.scan_timeout_ms,    XURY_DEFAULT_SCAN_TIMEOUT_MS);
    TEST_ASSERT_EQ(out.sensing_timeout_ms, XURY_DEFAULT_SENSING_TIMEOUT_MS);
    TEST_ASSERT_EQ(out.probing_timeout_ms, XURY_DEFAULT_PROBING_TIMEOUT_MS);
    TEST_ASSERT_EQ(out.strike_timeout_ms,  XURY_DEFAULT_STRIKE_TIMEOUT_MS);
    TEST_ASSERT_EQ(out.blitz_timeout_ms,   XURY_DEFAULT_BLITZ_TIMEOUT_MS);
    TEST_ASSERT_EQ(out.connect_timeout_ms, XURY_DEFAULT_CONNECT_TIMEOUT_MS);
    TEST_ASSERT_EQ(out.mapping_timeout_ms, XURY_DEFAULT_MAPPING_TIMEOUT_MS);
    TEST_ASSERT_EQ(out.mirror_timeout_ms,  XURY_DEFAULT_MIRROR_TIMEOUT_MS);
    TEST_ASSERT_EQ(out.relay_timeout_ms,   XURY_DEFAULT_RELAY_TIMEOUT_MS);

    TEST_ASSERT_EQ(out.max_parallel, XURY_DEFAULT_MAX_PARALLEL);
    TEST_ASSERT_EQ(out.cache_ttl_sec, XURY_DEFAULT_CACHE_TTL_SEC);
    TEST_ASSERT_EQ(out.learning_min_samples,
                   XURY_DEFAULT_LEARNING_MIN_SAMPLES);

    /* Booleans enabled when the input was all-zero. */
    TEST_ASSERT(out.enable_scan);
    TEST_ASSERT(out.enable_strike);
    TEST_ASSERT(out.enable_blitz);
    TEST_ASSERT(out.enable_early_term);
    TEST_ASSERT(out.enable_cache);
    TEST_ASSERT(out.enable_learning);
    TEST_ASSERT(out.enable_sweet);
    TEST_ASSERT(out.enable_mirror);
    TEST_ASSERT(out.enable_relay);
    TEST_ASSERT(out.enable_relay_upgrade);
    TEST_ASSERT(!out.enable_sweet_aggressive);
}

static void test_defaults_preserves_explicit_values(void)
{
    xury_config_t in  = explicit_cfg();
    xury_config_t out = zero_cfg();

    in.scan_timeout_ms    = 2500u;
    in.connect_timeout_ms = 60000u;
    in.max_parallel       = 4u;

    TEST_ASSERT_EQ(xury_config_apply_defaults(&in, &out), XURY_OK);

    TEST_ASSERT_EQ(out.scan_timeout_ms, 2500u);
    TEST_ASSERT_EQ(out.connect_timeout_ms, 60000u);
    TEST_ASSERT_EQ(out.max_parallel, 4u);
}

static void test_defaults_explicit_version_keeps_booleans_off(void)
{
    /*
     * With an explicit struct_version, the booleans are taken as the
     * caller wrote them. An explicit_version config has them all off.
     */
    xury_config_t in  = explicit_cfg();
    xury_config_t out = zero_cfg();

    TEST_ASSERT_EQ(xury_config_apply_defaults(&in, &out), XURY_OK);

    TEST_ASSERT(!out.enable_scan);
    TEST_ASSERT(!out.enable_strike);
    TEST_ASSERT(!out.enable_blitz);
}

/* ---- continued in part 2/2 ---- */
