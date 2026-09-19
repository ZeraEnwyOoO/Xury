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
#include "test/test.h"

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

 /* ---- continued from part 1/2 ---- */

/*
 * ============================================================================
 * NORMALIZE
 * ============================================================================
 */

static void test_normalize_null(void)
{
    TEST_ASSERT_EQ(xury_config_normalize(NULL), XURY_ERR_INVAL);
}

static void test_normalize_clamps_scan_timeout(void)
{
    /* Build a config with a value above MAX and confirm it's clamped. */
    xury_config_t in  = zero_cfg();
    xury_config_t out = zero_cfg();

    in.scan_timeout_ms = XURY_CONFIG_MAX_SCAN_MS + 10000u;
    TEST_ASSERT_EQ(xury_config_apply_defaults(&in, &out), XURY_OK);
    TEST_ASSERT_EQ(xury_config_normalize(&out), XURY_OK);
    TEST_ASSERT_EQ(out.scan_timeout_ms, XURY_CONFIG_MAX_SCAN_MS);

    /* Below MIN. */
    in.scan_timeout_ms = 1u;
    TEST_ASSERT_EQ(xury_config_apply_defaults(&in, &out), XURY_OK);
    TEST_ASSERT_EQ(xury_config_normalize(&out), XURY_OK);
    TEST_ASSERT_EQ(out.scan_timeout_ms, XURY_CONFIG_MIN_SCAN_MS);
}

static void test_normalize_clamps_max_parallel(void)
{
    xury_config_t in  = zero_cfg();
    xury_config_t out = zero_cfg();

    in.max_parallel = 0u;
    xury_config_apply_defaults(&in, &out);
    xury_config_normalize(&out);
    TEST_ASSERT(out.max_parallel >= XURY_CONFIG_MIN_PARALLEL);
    TEST_ASSERT(out.max_parallel <= XURY_CONFIG_MAX_PARALLEL);
}

static void test_normalize_aggressive_gate(void)
{
    /*
     * BIRTHDAY and UPGRADE must be cleared unless the host opted in
     * via enable_sweet_aggressive.
     */
    xury_config_t c = zero_cfg();
    xury_config_apply_defaults(&c, &c);

    c.enable_weapons = XURY_WEAPON_BIT(XURY_WEAPON_IPV6) |
                       XURY_WEAPON_BIT(XURY_WEAPON_BIRTHDAY) |
                       XURY_WEAPON_BIT(XURY_WEAPON_UPGRADE);
    c.enable_sweet_aggressive = false;

    TEST_ASSERT_EQ(xury_config_normalize(&c), XURY_OK);

    TEST_ASSERT(!xury_config_weapon_enabled(&c, XURY_WEAPON_BIRTHDAY));
    TEST_ASSERT(!xury_config_weapon_enabled(&c, XURY_WEAPON_UPGRADE));
    TEST_ASSERT(xury_config_weapon_enabled(&c, XURY_WEAPON_IPV6));
}

static void test_normalize_aggressive_allowed(void)
{
    xury_config_t c = zero_cfg();
    xury_config_apply_defaults(&c, &c);

    c.enable_weapons = XURY_WEAPON_BIT(XURY_WEAPON_BIRTHDAY) |
                       XURY_WEAPON_BIT(XURY_WEAPON_HOLE);
    c.enable_sweet_aggressive = true;

    TEST_ASSERT_EQ(xury_config_normalize(&c), XURY_OK);
    TEST_ASSERT(xury_config_weapon_enabled(&c, XURY_WEAPON_BIRTHDAY));
}

static void test_normalize_sweet_needs_traversal(void)
{
    /*
     * If neither HOLE nor PREDICT is enabled, sweet is disabled
     * because it has no traversal to build on.
     */
    xury_config_t c = zero_cfg();
    xury_config_apply_defaults(&c, &c);

    c.enable_weapons = XURY_WEAPON_BIT(XURY_WEAPON_IPV6) |
                       XURY_WEAPON_BIT(XURY_WEAPON_UPNP);
    c.enable_sweet = true;

    TEST_ASSERT_EQ(xury_config_normalize(&c), XURY_OK);
    TEST_ASSERT(!c.enable_sweet);

    /* Now enable HOLE: sweet stays on. */
    c.enable_weapons |= XURY_WEAPON_BIT(XURY_WEAPON_HOLE);
    c.enable_sweet = true;
    TEST_ASSERT_EQ(xury_config_normalize(&c), XURY_OK);
    TEST_ASSERT(c.enable_sweet);
}

static void test_normalize_upgrade_needs_relay(void)
{
    xury_config_t c = zero_cfg();
    xury_config_apply_defaults(&c, &c);

    c.enable_relay = false;
    c.enable_relay_upgrade = true;

    TEST_ASSERT_EQ(xury_config_normalize(&c), XURY_OK);
    TEST_ASSERT(!c.enable_relay_upgrade);
}

static void test_normalize_disables_phases_when_no_weapons(void)
{
    xury_config_t c = zero_cfg();
    xury_config_apply_defaults(&c, &c);

    c.enable_weapons = 0u;
    c.enable_strike = true;
    c.enable_blitz  = true;

    TEST_ASSERT_EQ(xury_config_normalize(&c), XURY_OK);
    TEST_ASSERT(!c.enable_strike);
    TEST_ASSERT(!c.enable_blitz);
}

static void test_normalize_is_idempotent(void)
{
    xury_config_t c = zero_cfg();
    xury_config_apply_defaults(&c, &c);

    TEST_ASSERT_EQ(xury_config_normalize(&c), XURY_OK);

    /* Snapshot a few fields. */
    uint32_t w = c.enable_weapons;
    uint32_t s = c.scan_timeout_ms;
    bool     e = c.enable_sweet;

    TEST_ASSERT_EQ(xury_config_normalize(&c), XURY_OK);

    TEST_ASSERT_EQ(c.enable_weapons, w);
    TEST_ASSERT_EQ(c.scan_timeout_ms, s);
    TEST_ASSERT_EQ(c.enable_sweet, e);
}

/*
 * ============================================================================
 * WEAPON ENABLED
 * ============================================================================
 */

static void test_weapon_enabled_null(void)
{
    TEST_ASSERT(!xury_config_weapon_enabled(NULL, XURY_WEAPON_IPV6));
}

static void test_weapon_enabled_invalid(void)
{
    xury_config_t c = zero_cfg();
    c.enable_weapons = XURY_DEFAULT_WEAPONS;
    TEST_ASSERT(!xury_config_weapon_enabled(&c, XURY_WEAPON_NONE));
    TEST_ASSERT(!xury_config_weapon_enabled(&c, (xury_weapon_t)999));
}

static void test_weapon_enabled_bit_set(void)
{
    xury_config_t c = zero_cfg();
    c.enable_weapons = XURY_WEAPON_BIT(XURY_WEAPON_IPV6) |
                       XURY_WEAPON_BIT(XURY_WEAPON_HOLE);

    TEST_ASSERT(xury_config_weapon_enabled(&c, XURY_WEAPON_IPV6));
    TEST_ASSERT(xury_config_weapon_enabled(&c, XURY_WEAPON_HOLE));
    TEST_ASSERT(!xury_config_weapon_enabled(&c, XURY_WEAPON_UPNP));
    TEST_ASSERT(!xury_config_weapon_enabled(&c, XURY_WEAPON_RELAY));
}

/*
 * ============================================================================
 * EFFECTIVE CONNECT TIMEOUT
 * ============================================================================
 */

static void test_effective_timeout_null(void)
{
    uint32_t t = xury_config_effective_connect_timeout(NULL);
    TEST_ASSERT_EQ(t, XURY_DEFAULT_CONNECT_TIMEOUT_MS);
}

static void test_effective_timeout_zero_uses_default(void)
{
    xury_config_t c = zero_cfg();
    uint32_t t = xury_config_effective_connect_timeout(&c);
    TEST_ASSERT_EQ(t, XURY_DEFAULT_CONNECT_TIMEOUT_MS);
}

static void test_effective_timeout_explicit(void)
{
    xury_config_t c = zero_cfg();
    c.connect_timeout_ms = 45000u;
    uint32_t t = xury_config_effective_connect_timeout(&c);
    TEST_ASSERT_EQ(t, 45000u);
}

/*
 * ============================================================================
 * FINGERPRINT
 * ============================================================================
 */

static void test_fingerprint_null_is_zero(void)
{
    TEST_ASSERT_EQ(xury_config_fingerprint(NULL), 0u);
}

static void test_fingerprint_deterministic(void)
{
    xury_config_t c = zero_cfg();
    c.struct_version = XURY_CONFIG_VERSION;
    c.enable_weapons = XURY_DEFAULT_WEAPONS;

    uint64_t a = xury_config_fingerprint(&c);
    uint64_t b = xury_config_fingerprint(&c);
    TEST_ASSERT_EQ(a, b);
    TEST_ASSERT(a != 0u);
}

static void test_fingerprint_changes_with_weapons(void)
{
    xury_config_t a = zero_cfg();
    xury_config_t b = zero_cfg();

    a.struct_version = XURY_CONFIG_VERSION;
    b.struct_version = XURY_CONFIG_VERSION;

    a.enable_weapons = XURY_WEAPON_BIT(XURY_WEAPON_IPV6);
    b.enable_weapons = XURY_WEAPON_BIT(XURY_WEAPON_IPV6) |
                       XURY_WEAPON_BIT(XURY_WEAPON_HOLE);

    uint64_t fa = xury_config_fingerprint(&a);
    uint64_t fb = xury_config_fingerprint(&b);
    TEST_ASSERT_NE(fa, fb);
}

static void test_fingerprint_ignores_hooks(void)
{
    /*
     * Hooks and their userdata must not affect the fingerprint:
     * changing them must not invalidate the scan cache.
     */
    xury_config_t a = zero_cfg();
    xury_config_t b = zero_cfg();

    a.struct_version = XURY_CONFIG_VERSION;
    b.struct_version = XURY_CONFIG_VERSION;

    /* Same behavior fields. */
    a.enable_weapons = b.enable_weapons = XURY_DEFAULT_WEAPONS;

    /* Different hook pointers. */
    a.on_log = (void (*)(int, const char *, void *))0x1;
    a.log_userdata = (void *)0x1;
    b.on_log = (void (*)(int, const char *, void *))0x2;
    b.log_userdata = (void *)0x2;

    uint64_t fa = xury_config_fingerprint(&a);
    uint64_t fb = xury_config_fingerprint(&b);
    TEST_ASSERT_EQ(fa, fb);
}

static void test_fingerprint_changes_with_timeout(void)
{
    xury_config_t a = zero_cfg();
    xury_config_t b = zero_cfg();

    a.struct_version = XURY_CONFIG_VERSION;
    b.struct_version = XURY_CONFIG_VERSION;

    a.scan_timeout_ms = 1000u;
    b.scan_timeout_ms = 2000u;

    TEST_ASSERT_NE(xury_config_fingerprint(&a),
                   xury_config_fingerprint(&b));
}

static void test_fingerprint_changes_with_strategy(void)
{
    xury_config_t a = zero_cfg();
    xury_config_t b = zero_cfg();

    a.struct_version = XURY_CONFIG_VERSION;
    b.struct_version = XURY_CONFIG_VERSION;

    a.force_strategy = XURY_STRATEGY_AUTO;
    b.force_strategy = XURY_STRATEGY_RELAY;

    TEST_ASSERT_NE(xury_config_fingerprint(&a),
                   xury_config_fingerprint(&b));
}

static void test_fingerprint_includes_interface(void)
{
    xury_config_t a = zero_cfg();
    xury_config_t b = zero_cfg();

    a.struct_version = XURY_CONFIG_VERSION;
    b.struct_version = XURY_CONFIG_VERSION;

    /* Same behavior, different interface name. */
    memset(a.local_interface, 0, sizeof(a.local_interface));
    memset(b.local_interface, 0, sizeof(b.local_interface));
    strncpy(a.local_interface, "wlan0", sizeof(a.local_interface) - 1);
    strncpy(b.local_interface, "eth0",  sizeof(b.local_interface) - 1);

    TEST_ASSERT_NE(xury_config_fingerprint(&a),
                   xury_config_fingerprint(&b));
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    /* Validate */
    TEST_RUN(test_validate_null);
    TEST_RUN(test_validate_zero_ok);
    TEST_RUN(test_validate_explicit_version_ok);
    TEST_RUN(test_validate_bad_struct_version);
    TEST_RUN(test_validate_bad_strategy);
    TEST_RUN(test_validate_weapon_mask_unknown_bit);
    TEST_RUN(test_validate_weapon_mask_none_bit);
    TEST_RUN(test_validate_weapon_mask_ok);
    TEST_RUN(test_validate_timeout_too_small);
    TEST_RUN(test_validate_timeout_too_large);
    TEST_RUN(test_validate_timeout_ok);
    TEST_RUN(test_validate_max_parallel_out_of_range);
    TEST_RUN(test_validate_interface_not_terminated);
    TEST_RUN(test_validate_allocator_partial);
    TEST_RUN(test_validate_allocator_all_set);
    TEST_RUN(test_validate_storage_partial);
    TEST_RUN(test_validate_storage_both_set);

    /* Defaults */
    TEST_RUN(test_defaults_null_args);
    TEST_RUN(test_defaults_zero_fills_everything);
    TEST_RUN(test_defaults_preserves_explicit_values);
    TEST_RUN(test_defaults_explicit_version_keeps_booleans_off);

    /* Normalize */
    TEST_RUN(test_normalize_null);
    TEST_RUN(test_normalize_clamps_scan_timeout);
    TEST_RUN(test_normalize_clamps_max_parallel);
    TEST_RUN(test_normalize_aggressive_gate);
    TEST_RUN(test_normalize_aggressive_allowed);
    TEST_RUN(test_normalize_sweet_needs_traversal);
    TEST_RUN(test_normalize_upgrade_needs_relay);
    TEST_RUN(test_normalize_disables_phases_when_no_weapons);
    TEST_RUN(test_normalize_is_idempotent);

    /* Weapon enabled */
    TEST_RUN(test_weapon_enabled_null);
    TEST_RUN(test_weapon_enabled_invalid);
    TEST_RUN(test_weapon_enabled_bit_set);

    /* Effective timeout */
    TEST_RUN(test_effective_timeout_null);
    TEST_RUN(test_effective_timeout_zero_uses_default);
    TEST_RUN(test_effective_timeout_explicit);

    /* Fingerprint */
    TEST_RUN(test_fingerprint_null_is_zero);
    TEST_RUN(test_fingerprint_deterministic);
    TEST_RUN(test_fingerprint_changes_with_weapons);
    TEST_RUN(test_fingerprint_ignores_hooks);
    TEST_RUN(test_fingerprint_changes_with_timeout);
    TEST_RUN(test_fingerprint_changes_with_strategy);
    TEST_RUN(test_fingerprint_includes_interface);
}

TEST_MAIN()
