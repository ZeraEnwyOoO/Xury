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
 * XURY CONFIG — IMPLEMENTATION
 * ============================================================================
 *
 * Implements the internal config helpers declared in
 * src/api/internal/config.h.
 *
 * The public config struct is defined in include/xury/config.h. This
 * file turns a caller-supplied config (which may be all-zero) into a
 * fully-resolved, normalized internal config.
 *
 * Pipeline:
 *
 *   caller cfg
 *      |
 *      v
 *   xury_config_validate()          -- reject bad input
 *      |
 *      v
 *   xury_config_apply_defaults()    -- zero -> default
 *      |
 *      v
 *   xury_config_normalize()         -- clamp + enforce invariants
 *      |
 *      v
 *   resolved cfg (stored in engine)
 *
 * All functions are pure except xury_config_normalize(), which
 * operates in place on its argument.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/config.h>
#include <xury/err.h>
#include <xury/weapon.h>

#include "api/internal/config.h"

/*
 * ============================================================================
 * VALIDATION
 * ============================================================================
 */

/*
 * True if the given value is a valid xury_strategy_t.
 */
static bool config_strategy_valid(xury_strategy_t s)
{
    switch (s) {
    case XURY_STRATEGY_AUTO:
    case XURY_STRATEGY_IPV6:
    case XURY_STRATEGY_LAN:
    case XURY_STRATEGY_UPNP:
    case XURY_STRATEGY_NATPMP:
    case XURY_STRATEGY_PCP:
    case XURY_STRATEGY_PUNCH:
    case XURY_STRATEGY_PREDICT:
    case XURY_STRATEGY_MIRROR:
    case XURY_STRATEGY_RELAY:
    case XURY_STRATEGY_BLITZ:
        return true;
    default:
        return false;
    }
}

/*
 * True if the local_interface field is NUL-terminated within its array.
 */
static bool config_interface_terminated(const char *iface, size_t cap)
{
    for (size_t i = 0; i < cap; i++) {
        if (iface[i] == '\0') {
            return true;
        }
    }
    return false;
}

/*
 * True if the weapon bitmask has no bits above XURY_WEAPON_COUNT.
 */
static bool config_weapon_mask_valid(uint32_t mask)
{
    /* Allowed bits: 1 .. XURY_WEAPON_COUNT-1 */
    uint32_t allowed = 0u;
    for (int w = 1; w < (int)XURY_WEAPON_COUNT; w++) {
        allowed |= XURY_WEAPON_BIT(w);
    }

    /* The NONE bit (bit 0) must not be set. */
    if (mask & XURY_WEAPON_BIT(XURY_WEAPON_NONE)) {
        return false;
    }

    /* No bits outside the allowed set. */
    if (mask & ~allowed) {
        return false;
    }

    return true;
}

xury_err_t xury_config_validate(const xury_config_t *cfg)
{
    if (cfg == NULL) {
        return XURY_ERR_INVAL;
    }

    /* struct_version: 0 means "current", otherwise must match. */
    if (cfg->struct_version != 0u &&
        cfg->struct_version != XURY_CONFIG_VERSION) {
        return XURY_ERR_INVAL;
    }

    /* force_strategy must be a known value. */
    if (!config_strategy_valid(cfg->force_strategy)) {
        return XURY_ERR_INVAL;
    }

    /* Weapon mask: no unknown bits, NONE not set. */
    if (cfg->enable_weapons != 0u &&
        !config_weapon_mask_valid(cfg->enable_weapons)) {
        return XURY_ERR_INVAL;
    }

    /*
     * Timeouts: 0 means default. Anything non-zero must be within
     * bounds. Negative values are impossible (unsigned), so we only
     * reject too-small non-zero values.
     */
    if (cfg->scan_timeout_ms != 0u &&
        (cfg->scan_timeout_ms < XURY_CONFIG_MIN_SCAN_MS ||
         cfg->scan_timeout_ms > XURY_CONFIG_MAX_SCAN_MS)) {
        return XURY_ERR_INVAL;
    }
    if (cfg->sensing_timeout_ms != 0u &&
        (cfg->sensing_timeout_ms < XURY_CONFIG_MIN_SENSING_MS ||
         cfg->sensing_timeout_ms > XURY_CONFIG_MAX_SENSING_MS)) {
        return XURY_ERR_INVAL;
    }
    if (cfg->probing_timeout_ms != 0u &&
        (cfg->probing_timeout_ms < XURY_CONFIG_MIN_PROBING_MS ||
         cfg->probing_timeout_ms > XURY_CONFIG_MAX_PROBING_MS)) {
        return XURY_ERR_INVAL;
    }
    if (cfg->strike_timeout_ms != 0u &&
        (cfg->strike_timeout_ms < XURY_CONFIG_MIN_STRIKE_MS ||
         cfg->strike_timeout_ms > XURY_CONFIG_MAX_STRIKE_MS)) {
        return XURY_ERR_INVAL;
    }
    if (cfg->blitz_timeout_ms != 0u &&
        (cfg->blitz_timeout_ms < XURY_CONFIG_MIN_BLITZ_MS ||
         cfg->blitz_timeout_ms > XURY_CONFIG_MAX_BLITZ_MS)) {
        return XURY_ERR_INVAL;
    }
    if (cfg->connect_timeout_ms != 0u &&
        (cfg->connect_timeout_ms < XURY_CONFIG_MIN_TIMEOUT_MS ||
         cfg->connect_timeout_ms > XURY_CONFIG_MAX_TIMEOUT_MS)) {
        return XURY_ERR_INVAL;
    }
    if (cfg->mapping_timeout_ms != 0u &&
        (cfg->mapping_timeout_ms < XURY_CONFIG_MIN_MAPPING_MS ||
         cfg->mapping_timeout_ms > XURY_CONFIG_MAX_MAPPING_MS)) {
        return XURY_ERR_INVAL;
    }
    if (cfg->mirror_timeout_ms != 0u &&
        (cfg->mirror_timeout_ms < XURY_CONFIG_MIN_MIRROR_MS ||
         cfg->mirror_timeout_ms > XURY_CONFIG_MAX_MIRROR_MS)) {
        return XURY_ERR_INVAL;
    }
    if (cfg->relay_timeout_ms != 0u &&
        (cfg->relay_timeout_ms < XURY_CONFIG_MIN_RELAY_MS ||
         cfg->relay_timeout_ms > XURY_CONFIG_MAX_RELAY_MS)) {
        return XURY_ERR_INVAL;
    }

    /* max_parallel: 0 means default, else in range. */
    if (cfg->max_parallel != 0u &&
        (cfg->max_parallel < XURY_CONFIG_MIN_PARALLEL ||
         cfg->max_parallel > XURY_CONFIG_MAX_PARALLEL)) {
        return XURY_ERR_INVAL;
    }

    /* cache_ttl_sec: 0 means default, else in range. */
    if (cfg->cache_ttl_sec != 0u &&
        (cfg->cache_ttl_sec < XURY_CONFIG_MIN_CACHE_TTL_SEC ||
         cfg->cache_ttl_sec > XURY_CONFIG_MAX_CACHE_TTL_SEC)) {
        return XURY_ERR_INVAL;
    }

    /* learning_min_samples: 0 means default, else in range. */
    if (cfg->learning_min_samples != 0u &&
        (cfg->learning_min_samples < XURY_CONFIG_MIN_LEARN_SAMPLES ||
         cfg->learning_min_samples > XURY_CONFIG_MAX_LEARN_SAMPLES)) {
        return XURY_ERR_INVAL;
    }

    /* local_interface must be NUL-terminated. */
    if (!config_interface_terminated(cfg->local_interface,
                                     sizeof(cfg->local_interface))) {
        return XURY_ERR_INVAL;
    }

    /*
     * Allocator: either all three callbacks are set, or all are NULL.
     */
    if (cfg->allocator != NULL) {
        const xury_allocator_t *a = cfg->allocator;
        const bool any =
            (a->malloc_fn  != NULL) ||
            (a->realloc_fn != NULL) ||
            (a->free_fn    != NULL);
        const bool all =
            (a->malloc_fn  != NULL) &&
            (a->realloc_fn != NULL) &&
            (a->free_fn    != NULL);
        if (any && !all) {
            return XURY_ERR_INVAL;
        }
    }

    /*
     * Storage: either both callbacks are set, or both are NULL.
     */
    if (cfg->storage != NULL) {
        const xury_storage_iface_t *s = cfg->storage;
        const bool load_set = (s->load != NULL);
        const bool save_set = (s->save != NULL);
        if (load_set != save_set) {
            return XURY_ERR_INVAL;
        }
    }

    return XURY_OK;
}

/*
 * ============================================================================
 * DEFAULTING
 * ============================================================================
 *
 * Copy cfg into out and replace every zero-valued field with its
 * default. NULL pointers are preserved (they mean "not installed").
 *
 * The caller must have already validated cfg.
 */

xury_err_t xury_config_apply_defaults(const xury_config_t *cfg,
                                      xury_config_t *out)
{
    if (cfg == NULL || out == NULL) {
        return XURY_ERR_INVAL;
    }

    /*
     * Start from a clean copy. We must not leave out partially
     * initialized if cfg has padding bytes.
     */
    memset(out, 0, sizeof(*out));
    *out = *cfg;

    /* struct_version: fill in if zero. */
    if (out->struct_version == 0u) {
        out->struct_version = XURY_CONFIG_VERSION;
    }

    /* enable_weapons: 0 means "safe defaults". */
    if (out->enable_weapons == 0u) {
        out->enable_weapons = XURY_DEFAULT_WEAPONS;
    }

    /* force_strategy: already validated; nothing to default. */

    /*
     * Booleans: the public header documents "true when unset" for a
     * few fields. A zero-initialized config therefore has those
     * disabled, which is the opposite of the documented default.
     *
     * To honor the documented defaults, we detect "all-zero config"
     * by checking the struct_version field. If the caller passed an
     * all-zero struct, struct_version is 0 and we enable the default
     * booleans. If the caller set struct_version explicitly, we trust
     * their boolean choices.
     *
     * This is the only place where the library infers intent from a
     * zero pattern, and it is documented in the public header.
     */
    const bool all_zero = (cfg->struct_version == 0u);

    if (all_zero) {
        out->enable_scan           = true;
        out->enable_strike         = true;
        out->enable_blitz          = true;
        out->enable_early_term     = true;
        out->enable_cache          = true;
        out->enable_learning       = true;
        out->enable_sweet          = true;
        out->enable_mirror         = true;
        out->enable_relay          = true;
        out->enable_relay_upgrade  = true;
        out->enable_sweet_aggressive = false;
    }

    /* Timeouts: zero -> default. */
    if (out->scan_timeout_ms == 0u) {
        out->scan_timeout_ms = XURY_DEFAULT_SCAN_TIMEOUT_MS;
    }
    if (out->sensing_timeout_ms == 0u) {
        out->sensing_timeout_ms = XURY_DEFAULT_SENSING_TIMEOUT_MS;
    }
    if (out->probing_timeout_ms == 0u) {
        out->probing_timeout_ms = XURY_DEFAULT_PROBING_TIMEOUT_MS;
    }
    if (out->strike_timeout_ms == 0u) {
        out->strike_timeout_ms = XURY_DEFAULT_STRIKE_TIMEOUT_MS;
    }
    if (out->blitz_timeout_ms == 0u) {
        out->blitz_timeout_ms = XURY_DEFAULT_BLITZ_TIMEOUT_MS;
    }
    if (out->connect_timeout_ms == 0u) {
        out->connect_timeout_ms = XURY_DEFAULT_CONNECT_TIMEOUT_MS;
    }
    if (out->mapping_timeout_ms == 0u) {
        out->mapping_timeout_ms = XURY_DEFAULT_MAPPING_TIMEOUT_MS;
    }
    if (out->mirror_timeout_ms == 0u) {
        out->mirror_timeout_ms = XURY_DEFAULT_MIRROR_TIMEOUT_MS;
    }
    if (out->relay_timeout_ms == 0u) {
        out->relay_timeout_ms = XURY_DEFAULT_RELAY_TIMEOUT_MS;
    }

    if (out->max_parallel == 0u) {
        out->max_parallel = XURY_DEFAULT_MAX_PARALLEL;
    }

    if (out->cache_ttl_sec == 0u) {
        out->cache_ttl_sec = XURY_DEFAULT_CACHE_TTL_SEC;
    }

    if (out->learning_min_samples == 0u) {
        out->learning_min_samples = XURY_DEFAULT_LEARNING_MIN_SAMPLES;
    }

    /*
     * local_port: 0 means "let the OS choose". Not a default, it is
     * the intended value. Leave as-is.
     */

    return XURY_OK;
}
/* ---- continued from part 1/2 ---- */

/*
 * ============================================================================
 * NORMALIZATION
 * ============================================================================
 *
 * Clamp and enforce invariants on an already-defaulted config.
 *
 * This runs after xury_config_apply_defaults(), so every numeric field
 * is already non-zero. We only need to clamp values that the caller
 * may have set out of range, and enforce cross-field invariants.
 *
 * Cross-field invariants:
 *
 *   1. Aggressive weapons (BIRTHDAY, UPGRADE) are cleared unless
 *      enable_sweet_aggressive is true.
 *
 *   2. enable_sweet is cleared if both HOLE and PREDICT are disabled,
 *      because sweet has no way to create a path on its own.
 *
 *   3. enable_relay_upgrade is cleared if enable_relay is false,
 *      because upgrade requires a relay to upgrade from.
 *
 *   4. If force_strategy is set, weapons not used by that strategy are
 *      still left enabled. The orchestrator ignores them. This keeps
 *      the config copy faithful to what the caller wrote.
 */

/*
 * Clamp helper. Kept static.
 */
static uint32_t config_clamp(uint32_t v, uint32_t lo, uint32_t hi)
{
    if (v < lo) {
        return lo;
    }
    if (v > hi) {
        return hi;
    }
    return v;
}

xury_err_t xury_config_normalize(xury_config_t *cfg)
{
    if (cfg == NULL) {
        return XURY_ERR_INVAL;
    }

    /*
     * ----------------------------------------------------------------
     * Clamp numeric fields
     * ----------------------------------------------------------------
     */
    cfg->scan_timeout_ms = config_clamp(cfg->scan_timeout_ms,
                                        XURY_CONFIG_MIN_SCAN_MS,
                                        XURY_CONFIG_MAX_SCAN_MS);
    cfg->sensing_timeout_ms = config_clamp(cfg->sensing_timeout_ms,
                                           XURY_CONFIG_MIN_SENSING_MS,
                                           XURY_CONFIG_MAX_SENSING_MS);
    cfg->probing_timeout_ms = config_clamp(cfg->probing_timeout_ms,
                                           XURY_CONFIG_MIN_PROBING_MS,
                                           XURY_CONFIG_MAX_PROBING_MS);
    cfg->strike_timeout_ms = config_clamp(cfg->strike_timeout_ms,
                                          XURY_CONFIG_MIN_STRIKE_MS,
                                          XURY_CONFIG_MAX_STRIKE_MS);
    cfg->blitz_timeout_ms = config_clamp(cfg->blitz_timeout_ms,
                                         XURY_CONFIG_MIN_BLITZ_MS,
                                         XURY_CONFIG_MAX_BLITZ_MS);
    cfg->connect_timeout_ms = config_clamp(cfg->connect_timeout_ms,
                                           XURY_CONFIG_MIN_TIMEOUT_MS,
                                           XURY_CONFIG_MAX_TIMEOUT_MS);
    cfg->mapping_timeout_ms = config_clamp(cfg->mapping_timeout_ms,
                                           XURY_CONFIG_MIN_MAPPING_MS,
                                           XURY_CONFIG_MAX_MAPPING_MS);
    cfg->mirror_timeout_ms = config_clamp(cfg->mirror_timeout_ms,
                                          XURY_CONFIG_MIN_MIRROR_MS,
                                          XURY_CONFIG_MAX_MIRROR_MS);
    cfg->relay_timeout_ms = config_clamp(cfg->relay_timeout_ms,
                                         XURY_CONFIG_MIN_RELAY_MS,
                                         XURY_CONFIG_MAX_RELAY_MS);

    cfg->max_parallel = config_clamp(cfg->max_parallel,
                                     XURY_CONFIG_MIN_PARALLEL,
                                     XURY_CONFIG_MAX_PARALLEL);

    cfg->cache_ttl_sec = config_clamp(cfg->cache_ttl_sec,
                                      XURY_CONFIG_MIN_CACHE_TTL_SEC,
                                      XURY_CONFIG_MAX_CACHE_TTL_SEC);

    cfg->learning_min_samples = config_clamp(cfg->learning_min_samples,
                                             XURY_CONFIG_MIN_LEARN_SAMPLES,
                                             XURY_CONFIG_MAX_LEARN_SAMPLES);

    /*
     * ----------------------------------------------------------------
     * Invariant 1: aggressive weapons require opt-in
     * ----------------------------------------------------------------
     */
    if (!cfg->enable_sweet_aggressive) {
        cfg->enable_weapons &= ~XURY_WEAPON_BIT(XURY_WEAPON_BIRTHDAY);
        cfg->enable_weapons &= ~XURY_WEAPON_BIT(XURY_WEAPON_UPGRADE);
    }

    /*
     * ----------------------------------------------------------------
     * Invariant 2: sweet needs a traversal weapon to build on
     * ----------------------------------------------------------------
     *
     * If neither HOLE nor PREDICT is enabled, sweet has nothing to
     * exploit. Disable it rather than let it run with no effect.
     */
    {
        const uint32_t hole_bit =
            XURY_WEAPON_BIT(XURY_WEAPON_HOLE);
        const uint32_t predict_bit =
            XURY_WEAPON_BIT(XURY_WEAPON_PREDICT);

        if ((cfg->enable_weapons & (hole_bit | predict_bit)) == 0u) {
            cfg->enable_sweet = false;
        }
    }

    /*
     * ----------------------------------------------------------------
     * Invariant 3: relay upgrade requires relay
     * ----------------------------------------------------------------
     */
    if (!cfg->enable_relay) {
        cfg->enable_relay_upgrade = false;
    }

    /*
     * ----------------------------------------------------------------
     * Invariant 4: blitz requires at least one enabled weapon
     * ----------------------------------------------------------------
     *
     * If every weapon was disabled, blitz would spin on an empty set.
     * Turn blitz off rather than waste the caller's time budget.
     */
    if (cfg->enable_weapons == 0u) {
        cfg->enable_blitz = false;
        cfg->enable_strike = false;
    }

    /*
     * ----------------------------------------------------------------
     * Invariant 5: cache TTL sanity
     * ----------------------------------------------------------------
     *
     * A zero cache TTL would defeat the cache. The clamp above already
     * raised it to the minimum, so nothing to do here.
     */

    /*
     * ----------------------------------------------------------------
     * Invariant 6: interface string termination
     * ----------------------------------------------------------------
     *
     * Validation already checked it. Nothing to do.
     */

    return XURY_OK;
}

/*
 * ============================================================================
 * QUERY HELPERS
 * ============================================================================
 */

bool xury_config_weapon_enabled(const xury_config_t *cfg,
                                xury_weapon_t weapon)
{
    if (cfg == NULL) {
        return false;
    }
    if (!xury_weapon_is_valid(weapon)) {
        return false;
    }
    return (cfg->enable_weapons & XURY_WEAPON_BIT(weapon)) != 0u;
}

uint32_t xury_config_effective_connect_timeout(const xury_config_t *cfg)
{
    if (cfg == NULL || cfg->connect_timeout_ms == 0u) {
        return XURY_DEFAULT_CONNECT_TIMEOUT_MS;
    }
    return cfg->connect_timeout_ms;
}

/*
 * ============================================================================
 * FINGERPRINT
 * ============================================================================
 *
 * A stable 64-bit hash of the config fields that affect scan and
 * traversal behavior.
 *
 * Deliberately EXCLUDED:
 *   - hooks and their userdata (do not affect traversal)
 *   - allocator (does not affect traversal)
 *   - storage (does not affect traversal)
 *   - local_interface (a transport hint, not a semantic)
 *
 * Those fields may change between two runs of the same host without
 * invalidating the scan cache, so they must not be part of the hash.
 *
 * Deliberately INCLUDED:
 *   - enable_weapons
 *   - force_strategy
 *   - phase enables (scan / strike / blitz / early_term)
 *   - all timeouts
 *   - max_parallel
 *   - cache_ttl_sec
 *   - learning_min_samples
 *   - enable_sweet, enable_sweet_aggressive
 *   - enable_mirror, enable_relay, enable_relay_upgrade
 *   - struct_version
 *
 * Algorithm: FNV-1a 64-bit.
 *   offset basis: 14695981039346656037
 *   prime:        1099511628211
 *
 * Chosen because it is small, fast, deterministic, and has no
 * dependency on endianness beyond reading bytes in order.
 */

#define XURY_FNV64_OFFSET  14695981039346656037ull
#define XURY_FNV64_PRIME           1099511628211ull

static uint64_t config_fnv64_init(void)
{
    return XURY_FNV64_OFFSET;
}

static uint64_t config_fnv64_update_u8(uint64_t h, uint8_t b)
{
    h ^= (uint64_t)b;
    h *= XURY_FNV64_PRIME;
    return h;
}

static uint64_t config_fnv64_update_u32(uint64_t h, uint32_t v)
{
    /* Feed bytes little-endian for determinism across platforms. */
    h = config_fnv64_update_u8(h, (uint8_t)(v & 0xFFu));
    h = config_fnv64_update_u8(h, (uint8_t)((v >>  8) & 0xFFu));
    h = config_fnv64_update_u8(h, (uint8_t)((v >> 16) & 0xFFu));
    h = config_fnv64_update_u8(h, (uint8_t)((v >> 24) & 0xFFu));
    return h;
}

static uint64_t config_fnv64_update_bool(uint64_t h, bool b)
{
    return config_fnv64_update_u8(h, b ? 1u : 0u);
}

static uint64_t config_fnv64_update_str(uint64_t h, const char *s)
{
    if (s == NULL) {
        return config_fnv64_update_u8(h, 0u);
    }
    while (*s != '\0') {
        h = config_fnv64_update_u8(h, (uint8_t)(unsigned char)*s);
        s++;
    }
    /* Separator so "ab" + "c" != "a" + "bc" */
    h = config_fnv64_update_u8(h, 0xFFu);
    return h;
}

uint64_t xury_config_fingerprint(const xury_config_t *cfg)
{
    if (cfg == NULL) {
        return 0u;
    }

    uint64_t h = config_fnv64_init();

    /* Struct version: a change in layout invalidates the cache. */
    h = config_fnv64_update_u32(h, cfg->struct_version);

    /* Weapon selection. */
    h = config_fnv64_update_u32(h, cfg->enable_weapons);
    h = config_fnv64_update_u32(h, (uint32_t)cfg->force_strategy);

    /* Phase enables. */
    h = config_fnv64_update_bool(h, cfg->enable_scan);
    h = config_fnv64_update_bool(h, cfg->enable_strike);
    h = config_fnv64_update_bool(h, cfg->enable_blitz);
    h = config_fnv64_update_bool(h, cfg->enable_early_term);

    /* Timeouts. */
    h = config_fnv64_update_u32(h, cfg->scan_timeout_ms);
    h = config_fnv64_update_u32(h, cfg->sensing_timeout_ms);
    h = config_fnv64_update_u32(h, cfg->probing_timeout_ms);
    h = config_fnv64_update_u32(h, cfg->strike_timeout_ms);
    h = config_fnv64_update_u32(h, cfg->blitz_timeout_ms);
    h = config_fnv64_update_u32(h, cfg->connect_timeout_ms);
    h = config_fnv64_update_u32(h, cfg->mapping_timeout_ms);
    h = config_fnv64_update_u32(h, cfg->mirror_timeout_ms);
    h = config_fnv64_update_u32(h, cfg->relay_timeout_ms);

    /* Parallelism and tuning. */
    h = config_fnv64_update_u32(h, cfg->max_parallel);
    h = config_fnv64_update_u32(h, cfg->cache_ttl_sec);
    h = config_fnv64_update_u32(h, cfg->learning_min_samples);

    /* Subsystem enables. */
    h = config_fnv64_update_bool(h, cfg->enable_cache);
    h = config_fnv64_update_bool(h, cfg->enable_learning);
    h = config_fnv64_update_bool(h, cfg->enable_sweet);
    h = config_fnv64_update_bool(h, cfg->enable_sweet_aggressive);
    h = config_fnv64_update_bool(h, cfg->enable_mirror);
    h = config_fnv64_update_bool(h, cfg->enable_relay);
    h = config_fnv64_update_bool(h, cfg->enable_relay_upgrade);

    /*
     * local_interface is a transport hint, but it does change which
     * subnet we bind to, which can change the scan result. Include it
     * but as a short string, not a pointer.
     */
    h = config_fnv64_update_str(h, cfg->local_interface);

    /*
     * local_port: 0 means "OS chooses", which is the common case and
     * should hash the same across runs. Non-zero is a semantic choice
     * and must be included.
     */
    h = config_fnv64_update_u32(h, (uint32_t)cfg->local_port);

    return h;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
 
