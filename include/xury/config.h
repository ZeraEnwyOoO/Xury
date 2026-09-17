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

#ifndef XURY_CONFIG_H
#define XURY_CONFIG_H

/*
 * ============================================================================
 * XURY CONFIGURATION
 * ============================================================================
 *
 * xury_config_t is passed to xury_create().
 *
 * Rules:
 *   - All fields are optional.
 *   - Zero-initialized config (or NULL) selects defaults.
 *   - Defaults are sane for WAN usage.
 *   - Fields are grouped by purpose.
 *   - No field changes behavior silently.
 *
 * Default policy:
 *   - Enable all weapons that are safe by default.
 *   - Disable aggressive / experimental options.
 *   - Timeouts tuned for WAN with mobile-friendly fallbacks.
 *
 * Usage:
 *
 *   xury_config_t cfg = {0};           // all defaults
 *   xury_engine_t *e = xury_create(&cfg);
 *
 * Or:
 *
 *   xury_engine_t *e = xury_create(NULL);  // same as {0}
 *
 * Or fine-grained:
 *
 *   xury_config_t cfg = {
 *       .enable_weapons    = XURY_WEAPON_BIT(XURY_WEAPON_IPV6) |
 *                            XURY_WEAPON_BIT(XURY_WEAPON_HOLE),
 *       .connect_timeout_ms = 15000,
 *   };
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/version.h>
#include <xury/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * CONFIG STRUCT
 * ============================================================================
 *
 * IMPORTANT: This struct is passed by pointer and copied by xury_create().
 * The host may free it immediately after xury_create() returns.
 *
 * The struct is versioned via the "struct_version" field so that ABI
 * changes can be handled gracefully. Host must set it to
 * XURY_CONFIG_VERSION. Zero means "use current version".
 */

#define XURY_CONFIG_VERSION 1u

typedef struct {
    /*
     * ------------------------------------------------------------------------
     * STRUCT VERSION
     * ------------------------------------------------------------------------
     *
     * Set to XURY_CONFIG_VERSION, or leave 0 for current.
     */
    uint32_t struct_version;

    /*
     * ------------------------------------------------------------------------
     * WEAPON CONTROL
     * ------------------------------------------------------------------------
     *
     * Bitmask of enabled weapons.
     *
     * Bit N corresponds to weapon N:
     *   bit 0  XURY_WEAPON_NONE      (never enabled)
     *   bit 1  XURY_WEAPON_IPV6
     *   bit 2  XURY_WEAPON_LAN
     *   bit 3  XURY_WEAPON_UPNP
     *   bit 4  XURY_WEAPON_NATPMP
     *   bit 5  XURY_WEAPON_PCP
     *   bit 6  XURY_WEAPON_HOLE
     *   bit 7  XURY_WEAPON_PREDICT
     *   bit 8  XURY_WEAPON_BIRTHDAY
     *   bit 9  XURY_WEAPON_MIRROR
     *   bit 10 XURY_WEAPON_RELAY
     *   bit 11 XURY_WEAPON_UPGRADE
     *
     * If 0, XURY_DEFAULT_WEAPONS is used.
     *
     * Use XURY_WEAPON_BIT(w) to build the mask.
     */
    uint32_t enable_weapons;

    /*
     * Strategy override.
     *
     * XURY_STRATEGY_AUTO  — engine chooses (default)
     * Other values        — force a specific strategy
     *
     * If forcing a strategy, incompatible weapons are ignored.
     */
    xury_strategy_t force_strategy;

    /*
     * ------------------------------------------------------------------------
     * PHASE CONTROL
     * ------------------------------------------------------------------------
     *
     * Enable / disable each phase of the 3-pillar model.
     *
     * Defaults (when 0):
     *   enable_scan   = true
     *   enable_strike = true
     *   enable_blitz  = true
     *
     * Host may disable blitz to save bandwidth, or disable strike
     * to jump straight to blitz (unusual).
     */
    bool enable_scan;
    bool enable_strike;
    bool enable_blitz;

    /*
     * Early termination.
     *
     * If true and a very strong signal is found during scan
     * (IPv6 global, LAN peer, public IP), skip remaining scan steps.
     *
     * Default: true
     */
    bool enable_early_term;

    /*
     * ------------------------------------------------------------------------
     * TIMEOUTS (milliseconds)
     * ------------------------------------------------------------------------
     *
     * All timeouts are wall-clock durations, not deadlines.
     *
     * 0 means "use default". Negative values are rejected.
     */

    /* Scan phase total budget. Default: 1500 */
    uint32_t scan_timeout_ms;

    /* Sensing sub-phase budget. Default: 500 */
    uint32_t sensing_timeout_ms;

    /* Probing sub-phase budget. Default: 1000 */
    uint32_t probing_timeout_ms;

    /* Strike phase: time for the chosen weapon. Default: 5000 */
    uint32_t strike_timeout_ms;

    /* Blitz phase: parallel weapons, total budget. Default: 15000 */
    uint32_t blitz_timeout_ms;

    /* Full connect() budget across all phases. Default: 30000 */
    uint32_t connect_timeout_ms;

    /* Single port-mapping request (UPnP/NAT-PMP/PCP). Default: 3000 */
    uint32_t mapping_timeout_ms;

    /* Peer-as-mirror query. Default: 3000 */
    uint32_t mirror_timeout_ms;

    /* Peer relay setup. Default: 5000 */
    uint32_t relay_timeout_ms;

    /*
     * ------------------------------------------------------------------------
     * PARALLELISM
     * ------------------------------------------------------------------------
     *
     * Upper bound on parallel probes / weapons.
     *
     * Default: 8.
     * Set to 1 to force sequential behavior.
     */
    uint32_t max_parallel;

    /*
     * ------------------------------------------------------------------------
     * LOCAL BINDING
     * ------------------------------------------------------------------------
     *
     * Local port to bind for outbound probes.
     *
     * 0    — let the OS choose
     * else — attempt this exact port; if in use, error
     *
     * Default: 0.
     */
    uint16_t local_port;

    /*
     * Interface hint.
     *
     * Empty string means "any interface".
     *
     * On Linux this is the interface name (e.g. "wlan0").
     * On Android, ignored (system chooses).
     */
    char local_interface[32];

    /*
     * ------------------------------------------------------------------------
     * CACHE
     * ------------------------------------------------------------------------
     *
     * Enable scan cache.
     *
     * If true, the result of a successful scan is cached and keyed by
     * the local network fingerprint (gateway MAC, subnet). Subsequent
     * scans on the same network reuse the cache.
     *
     * Default: true.
     */
    bool enable_cache;

    /*
     * Cache TTL in seconds.
     *
     * 0 means "default" (3600 = 1 hour).
     *
     * Cache is automatically invalidated when:
     *   - gateway MAC changes
     *   - gateway IP changes
     *   - cache entry is older than TTL
     *   - a connect() fails on cached data
     */
    uint32_t cache_ttl_sec;

    /*
     * ------------------------------------------------------------------------
     * LEARNING
     * ------------------------------------------------------------------------
     *
     * Adjust weapon preference based on observed success/failure.
     *
     * If true, Xury tracks per-network weapon statistics and
     * deprioritizes weapons that consistently fail.
     *
     * Default: true.
     */
    bool enable_learning;

    /*
     * Minimum number of samples before a weapon is penalized.
     * Default: 5.
     */
    uint32_t learning_min_samples;

    /*
     * ------------------------------------------------------------------------
     * SWEET (CGNAT)
     * ------------------------------------------------------------------------
     *
     * Enable CGNAT persuasion subsystem.
     *
     * If false, CGNAT is detected but no exploit is attempted.
     *
     * Default: true.
     */
    bool enable_sweet;

    /*
     * Enable aggressive techniques inside sweet:
     *   - birthday paradox port scan
     *   - traffic mimicry (HTTPS/QUIC/DNS)
     *
     * These cost bandwidth and may be flagged by some ISPs.
     * Default: false.
     */
    bool enable_sweet_aggressive;

    /*
     * ------------------------------------------------------------------------
     * MIRROR / RELAY (peer-assisted)
     * ------------------------------------------------------------------------
     *
     * Allow Xury to use peer-as-mirror to discover the local public
     * endpoint. Requires at least one reachable peer provided by host.
     *
     * Default: true.
     */
    bool enable_mirror;

    /*
     * Allow Xury to use a peer as relay when direct traversal fails.
     * Requires host to supply a relay-capable peer.
     *
     * Default: true.
     */
    bool enable_relay;

    /*
     * Attempt to upgrade a relay connection to a direct connection
     * once conditions allow. Purely an optimization.
     *
     * Default: true.
     */
    bool enable_relay_upgrade;

    /*
     * ------------------------------------------------------------------------
     * HOOKS (callbacks)
     * ------------------------------------------------------------------------
     *
     * All hooks are optional (NULL = ignore).
     *
     * Hooks are invoked synchronously on the caller thread of
     * xury_scan() / xury_connect() unless documented otherwise.
     *
     * Hook implementations must be fast and must not call back into
     * Xury from the same engine.
     *
     * See hooks.h for the callback typedefs.
     */
    void (*on_log)(int level, const char *msg, void *userdata);
    void *log_userdata;

    void (*on_phase)(xury_phase_t phase, void *userdata);
    void *phase_userdata;

    void (*on_scan_done)(const void *scan_result, void *userdata);
    void *scan_userdata;

    void (*on_weapon_result)(xury_weapon_t weapon,
                             xury_err_t    result,
                             void         *userdata);
    void *weapon_userdata;

    /*
     * ------------------------------------------------------------------------
     * CUSTOM ALLOCATOR
     * ------------------------------------------------------------------------
     *
     * Optional. If NULL, malloc/realloc/free are used.
     */
    const xury_allocator_t *allocator;

    /*
     * ------------------------------------------------------------------------
     * STORAGE
     * ------------------------------------------------------------------------
     *
     * Optional. If NULL, cache is memory-only for this engine.
     *
     * If provided, the cache can survive process restart.
     */
    const xury_storage_iface_t *storage;

} xury_config_t;

/*
 * ============================================================================
 * DEFAULT CONFIG
 * ============================================================================
 *
 * A compile-time constant that represents the recommended defaults.
 *
 * Host code can do:
 *
 *   xury_config_t cfg = XURY_CONFIG_DEFAULT;
 *   cfg.connect_timeout_ms = 60000;
 *   xury_engine_t *e = xury_create(&cfg);
 *
 * Never rely on the exact contents of this macro across releases.
 * Use individual fields to change what you care about.
 */

#define XURY_DEFAULT_WEAPONS \
    ( XURY_WEAPON_BIT(XURY_WEAPON_IPV6)    | \
      XURY_WEAPON_BIT(XURY_WEAPON_LAN)     | \
      XURY_WEAPON_BIT(XURY_WEAPON_UPNP)    | \
      XURY_WEAPON_BIT(XURY_WEAPON_NATPMP)  | \
      XURY_WEAPON_BIT(XURY_WEAPON_PCP)     | \
      XURY_WEAPON_BIT(XURY_WEAPON_HOLE)    | \
      XURY_WEAPON_BIT(XURY_WEAPON_PREDICT) | \
      XURY_WEAPON_BIT(XURY_WEAPON_MIRROR)  | \
      XURY_WEAPON_BIT(XURY_WEAPON_RELAY) )

#define XURY_DEFAULT_SCAN_TIMEOUT_MS      1500u
#define XURY_DEFAULT_SENSING_TIMEOUT_MS    500u
#define XURY_DEFAULT_PROBING_TIMEOUT_MS   1000u
#define XURY_DEFAULT_STRIKE_TIMEOUT_MS    5000u
#define XURY_DEFAULT_BLITZ_TIMEOUT_MS    15000u
#define XURY_DEFAULT_CONNECT_TIMEOUT_MS  30000u
#define XURY_DEFAULT_MAPPING_TIMEOUT_MS   3000u
#define XURY_DEFAULT_MIRROR_TIMEOUT_MS    3000u
#define XURY_DEFAULT_RELAY_TIMEOUT_MS     5000u
#define XURY_DEFAULT_MAX_PARALLEL            8u
#define XURY_DEFAULT_CACHE_TTL_SEC        3600u
#define XURY_DEFAULT_LEARNING_MIN_SAMPLES    5u

#define XURY_CONFIG_DEFAULT                              \
    {                                                    \
        .struct_version         = XURY_CONFIG_VERSION,   \
        .enable_weapons         = XURY_DEFAULT_WEAPONS,  \
        .force_strategy         = XURY_STRATEGY_AUTO,    \
        .enable_scan            = true,                  \
        .enable_strike          = true,                  \
        .enable_blitz           = true,                  \
        .enable_early_term      = true,                  \
        .scan_timeout_ms        = 0,                     \
        .sensing_timeout_ms     = 0,                     \
        .probing_timeout_ms     = 0,                     \
        .strike_timeout_ms      = 0,                     \
        .blitz_timeout_ms       = 0,                     \
        .connect_timeout_ms     = 0,                     \
        .mapping_timeout_ms     = 0,                     \
        .mirror_timeout_ms      = 0,                     \
        .relay_timeout_ms       = 0,                     \
        .max_parallel           = 0,                     \
        .local_port             = 0,                     \
        .local_interface        = {0},                   \
        .enable_cache           = true,                  \
        .cache_ttl_sec          = 0,                     \
        .enable_learning        = true,                  \
        .learning_min_samples   = 0,                     \
        .enable_sweet           = true,                  \
        .enable_sweet_aggressive= false,                 \
        .enable_mirror          = true,                  \
        .enable_relay           = true,                  \
        .enable_relay_upgrade   = true,                  \
        .on_log                 = NULL,                  \
        .log_userdata           = NULL,                  \
        .on_phase               = NULL,                  \
        .phase_userdata         = NULL,                  \
        .on_scan_done           = NULL,                  \
        .scan_userdata          = NULL,                  \
        .on_weapon_result       = NULL,                  \
        .weapon_userdata        = NULL,                  \
        .allocator              = NULL,                  \
        .storage                = NULL,                  \
    }

/*
 * ============================================================================
 * VALIDATION
 * ============================================================================
 *
 * xury_create() validates the config. Invalid configs are rejected with
 * XURY_ERR_INVAL. The following rules are enforced:
 *
 *   - struct_version is 0 or XURY_CONFIG_VERSION
 *   - force_strategy is a known value
 *   - enable_weapons has no bits set above XURY_WEAPON_COUNT
 *   - XURY_WEAPON_NONE bit is not set
 *   - timeouts are either 0 or >= 100ms
 *   - max_parallel is either 0 or in [1, 64]
 *   - local_interface is NUL-terminated within its array
 *   - allocator: either all three callbacks set, or all NULL
 *   - storage:   either both callbacks set, or both NULL
 *
 * Zero always means "use default" for numeric fields.
 *
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY CONFIG HEADER
 * ============================================================================
 */

#endif /* XURY_CONFIG_H */
