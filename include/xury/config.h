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
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/version.h>
#include <xury/types.h>
#include <xury/err.h>
#include <xury/hooks.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XURY_CONFIG_VERSION 1u

typedef struct {
    /*
     * ------------------------------------------------------------------------
     * STRUCT VERSION
     * ------------------------------------------------------------------------
     */
    uint32_t struct_version;

    /*
     * ------------------------------------------------------------------------
     * WEAPON CONTROL
     * ------------------------------------------------------------------------
     */
    uint32_t enable_weapons;

    /*
     * Strategy override.
     */
    xury_strategy_t force_strategy;

    /*
     * ------------------------------------------------------------------------
     * PHASE CONTROL
     * ------------------------------------------------------------------------
     */
    bool enable_scan;
    bool enable_strike;
    bool enable_blitz;
    bool enable_early_term;

    /*
     * ------------------------------------------------------------------------
     * TIMEOUTS (milliseconds)
     * ------------------------------------------------------------------------
     */
    uint32_t scan_timeout_ms;
    uint32_t sensing_timeout_ms;
    uint32_t probing_timeout_ms;
    uint32_t strike_timeout_ms;
    uint32_t blitz_timeout_ms;
    uint32_t connect_timeout_ms;
    uint32_t mapping_timeout_ms;
    uint32_t mirror_timeout_ms;
    uint32_t relay_timeout_ms;

    /*
     * ------------------------------------------------------------------------
     * PARALLELISM
     * ------------------------------------------------------------------------
     */
    uint32_t max_parallel;

    /*
     * ------------------------------------------------------------------------
     * LOCAL BINDING
     * ------------------------------------------------------------------------
     */
    uint16_t local_port;
    char     local_interface[32];

    /*
     * ------------------------------------------------------------------------
     * CACHE
     * ------------------------------------------------------------------------
     */
    bool     enable_cache;
    uint32_t cache_ttl_sec;

    /*
     * ------------------------------------------------------------------------
     * LEARNING
     * ------------------------------------------------------------------------
     */
    bool     enable_learning;
    uint32_t learning_min_samples;

    /*
     * ------------------------------------------------------------------------
     * SWEET (CGNAT)
     * ------------------------------------------------------------------------
     */
    bool enable_sweet;
    bool enable_sweet_aggressive;

    /*
     * ------------------------------------------------------------------------
     * MIRROR / RELAY (peer-assisted)
     * ------------------------------------------------------------------------
     */
    bool enable_mirror;
    bool enable_relay;
    bool enable_relay_upgrade;

    /*
     * ------------------------------------------------------------------------
     * HOOKS (callbacks)
     * ------------------------------------------------------------------------
     *
     * All hooks are optional (NULL = ignore).
     * See hooks.h for the callback typedefs.
     */
    void (*on_log)(xury_log_level_t level, const char *msg, void *userdata);
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
     */
    const xury_allocator_t *allocator;

    /*
     * ------------------------------------------------------------------------
     * STORAGE
     * ------------------------------------------------------------------------
     */
    const xury_storage_iface_t *storage;

} xury_config_t;

/*
 * ============================================================================
 * DEFAULT CONFIG
 * ============================================================================
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

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY CONFIG HEADER
 * ============================================================================
 */

#endif /* XURY_CONFIG_H */
