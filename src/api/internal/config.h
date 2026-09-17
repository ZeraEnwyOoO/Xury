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

#ifndef XURY_API_INTERNAL_CONFIG_H
#define XURY_API_INTERNAL_CONFIG_H

/*
 * ============================================================================
 * XURY INTERNAL CONFIG HELPERS
 * ============================================================================
 *
 * Internal helpers used by src/api/config.c and by the engine at startup.
 *
 * This header is NOT installed. It is private to the Xury build.
 *
 * The public config struct (xury_config_t) is declared in
 * include/xury/config.h. This header adds private operations that must
 * NOT be part of the public ABI:
 *
 *   - validation
 *   - defaulting (zero -> default)
 *   - normalization (clamping, trimming)
 *   - hashing (for caching by config)
 *
 * Rules:
 *   - Never expose these functions in include/xury/.
 *   - Never call them from public headers.
 *   - Keep them free of I/O and allocation.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/config.h>
#include <xury/err.h>
#include <xury/weapon.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * VALIDATION
 * ============================================================================
 *
 * xury_config_validate() checks a caller-supplied config for:
 *
 *   - struct_version is 0 or XURY_CONFIG_VERSION
 *   - force_strategy is a known enum value
 *   - enable_weapons has no bits set above XURY_WEAPON_COUNT
 *   - XURY_WEAPON_NONE bit is not set
 *   - timeouts are either 0 or >= XURY_CONFIG_MIN_TIMEOUT_MS
 *   - max_parallel is either 0 or in [1, XURY_CONFIG_MAX_PARALLEL]
 *   - local_interface is NUL-terminated within its array
 *   - allocator: all three callbacks set, or all NULL
 *   - storage:   both callbacks set, or both NULL
 *
 * Zero always means "use default" for numeric fields.
 *
 * Returns:
 *   XURY_OK        — config is valid
 *   XURY_ERR_INVAL — one or more fields are invalid
 *
 * Does not modify cfg.
 */
xury_err_t xury_config_validate(const xury_config_t *cfg);

/*
 * ============================================================================
 * DEFAULTING
 * ============================================================================
 *
 * xury_config_apply_defaults() copies a caller config into an internal
 * fully-resolved form. Every zero-valued field is replaced with the
 * default. Every NULL hook stays NULL.
 *
 * The internal form is what the engine actually uses. It has no zero
 * fields (except NULL pointers and intentional zeros like local_port).
 *
 * Returns:
 *   XURY_OK        — out filled, caller config unchanged
 *   XURY_ERR_INVAL — cfg or out is NULL
 *
 * Preconditions:
 *   cfg must already pass xury_config_validate().
 */
xury_err_t xury_config_apply_defaults(const xury_config_t *cfg,
                                      xury_config_t *out);

/*
 * ============================================================================
 * NORMALIZATION
 * ============================================================================
 *
 * xury_config_normalize() clamps and trims an already-defaulted config:
 *
 *   - scan_timeout_ms     -> [100, 60000]
 *   - sensing_timeout_ms  -> [50,  10000]
 *   - probing_timeout_ms  -> [50,  10000]
 *   - strike_timeout_ms   -> [100, 60000]
 *   - blitz_timeout_ms    -> [100, 120000]
 *   - connect_timeout_ms  -> [100, 300000]
 *   - mapping_timeout_ms  -> [100, 30000]
 *   - mirror_timeout_ms   -> [100, 30000]
 *   - relay_timeout_ms    -> [100, 60000]
 *   - max_parallel        -> [1, 64]
 *   - cache_ttl_sec       -> [60, 86400]
 *   - learning_min_samples-> [1, 100]
 *
 * It also:
 *   - forces XURY_WEAPON_BIRTHDAY and XURY_WEAPON_UPGRADE off unless
 *     enable_sweet_aggressive is true
 *   - clears enable_sweet entirely if XURY_WEAPON_HOLE and
 *     XURY_WEAPON_PREDICT are both disabled (sweet needs a way out)
 *
 * Operates in place.
 *
 * Returns:
 *   XURY_OK        — normalized
 *   XURY_ERR_INVAL — cfg is NULL
 */
xury_err_t xury_config_normalize(xury_config_t *cfg);

/*
 * ============================================================================
 * QUERY HELPERS
 * ============================================================================
 */

/*
 * True if the weapon is enabled in the config's bitmask.
 */
bool xury_config_weapon_enabled(const xury_config_t *cfg,
                                xury_weapon_t weapon);

/*
 * Return the effective connect timeout, in milliseconds, honoring the
 * caller's zero-as-default convention. Never returns 0.
 */
uint32_t xury_config_effective_connect_timeout(const xury_config_t *cfg);

/*
 * ============================================================================
 * FINGERPRINT
 * ============================================================================
 *
 * A stable 64-bit hash of the parts of the config that affect scan and
 * traversal behavior.
 *
 * Used to detect config changes that must invalidate the scan cache.
 * Hooks, userdata, allocator and storage are intentionally EXCLUDED:
 * they do not change traversal semantics.
 *
 * Deterministic: same config fields -> same hash across runs.
 * Not cryptographic.
 */
uint64_t xury_config_fingerprint(const xury_config_t *cfg);

/*
 * ============================================================================
 * BOUNDS (used by validation and normalization)
 * ============================================================================
 */

#define XURY_CONFIG_MIN_TIMEOUT_MS          100u
#define XURY_CONFIG_MAX_TIMEOUT_MS       300000u

#define XURY_CONFIG_MIN_SCAN_MS             100u
#define XURY_CONFIG_MAX_SCAN_MS           60000u

#define XURY_CONFIG_MIN_SENSING_MS           50u
#define XURY_CONFIG_MAX_SENSING_MS        10000u

#define XURY_CONFIG_MIN_PROBING_MS           50u
#define XURY_CONFIG_MAX_PROBING_MS        10000u

#define XURY_CONFIG_MIN_STRIKE_MS           100u
#define XURY_CONFIG_MAX_STRIKE_MS         60000u

#define XURY_CONFIG_MIN_BLITZ_MS            100u
#define XURY_CONFIG_MAX_BLITZ_MS         120000u

#define XURY_CONFIG_MIN_MAPPING_MS          100u
#define XURY_CONFIG_MAX_MAPPING_MS        30000u

#define XURY_CONFIG_MIN_MIRROR_MS           100u
#define XURY_CONFIG_MAX_MIRROR_MS         30000u

#define XURY_CONFIG_MIN_RELAY_MS            100u
#define XURY_CONFIG_MAX_RELAY_MS          60000u

#define XURY_CONFIG_MIN_PARALLEL              1u
#define XURY_CONFIG_MAX_PARALLEL             64u

#define XURY_CONFIG_MIN_CACHE_TTL_SEC        60u
#define XURY_CONFIG_MAX_CACHE_TTL_SEC     86400u

#define XURY_CONFIG_MIN_LEARN_SAMPLES         1u
#define XURY_CONFIG_MAX_LEARN_SAMPLES       100u

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY INTERNAL CONFIG HEADER
 * ============================================================================
 */

#endif /* XURY_API_INTERNAL_CONFIG_H */
