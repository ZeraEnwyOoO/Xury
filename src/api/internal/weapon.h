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

#ifndef XURY_API_INTERNAL_WEAPON_H
#define XURY_API_INTERNAL_WEAPON_H

/*
 * ============================================================================
 * XURY INTERNAL WEAPON HELPERS
 * ============================================================================
 *
 * Internal helpers used by src/api/weapon.c, the orchestrator, the
 * analysis layer, and the blitz layer.
 *
 * Public API (include/xury/weapon.h) already exposes:
 *
 *   xury_weapon_get_info()
 *   xury_weapon_tag()
 *   xury_weapon_name()
 *   xury_weapon_category()
 *   xury_weapon_category_tag()
 *   xury_weapon_has_flag()
 *   xury_weapon_is_valid()  (inline)
 *
 * Public macros:
 *
 *   XURY_WEAPONS_DIRECT / ROUTER / TRAVERSAL / PEER
 *   XURY_WEAPONS_AGGRESSIVE / SAFE / ALL
 *   XURY_WEAPON_BIT(w)
 *
 * This header adds:
 *
 *   - the static metadata table (for iteration)
 *   - prior strength / cost as plain integers (public struct uses u8)
 *   - applicability checks against a scan result (declared here so the
 *     scan layer can include weapon.h without pulling in scan.h)
 *   - priority ordering used when no scan result is available
 *   - bitmask iteration helpers
 *
 * Rules:
 *   - Never expose these in include/xury/.
 *   - Never call them from public headers.
 *   - All functions are pure: no allocation, no I/O.
 *   - No dependency on scan internals: applicability takes only
 *     pre-extracted flags.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/types.h>
#include <xury/weapon.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * APPLICABILITY FLAGS
 * ============================================================================
 *
 * A compact summary of a scan result that the weapon layer cares about.
 * Filled by the analysis layer and passed to xury_weapon_applicable().
 *
 * Kept independent of xury_scan_result_t to avoid a header cycle.
 */

typedef struct {
    /* Network facts */
    bool ipv6_present;      /* any IPv6 on the host */
    bool ipv6_global;       /* global IPv6 usable */
    bool peer_has_ipv6;     /* peer answered an IPv6 probe */
    bool peer_is_lan;       /* peer is on the same LAN */
    bool peer_reachable;    /* peer endpoint responded on UDP */

    /* Router capabilities */
    bool upnp_available;
    bool natpmp_available;
    bool pcp_available;

    /* NAT classification */
    bool symmetric;         /* NAT appears symmetric */
    bool cgnat;             /* NAT appears to be CGNAT */
    bool port_predictable;  /* observed external ports are predictable */

    /* Peer-assisted resources */
    bool helper_available;  /* at least one reachable mirror/relay peer */

    /* Host preferences */
    bool allow_aggressive;  /* aggressive weapons permitted */
} xury_weapon_context_t;

/*
 * ============================================================================
 * METADATA TABLE
 * ============================================================================
 *
 * The static table of all weapon descriptors. Entries are indexed by
 * the weapon enum value (XURY_WEAPON_IPV6 == 1, etc.).
 *
 * Index 0 (XURY_WEAPON_NONE) is a sentinel with all-zero fields.
 *
 * The table is exactly XURY_WEAPON_COUNT entries long.
 */

/*
 * Return the number of entries in the table.
 * Always equals XURY_WEAPON_COUNT.
 */
size_t xury_weapon_table_size(void);

/*
 * Return the descriptor at index i.
 *
 * Returns NULL if i >= xury_weapon_table_size().
 * For XURY_WEAPON_NONE (i == 0) returns a valid all-zero descriptor,
 * not NULL.
 */
const xury_weapon_info_t *xury_weapon_table_at(size_t i);

/*
 * Return the descriptor for a weapon, or NULL if the enum is invalid.
 * Never returns NULL for a value in (0, XURY_WEAPON_COUNT).
 */
const xury_weapon_info_t *xury_weapon_info_or_null(xury_weapon_t w);

/*
 * ============================================================================
 * PRIOR STRENGTH / COST
 * ============================================================================
 *
 * The public struct stores these as uint8_t. These helpers return them
 * widened, so callers can do arithmetic without casts.
 *
 * Both are 0..100.
 */

uint32_t xury_weapon_base_strength(xury_weapon_t w);
uint32_t xury_weapon_base_cost(xury_weapon_t w);

/*
 * Priority used when there is no scan result to guide selection.
 *
 * Lower value = tried earlier. Range 1..N.
 *
 * Order (matching include/xury/weapon.h documentation):
 *
 *   1  IPV6
 *   2  LAN
 *   3  UPNP
 *   4  NATPMP
 *   5  PCP
 *   6  HOLE
 *   7  PREDICT
 *   8  MIRROR
 *   9  RELAY
 *  10  UPGRADE
 *  11  BIRTHDAY
 *
 * Returns 0 for XURY_WEAPON_NONE or an invalid weapon.
 */
uint32_t xury_weapon_priority(xury_weapon_t w);

/*
 * Return the weapon at a given priority (inverse of xury_weapon_priority).
 *
 * Returns XURY_WEAPON_NONE if priority is out of range.
 */
xury_weapon_t xury_weapon_at_priority(uint32_t priority);

/*
 * ============================================================================
 * APPLICABILITY
 * ============================================================================
 *
 * Decide whether a weapon is worth trying in the given context.
 *
 * This is a pure, side-effect-free decision. It is advisory: the
 * orchestrator may still try a weapon that is not applicable if the
 * caller forces it, but it will not waste time on weapons that clearly
 * cannot work.
 *
 * Rules:
 *   - A weapon that is disabled in the config is never applicable.
 *     (Config bits are checked by the caller; this function assumes
 *     the weapon is enabled.)
 *   - NEEDS_IPV6 / NEEDS_GLOBAL_V6 / NEEDS_UPNP / NEEDS_NATPMP /
 *     NEEDS_PCP / NEEDS_PEER flags are honored.
 *   - AGGRESSIVE weapons require ctx->allow_aggressive.
 *   - For a NAT type that makes a weapon pointless, the weapon is
 *     rejected (e.g. PREDICT when ports are not predictable).
 */

/*
 * Return true if the weapon can be attempted given the context.
 *
 * Returns false for XURY_WEAPON_NONE or an invalid weapon.
 */
bool xury_weapon_applicable(xury_weapon_t w,
                            const xury_weapon_context_t *ctx);

/*
 * Fill a bitmask of applicable weapons for the given context.
 *
 * The result is a subset of XURY_WEAPON_ALL_MASK.
 *
 * If ctx is NULL, all non-aggressive weapons are marked applicable.
 */
uint32_t xury_weapon_applicable_mask(const xury_weapon_context_t *ctx);

/*
 * ============================================================================
 * BITMASK ITERATION
 * ============================================================================
 *
 * Helper to walk a weapon bitmask in priority order.
 *
 * Typical use:
 *
 *   uint32_t mask = xury_weapon_applicable_mask(&ctx);
 *   xury_weapon_t w = XURY_WEAPON_NONE;
 *   while ((w = xury_weapon_mask_next(&mask, w)) != XURY_WEAPON_NONE) {
 *       try(w);
 *   }
 *
 * The mask is passed by pointer because each call clears the bit it
 * returns.
 */

/*
 * Return the highest-priority weapon that is set in *mask and comes
 * after prev, then clear its bit in *mask.
 *
 * If prev is XURY_WEAPON_NONE, start from the top of the priority list.
 *
 * Returns XURY_WEAPON_NONE when *mask has no more bits set.
 */
xury_weapon_t xury_weapon_mask_next(uint32_t *mask, xury_weapon_t prev);

/*
 * Count how many weapons are set in a mask.
 */
size_t xury_weapon_mask_count(uint32_t mask);

/*
 * Format a mask into buf as a comma-separated list of tags, in priority
 * order.
 *
 * Example: "ipv6,upnp,hole"
 *
 * Writes at most buflen - 1 bytes and always NUL-terminates.
 *
 * Returns the number of bytes that WOULD have been written, excluding
 * the NUL, so the caller can detect truncation.
 */
size_t xury_weapon_mask_format(uint32_t mask,
                               char *buf,
                               size_t buflen);

/*
 * ============================================================================
 * PARSING
 * ============================================================================
 *
 * Convert tags to weapons and back. Used by config parsing and by tests.
 */

/*
 * Parse a single weapon tag.
 *
 * Recognized tags (case-insensitive):
 *
 *   "none"
 *   "ipv6", "lan"
 *   "upnp", "natpmp", "pcp"
 *   "hole", "predict", "birthday"
 *   "mirror", "relay", "upgrade"
 *
 * Returns XURY_WEAPON_NONE if the tag is unknown.
 * (XURY_WEAPON_NONE is ambiguous with a failed parse; callers that
 * need to distinguish should check the tag against "none" explicitly.)
 */
xury_weapon_t xury_weapon_from_tag(const char *tag);

/*
 * Parse a comma-separated list of weapon tags into a mask.
 *
 * Whitespace around tags is ignored. Unknown tags are skipped and
 * reported through *out_unknown (optional).
 *
 * Returns the parsed mask.
 */
uint32_t xury_weapon_mask_from_string(const char *str,
                                      size_t *out_unknown);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY INTERNAL WEAPON HEADER
 * ============================================================================
 */

#endif /* XURY_API_INTERNAL_WEAPON_H */
