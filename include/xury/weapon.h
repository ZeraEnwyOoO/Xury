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

#ifndef XURY_WEAPON_H
#define XURY_WEAPON_H

/*
 * ============================================================================
 * XURY WEAPONS
 * ============================================================================
 *
 * A "weapon" is a single NAT traversal technique.
 *
 * Weapons are chosen by the orchestrator based on scan results.
 * Multiple weapons may be attempted in STRIKE mode (one) or BLITZ mode
 * (all, in parallel).
 *
 * This header defines:
 *   - xury_weapon_t          (enum, in types.h)
 *   - xury_weapon_info_t     (static metadata per weapon)
 *   - helpers to query metadata at runtime
 *
 * The enum values are declared in types.h so that both config.h and
 * this header can reference them without a cycle.
 *
 * Categories:
 *
 *   Direct
 *     IPV6      — connect over global IPv6 (no NAT)
 *     LAN       — connect on the same LAN segment
 *
 *   Router mapping
 *     UPNP      — UPnP IGD (SOAP)
 *     NATPMP    — NAT Port Mapping Protocol
 *     PCP       — Port Control Protocol
 *
 *   Traversal
 *     HOLE      — UDP hole punching (simultaneous open)
 *     PREDICT   — external port prediction
 *     BIRTHDAY  — birthday-paradox port spray
 *
 *   Peer-assisted
 *     MIRROR    — peer reflects our public endpoint back to us
 *     RELAY     — peer forwards our traffic
 *     UPGRADE   — relay-first, then upgrade to direct
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stdbool.h>

#include <xury/version.h>
#include <xury/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * WEAPON CATEGORY
 * ============================================================================
 *
 * Used for grouping, metrics, and documentation.
 */

typedef enum {
    XURY_WCAT_NONE      = 0,
    XURY_WCAT_DIRECT    = 1,   /* IPV6, LAN */
    XURY_WCAT_ROUTER    = 2,   /* UPNP, NATPMP, PCP */
    XURY_WCAT_TRAVERSAL = 3,   /* HOLE, PREDICT, BIRTHDAY */
    XURY_WCAT_PEER      = 4,   /* MIRROR, RELAY, UPGRADE */
} xury_weapon_category_t;

/*
 * ============================================================================
 * WEAPON FLAGS
 * ============================================================================
 *
 * Properties that describe how a weapon behaves.
 *
 * These are advisory. Actual applicability is decided per-scan.
 */

typedef enum {
    /* Weapon requires IPv6 to be available */
    XURY_WFLAG_NEEDS_IPV6      = 1u << 0,

    /* Weapon requires a global (non-link-local) IPv6 */
    XURY_WFLAG_NEEDS_GLOBAL_V6 = 1u << 1,

    /* Weapon requires UPnP IGD on the gateway */
    XURY_WFLAG_NEEDS_UPNP      = 1u << 2,

    /* Weapon requires NAT-PMP on the gateway */
    XURY_WFLAG_NEEDS_NATPMP    = 1u << 3,

    /* Weapon requires PCP on the gateway */
    XURY_WFLAG_NEEDS_PCP       = 1u << 4,

    /* Weapon requires at least one peer (mirror/relay) */
    XURY_WFLAG_NEEDS_PEER      = 1u << 5,

    /* Weapon may consume significant bandwidth */
    XURY_WFLAG_BANDWIDTH_HEAVY = 1u << 6,

    /* Weapon may be flagged by strict ISP / firewall */
    XURY_WFLAG_AGGRESSIVE      = 1u << 7,

    /* Weapon works without any gateway support */
    XURY_WFLAG_STANDALONE      = 1u << 8,

    /* Weapon benefits from a reachable (non-NAT) peer */
    XURY_WFLAG_NEEDS_PUBLIC    = 1u << 9,

} xury_weapon_flags_t;

/*
 * ============================================================================
 * WEAPON METADATA
 * ============================================================================
 *
 * Static, immutable information about each weapon.
 *
 * This struct is exposed read-only through xury_weapon_get_info().
 *
 * Fields:
 *   weapon        — the enum value
 *   tag           — short stable string ("ipv6", "upnp", "relay")
 *   name          — human-readable name ("IPv6 Direct")
 *   description   — one-line explanation
 *   category      — see xury_weapon_category_t
 *   flags         — bitmask of xury_weapon_flags_t
 *   base_strength — 0..100 prior probability of success
 *   base_cost     — 0..100 relative cost (latency + bandwidth)
 *
 * base_strength and base_cost are priors. The engine adjusts them
 * per-network based on the scan result and cache. Hosts should treat
 * them as informational only.
 */

typedef struct {
    xury_weapon_t          weapon;
    const char            *tag;
    const char            *name;
    const char            *description;
    xury_weapon_category_t category;
    uint32_t               flags;
    uint8_t                base_strength;
    uint8_t                base_cost;
} xury_weapon_info_t;

/*
 * ============================================================================
 * METADATA ACCESS
 * ============================================================================
 */

/*
 * Return the static info for a weapon.
 *
 * Returns NULL if the weapon value is out of range or XURY_WEAPON_NONE.
 * Never returns NULL for a valid weapon.
 */
const xury_weapon_info_t *xury_weapon_get_info(xury_weapon_t w);

/*
 * Return the short tag for a weapon.
 *
 * Examples:
 *   XURY_WEAPON_IPV6    -> "ipv6"
 *   XURY_WEAPON_HOLE    -> "hole"
 *   XURY_WEAPON_RELAY   -> "relay"
 *
 * Never returns NULL. Unknown weapons return "unknown".
 */
const char *xury_weapon_tag(xury_weapon_t w);

/*
 * Return the human-readable name for a weapon.
 *
 * Examples:
 *   XURY_WEAPON_IPV6    -> "IPv6 Direct"
 *   XURY_WEAPON_RELAY   -> "Peer Relay"
 *
 * Never returns NULL. Unknown weapons return "Unknown".
 */
const char *xury_weapon_name(xury_weapon_t w);

/*
 * Return the category for a weapon.
 */
xury_weapon_category_t xury_weapon_category(xury_weapon_t w);

/*
 * Return the category tag.
 *
 * Examples:
 *   XURY_WCAT_DIRECT    -> "direct"
 *   XURY_WCAT_ROUTER    -> "router"
 *   XURY_WCAT_TRAVERSAL -> "traversal"
 *   XURY_WCAT_PEER      -> "peer"
 *
 * Never returns NULL.
 */
const char *xury_weapon_category_tag(xury_weapon_category_t cat);

/*
 * Test flags on a weapon.
 */
bool xury_weapon_has_flag(xury_weapon_t w, uint32_t flag);

/*
 * ============================================================================
 * WEAPON SETS
 * ============================================================================
 *
 * Convenience bitmasks that describe common groups.
 *
 * These match XURY_DEFAULT_WEAPONS in config.h for the "safe" set.
 * Aggressive weapons (BIRTHDAY, UPGRADE) are opt-in.
 *
 * Note: XURY_WEAPON_BIT is defined in types.h.
 */

/* Direct only: IPv6 + LAN. Cheapest, no router help. */
#define XURY_WEAPONS_DIRECT \
    ( XURY_WEAPON_BIT(XURY_WEAPON_IPV6) | \
      XURY_WEAPON_BIT(XURY_WEAPON_LAN) )

/* Router mapping only: UPnP + NAT-PMP + PCP. */
#define XURY_WEAPONS_ROUTER \
    ( XURY_WEAPON_BIT(XURY_WEAPON_UPNP)   | \
      XURY_WEAPON_BIT(XURY_WEAPON_NATPMP) | \
      XURY_WEAPON_BIT(XURY_WEAPON_PCP) )

/* Traversal only: HOLE + PREDICT. Aggressive BIRTHDAY excluded. */
#define XURY_WEAPONS_TRAVERSAL \
    ( XURY_WEAPON_BIT(XURY_WEAPON_HOLE)    | \
      XURY_WEAPON_BIT(XURY_WEAPON_PREDICT) )

/* Peer-assisted only: MIRROR + RELAY. UPGRADE excluded (opt-in). */
#define XURY_WEAPONS_PEER \
    ( XURY_WEAPON_BIT(XURY_WEAPON_MIRROR) | \
      XURY_WEAPON_BIT(XURY_WEAPON_RELAY) )

/* Aggressive: weapons that cost bandwidth or may alarm ISPs. */
#define XURY_WEAPONS_AGGRESSIVE \
    ( XURY_WEAPON_BIT(XURY_WEAPON_BIRTHDAY) | \
      XURY_WEAPON_BIT(XURY_WEAPON_UPGRADE) )

/* Safe defaults (matches XURY_DEFAULT_WEAPONS). */
#define XURY_WEAPONS_SAFE \
    ( XURY_WEAPONS_DIRECT    | \
      XURY_WEAPONS_ROUTER    | \
      XURY_WEAPONS_TRAVERSAL | \
      XURY_WEAPONS_PEER )

/* Everything. */
#define XURY_WEAPONS_ALL \
    ( XURY_WEAPONS_SAFE | XURY_WEAPONS_AGGRESSIVE )

/*
 * ============================================================================
 * WEAPON SELECTION PRIORITY
 * ============================================================================
 *
 * Recommended STRIKE order when no scan result is available yet.
 *
 * The engine uses this as a fallback. It is also useful for hosts that
 * want to reason about likely behavior.
 *
 *   1. IPV6     — free, fastest
 *   2. LAN      — free, fastest
 *   3. UPNP     — free, no bandwidth
 *   4. NATPMP   — free, no bandwidth
 *   5. PCP      — free, no bandwidth
 *   6. HOLE     — some bandwidth, moderate
 *   7. PREDICT  — some bandwidth, moderate
 *   8. MIRROR   — needs a peer
 *   9. RELAY    — needs a peer, adds latency
 *  10. UPGRADE  — needs a peer, relay->direct
 *  11. BIRTHDAY — bandwidth heavy, last resort
 *
 * This order is exposed for documentation only. The engine may deviate
 * based on scan, cache, and learning.
 */

/*
 * ============================================================================
 * VALIDATION
 * ============================================================================
 *
 * A weapon enum value is valid if:
 *   0 < value < XURY_WEAPON_COUNT
 *
 * XURY_WEAPON_NONE is not a valid target. It is a sentinel used
 * internally to mean "no weapon selected".
 */

static inline bool xury_weapon_is_valid(xury_weapon_t w)
{
    return (int)w > (int)XURY_WEAPON_NONE &&
           (int)w < (int)XURY_WEAPON_COUNT;
}

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY WEAPON HEADER
 * ============================================================================
 */

#endif /* XURY_WEAPON_H */
