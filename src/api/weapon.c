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
 * XURY WEAPON — IMPLEMENTATION
 * ============================================================================
 *
 * Implements:
 *   - public weapon metadata API (include/xury/weapon.h)
 *   - internal weapon helpers   (src/api/internal/weapon.h)
 *
 * The metadata table lives here and is the single source of truth for:
 *   - tag / name / description
 *   - category
 *   - flags
 *   - base_strength (prior)
 *   - base_cost     (prior)
 *
 * The numbers are priors chosen from known NAT behavior:
 *
 *   strength  — how often this weapon works in a typical home network
 *   cost      — relative latency + bandwidth, 0 = cheapest
 *
 * They are NOT learned from data. They are starting points. The scan
 * layer and the learning layer adjust them per-network at runtime.
 *
 * Everything in this file is pure:
 *   - no allocation
 *   - no I/O
 *   - no global mutable state
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/types.h>
#include <xury/err.h>
#include <xury/weapon.h>

#include "api/internal/weapon.h"

/*
 * ============================================================================
 * WEAPON TABLE
 * ============================================================================
 *
 * Index 0 is XURY_WEAPON_NONE, a sentinel. It must stay first.
 *
 * The order after index 0 does not have to match the enum values, but
 * for clarity it does. The table size must equal XURY_WEAPON_COUNT.
 */

static const xury_weapon_info_t g_weapon_table[XURY_WEAPON_COUNT] = {
    /*
     * ----------------------------------------------------------------
     * 0. NONE (sentinel — never attempted)
     * ----------------------------------------------------------------
     */
    {
        .weapon      = XURY_WEAPON_NONE,
        .tag         = "none",
        .name        = "None",
        .description = "no weapon selected",
        .category    = XURY_WCAT_NONE,
        .flags       = 0u,
        .base_strength = 0u,
        .base_cost     = 0u,
    },

    /*
     * ----------------------------------------------------------------
     * 1. IPv6 direct
     * ----------------------------------------------------------------
     * If the host has global IPv6 and the peer answered on it, this
     * always works. Cheapest possible path. No NAT involved.
     */
    {
        .weapon      = XURY_WEAPON_IPV6,
        .tag         = "ipv6",
        .name        = "IPv6 Direct",
        .description = "direct connection over global IPv6 (no NAT)",
        .category    = XURY_WCAT_DIRECT,
        .flags       = XURY_WFLAG_NEEDS_IPV6 |
                       XURY_WFLAG_NEEDS_GLOBAL_V6 |
                       XURY_WFLAG_STANDALONE,
        .base_strength = 100u,
        .base_cost     =   5u,
    },

    /*
     * ----------------------------------------------------------------
     * 2. LAN direct
     * ----------------------------------------------------------------
     * Same subnet, no NAT to cross. Fast and free.
     */
    {
        .weapon      = XURY_WEAPON_LAN,
        .tag         = "lan",
        .name        = "LAN Direct",
        .description = "direct connection on the same LAN segment",
        .category    = XURY_WCAT_DIRECT,
        .flags       = XURY_WFLAG_STANDALONE,
        .base_strength = 100u,
        .base_cost     =   3u,
    },

    /*
     * ----------------------------------------------------------------
     * 3. UPnP IGD
     * ----------------------------------------------------------------
     * Works on the majority of home routers. Creates a real port
     * mapping so the peer can reach us. No bandwidth cost.
     */
    {
        .weapon      = XURY_WEAPON_UPNP,
        .tag         = "upnp",
        .name        = "UPnP IGD",
        .description = "create a port mapping via UPnP IGD (SOAP)",
        .category    = XURY_WCAT_ROUTER,
        .flags       = XURY_WFLAG_NEEDS_UPNP,
        .base_strength = 80u,
        .base_cost     =  15u,
    },

    /*
     * ----------------------------------------------------------------
     * 4. NAT-PMP
     * ----------------------------------------------------------------
     * Apple / Fritz!Box and a growing set of modern routers.
     */
    {
        .weapon      = XURY_WEAPON_NATPMP,
        .tag         = "natpmp",
        .name        = "NAT-PMP",
        .description = "create a port mapping via NAT-PMP",
        .category    = XURY_WCAT_ROUTER,
        .flags       = XURY_WFLAG_NEEDS_NATPMP,
        .base_strength = 75u,
        .base_cost     =  12u,
    },

    /*
     * ----------------------------------------------------------------
     * 5. PCP
     * ----------------------------------------------------------------
     * NAT-PMP successor. Same idea, slightly newer.
     */
    {
        .weapon      = XURY_WEAPON_PCP,
        .tag         = "pcp",
        .name        = "PCP",
        .description = "create a port mapping via PCP",
        .category    = XURY_WCAT_ROUTER,
        .flags       = XURY_WFLAG_NEEDS_PCP,
        .base_strength = 70u,
        .base_cost     =  12u,
    },

    /*
     * ----------------------------------------------------------------
     * 6. Hole punch
     * ----------------------------------------------------------------
     * The workhorse for cone NATs. Needs a peer endpoint and a moment
     * of coordination. Moderate bandwidth.
     */
    {
        .weapon      = XURY_WEAPON_HOLE,
        .tag         = "hole",
        .name        = "Hole Punch",
        .description = "UDP hole punch via simultaneous open",
        .category    = XURY_WCAT_TRAVERSAL,
        .flags       = XURY_WFLAG_NEEDS_PEER |
                       XURY_WFLAG_STANDALONE,
        .base_strength = 70u,
        .base_cost     =  35u,
    },

    /*
     * ----------------------------------------------------------------
     * 7. Port prediction
     * ----------------------------------------------------------------
     * Predicts the next external port from an observed pattern.
     * Only useful on predictable NATs (simple CGNAT, some cone NATs).
     */
    {
        .weapon      = XURY_WEAPON_PREDICT,
        .tag         = "predict",
        .name        = "Port Prediction",
        .description = "predict the next external port and punch it",
        .category    = XURY_WCAT_TRAVERSAL,
        .flags       = XURY_WFLAG_NEEDS_PEER,
        .base_strength = 50u,
        .base_cost     =  30u,
    },

    /*
     * ----------------------------------------------------------------
     * 8. Birthday paradox
     * ----------------------------------------------------------------
     * Sprays packets across the port range. Expensive. Last resort
     * for random NAT. Off by default.
     */
    {
        .weapon      = XURY_WEAPON_BIRTHDAY,
        .tag         = "birthday",
        .name        = "Birthday Paradox",
        .description = "spray packets across the port range",
        .category    = XURY_WCAT_TRAVERSAL,
        .flags       = XURY_WFLAG_NEEDS_PEER |
                       XURY_WFLAG_BANDWIDTH_HEAVY |
                       XURY_WFLAG_AGGRESSIVE,
        .base_strength = 25u,
        .base_cost     =  90u,
    },

    /*
     * ----------------------------------------------------------------
     * 9. Peer-as-mirror
     * ----------------------------------------------------------------
     * Ask a peer what our public endpoint looks like. Replaces the
     * STUN server role. Requires at least one reachable peer.
     */
    {
        .weapon      = XURY_WEAPON_MIRROR,
        .tag         = "mirror",
        .name        = "Peer Mirror",
        .description = "ask a peer to reflect our public endpoint",
        .category    = XURY_WCAT_PEER,
        .flags       = XURY_WFLAG_NEEDS_PEER,
        .base_strength = 80u,
        .base_cost     =  20u,
    },

    /*
     * ----------------------------------------------------------------
     * 10. Peer relay
     * ----------------------------------------------------------------
     * Send all traffic through a peer. Replaces the TURN server role.
     * Works on strict CGNAT. Adds latency.
     */
    {
        .weapon      = XURY_WEAPON_RELAY,
        .tag         = "relay",
        .name        = "Peer Relay",
        .description = "forward traffic through a peer",
        .category    = XURY_WCAT_PEER,
        .flags       = XURY_WFLAG_NEEDS_PEER,
        .base_strength = 90u,
        .base_cost     =  60u,
    },

    /*
     * ----------------------------------------------------------------
     * 11. Relay upgrade
     * ----------------------------------------------------------------
     * Start on relay, then replace it with a direct path. Off by
     * default; only useful when the host asked for the lowest latency.
     */
    {
        .weapon      = XURY_WEAPON_UPGRADE,
        .tag         = "upgrade",
        .name        = "Relay Upgrade",
        .description = "upgrade a relay path to a direct path",
        .category    = XURY_WCAT_PEER,
        .flags       = XURY_WFLAG_NEEDS_PEER |
                       XURY_WFLAG_AGGRESSIVE,
        .base_strength = 40u,
        .base_cost     =  50u,
    },
};

/*
 * Compile-time check: the table must match the enum count.
 *
 * If someone adds a weapon to the enum but forgets the table (or vice
 * versa), this fails the build.
 */
_Static_assert(
    sizeof(g_weapon_table) / sizeof(g_weapon_table[0]) ==
        (size_t)XURY_WEAPON_COUNT,
    "weapon table size must equal XURY_WEAPON_COUNT");

/*
 * ============================================================================
 * PUBLIC API — METADATA LOOKUP
 * ============================================================================
 */

const xury_weapon_info_t *xury_weapon_get_info(xury_weapon_t w)
{
    if (!xury_weapon_is_valid(w)) {
        return NULL;
    }
    return &g_weapon_table[(size_t)w];
}

const char *xury_weapon_tag(xury_weapon_t w)
{
    if (!xury_weapon_is_valid(w)) {
        return "unknown";
    }
    return g_weapon_table[(size_t)w].tag;
}

const char *xury_weapon_name(xury_weapon_t w)
{
    if (!xury_weapon_is_valid(w)) {
        return "Unknown";
    }
    return g_weapon_table[(size_t)w].name;
}

xury_weapon_category_t xury_weapon_category(xury_weapon_t w)
{
    if (!xury_weapon_is_valid(w)) {
        return XURY_WCAT_NONE;
    }
    return g_weapon_table[(size_t)w].category;
}

const char *xury_weapon_category_tag(xury_weapon_category_t cat)
{
    switch (cat) {
    case XURY_WCAT_NONE:      return "none";
    case XURY_WCAT_DIRECT:    return "direct";
    case XURY_WCAT_ROUTER:    return "router";
    case XURY_WCAT_TRAVERSAL: return "traversal";
    case XURY_WCAT_PEER:      return "peer";
    default:                  return "unknown";
    }
}

bool xury_weapon_has_flag(xury_weapon_t w, uint32_t flag)
{
    if (!xury_weapon_is_valid(w)) {
        return false;
    }
    return (g_weapon_table[(size_t)w].flags & flag) != 0u;
}
 /* ---- continued from part 1/2 ---- */

/*
 * ============================================================================
 * TABLE ITERATION
 * ============================================================================
 */

size_t xury_weapon_table_size(void)
{
    return (size_t)XURY_WEAPON_COUNT;
}

const xury_weapon_info_t *xury_weapon_table_at(size_t i)
{
    if (i >= (size_t)XURY_WEAPON_COUNT) {
        return NULL;
    }
    return &g_weapon_table[i];
}

const xury_weapon_info_t *xury_weapon_info_or_null(xury_weapon_t w)
{
    return xury_weapon_get_info(w);
}

/*
 * ============================================================================
 * PRIOR STRENGTH / COST
 * ============================================================================
 */

uint32_t xury_weapon_base_strength(xury_weapon_t w)
{
    if (!xury_weapon_is_valid(w)) {
        return 0u;
    }
    return (uint32_t)g_weapon_table[(size_t)w].base_strength;
}

uint32_t xury_weapon_base_cost(xury_weapon_t w)
{
    if (!xury_weapon_is_valid(w)) {
        return 0u;
    }
    return (uint32_t)g_weapon_table[(size_t)w].base_cost;
}

/*
 * ============================================================================
 * PRIORITY
 * ============================================================================
 *
 * The priority is a dense ordering 1..11 over the weapons. Lower value
 * means "try earlier".
 *
 * The order is fixed and documented in include/xury/weapon.h:
 *
 *   1  IPv6
 *   2  LAN
 *   3  UPnP
 *   4  NAT-PMP
 *   5  PCP
 *   6  HOLE
 *   7  PREDICT
 *   8  MIRROR
 *   9  RELAY
 *  10  UPGRADE
 *  11  BIRTHDAY
 *
 * The priorities are derived from the enum values, not from a second
 * table, so that adding a weapon only requires editing the enum and
 * the metadata table.
 *
 * Mapping from enum to priority:
 *
 *   IPV6      (1)  ->  1
 *   LAN       (2)  ->  2
 *   UPNP      (3)  ->  3
 *   NATPMP    (4)  ->  4
 *   PCP       (5)  ->  5
 *   HOLE      (6)  ->  6
 *   PREDICT   (7)  ->  7
 *   MIRROR    (9)  ->  8
 *   RELAY    (10)  ->  9
 *   UPGRADE  (11)  -> 10
 *   BIRTHDAY  (8)  -> 11
 *
 * BIRTHDAY is the only one that is moved to the end, on purpose: it
 * is the most expensive and the least likely to help.
 */

/*
 * Priority table, indexed by weapon enum value. Index 0 is unused
 * (XURY_WEAPON_NONE has no priority and returns 0).
 */
static const uint8_t g_priority[XURY_WEAPON_COUNT] = {
    /* NONE     */ 0u,
    /* IPV6     */ 1u,
    /* LAN      */ 2u,
    /* UPNP     */ 3u,
    /* NATPMP   */ 4u,
    /* PCP      */ 5u,
    /* HOLE     */ 6u,
    /* PREDICT  */ 7u,
    /* BIRTHDAY */ 11u,   /* last on purpose */
    /* MIRROR   */ 8u,
    /* RELAY    */ 9u,
    /* UPGRADE  */ 10u,
};

_Static_assert(
    sizeof(g_priority) / sizeof(g_priority[0]) ==
        (size_t)XURY_WEAPON_COUNT,
    "priority table size must equal XURY_WEAPON_COUNT");

uint32_t xury_weapon_priority(xury_weapon_t w)
{
    if (!xury_weapon_is_valid(w)) {
        return 0u;
    }
    return (uint32_t)g_priority[(size_t)w];
}

xury_weapon_t xury_weapon_at_priority(uint32_t priority)
{
    if (priority == 0u) {
        return XURY_WEAPON_NONE;
    }
    for (int w = 1; w < (int)XURY_WEAPON_COUNT; w++) {
        if ((uint32_t)g_priority[w] == priority) {
            return (xury_weapon_t)w;
        }
    }
    return XURY_WEAPON_NONE;
}

/*
 * ============================================================================
 * APPLICABILITY
 * ============================================================================
 */

bool xury_weapon_applicable(xury_weapon_t w,
                            const xury_weapon_context_t *ctx)
{
    if (!xury_weapon_is_valid(w)) {
        return false;
    }
    if (ctx == NULL) {
        /*
         * No context: only non-aggressive weapons are applicable.
         * This matches the "safe defaults" policy.
         */
        return !xury_weapon_has_flag(w, XURY_WFLAG_AGGRESSIVE);
    }

    const uint32_t flags = g_weapon_table[(size_t)w].flags;

    /* Aggressive weapons need explicit opt-in. */
    if ((flags & XURY_WFLAG_AGGRESSIVE) && !ctx->allow_aggressive) {
        return false;
    }

    /* IPv6 requirements. */
    if (flags & XURY_WFLAG_NEEDS_IPV6) {
        if (!ctx->ipv6_present) {
            return false;
        }
    }
    if (flags & XURY_WFLAG_NEEDS_GLOBAL_V6) {
        if (!ctx->ipv6_global || !ctx->peer_has_ipv6) {
            return false;
        }
    }

    /* Router support requirements. */
    if (flags & XURY_WFLAG_NEEDS_UPNP) {
        if (!ctx->upnp_available) {
            return false;
        }
    }
    if (flags & XURY_WFLAG_NEEDS_NATPMP) {
        if (!ctx->natpmp_available) {
            return false;
        }
    }
    if (flags & XURY_WFLAG_NEEDS_PCP) {
        if (!ctx->pcp_available) {
            return false;
        }
    }

    /* Peer requirements. */
    if (flags & XURY_WFLAG_NEEDS_PEER) {
        if (!ctx->peer_reachable && !ctx->helper_available) {
            return false;
        }
    }

    /*
     * Weapon-specific extra rules beyond the flag set.
     */
    switch (w) {
    case XURY_WEAPON_LAN:
        /* Only make sense if the peer is on the same LAN. */
        return ctx->peer_is_lan;

    case XURY_WEAPON_PREDICT:
        /* Only worth trying on a predictable NAT. */
        return ctx->port_predictable;

    case XURY_WEAPON_BIRTHDAY:
        /* Only for random / symmetric NATs. */
        return ctx->symmetric || ctx->cgnat;

    case XURY_WEAPON_HOLE:
        /*
         * Hole punch is worth a try on anything that is not CGNAT
         * strict. We do not have a "strict" flag here, so we let it
         * through unless the peer is unreachable AND there is no
         * helper. The flag check above already handled that.
         */
        return true;

    case XURY_WEAPON_RELAY:
    case XURY_WEAPON_UPGRADE:
        /* Require at least one helper peer. */
        return ctx->helper_available;

    case XURY_WEAPON_MIRROR:
        /* Require at least one peer (used as a mirror). */
        return ctx->helper_available || ctx->peer_reachable;

    case XURY_WEAPON_IPV6:
    case XURY_WEAPON_UPNP:
    case XURY_WEAPON_NATPMP:
    case XURY_WEAPON_PCP:
        /* Flags already covered these. */
        return true;

    default:
        return false;
    }
}

uint32_t xury_weapon_applicable_mask(const xury_weapon_context_t *ctx)
{
    uint32_t mask = 0u;
    for (int w = 1; w < (int)XURY_WEAPON_COUNT; w++) {
        if (xury_weapon_applicable((xury_weapon_t)w, ctx)) {
            mask |= XURY_WEAPON_BIT((xury_weapon_t)w);
        }
    }
    return mask;
}

/*
 * ============================================================================
 * BITMASK ITERATION
 * ============================================================================
 */

size_t xury_weapon_mask_count(uint32_t mask)
{
    /* Strip the NONE bit; it must never be counted. */
    mask &= ~XURY_WEAPON_BIT(XURY_WEAPON_NONE);

    size_t n = 0;
    while (mask != 0u) {
        n += (size_t)(mask & 1u);
        mask >>= 1;
    }
    return n;
}

xury_weapon_t xury_weapon_mask_next(uint32_t *mask, xury_weapon_t prev)
{
    if (mask == NULL) {
        return XURY_WEAPON_NONE;
    }

    /*
     * Walk from priority 1 upward. For each priority, look up the
     * weapon; if its bit is set in *mask, return it and clear the bit.
     *
     * The "prev" parameter lets callers resume from a known point
     * without keeping their own priority cursor. If prev is NONE,
     * start at priority 1.
     */
    uint32_t start_priority = 1u;
    if (prev != XURY_WEAPON_NONE && xury_weapon_is_valid(prev)) {
        uint32_t p = xury_weapon_priority(prev);
        if (p > 0u) {
            start_priority = p + 1u;
        }
    }

    for (uint32_t p = start_priority;
         p <= (uint32_t)XURY_WEAPON_COUNT;
         p++) {
        xury_weapon_t w = xury_weapon_at_priority(p);
        if (w == XURY_WEAPON_NONE) {
            continue;
        }
        uint32_t bit = XURY_WEAPON_BIT(w);
        if ((*mask & bit) != 0u) {
            *mask &= ~bit;
            return w;
        }
    }
    return XURY_WEAPON_NONE;
}

/*
 * ============================================================================
 * FORMATTING
 * ============================================================================
 */

size_t xury_weapon_mask_format(uint32_t mask,
                               char *buf,
                               size_t buflen)
{
    size_t written = 0;
    bool first = true;

    /* Iterate in priority order for stable output. */
    for (uint32_t p = 1u; p <= (uint32_t)XURY_WEAPON_COUNT; p++) {
        xury_weapon_t w = xury_weapon_at_priority(p);
        if (w == XURY_WEAPON_NONE) {
            continue;
        }
        if ((mask & XURY_WEAPON_BIT(w)) == 0u) {
            continue;
        }

        if (!first) {
            if (buf != NULL && written + 1 < buflen) {
                buf[written] = ',';
            }
            written++;
        }
        first = false;

        const char *tag = g_weapon_table[(size_t)w].tag;
        for (size_t i = 0; tag[i] != '\0'; i++) {
            if (buf != NULL && written + 1 < buflen) {
                buf[written] = tag[i];
            }
            written++;
        }
    }

    if (buf != NULL && buflen > 0) {
        size_t term = written < buflen ? written : buflen - 1;
        buf[term] = '\0';
    }
    return written;
}

/*
 * ============================================================================
 * PARSING
 * ============================================================================
 */

xury_weapon_t xury_weapon_from_tag(const char *tag)
{
    if (tag == NULL) {
        return XURY_WEAPON_NONE;
    }

    /* Exact match against the table's tags. */
    for (int w = 0; w < (int)XURY_WEAPON_COUNT; w++) {
        if (strcmp(g_weapon_table[w].tag, tag) == 0) {
            return (xury_weapon_t)w;
        }
    }
    return XURY_WEAPON_NONE;
}

/*
 * Parse a comma-separated list of weapon tags into a mask.
 *
 * Whitespace around each tag is ignored. Unknown tags are skipped and
 * counted through *out_unknown (if not NULL).
 */
uint32_t xury_weapon_mask_from_string(const char *str,
                                      size_t *out_unknown)
{
    size_t unknown = 0;
    uint32_t mask = 0u;

    if (str == NULL) {
        if (out_unknown != NULL) {
            *out_unknown = 0;
        }
        return 0u;
    }

    const char *p = str;
    while (*p != '\0') {
        /* Skip leading whitespace. */
        while (*p == ' ' || *p == '\t' || *p == ',') {
            p++;
        }
        if (*p == '\0') {
            break;
        }

        /* Find the end of the token. */
        const char *start = p;
        while (*p != '\0' && *p != ',' &&
               *p != ' ' && *p != '\t') {
            p++;
        }
        size_t len = (size_t)(p - start);
        if (len == 0u || len >= 32u) {
            unknown++;
            continue;
        }

        char tmp[32];
        for (size_t i = 0; i < len; i++) {
            tmp[i] = start[i];
        }
        tmp[len] = '\0';

        xury_weapon_t w = xury_weapon_from_tag(tmp);
        if (w == XURY_WEAPON_NONE) {
            /*
             * The tag was either "none" (skip silently, not an error)
             * or truly unknown (count).
             */
            if (strcmp(tmp, "none") != 0) {
                unknown++;
            }
        } else {
            mask |= XURY_WEAPON_BIT(w);
        }
    }

    if (out_unknown != NULL) {
        *out_unknown = unknown;
    }
    return mask;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
