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
 * TESTS — src/api/weapon.c
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "api/internal/weapon.h"
#include "tests/test.h"

/*
 * ============================================================================
 * TABLE
 * ============================================================================
 */

static void test_table_size(void)
{
    TEST_ASSERT_EQ(xury_weapon_table_size(),
                   (size_t)XURY_WEAPON_COUNT);
}

static void test_table_at_out_of_range(void)
{
    size_t n = xury_weapon_table_size();
    TEST_ASSERT_NULL(xury_weapon_table_at(n));
    TEST_ASSERT_NULL(xury_weapon_table_at(n + 100u));
}

static void test_table_at_none_first(void)
{
    const xury_weapon_info_t *info = xury_weapon_table_at(0);
    TEST_ASSERT_NOT_NULL(info);
    TEST_ASSERT_EQ(info->weapon, XURY_WEAPON_NONE);
    TEST_ASSERT_STREQ(info->tag, "none");
}

static void test_table_every_entry_well_formed(void)
{
    size_t n = xury_weapon_table_size();
    for (size_t i = 0; i < n; i++) {
        const xury_weapon_info_t *info = xury_weapon_table_at(i);
        TEST_ASSERT_NOT_NULL(info);
        TEST_ASSERT_NOT_NULL(info->tag);
        TEST_ASSERT_NOT_NULL(info->name);
        TEST_ASSERT_NOT_NULL(info->description);
        TEST_ASSERT(info->tag[0] != '\0');
        TEST_ASSERT(info->name[0] != '\0');
        TEST_ASSERT(info->description[0] != '\0');
        TEST_ASSERT_EQ((size_t)info->weapon, i);
    }
}

static void test_table_tags_unique(void)
{
    size_t n = xury_weapon_table_size();
    for (size_t i = 0; i < n; i++) {
        const xury_weapon_info_t *a = xury_weapon_table_at(i);
        for (size_t j = i + 1u; j < n; j++) {
            const xury_weapon_info_t *b = xury_weapon_table_at(j);
            TEST_ASSERT(strcmp(a->tag, b->tag) != 0);
        }
    }
}

/*
 * ============================================================================
 * LOOKUP
 * ============================================================================
 */

static void test_get_info_valid(void)
{
    const xury_weapon_info_t *info =
        xury_weapon_get_info(XURY_WEAPON_IPV6);
    TEST_ASSERT_NOT_NULL(info);
    TEST_ASSERT_EQ(info->weapon, XURY_WEAPON_IPV6);
    TEST_ASSERT_STREQ(info->tag, "ipv6");
}

static void test_get_info_invalid(void)
{
    TEST_ASSERT_NULL(xury_weapon_get_info(XURY_WEAPON_NONE));
    TEST_ASSERT_NULL(xury_weapon_get_info((xury_weapon_t)999));
}

static void test_info_or_null_matches_get_info(void)
{
    const xury_weapon_info_t *a =
        xury_weapon_info_or_null(XURY_WEAPON_HOLE);
    const xury_weapon_info_t *b =
        xury_weapon_get_info(XURY_WEAPON_HOLE);
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT(a == b);
}

/*
 * ============================================================================
 * TAGS AND NAMES
 * ============================================================================
 */

static void test_weapon_tag(void)
{
    TEST_ASSERT_STREQ(xury_weapon_tag(XURY_WEAPON_IPV6), "ipv6");
    TEST_ASSERT_STREQ(xury_weapon_tag(XURY_WEAPON_LAN), "lan");
    TEST_ASSERT_STREQ(xury_weapon_tag(XURY_WEAPON_UPNP), "upnp");
    TEST_ASSERT_STREQ(xury_weapon_tag(XURY_WEAPON_NATPMP), "natpmp");
    TEST_ASSERT_STREQ(xury_weapon_tag(XURY_WEAPON_PCP), "pcp");
    TEST_ASSERT_STREQ(xury_weapon_tag(XURY_WEAPON_HOLE), "hole");
    TEST_ASSERT_STREQ(xury_weapon_tag(XURY_WEAPON_PREDICT), "predict");
    TEST_ASSERT_STREQ(xury_weapon_tag(XURY_WEAPON_BIRTHDAY), "birthday");
    TEST_ASSERT_STREQ(xury_weapon_tag(XURY_WEAPON_MIRROR), "mirror");
    TEST_ASSERT_STREQ(xury_weapon_tag(XURY_WEAPON_RELAY), "relay");
    TEST_ASSERT_STREQ(xury_weapon_tag(XURY_WEAPON_UPGRADE), "upgrade");

    TEST_ASSERT_STREQ(xury_weapon_tag(XURY_WEAPON_NONE), "unknown");
    TEST_ASSERT_STREQ(xury_weapon_tag((xury_weapon_t)999), "unknown");
}

static void test_weapon_name_not_null(void)
{
    size_t n = xury_weapon_table_size();
    for (size_t i = 1; i < n; i++) {
        const char *name = xury_weapon_name((xury_weapon_t)i);
        TEST_ASSERT_NOT_NULL(name);
        TEST_ASSERT(name[0] != '\0');
    }
    TEST_ASSERT_NOT_NULL(xury_weapon_name((xury_weapon_t)999));
}

/*
 * ============================================================================
 * CATEGORY
 * ============================================================================
 */

static void test_weapon_category(void)
{
    TEST_ASSERT_EQ(xury_weapon_category(XURY_WEAPON_IPV6),
                   XURY_WCAT_DIRECT);
    TEST_ASSERT_EQ(xury_weapon_category(XURY_WEAPON_LAN),
                   XURY_WCAT_DIRECT);
    TEST_ASSERT_EQ(xury_weapon_category(XURY_WEAPON_UPNP),
                   XURY_WCAT_ROUTER);
    TEST_ASSERT_EQ(xury_weapon_category(XURY_WEAPON_NATPMP),
                   XURY_WCAT_ROUTER);
    TEST_ASSERT_EQ(xury_weapon_category(XURY_WEAPON_PCP),
                   XURY_WCAT_ROUTER);
    TEST_ASSERT_EQ(xury_weapon_category(XURY_WEAPON_HOLE),
                   XURY_WCAT_TRAVERSAL);
    TEST_ASSERT_EQ(xury_weapon_category(XURY_WEAPON_PREDICT),
                   XURY_WCAT_TRAVERSAL);
    TEST_ASSERT_EQ(xury_weapon_category(XURY_WEAPON_BIRTHDAY),
                   XURY_WCAT_TRAVERSAL);
    TEST_ASSERT_EQ(xury_weapon_category(XURY_WEAPON_MIRROR),
                   XURY_WCAT_PEER);
    TEST_ASSERT_EQ(xury_weapon_category(XURY_WEAPON_RELAY),
                   XURY_WCAT_PEER);
    TEST_ASSERT_EQ(xury_weapon_category(XURY_WEAPON_UPGRADE),
                   XURY_WCAT_PEER);

    TEST_ASSERT_EQ(xury_weapon_category((xury_weapon_t)999),
                   XURY_WCAT_NONE);
}

static void test_weapon_category_tag(void)
{
    TEST_ASSERT_STREQ(xury_weapon_category_tag(XURY_WCAT_NONE), "none");
    TEST_ASSERT_STREQ(xury_weapon_category_tag(XURY_WCAT_DIRECT),
                      "direct");
    TEST_ASSERT_STREQ(xury_weapon_category_tag(XURY_WCAT_ROUTER),
                      "router");
    TEST_ASSERT_STREQ(xury_weapon_category_tag(XURY_WCAT_TRAVERSAL),
                      "traversal");
    TEST_ASSERT_STREQ(xury_weapon_category_tag(XURY_WCAT_PEER), "peer");
    TEST_ASSERT_STREQ(xury_weapon_category_tag((xury_weapon_category_t)999),
                      "unknown");
}

/*
 * ============================================================================
 * FLAGS
 * ============================================================================
 */

static void test_has_flag(void)
{
    TEST_ASSERT(xury_weapon_has_flag(XURY_WEAPON_IPV6,
                                     XURY_WFLAG_NEEDS_IPV6));
    TEST_ASSERT(xury_weapon_has_flag(XURY_WEAPON_IPV6,
                                     XURY_WFLAG_NEEDS_GLOBAL_V6));
    TEST_ASSERT(xury_weapon_has_flag(XURY_WEAPON_IPV6,
                                     XURY_WFLAG_STANDALONE));
    TEST_ASSERT(!xury_weapon_has_flag(XURY_WEAPON_IPV6,
                                      XURY_WFLAG_NEEDS_UPNP));

    TEST_ASSERT(xury_weapon_has_flag(XURY_WEAPON_UPNP,
                                     XURY_WFLAG_NEEDS_UPNP));
    TEST_ASSERT(xury_weapon_has_flag(XURY_WEAPON_BIRTHDAY,
                                     XURY_WFLAG_AGGRESSIVE));
    TEST_ASSERT(xury_weapon_has_flag(XURY_WEAPON_BIRTHDAY,
                                     XURY_WFLAG_BANDWIDTH_HEAVY));
}

static void test_has_flag_invalid(void)
{
    TEST_ASSERT(!xury_weapon_has_flag(XURY_WEAPON_NONE,
                                      XURY_WFLAG_NEEDS_IPV6));
    TEST_ASSERT(!xury_weapon_has_flag((xury_weapon_t)999,
                                      XURY_WFLAG_NEEDS_IPV6));
}

/*
 * ============================================================================
 * STRENGTH / COST
 * ============================================================================
 */

static void test_base_strength_range(void)
{
    size_t n = xury_weapon_table_size();
    for (size_t i = 1; i < n; i++) {
        uint32_t s = xury_weapon_base_strength((xury_weapon_t)i);
        TEST_ASSERT(s <= 100u);
    }
}

static void test_base_cost_range(void)
{
    size_t n = xury_weapon_table_size();
    for (size_t i = 1; i < n; i++) {
        uint32_t c = xury_weapon_base_cost((xury_weapon_t)i);
        TEST_ASSERT(c <= 100u);
    }
}

static void test_base_strength_ipv6_is_max(void)
{
    TEST_ASSERT_EQ(xury_weapon_base_strength(XURY_WEAPON_IPV6), 100u);
}

static void test_base_cost_ipv6_is_cheap(void)
{
    uint32_t c = xury_weapon_base_cost(XURY_WEAPON_IPV6);
    TEST_ASSERT(c <= 10u);
}

static void test_strength_cost_invalid(void)
{
    TEST_ASSERT_EQ(xury_weapon_base_strength(XURY_WEAPON_NONE), 0u);
    TEST_ASSERT_EQ(xury_weapon_base_strength((xury_weapon_t)999), 0u);
    TEST_ASSERT_EQ(xury_weapon_base_cost(XURY_WEAPON_NONE), 0u);
    TEST_ASSERT_EQ(xury_weapon_base_cost((xury_weapon_t)999), 0u);
}

/*
 * ============================================================================
 * PRIORITY
 * ============================================================================
 */

static void test_priority_range(void)
{
    size_t n = xury_weapon_table_size();
    for (size_t i = 1; i < n; i++) {
        uint32_t p = xury_weapon_priority((xury_weapon_t)i);
        TEST_ASSERT(p >= 1u);
        TEST_ASSERT(p <= (uint32_t)XURY_WEAPON_COUNT);
    }
}

static void test_priority_unique(void)
{
    size_t n = xury_weapon_table_size();
    for (size_t i = 1; i < n; i++) {
        uint32_t pi = xury_weapon_priority((xury_weapon_t)i);
        for (size_t j = i + 1u; j < n; j++) {
            uint32_t pj = xury_weapon_priority((xury_weapon_t)j);
            TEST_ASSERT_NE(pi, pj);
        }
    }
}

static void test_priority_ipv6_first(void)
{
    uint32_t p = xury_weapon_priority(XURY_WEAPON_IPV6);
    TEST_ASSERT_EQ(p, 1u);
}

static void test_priority_lan_second(void)
{
    uint32_t p = xury_weapon_priority(XURY_WEAPON_LAN);
    TEST_ASSERT_EQ(p, 2u);
}

static void test_priority_birthday_last(void)
{
    uint32_t p = xury_weapon_priority(XURY_WEAPON_BIRTHDAY);
    TEST_ASSERT_EQ(p, (uint32_t)XURY_WEAPON_COUNT - 1u);
}

static void test_priority_invalid(void)
{
    TEST_ASSERT_EQ(xury_weapon_priority(XURY_WEAPON_NONE), 0u);
    TEST_ASSERT_EQ(xury_weapon_priority((xury_weapon_t)999), 0u);
}

static void test_at_priority_roundtrip(void)
{
    size_t n = xury_weapon_table_size();
    for (size_t i = 1; i < n; i++) {
        xury_weapon_t w = (xury_weapon_t)i;
        uint32_t p = xury_weapon_priority(w);
        xury_weapon_t back = xury_weapon_at_priority(p);
        TEST_ASSERT_EQ(back, w);
    }
}

static void test_at_priority_out_of_range(void)
{
    TEST_ASSERT_EQ(xury_weapon_at_priority(0u), XURY_WEAPON_NONE);
    TEST_ASSERT_EQ(xury_weapon_at_priority(999u), XURY_WEAPON_NONE);
}

/*
 * ============================================================================
 * APPLICABILITY
 * ============================================================================
 */

static xury_weapon_context_t make_ctx_all_off(void)
{
    xury_weapon_context_t c;
    memset(&c, 0, sizeof(c));
    return c;
}

static xury_weapon_context_t make_ctx_full(void)
{
    xury_weapon_context_t c;
    memset(&c, 0, sizeof(c));
    c.ipv6_present       = true;
    c.ipv6_global        = true;
    c.peer_has_ipv6      = true;
    c.peer_is_lan        = true;
    c.peer_reachable     = true;
    c.upnp_available     = true;
    c.natpmp_available   = true;
    c.pcp_available      = true;
    c.symmetric          = true;    /* ✅ FIX: was false — BIRTHDAY needs this */
    c.cgnat              = false;
    c.port_predictable   = true;
    c.helper_available   = true;
    c.allow_aggressive   = true;
    return c;
}

static void test_applicable_invalid_weapon(void)
{
    xury_weapon_context_t c = make_ctx_full();
    TEST_ASSERT(!xury_weapon_applicable(XURY_WEAPON_NONE, &c));
    TEST_ASSERT(!xury_weapon_applicable((xury_weapon_t)999, &c));
}

static void test_applicable_null_ctx_blocks_aggressive(void)
{
    TEST_ASSERT(!xury_weapon_applicable(XURY_WEAPON_BIRTHDAY, NULL));
    TEST_ASSERT(!xury_weapon_applicable(XURY_WEAPON_UPGRADE, NULL));

    TEST_ASSERT(xury_weapon_applicable(XURY_WEAPON_IPV6, NULL));
    TEST_ASSERT(xury_weapon_applicable(XURY_WEAPON_HOLE, NULL));
}

static void test_applicable_ipv6_needs_ipv6(void)
{
    xury_weapon_context_t c = make_ctx_all_off();
    TEST_ASSERT(!xury_weapon_applicable(XURY_WEAPON_IPV6, &c));

    c.ipv6_present  = true;
    c.ipv6_global   = true;
    c.peer_has_ipv6 = true;
    TEST_ASSERT(xury_weapon_applicable(XURY_WEAPON_IPV6, &c));
}

static void test_applicable_ipv6_needs_global(void)
{
    xury_weapon_context_t c = make_ctx_all_off();
    c.ipv6_present  = true;
    c.ipv6_global   = false;
    c.peer_has_ipv6 = true;
    TEST_ASSERT(!xury_weapon_applicable(XURY_WEAPON_IPV6, &c));
}

static void test_applicable_lan_needs_same_lan(void)
{
    xury_weapon_context_t c = make_ctx_full();
    c.peer_is_lan = false;
    TEST_ASSERT(!xury_weapon_applicable(XURY_WEAPON_LAN, &c));

    c.peer_is_lan = true;
    TEST_ASSERT(xury_weapon_applicable(XURY_WEAPON_LAN, &c));
}

static void test_applicable_upnp_needs_upnp(void)
{
    xury_weapon_context_t c = make_ctx_full();
    c.upnp_available = false;
    TEST_ASSERT(!xury_weapon_applicable(XURY_WEAPON_UPNP, &c));

    c.upnp_available = true;
    TEST_ASSERT(xury_weapon_applicable(XURY_WEAPON_UPNP, &c));
}

static void test_applicable_hole_needs_peer(void)
{
    xury_weapon_context_t c = make_ctx_all_off();
    TEST_ASSERT(!xury_weapon_applicable(XURY_WEAPON_HOLE, &c));

    c.peer_reachable = true;
    TEST_ASSERT(xury_weapon_applicable(XURY_WEAPON_HOLE, &c));
}

static void test_applicable_predict_needs_predictable(void)
{
    xury_weapon_context_t c = make_ctx_full();
    c.port_predictable = false;
    TEST_ASSERT(!xury_weapon_applicable(XURY_WEAPON_PREDICT, &c));

    c.port_predictable = true;
    TEST_ASSERT(xury_weapon_applicable(XURY_WEAPON_PREDICT, &c));
}

static void test_applicable_birthday_needs_symmetric_or_cgnat(void)
{
    xury_weapon_context_t c = make_ctx_full();
    c.symmetric = false;
    c.cgnat     = false;
    TEST_ASSERT(!xury_weapon_applicable(XURY_WEAPON_BIRTHDAY, &c));

    c.symmetric = true;
    TEST_ASSERT(xury_weapon_applicable(XURY_WEAPON_BIRTHDAY, &c));

    c.symmetric = false;
    c.cgnat     = true;
    TEST_ASSERT(xury_weapon_applicable(XURY_WEAPON_BIRTHDAY, &c));
}

static void test_applicable_relay_needs_helper(void)
{
    xury_weapon_context_t c = make_ctx_full();
    c.helper_available = false;
    TEST_ASSERT(!xury_weapon_applicable(XURY_WEAPON_RELAY, &c));

    c.helper_available = true;
    TEST_ASSERT(xury_weapon_applicable(XURY_WEAPON_RELAY, &c));
}

static void test_applicable_aggressive_needs_opt_in(void)
{
    xury_weapon_context_t c = make_ctx_full();

    c.allow_aggressive = false;
    TEST_ASSERT(!xury_weapon_applicable(XURY_WEAPON_BIRTHDAY, &c));
    TEST_ASSERT(!xury_weapon_applicable(XURY_WEAPON_UPGRADE, &c));

    c.allow_aggressive = true;
    /* ✅ FIX: symmetric=true in make_ctx_full → BIRTHDAY applicable */
    TEST_ASSERT(xury_weapon_applicable(XURY_WEAPON_BIRTHDAY, &c));
    TEST_ASSERT(xury_weapon_applicable(XURY_WEAPON_UPGRADE, &c));
}

/*
 * ============================================================================
 * APPLICABLE MASK
 * ============================================================================
 */

static void test_applicable_mask_empty_context(void)
{
    xury_weapon_context_t c = make_ctx_all_off();
    uint32_t mask = xury_weapon_applicable_mask(&c);
    TEST_ASSERT_EQ(mask, 0u);
}

static void test_applicable_mask_full_context(void)
{
    xury_weapon_context_t c = make_ctx_full();
    uint32_t mask = xury_weapon_applicable_mask(&c);
    /* ✅ FIX: with symmetric=true, BIRTHDAY is included → all pass */
    TEST_ASSERT_EQ(mask, XURY_WEAPON_ALL_MASK);
}

static void test_applicable_mask_null_ctx_blocks_aggressive(void)
{
    uint32_t mask = xury_weapon_applicable_mask(NULL);
    TEST_ASSERT(!(mask & XURY_WEAPON_BIT(XURY_WEAPON_BIRTHDAY)));
    TEST_ASSERT(!(mask & XURY_WEAPON_BIT(XURY_WEAPON_UPGRADE)));
    TEST_ASSERT(mask & XURY_WEAPON_BIT(XURY_WEAPON_IPV6));
}

/*
 * ============================================================================
 * BITMASK ITERATION
 * ============================================================================
 */

static void test_mask_count(void)
{
    TEST_ASSERT_EQ(xury_weapon_mask_count(0u), 0u);
    TEST_ASSERT_EQ(xury_weapon_mask_count(
        XURY_WEAPON_BIT(XURY_WEAPON_IPV6)), 1u);
    TEST_ASSERT_EQ(xury_weapon_mask_count(
        XURY_WEAPON_BIT(XURY_WEAPON_IPV6) |
        XURY_WEAPON_BIT(XURY_WEAPON_HOLE)), 2u);
    TEST_ASSERT_EQ(xury_weapon_mask_count(XURY_WEAPON_ALL_MASK),
                   (size_t)(XURY_WEAPON_COUNT - 1));
}

static void test_mask_next_priority_order(void)
{
    uint32_t mask = XURY_WEAPON_BIT(XURY_WEAPON_IPV6) |
                    XURY_WEAPON_BIT(XURY_WEAPON_HOLE) |
                    XURY_WEAPON_BIT(XURY_WEAPON_UPNP);

    xury_weapon_t first = xury_weapon_mask_next(&mask, XURY_WEAPON_NONE);
    TEST_ASSERT_EQ(first, XURY_WEAPON_IPV6);

    xury_weapon_t second = xury_weapon_mask_next(&mask, first);
    TEST_ASSERT_EQ(second, XURY_WEAPON_UPNP);

    xury_weapon_t third = xury_weapon_mask_next(&mask, second);
    TEST_ASSERT_EQ(third, XURY_WEAPON_HOLE);

    xury_weapon_t fourth = xury_weapon_mask_next(&mask, third);
    TEST_ASSERT_EQ(fourth, XURY_WEAPON_NONE);

    TEST_ASSERT_EQ(mask, 0u);
}

static void test_mask_next_null_mask(void)
{
    xury_weapon_t w = xury_weapon_mask_next(NULL, XURY_WEAPON_NONE);
    TEST_ASSERT_EQ(w, XURY_WEAPON_NONE);
}

static void test_mask_next_empty(void)
{
    uint32_t mask = 0u;
    xury_weapon_t w = xury_weapon_mask_next(&mask, XURY_WEAPON_NONE);
    TEST_ASSERT_EQ(w, XURY_WEAPON_NONE);
}

static void test_mask_format_empty(void)
{
    char buf[64];
    size_t n = xury_weapon_mask_format(0u, buf, sizeof(buf));
    TEST_ASSERT_EQ(n, 0u);
    TEST_ASSERT_STREQ(buf, "");
}

static void test_mask_format_single(void)
{
    char buf[64];
    xury_weapon_mask_format(XURY_WEAPON_BIT(XURY_WEAPON_IPV6),
                            buf, sizeof(buf));
    TEST_ASSERT_STREQ(buf, "ipv6");
}

static void test_mask_format_multiple_priority_order(void)
{
    char buf[128];
    uint32_t mask = XURY_WEAPON_BIT(XURY_WEAPON_HOLE) |
                    XURY_WEAPON_BIT(XURY_WEAPON_IPV6) |
                    XURY_WEAPON_BIT(XURY_WEAPON_UPNP);
    xury_weapon_mask_format(mask, buf, sizeof(buf));
    TEST_ASSERT_STREQ(buf, "ipv6,upnp,hole");
}

static void test_mask_format_truncation(void)
{
    char buf[4];
    uint32_t mask = XURY_WEAPON_BIT(XURY_WEAPON_IPV6) |
                    XURY_WEAPON_BIT(XURY_WEAPON_UPNP) |
                    XURY_WEAPON_BIT(XURY_WEAPON_HOLE);
    size_t need = xury_weapon_mask_format(mask, buf, sizeof(buf));

    TEST_ASSERT(need >= sizeof(buf));
    TEST_ASSERT_EQ(buf[sizeof(buf) - 1u], '\0');
}

/*
 * ============================================================================
 * PARSING
 * ============================================================================
 */

static void test_from_tag_all(void)
{
    TEST_ASSERT_EQ(xury_weapon_from_tag("none"),
                   XURY_WEAPON_NONE);
    TEST_ASSERT_EQ(xury_weapon_from_tag("ipv6"),
                   XURY_WEAPON_IPV6);
    TEST_ASSERT_EQ(xury_weapon_from_tag("lan"),
                   XURY_WEAPON_LAN);
    TEST_ASSERT_EQ(xury_weapon_from_tag("upnp"),
                   XURY_WEAPON_UPNP);
    TEST_ASSERT_EQ(xury_weapon_from_tag("natpmp"),
                   XURY_WEAPON_NATPMP);
    TEST_ASSERT_EQ(xury_weapon_from_tag("pcp"),
                   XURY_WEAPON_PCP);
    TEST_ASSERT_EQ(xury_weapon_from_tag("hole"),
                   XURY_WEAPON_HOLE);
    TEST_ASSERT_EQ(xury_weapon_from_tag("predict"),
                   XURY_WEAPON_PREDICT);
    TEST_ASSERT_EQ(xury_weapon_from_tag("birthday"),
                   XURY_WEAPON_BIRTHDAY);
    TEST_ASSERT_EQ(xury_weapon_from_tag("mirror"),
                   XURY_WEAPON_MIRROR);
    TEST_ASSERT_EQ(xury_weapon_from_tag("relay"),
                   XURY_WEAPON_RELAY);
    TEST_ASSERT_EQ(xury_weapon_from_tag("upgrade"),
                   XURY_WEAPON_UPGRADE);
}

static void test_from_tag_invalid(void)
{
    TEST_ASSERT_EQ(xury_weapon_from_tag(NULL), XURY_WEAPON_NONE);
    TEST_ASSERT_EQ(xury_weapon_from_tag(""), XURY_WEAPON_NONE);
    TEST_ASSERT_EQ(xury_weapon_from_tag("bogus"), XURY_WEAPON_NONE);
    TEST_ASSERT_EQ(xury_weapon_from_tag("IPV6"), XURY_WEAPON_NONE);
}

static void test_mask_from_string_single(void)
{
    size_t unknown = 0;
    uint32_t mask = xury_weapon_mask_from_string("ipv6", &unknown);
    TEST_ASSERT_EQ(mask, XURY_WEAPON_BIT(XURY_WEAPON_IPV6));
    TEST_ASSERT_EQ(unknown, 0u);
}

static void test_mask_from_string_multiple(void)
{
    size_t unknown = 0;
    uint32_t mask = xury_weapon_mask_from_string("ipv6,upnp,hole",
                                                 &unknown);
    uint32_t expect = XURY_WEAPON_BIT(XURY_WEAPON_IPV6) |
                      XURY_WEAPON_BIT(XURY_WEAPON_UPNP) |
                      XURY_WEAPON_BIT(XURY_WEAPON_HOLE);
    TEST_ASSERT_EQ(mask, expect);
    TEST_ASSERT_EQ(unknown, 0u);
}

static void test_mask_from_string_whitespace(void)
{
    size_t unknown = 0;
    uint32_t mask = xury_weapon_mask_from_string(
        "  ipv6 , upnp , hole  ", &unknown);
    uint32_t expect = XURY_WEAPON_BIT(XURY_WEAPON_IPV6) |
                      XURY_WEAPON_BIT(XURY_WEAPON_UPNP) |
                      XURY_WEAPON_BIT(XURY_WEAPON_HOLE);
    TEST_ASSERT_EQ(mask, expect);
    TEST_ASSERT_EQ(unknown, 0u);
}

static void test_mask_from_string_unknown_counted(void)
{
    size_t unknown = 0;
    uint32_t mask = xury_weapon_mask_from_string(
        "ipv6,bogus,hole,xxx", &unknown);
    uint32_t expect = XURY_WEAPON_BIT(XURY_WEAPON_IPV6) |
                      XURY_WEAPON_BIT(XURY_WEAPON_HOLE);
    TEST_ASSERT_EQ(mask, expect);
    TEST_ASSERT_EQ(unknown, 2u);
}

static void test_mask_from_string_none_is_silent(void)
{
    size_t unknown = 0;
    uint32_t mask = xury_weapon_mask_from_string("none", &unknown);
    TEST_ASSERT_EQ(mask, 0u);
    TEST_ASSERT_EQ(unknown, 0u);
}

static void test_mask_from_string_null(void)
{
    size_t unknown = 0;
    uint32_t mask = xury_weapon_mask_from_string(NULL, &unknown);
    TEST_ASSERT_EQ(mask, 0u);
    TEST_ASSERT_EQ(unknown, 0u);
}

static void test_mask_from_string_empty(void)
{
    size_t unknown = 0;
    uint32_t mask = xury_weapon_mask_from_string("", &unknown);
    TEST_ASSERT_EQ(mask, 0u);
    TEST_ASSERT_EQ(unknown, 0u);
}

static void test_mask_from_string_roundtrip(void)
{
    uint32_t mask = XURY_WEAPON_BIT(XURY_WEAPON_IPV6) |
                    XURY_WEAPON_BIT(XURY_WEAPON_HOLE) |
                    XURY_WEAPON_BIT(XURY_WEAPON_RELAY);

    char buf[128];
    xury_weapon_mask_format(mask, buf, sizeof(buf));

    size_t unknown = 0;
    uint32_t parsed = xury_weapon_mask_from_string(buf, &unknown);
    TEST_ASSERT_EQ(parsed, mask);
    TEST_ASSERT_EQ(unknown, 0u);
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    TEST_RUN(test_table_size);
    TEST_RUN(test_table_at_out_of_range);
    TEST_RUN(test_table_at_none_first);
    TEST_RUN(test_table_every_entry_well_formed);
    TEST_RUN(test_table_tags_unique);

    TEST_RUN(test_get_info_valid);
    TEST_RUN(test_get_info_invalid);
    TEST_RUN(test_info_or_null_matches_get_info);

    TEST_RUN(test_weapon_tag);
    TEST_RUN(test_weapon_name_not_null);

    TEST_RUN(test_weapon_category);
    TEST_RUN(test_weapon_category_tag);

    TEST_RUN(test_has_flag);
    TEST_RUN(test_has_flag_invalid);

    TEST_RUN(test_base_strength_range);
    TEST_RUN(test_base_cost_range);
    TEST_RUN(test_base_strength_ipv6_is_max);
    TEST_RUN(test_base_cost_ipv6_is_cheap);
    TEST_RUN(test_strength_cost_invalid);

    TEST_RUN(test_priority_range);
    TEST_RUN(test_priority_unique);
    TEST_RUN(test_priority_ipv6_first);
    TEST_RUN(test_priority_lan_second);
    TEST_RUN(test_priority_birthday_last);
    TEST_RUN(test_priority_invalid);
    TEST_RUN(test_at_priority_roundtrip);
    TEST_RUN(test_at_priority_out_of_range);

    TEST_RUN(test_applicable_invalid_weapon);
    TEST_RUN(test_applicable_null_ctx_blocks_aggressive);
    TEST_RUN(test_applicable_ipv6_needs_ipv6);
    TEST_RUN(test_applicable_ipv6_needs_global);
    TEST_RUN(test_applicable_lan_needs_same_lan);
    TEST_RUN(test_applicable_upnp_needs_upnp);
    TEST_RUN(test_applicable_hole_needs_peer);
    TEST_RUN(test_applicable_predict_needs_predictable);
    TEST_RUN(test_applicable_birthday_needs_symmetric_or_cgnat);
    TEST_RUN(test_applicable_relay_needs_helper);
    TEST_RUN(test_applicable_aggressive_needs_opt_in);
    TEST_RUN(test_applicable_mask_empty_context);
    TEST_RUN(test_applicable_mask_full_context);
    TEST_RUN(test_applicable_mask_null_ctx_blocks_aggressive);

    TEST_RUN(test_mask_count);
    TEST_RUN(test_mask_next_priority_order);
    TEST_RUN(test_mask_next_null_mask);
    TEST_RUN(test_mask_next_empty);
    TEST_RUN(test_mask_format_empty);
    TEST_RUN(test_mask_format_single);
    TEST_RUN(test_mask_format_multiple_priority_order);
    TEST_RUN(test_mask_format_truncation);

    TEST_RUN(test_from_tag_all);
    TEST_RUN(test_from_tag_invalid);
    TEST_RUN(test_mask_from_string_single);
    TEST_RUN(test_mask_from_string_multiple);
    TEST_RUN(test_mask_from_string_whitespace);
    TEST_RUN(test_mask_from_string_unknown_counted);
    TEST_RUN(test_mask_from_string_none_is_silent);
    TEST_RUN(test_mask_from_string_null);
    TEST_RUN(test_mask_from_string_empty);
    TEST_RUN(test_mask_from_string_roundtrip);
}

TEST_MAIN()
