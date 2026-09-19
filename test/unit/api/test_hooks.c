
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
 * TESTS — src/api/hooks.c
 * ============================================================================
 *
 * Exercise the real hook primitives:
 *
 *   xury_hooks_init()
 *   xury_hooks_set_log_level() / _get_log_level()
 *   xury_hooks_any_set() / _has_log()
 *   xury_hooks_enter() / _leave() / _in_hook()
 *   xury_hooks_fire_log() / _fire_log_tagged()
 *   xury_hooks_fire_phase() / _fire_scan_done() / _fire_weapon_result()
 *   xury_log_level_name() / _from_name() / _char()
 *
 * A capture hook records what the fire functions delivered.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "api/internal/hooks.h"
#include "test/test.h"

/*
 * ============================================================================
 * CAPTURE STATE
 * ============================================================================
 */

typedef struct {
    int              log_calls;
    xury_log_level_t log_last_level;
    char             log_last_msg[512];

    int              phase_calls;
    xury_phase_t     phase_last;

    int              scan_calls;
    const void      *scan_last_ptr;

    int              weapon_calls;
    xury_weapon_t    weapon_last_weapon;
    xury_err_t       weapon_last_result;
} capture_t;

static capture_t g_cap;

static void capture_reset(void)
{
    memset(&g_cap, 0, sizeof(g_cap));
}

static void cap_log_hook(xury_log_level_t level,
                         const char *msg,
                         void *ud)
{
    capture_t *c = (capture_t *)ud;
    c->log_calls++;
    c->log_last_level = level;
    size_t i = 0;
    while (msg[i] != '\0' && i + 1u < sizeof(c->log_last_msg)) {
        c->log_last_msg[i] = msg[i];
        i++;
    }
    c->log_last_msg[i] = '\0';
}

static void cap_phase_hook(xury_phase_t phase, void *ud)
{
    capture_t *c = (capture_t *)ud;
    c->phase_calls++;
    c->phase_last = phase;
}

static void cap_scan_hook(const void *scan_result, void *ud)
{
    capture_t *c = (capture_t *)ud;
    c->scan_calls++;
    c->scan_last_ptr = scan_result;
}

static void cap_weapon_hook(xury_weapon_t w, xury_err_t rc, void *ud)
{
    capture_t *c = (capture_t *)ud;
    c->weapon_calls++;
    c->weapon_last_weapon = w;
    c->weapon_last_result = rc;
}

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

static xury_hook_set_t make_hook_set(void)
{
    xury_hook_set_t hs;
    xury_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.on_log            = cap_log_hook;
    cfg.log_userdata      = &g_cap;
    cfg.on_phase          = cap_phase_hook;
    cfg.phase_userdata    = &g_cap;
    cfg.on_scan_done      = cap_scan_hook;
    cfg.scan_userdata     = &g_cap;
    cfg.on_weapon_result  = cap_weapon_hook;
    cfg.weapon_userdata   = &g_cap;
    xury_hooks_init(&hs, &cfg);
    return hs;
}

/*
 * ============================================================================
 * INIT
 * ============================================================================
 */

static void test_init_null_is_noop(void)
{
    xury_hooks_init(NULL, NULL);
    /* No crash. */
}

static void test_init_defaults(void)
{
    xury_hook_set_t hs;
    xury_hooks_init(&hs, NULL);

    TEST_ASSERT_NULL(hs.log);
    TEST_ASSERT_NULL(hs.phase);
    TEST_ASSERT_NULL(hs.scan_done);
    TEST_ASSERT_NULL(hs.weapon_result);
    TEST_ASSERT_NULL(hs.in_hook_flag);
    TEST_ASSERT_EQ(hs.log_min_level, XURY_LOG_INFO);
    TEST_ASSERT(hs.slow_hook_warn_us > 0u);
}

static void test_init_copies_hooks(void)
{
    capture_reset();
    xury_hook_set_t hs = make_hook_set();

    TEST_ASSERT(hs.log == cap_log_hook);
    TEST_ASSERT(hs.phase == cap_phase_hook);
    TEST_ASSERT(hs.scan_done == cap_scan_hook);
    TEST_ASSERT(hs.weapon_result == cap_weapon_hook);
    TEST_ASSERT(hs.log_userdata == &g_cap);
}

static void test_any_set(void)
{
    xury_hook_set_t hs;
    xury_hooks_init(&hs, NULL);
    TEST_ASSERT(!xury_hooks_any_set(&hs));
    TEST_ASSERT(!xury_hooks_any_set(NULL));

    xury_hook_set_t hs2 = make_hook_set();
    TEST_ASSERT(xury_hooks_any_set(&hs2));
}

static void test_has_log(void)
{
    xury_hook_set_t hs;
    xury_hooks_init(&hs, NULL);
    TEST_ASSERT(!xury_hooks_has_log(&hs));
    TEST_ASSERT(!xury_hooks_has_log(NULL));

    xury_hook_set_t hs2 = make_hook_set();
    TEST_ASSERT(xury_hooks_has_log(&hs2));
}

/*
 * ============================================================================
 * LOG LEVEL
 * ============================================================================
 */

static void test_set_get_level(void)
{
    xury_hook_set_t hs;
    xury_hooks_init(&hs, NULL);

    xury_hooks_set_log_level(&hs, XURY_LOG_ERROR);
    TEST_ASSERT_EQ(xury_hooks_get_log_level(&hs), XURY_LOG_ERROR);

    xury_hooks_set_log_level(&hs, XURY_LOG_TRACE);
    TEST_ASSERT_EQ(xury_hooks_get_log_level(&hs), XURY_LOG_TRACE);
}

static void test_get_level_null(void)
{
    TEST_ASSERT_EQ(xury_hooks_get_log_level(NULL), XURY_LOG_INFO);
}

static void test_set_level_null(void)
{
    xury_hooks_set_log_level(NULL, XURY_LOG_DEBUG);
    /* No crash. */
}

/*
 * ============================================================================
 * FIRE LOG
 * ============================================================================
 */

static void test_fire_log_basic(void)
{
    capture_reset();
    xury_hook_set_t hs = make_hook_set();
    xury_hooks_set_log_level(&hs, XURY_LOG_TRACE);

    xury_hooks_fire_log(&hs, XURY_LOG_INFO, "hello");

    TEST_ASSERT_EQ(g_cap.log_calls, 1);
    TEST_ASSERT_EQ(g_cap.log_last_level, XURY_LOG_INFO);
    TEST_ASSERT_STREQ(g_cap.log_last_msg, "hello");
}

static void test_fire_log_filters_below_level(void)
{
    capture_reset();
    xury_hook_set_t hs = make_hook_set();
    xury_hooks_set_log_level(&hs, XURY_LOG_WARN);

    xury_hooks_fire_log(&hs, XURY_LOG_INFO, "should drop");

    TEST_ASSERT_EQ(g_cap.log_calls, 0);
}

static void test_fire_log_null_safe(void)
{
    capture_reset();
    xury_hook_set_t hs = make_hook_set();
    xury_hooks_set_log_level(&hs, XURY_LOG_TRACE);

    xury_hooks_fire_log(NULL, XURY_LOG_INFO, "x");
    xury_hooks_fire_log(&hs, XURY_LOG_INFO, NULL);

    TEST_ASSERT_EQ(g_cap.log_calls, 0);
}

static void test_fire_log_tagged(void)
{
    capture_reset();
    xury_hook_set_t hs = make_hook_set();
    xury_hooks_set_log_level(&hs, XURY_LOG_TRACE);

    xury_hooks_fire_log_tagged(&hs, XURY_LOG_INFO, "scan", "ok");

    TEST_ASSERT_EQ(g_cap.log_calls, 1);
    TEST_ASSERT_STREQ(g_cap.log_last_msg, "[scan] ok");
}

static void test_fire_log_tagged_no_tag(void)
{
    capture_reset();
    xury_hook_set_t hs = make_hook_set();
    xury_hooks_set_log_level(&hs, XURY_LOG_TRACE);

    xury_hooks_fire_log_tagged(&hs, XURY_LOG_INFO, NULL, "plain");

    TEST_ASSERT_STREQ(g_cap.log_last_msg, "plain");
}

/*
 * ============================================================================
 * FIRE PHASE / SCAN / WEAPON
 * ============================================================================
 */

static void test_fire_phase(void)
{
    capture_reset();
    xury_hook_set_t hs = make_hook_set();

    xury_hooks_fire_phase(&hs, XURY_PHASE_SCAN);

    TEST_ASSERT_EQ(g_cap.phase_calls, 1);
    TEST_ASSERT_EQ(g_cap.phase_last, XURY_PHASE_SCAN);
}

static void test_fire_scan_done(void)
{
    capture_reset();
    xury_hook_set_t hs = make_hook_set();
    int dummy = 0;

    xury_hooks_fire_scan_done(&hs, &dummy);

    TEST_ASSERT_EQ(g_cap.scan_calls, 1);
    TEST_ASSERT(g_cap.scan_last_ptr == &dummy);
}

static void test_fire_weapon_result(void)
{
    capture_reset();
    xury_hook_set_t hs = make_hook_set();

    xury_hooks_fire_weapon_result(&hs, XURY_WEAPON_HOLE, XURY_OK);

    TEST_ASSERT_EQ(g_cap.weapon_calls, 1);
    TEST_ASSERT_EQ(g_cap.weapon_last_weapon, XURY_WEAPON_HOLE);
    TEST_ASSERT_EQ(g_cap.weapon_last_result, XURY_OK);
}

/*
 * ============================================================================
 * REENTRANCY
 * ============================================================================
 */

static void test_enter_leave(void)
{
    xury_hook_set_t hs = make_hook_set();
    int flag = 0;
    hs.in_hook_flag = &flag;

    uint64_t t0 = 0;
    TEST_ASSERT(xury_hooks_enter(&hs, &t0));
    TEST_ASSERT_EQ(flag, 1);
    TEST_ASSERT(xury_hooks_in_hook(&hs));

    xury_hooks_leave(&hs, "test", t0);
    TEST_ASSERT_EQ(flag, 0);
    TEST_ASSERT(!xury_hooks_in_hook(&hs));
}

static void test_enter_when_already_in_hook(void)
{
    xury_hook_set_t hs = make_hook_set();
    int flag = 1;   /* pretend we are already in a hook */
    hs.in_hook_flag = &flag;

    uint64_t t0 = 0;
    TEST_ASSERT(!xury_hooks_enter(&hs, &t0));
    TEST_ASSERT_EQ(flag, 1);   /* unchanged */
}

static void test_enter_no_flag_allows(void)
{
    xury_hook_set_t hs = make_hook_set();
    hs.in_hook_flag = NULL;

    uint64_t t0 = 0;
    TEST_ASSERT(xury_hooks_enter(&hs, &t0));
}

static void test_in_hook_null(void)
{
    TEST_ASSERT(!xury_hooks_in_hook(NULL));
    xury_hook_set_t hs = make_hook_set();
    hs.in_hook_flag = NULL;
    TEST_ASSERT(!xury_hooks_in_hook(&hs));
}

/*
 * ============================================================================
 * LOG LEVEL NAMES
 * ============================================================================
 */

static void test_level_name(void)
{
    TEST_ASSERT_STREQ(xury_log_level_name(XURY_LOG_TRACE), "trace");
    TEST_ASSERT_STREQ(xury_log_level_name(XURY_LOG_DEBUG), "debug");
    TEST_ASSERT_STREQ(xury_log_level_name(XURY_LOG_INFO),  "info");
    TEST_ASSERT_STREQ(xury_log_level_name(XURY_LOG_WARN),  "warn");
    TEST_ASSERT_STREQ(xury_log_level_name(XURY_LOG_ERROR), "error");
    TEST_ASSERT_STREQ(xury_log_level_name((xury_log_level_t)99), "unknown");
}

static void test_level_char(void)
{
    TEST_ASSERT_EQ(xury_log_level_char(XURY_LOG_TRACE), 'T');
    TEST_ASSERT_EQ(xury_log_level_char(XURY_LOG_DEBUG), 'D');
    TEST_ASSERT_EQ(xury_log_level_char(XURY_LOG_INFO),  'I');
    TEST_ASSERT_EQ(xury_log_level_char(XURY_LOG_WARN),  'W');
    TEST_ASSERT_EQ(xury_log_level_char(XURY_LOG_ERROR), 'E');
    TEST_ASSERT_EQ(xury_log_level_char((xury_log_level_t)99), '?');
}

static void test_level_from_name(void)
{
    bool ok = false;

    TEST_ASSERT_EQ(xury_log_level_from_name("info", &ok), XURY_LOG_INFO);
    TEST_ASSERT(ok);

    TEST_ASSERT_EQ(xury_log_level_from_name("WARN", &ok), XURY_LOG_WARN);
    TEST_ASSERT(ok);

    TEST_ASSERT_EQ(xury_log_level_from_name("warning", &ok), XURY_LOG_WARN);
    TEST_ASSERT(ok);

    TEST_ASSERT_EQ(xury_log_level_from_name("err", &ok), XURY_LOG_ERROR);
    TEST_ASSERT(ok);

    TEST_ASSERT_EQ(xury_log_level_from_name(NULL, &ok), XURY_LOG_INFO);
    TEST_ASSERT(!ok);

    TEST_ASSERT_EQ(xury_log_level_from_name("bogus", &ok), XURY_LOG_INFO);
    TEST_ASSERT(!ok);

    /* ok may be NULL. */
    TEST_ASSERT_EQ(xury_log_level_from_name("debug", NULL), XURY_LOG_DEBUG);
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    TEST_RUN(test_init_null_is_noop);
    TEST_RUN(test_init_defaults);
    TEST_RUN(test_init_copies_hooks);
    TEST_RUN(test_any_set);
    TEST_RUN(test_has_log);

    TEST_RUN(test_set_get_level);
    TEST_RUN(test_get_level_null);
    TEST_RUN(test_set_level_null);

    TEST_RUN(test_fire_log_basic);
    TEST_RUN(test_fire_log_filters_below_level);
    TEST_RUN(test_fire_log_null_safe);
    TEST_RUN(test_fire_log_tagged);
    TEST_RUN(test_fire_log_tagged_no_tag);

    TEST_RUN(test_fire_phase);
    TEST_RUN(test_fire_scan_done);
    TEST_RUN(test_fire_weapon_result);

    TEST_RUN(test_enter_leave);
    TEST_RUN(test_enter_when_already_in_hook);
    TEST_RUN(test_enter_no_flag_allows);
    TEST_RUN(test_in_hook_null);

    TEST_RUN(test_level_name);
    TEST_RUN(test_level_char);
    TEST_RUN(test_level_from_name);
}

TEST_MAIN()
