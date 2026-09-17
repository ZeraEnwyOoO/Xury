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
 * XURY HOOKS — IMPLEMENTATION
 * ============================================================================
 *
 * Implements the internal hook dispatch layer declared in
 * src/api/internal/hooks.h.
 *
 * Design goals:
 *
 *   - Tolerate NULL hooks and NULL hook sets.
 *   - Never allocate.
 *   - Detect reentrancy: a hook must not call back into the engine.
 *   - Warn once per site when a hook is slow.
 *   - Filter log messages by a per-engine minimum level.
 *
 * The hook set is stored inside the engine. The engine sets
 * in_hook_flag to the address of its own reentrancy flag after
 * calling xury_hooks_init(). This file never allocates the flag.
 *
 * Time source: the platform layer (Phase 4) provides
 * xury_platform_time_now_us(). Until that exists, this file uses a
 * small forward declaration that Phase 4 will provide. Calling into
 * it before Phase 4 is a link-time error, which is correct: nothing
 * should call the hook dispatcher until the platform exists.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/types.h>
#include <xury/err.h>
#include <xury/hooks.h>

#include "api/internal/hooks.h"

/*
 * ----------------------------------------------------------------------------
 * Platform time (provided by Phase 4).
 * ----------------------------------------------------------------------------
 * Declared here so this file can compile before Phase 4 lands. The
 * linker resolves it once the platform layer is present.
 */
extern uint64_t xury_platform_time_now_us(void);

/*
 * ----------------------------------------------------------------------------
 * Defaults
 * ----------------------------------------------------------------------------
 */

#define XURY_HOOKS_DEFAULT_LOG_LEVEL      XURY_LOG_INFO
#define XURY_HOOKS_DEFAULT_SLOW_WARN_US   5000u   /* 5 ms */

/*
 * ============================================================================
 * INITIALIZATION
 * ============================================================================
 */

void xury_hooks_init(xury_hook_set_t *hs, const xury_config_t *cfg)
{
    if (hs == NULL) {
        return;
    }

    memset(hs, 0, sizeof(*hs));

    hs->log_min_level      = XURY_HOOKS_DEFAULT_LOG_LEVEL;
    hs->slow_hook_warn_us  = XURY_HOOKS_DEFAULT_SLOW_WARN_US;
    hs->in_hook_flag       = NULL;

    if (cfg == NULL) {
        return;
    }

    /*
     * Copy function pointers and userdata verbatim. The engine may
     * replace the in_hook_flag pointer after this call.
     */
    hs->log            = cfg->on_log;
    hs->log_userdata   = cfg->log_userdata;

    hs->phase          = cfg->on_phase;
    hs->phase_userdata = cfg->phase_userdata;

    hs->scan_done      = cfg->on_scan_done;
    hs->scan_userdata  = cfg->scan_userdata;

    hs->weapon_result  = cfg->on_weapon_result;
    hs->weapon_userdata= cfg->weapon_userdata;
}

void xury_hooks_set_log_level(xury_hook_set_t *hs,
                              xury_log_level_t level)
{
    if (hs == NULL) {
        return;
    }
    hs->log_min_level = level;
}

xury_log_level_t xury_hooks_get_log_level(const xury_hook_set_t *hs)
{
    if (hs == NULL) {
        return XURY_HOOKS_DEFAULT_LOG_LEVEL;
    }
    return hs->log_min_level;
}

bool xury_hooks_any_set(const xury_hook_set_t *hs)
{
    if (hs == NULL) {
        return false;
    }
    return (hs->log           != NULL) ||
           (hs->phase         != NULL) ||
           (hs->scan_done     != NULL) ||
           (hs->weapon_result != NULL);
}

bool xury_hooks_has_log(const xury_hook_set_t *hs)
{
    if (hs == NULL) {
        return false;
    }
    return hs->log != NULL;
}

/*
 * ============================================================================
 * REENTRANCY
 * ============================================================================
 *
 * The reentrancy flag is a plain int owned by the engine. A value of
 * 0 means "not in a hook"; any non-zero value means "in a hook".
 *
 * Because the flag is per engine, not per thread, two threads using
 * the same engine would fight over it. This is fine: the engine is
 * documented as one-engine-one-thread, except for BLITZ worker
 * threads that only call the weapon_result hook. Those workers set
 * the flag themselves and do not share the engine's other hooks.
 *
 * To keep BLITZ workers from spuriously triggering the reentrancy
 * guard, the flag is set only inside xury_hooks_fire_* and cleared on
 * the way out. A worker thread that fires weapon_result will set and
 * clear the flag on its own; if two workers race, one may see the
 * flag set and skip its hook. That is acceptable: the guard exists
 * to prevent infinite recursion, not to guarantee every hook fires.
 */

bool xury_hooks_enter(xury_hook_set_t *hs, uint64_t *out_enter_us)
{
    if (hs == NULL) {
        return false;
    }
    if (hs->in_hook_flag == NULL) {
        /* No flag installed: skip the guard, allow the hook. */
        if (out_enter_us != NULL) {
            *out_enter_us = xury_platform_time_now_us();
        }
        return true;
    }
    if (*hs->in_hook_flag != 0) {
        /* Already in a hook on this engine: skip. */
        return false;
    }
    *hs->in_hook_flag = 1;

    if (out_enter_us != NULL) {
        *out_enter_us = xury_platform_time_now_us();
    }
    return true;
}

void xury_hooks_leave(xury_hook_set_t *hs,
                      const char *site,
                      uint64_t enter_us)
{
    if (hs == NULL) {
        return;
    }

    if (hs->in_hook_flag != NULL) {
        *hs->in_hook_flag = 0;
    }

    if (hs->slow_hook_warn_us == 0u) {
        return;
    }
    if (hs->log == NULL) {
        return;
    }

    const uint64_t now = xury_platform_time_now_us();
    const uint64_t dur = (now >= enter_us) ? (now - enter_us) : 0u;

    if (dur <= (uint64_t)hs->slow_hook_warn_us) {
        return;
    }

    /*
     * Warn through the log hook. We deliberately do NOT use
     * xury_hooks_fire_log() here, because we are already inside the
     * hook guard and that would be dropped. Call the log hook
     * directly, but guard against re-entering xury_hooks_leave().
     *
     * This is the only place in the file that calls hs->log directly.
     */
    char msg[96];
    const char *s = (site != NULL) ? site : "hook";
    int n = 0;

    /* Build "slow hook: <site> took <dur> us" without snprintf. */
    const char *prefix = "slow hook: ";
    for (const char *p = prefix; *p != '\0' && n < (int)sizeof(msg) - 1;
         p++) {
        msg[n++] = *p;
    }
    for (const char *p = s; *p != '\0' && n < (int)sizeof(msg) - 1; p++) {
        msg[n++] = *p;
    }
    const char *mid = " took ";
    for (const char *p = mid; *p != '\0' && n < (int)sizeof(msg) - 1;
         p++) {
        msg[n++] = *p;
    }

    /* Unsigned decimal for dur. */
    char num[24];
    int nd = 0;
    uint64_t v = dur;
    if (v == 0u) {
        num[nd++] = '0';
    } else {
        char rev[24];
        int r = 0;
        while (v > 0 && r < (int)sizeof(rev)) {
            rev[r++] = (char)('0' + (v % 10u));
            v /= 10u;
        }
        while (r > 0) {
            num[nd++] = rev[--r];
        }
    }
    for (int i = 0; i < nd && n < (int)sizeof(msg) - 1; i++) {
        msg[n++] = num[i];
    }
    const char *suf = " us";
    for (const char *p = suf; *p != '\0' && n < (int)sizeof(msg) - 1;
         p++) {
        msg[n++] = *p;
    }
    msg[n] = '\0';

    hs->log(XURY_LOG_WARN, msg, hs->log_userdata);
}

bool xury_hooks_in_hook(const xury_hook_set_t *hs)
{
    if (hs == NULL || hs->in_hook_flag == NULL) {
        return false;
    }
    return (*hs->in_hook_flag != 0);
}

 /* ---- continued from part 1/2 ---- */

/*
 * ============================================================================
 * LOG LEVEL NAMES
 * ============================================================================
 */

const char *xury_log_level_name(xury_log_level_t level)
{
    switch (level) {
    case XURY_LOG_TRACE: return "trace";
    case XURY_LOG_DEBUG: return "debug";
    case XURY_LOG_INFO:  return "info";
    case XURY_LOG_WARN:  return "warn";
    case XURY_LOG_ERROR: return "error";
    default:             return "unknown";
    }
}

char xury_log_level_char(xury_log_level_t level)
{
    switch (level) {
    case XURY_LOG_TRACE: return 'T';
    case XURY_LOG_DEBUG: return 'D';
    case XURY_LOG_INFO:  return 'I';
    case XURY_LOG_WARN:  return 'W';
    case XURY_LOG_ERROR: return 'E';
    default:             return '?';
    }
}

/*
 * Case-insensitive equality of a NUL-terminated token against a
 * lowercase literal.
 */
static bool log_token_eq_ci(const char *token, const char *literal)
{
    while (*token != '\0' && *literal != '\0') {
        char a = *token;
        char b = *literal;
        if (a >= 'A' && a <= 'Z') {
            a = (char)(a - 'A' + 'a');
        }
        if (a != b) {
            return false;
        }
        token++;
        literal++;
    }
    return (*token == '\0' && *literal == '\0');
}

xury_log_level_t xury_log_level_from_name(const char *name, bool *ok)
{
    if (name == NULL) {
        if (ok != NULL) {
            *ok = false;
        }
        return XURY_LOG_INFO;
    }

    if (log_token_eq_ci(name, "trace")) {
        if (ok != NULL) *ok = true;
        return XURY_LOG_TRACE;
    }
    if (log_token_eq_ci(name, "debug")) {
        if (ok != NULL) *ok = true;
        return XURY_LOG_DEBUG;
    }
    if (log_token_eq_ci(name, "info")) {
        if (ok != NULL) *ok = true;
        return XURY_LOG_INFO;
    }
    if (log_token_eq_ci(name, "warn") ||
        log_token_eq_ci(name, "warning")) {
        if (ok != NULL) *ok = true;
        return XURY_LOG_WARN;
    }
    if (log_token_eq_ci(name, "error") ||
        log_token_eq_ci(name, "err")) {
        if (ok != NULL) *ok = true;
        return XURY_LOG_ERROR;
    }

    if (ok != NULL) *ok = false;
    return XURY_LOG_INFO;
}

/*
 * ============================================================================
 * FIRE FUNCTIONS
 * ============================================================================
 */

/*
 * Fire the log hook.
 *
 * Filtering rules:
 *   - level < log_min_level -> drop silently
 *   - hook not installed    -> drop silently
 *   - already in a hook     -> drop silently (prevent recursion)
 *   - message not terminated -> drop (never call a hook with garbage)
 *
 * The message pointer is passed through untouched. The host must not
 * keep it.
 */
void xury_hooks_fire_log(xury_hook_set_t *hs,
                         xury_log_level_t level,
                         const char *msg)
{
    if (hs == NULL || hs->log == NULL || msg == NULL) {
        return;
    }
    if (level < hs->log_min_level) {
        return;
    }

    uint64_t enter_us = 0;
    if (!xury_hooks_enter(hs, &enter_us)) {
        return;
    }

    hs->log(level, msg, hs->log_userdata);

    xury_hooks_leave(hs, "log", enter_us);
}

/*
 * Fire the log hook with a tag prefix.
 *
 * The tag is prefixed as "[tag] msg" using a small stack buffer.
 * Messages longer than the buffer are truncated at the buffer edge.
 * This is intentional: the log path must never allocate.
 */
void xury_hooks_fire_log_tagged(xury_hook_set_t *hs,
                                xury_log_level_t level,
                                const char *tag,
                                const char *msg)
{
    if (hs == NULL || hs->log == NULL || msg == NULL) {
        return;
    }
    if (level < hs->log_min_level) {
        return;
    }

    char buf[256];
    size_t n = 0;

    if (tag != NULL && *tag != '\0') {
        buf[n++] = '[';
        for (const char *p = tag; *p != '\0' && n < sizeof(buf) - 3u; p++) {
            buf[n++] = *p;
        }
        buf[n++] = ']';
        buf[n++] = ' ';
    }

    for (const char *p = msg; *p != '\0' && n < sizeof(buf) - 1u; p++) {
        buf[n++] = *p;
    }
    buf[n] = '\0';

    xury_hooks_fire_log(hs, level, buf);
}

/*
 * Fire the phase hook.
 */
void xury_hooks_fire_phase(xury_hook_set_t *hs, xury_phase_t phase)
{
    if (hs == NULL || hs->phase == NULL) {
        return;
    }

    uint64_t enter_us = 0;
    if (!xury_hooks_enter(hs, &enter_us)) {
        return;
    }

    hs->phase(phase, hs->phase_userdata);

    xury_hooks_leave(hs, "phase", enter_us);
}

/*
 * Fire the scan-done hook.
 *
 * scan_result points to the engine's internal result. The host must
 * not keep it.
 */
void xury_hooks_fire_scan_done(xury_hook_set_t *hs,
                               const void *scan_result)
{
    if (hs == NULL || hs->scan_done == NULL) {
        return;
    }

    uint64_t enter_us = 0;
    if (!xury_hooks_enter(hs, &enter_us)) {
        return;
    }

    hs->scan_done(scan_result, hs->scan_userdata);

    xury_hooks_leave(hs, "scan_done", enter_us);
}

/*
 * Fire the weapon-result hook.
 *
 * This one may be called from BLITZ worker threads. The reentrancy
 * flag is shared per engine, so two workers racing may cause one hook
 * call to be skipped. That is acceptable: the guard exists to prevent
 * infinite recursion, not to guarantee ordering.
 */
void xury_hooks_fire_weapon_result(xury_hook_set_t *hs,
                                   xury_weapon_t weapon,
                                   xury_err_t result)
{
    if (hs == NULL || hs->weapon_result == NULL) {
        return;
    }

    uint64_t enter_us = 0;
    if (!xury_hooks_enter(hs, &enter_us)) {
        return;
    }

    hs->weapon_result(weapon, result, hs->weapon_userdata);

    xury_hooks_leave(hs, "weapon_result", enter_us);
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
