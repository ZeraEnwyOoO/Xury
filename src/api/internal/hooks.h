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

#ifndef XURY_API_INTERNAL_HOOKS_H
#define XURY_API_INTERNAL_HOOKS_H

/*
 * ============================================================================
 * XURY INTERNAL HOOK HELPERS
 * ============================================================================
 *
 * Internal helpers used by src/api/hooks.c and by every layer that
 * needs to fire a hook safely.
 *
 * Public API (include/xury/hooks.h) already exposes:
 *
 *   xury_log_level_t
 *   xury_log_hook_t
 *   xury_phase_hook_t
 *   xury_scan_done_hook_t
 *   xury_weapon_result_hook_t
 *   xury_hooks_t
 *
 * This header adds the *dispatch* layer:
 *
 *   - a small internal struct that holds all hooks + userdata
 *   - safe invoke helpers that tolerate NULL hooks
 *   - log-level filtering (per-engine min level)
 *   - hook-thread tracking (detect reentrancy)
 *   - hook timing (so the engine can warn on slow hooks)
 *
 * Rules:
 *   - Never expose these in include/xury/.
 *   - Never call them from public headers.
 *   - Never allocate.
 *   - Never invoke a hook while holding an internal lock.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/types.h>
#include <xury/hooks.h>
#include <xury/err.h>
#include <xury/config.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * HOOK SET
 * ============================================================================
 *
 * The engine stores a copy of the host's hooks here after xury_create().
 * A NULL function pointer means "not installed".
 *
 * The struct is private and lives inside xury_engine_t. It is exposed
 * here so that dispatch helpers can be shared across layers.
 */

typedef struct {
    /* Log hook */
    xury_log_hook_t           log;
    void                     *log_userdata;
    xury_log_level_t          log_min_level;   /* filter, default INFO */

    /* Phase hook */
    xury_phase_hook_t         phase;
    void                     *phase_userdata;

    /* Scan-done hook */
    xury_scan_done_hook_t     scan_done;
    void                     *scan_userdata;

    /* Weapon-result hook */
    xury_weapon_result_hook_t weapon_result;
    void                     *weapon_userdata;

    /*
     * Reentrancy guard.
     *
     * The address of the thread-local flag that is set while a hook is
     * running. If a hook calls back into the engine, the guard fires.
     *
     * The flag lives on the engine, not here, so that it can be shared
     * across all hook sets of the same engine. This field is only a
     * convenience pointer.
     */
    volatile int             *in_hook_flag;

    /*
     * Slow-hook warning threshold, in microseconds.
     *
     * If a hook takes longer than this, the engine emits one WARN log
     * per hook site (per engine). 0 disables the warning.
     */
    uint32_t                  slow_hook_warn_us;
} xury_hook_set_t;

/*
 * ============================================================================
 * INITIALIZATION
 * ============================================================================
 */

/*
 * Populate a hook set from a config.
 *
 * Copies function pointers and userdata. Applies the default log level
 * (INFO). Sets slow_hook_warn_us to a sane default.
 *
 * The in_hook_flag pointer is left NULL; the engine sets it.
 */
void xury_hooks_init(xury_hook_set_t *hs, const xury_config_t *cfg);

/*
 * Set the minimum log level. Log calls below this level are dropped
 * before reaching the host hook.
 */
void xury_hooks_set_log_level(xury_hook_set_t *hs,
                              xury_log_level_t level);

/*
 * Return the current minimum log level.
 * Defaults to XURY_LOG_INFO if hs is NULL.
 */
xury_log_level_t xury_hooks_get_log_level(const xury_hook_set_t *hs);

/*
 * True if any hook is installed.
 */
bool xury_hooks_any_set(const xury_hook_set_t *hs);

/*
 * True if the log hook is installed.
 */
bool xury_hooks_has_log(const xury_hook_set_t *hs);

/*
 * ============================================================================
 * INVOCATION
 * ============================================================================
 *
 * Safe dispatch. All of these tolerate NULL hs, NULL hooks, and
 * reentrancy. None of them allocate.
 */

/*
 * Fire the log hook.
 *
 * The message is formatted by the caller; this function only filters by
 * level and invokes the hook.
 *
 * If the level is below log_min_level, the call is dropped silently.
 *
 * Reentrancy: if called while the engine is already inside a hook, the
 * message is dropped (to avoid infinite recursion through the host's
 * own logging).
 */
void xury_hooks_fire_log(xury_hook_set_t *hs,
                         xury_log_level_t level,
                         const char *msg);

/*
 * Fire the log hook with a pre-tagged message.
 *
 * The tag is prefixed to the message as "[tag] msg".
 * Implemented by the caller building a small stack buffer; this
 * declaration exists for symmetry.
 *
 * Not defined here — use xury_hooks_fire_log_tagged() below.
 */
void xury_hooks_fire_log_tagged(xury_hook_set_t *hs,
                                xury_log_level_t level,
                                const char *tag,
                                const char *msg);

/*
 * Fire the phase hook.
 *
 * Reentrancy: dropped if already inside a hook.
 * Threading: caller must be the engine's thread.
 */
void xury_hooks_fire_phase(xury_hook_set_t *hs, xury_phase_t phase);

/*
 * Fire the scan-done hook.
 *
 * scan_result is a pointer to the engine's internal scan result.
 * Reentrancy: dropped if already inside a hook.
 */
void xury_hooks_fire_scan_done(xury_hook_set_t *hs,
                               const void *scan_result);

/*
 * Fire the weapon-result hook.
 *
 * Threading: may be called from BLITZ worker threads. The reentrancy
 * flag is thread-local, so this is safe.
 */
void xury_hooks_fire_weapon_result(xury_hook_set_t *hs,
                                   xury_weapon_t weapon,
                                   xury_err_t result);

/*
 * ============================================================================
 * REENTRANCY
 * ============================================================================
 *
 * A hook must never call back into the same engine. We detect it with
 * a per-thread flag stored on the engine.
 *
 * The flag is an int; 0 means "not in hook", non-zero means "in hook".
 * The engine owns the storage; the hook set only points to it.
 */

/*
 * Enter a hook. Sets the flag and records the enter time.
 * Returns false if already in a hook (caller must skip the hook).
 *
 * The returned token must be passed to xury_hooks_leave().
 */
bool xury_hooks_enter(xury_hook_set_t *hs, uint64_t *out_enter_us);

/*
 * Leave a hook. Clears the flag and, if the hook was slow, fires a
 * WARN log via the log hook (once per site).
 *
 * enter_us must be the value returned by xury_hooks_enter().
 */
void xury_hooks_leave(xury_hook_set_t *hs,
                      const char *site,
                      uint64_t enter_us);

/*
 * True if the current thread is inside a hook of this engine.
 */
bool xury_hooks_in_hook(const xury_hook_set_t *hs);

/*
 * ============================================================================
 * STRING HELPERS
 * ============================================================================
 */

/*
 * Return the short lowercase name of a log level.
 *
 *   XURY_LOG_TRACE -> "trace"
 *   XURY_LOG_DEBUG -> "debug"
 *   XURY_LOG_INFO  -> "info"
 *   XURY_LOG_WARN  -> "warn"
 *   XURY_LOG_ERROR -> "error"
 *
 * Never returns NULL.
 */
const char *xury_log_level_name(xury_log_level_t level);

/*
 * Parse a log level name (case-insensitive).
 *
 * Returns XURY_LOG_INFO on failure.
 * Sets *ok to false on failure if ok is not NULL.
 */
xury_log_level_t xury_log_level_from_name(const char *name, bool *ok);

/*
 * Return the single-character tag for a level, for compact logs.
 *
 *   TRACE -> 'T'
 *   DEBUG -> 'D'
 *   INFO  -> 'I'
 *   WARN  -> 'W'
 *   ERROR -> 'E'
 */
char xury_log_level_char(xury_log_level_t level);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY INTERNAL HOOKS HEADER
 * ============================================================================
 */

#endif /* XURY_API_INTERNAL_HOOKS_H */
