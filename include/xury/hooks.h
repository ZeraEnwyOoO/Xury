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

#ifndef XURY_HOOKS_H
#define XURY_HOOKS_H

/*
 * ============================================================================
 * XURY CALLBACK HOOKS
 * ============================================================================
 *
 * Hooks let the host observe what Xury is doing without polling.
 *
 * Rules:
 *   - All hooks are optional. NULL means "ignore".
 *   - Hooks are called synchronously on the caller's thread, unless
 *     the function that triggers them documents otherwise.
 *   - A hook MUST NOT call back into Xury on the same engine.
 *     Doing so may deadlock or corrupt state.
 *   - A hook MUST return quickly. Blocking delays the engine.
 *   - A hook MUST NOT free engine-owned memory passed to it.
 *     Pointers are valid only for the duration of the call.
 *   - A hook SHOULD NOT throw or longjmp.
 *
 * Config pairing:
 *   Each hook has a matching "userdata" pointer in xury_config_t:
 *
 *     on_log           <-> log_userdata
 *     on_phase         <-> phase_userdata
 *     on_scan_done     <-> scan_userdata
 *     on_weapon_result <-> weapon_userdata
 *
 * The userdata pointer is opaque to Xury and passed back unchanged.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/version.h>
#include <xury/types.h>
#include <xury/err.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * LOG LEVELS
 * ============================================================================
 *
 * Severity levels passed to the log hook.
 *
 * Values match syslog-like ordering for easy mapping:
 *   0 = most verbose
 *   4 = most severe
 *
 * Android logcat and Linux syslog can be mapped directly:
 *   0 -> ANDROID_LOG_VERBOSE / LOG_DEBUG
 *   1 -> ANDROID_LOG_DEBUG   / LOG_INFO
 *   2 -> ANDROID_LOG_INFO    / LOG_NOTICE
 *   3 -> ANDROID_LOG_WARN    / LOG_WARNING
 *   4 -> ANDROID_LOG_ERROR   / LOG_ERR
 */

typedef enum {
    XURY_LOG_TRACE = 0,   /* very verbose, dev only */
    XURY_LOG_DEBUG = 1,   /* debug info */
    XURY_LOG_INFO  = 2,   /* normal operation */
    XURY_LOG_WARN  = 3,   /* unexpected but recoverable */
    XURY_LOG_ERROR = 4,   /* failure */
} xury_log_level_t;

/*
 * ============================================================================
 * LOG HOOK
 * ============================================================================
 *
 * Called for every log message the engine emits.
 *
 * If not set, the engine writes nothing to stderr/stdout.
 * Host is expected to install its own logger.
 *
 * Arguments:
 *   level      — severity (see xury_log_level_t)
 *   msg        — NUL-terminated UTF-8 string, valid only during call
 *   userdata   — value from cfg.log_userdata
 *
 * Rules:
 *   - msg pointer is owned by Xury, do not free, do not store.
 *   - If you need to keep the message, copy it.
 *   - Called with internal engine lock held on some paths; keep it fast.
 */

typedef void (*xury_log_hook_t)(xury_log_level_t level,
                                 const char      *msg,
                                 void            *userdata);

/*
 * ============================================================================
 * PHASE HOOK
 * ============================================================================
 *
 * Called when the engine enters a new phase.
 *
 * Phase order in a normal connect():
 *
 *   SCAN   -> STRIKE -> DONE
 *   SCAN   -> STRIKE -> BLITZ -> DONE
 *   SCAN   -> STRIKE -> BLITZ -> FAILED
 *   SCAN   -> DONE                (IPv6 or LAN early exit)
 *
 * IDLE  — engine ready, no connect in progress
 * SCAN  — analyzing network
 * STRIKE— trying the chosen weapon
 * BLITZ — trying all weapons in parallel
 * DONE  — connected (socket available)
 * FAILED— all methods failed
 *
 * If the host calls xury_connect() again, the phase sequence restarts
 * at SCAN.
 *
 * Arguments:
 *   phase    — new phase
 *   userdata — value from cfg.phase_userdata
 *
 * Rules:
 *   - May be called multiple times with the same phase if retried.
 *   - Never called after engine is destroyed.
 */

typedef void (*xury_phase_hook_t)(xury_phase_t phase,
                                   void       *userdata);

/*
 * ============================================================================
 * SCAN-DONE HOOK
 * ============================================================================
 *
 * Called once per scan, after the scan phase completes.
 *
 * The pointer passed is a "const void *" so that this header does not
 * need to expose the full scan result structure. Host code that wants
 * the details can include <xury/scan.h> and cast.
 *
 * Arguments:
 *   scan_result — pointer to internal xury_scan_result_t
 *                 valid only during the call, do not store
 *   userdata    — value from cfg.scan_userdata
 *
 * Rules:
 *   - May be NULL if scan was skipped (cached hit + early term).
 *   - Called on the same thread as xury_scan() / xury_connect().
 */

typedef void (*xury_scan_done_hook_t)(const void *scan_result,
                                       void       *userdata);

/*
 * ============================================================================
 * WEAPON-RESULT HOOK
 * ============================================================================
 *
 * Called for each weapon attempt, whether from STRIKE or BLITZ.
 *
 * In STRIKE mode, this fires once.
 * In BLITZ mode, this fires for every weapon attempted, in
 * completion order (not launch order).
 *
 * Arguments:
 *   weapon   — which weapon was attempted
 *   result   — XURY_OK on success, error code otherwise
 *   userdata — value from cfg.weapon_userdata
 *
 * Rules:
 *   - A weapon that succeeded is reported with result == XURY_OK.
 *   - A weapon that was cancelled (another won) reports
 *     XURY_ERR_CANCELLED.
 *   - A weapon that was skipped (disabled or inapplicable) does not
 *     report at all.
 *   - Called on the caller's thread in STRIKE, and on internal worker
 *     threads in BLITZ. Host must be thread-aware if it uses BLITZ.
 */

typedef void (*xury_weapon_result_hook_t)(xury_weapon_t weapon,
                                            xury_err_t    result,
                                            void         *userdata);

/*
 * ============================================================================
 * CONNECT-DONE HOOK (reserved — not used in v0.1)
 * ============================================================================
 *
 * Placeholder for a future hook that fires when a connect() call
 * finishes, regardless of outcome. Not enabled in v0.1 to keep the
 * initial API surface small.
 *
 * Hosts should rely on the return value of xury_connect() for now.
 */

/* typedef void (*xury_connect_done_hook_t)(xury_err_t result,
 *                                           xury_sock_t sock,
 *                                           void *userdata); */

/*
 * ============================================================================
 * ALL HOOKS STRUCT (convenience)
 * ============================================================================
 *
 * Some hosts prefer to pass all hooks as a single struct. This is
 * optional. It mirrors the fields in xury_config_t exactly so that a
 * host can memcpy one into the other if desired.
 *
 * Usage:
 *
 *   xury_hooks_t hooks = {
 *       .log           = my_log,
 *       .log_userdata  = &my_state,
 *       .phase         = my_phase,
 *       .phase_userdata= &my_state,
 *   };
 *   xury_config_t cfg = XURY_CONFIG_DEFAULT;
 *   cfg.on_log            = hooks.log;
 *   cfg.log_userdata      = hooks.log_userdata;
 *   cfg.on_phase          = hooks.phase;
 *   cfg.phase_userdata    = hooks.phase_userdata;
 *   cfg.on_scan_done      = hooks.scan_done;
 *   cfg.scan_userdata     = hooks.scan_userdata;
 *   cfg.on_weapon_result  = hooks.weapon_result;
 *   cfg.weapon_userdata   = hooks.weapon_userdata;
 *
 * The struct itself is NOT passed to xury_create(). It exists purely
 * as a convenience grouping.
 */

typedef struct {
    xury_log_hook_t           log;
    void                     *log_userdata;

    xury_phase_hook_t         phase;
    void                     *phase_userdata;

    xury_scan_done_hook_t     scan_done;
    void                     *scan_userdata;

    xury_weapon_result_hook_t weapon_result;
    void                     *weapon_userdata;
} xury_hooks_t;

/*
 * ============================================================================
 * THREADING NOTES
 * ============================================================================
 *
 * Single-threaded host (recommended):
 *   All hooks are called on the host's calling thread.
 *   No synchronization required inside hooks.
 *
 * Multi-threaded host using BLITZ:
 *   xury_weapon_result_hook_t may be called from internal worker
 *   threads. If your hook touches shared state, guard it yourself.
 *
 * Log hook:
 *   May be called from any engine thread.
 *   Should be reentrant if your host uses BLITZ.
 *
 * Phase hook:
 *   Always called on the host's calling thread. Safe to touch host state.
 *
 * Scan-done hook:
 *   Always called on the host's calling thread.
 *
 * Weapon-result hook:
 *   STRIKE — caller thread.
 *   BLITZ  — worker thread. Host must be thread-safe here.
 *
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY HOOKS HEADER
 * ============================================================================
 */

#endif /* XURY_HOOKS_H */
