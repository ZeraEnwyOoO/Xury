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
 *   - A hook MUST return quickly.
 *   - A hook MUST NOT free engine-owned memory passed to it.
 *
 * The log level enum (xury_log_level_t) lives in <xury/types.h> so
 * that config.h and this header can both use it without a circular
 * include.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/types.h>
#include <xury/err.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * LOG HOOK
 * ============================================================================
 */

typedef void (*xury_log_hook_t)(xury_log_level_t level,
                                 const char      *msg,
                                 void            *userdata);

/*
 * ============================================================================
 * PHASE HOOK
 * ============================================================================
 */

typedef void (*xury_phase_hook_t)(xury_phase_t phase,
                                   void       *userdata);

/*
 * ============================================================================
 * SCAN-DONE HOOK
 * ============================================================================
 */

typedef void (*xury_scan_done_hook_t)(const void *scan_result,
                                       void       *userdata);

/*
 * ============================================================================
 * WEAPON-RESULT HOOK
 * ============================================================================
 */

typedef void (*xury_weapon_result_hook_t)(xury_weapon_t weapon,
                                            xury_err_t    result,
                                            void         *userdata);

/*
 * ============================================================================
 * ALL HOOKS STRUCT (convenience)
 * ============================================================================
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
 * Single-threaded host:
 *   All hooks are called on the host's calling thread.
 *
 * Multi-threaded host using BLITZ:
 *   weapon_result hook may be called from internal worker threads.
 *
 * Log hook:
 *   May be called from any engine thread.
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
