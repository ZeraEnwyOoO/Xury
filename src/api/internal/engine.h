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

#ifndef XURY_API_INTERNAL_ENGINE_H
#define XURY_API_INTERNAL_ENGINE_H

/*
 * ============================================================================
 * XURY INTERNAL ENGINE
 * ============================================================================
 *
 * This header defines the private layout of struct xury_engine and the
 * internal lifecycle / query helpers that the public API is built on.
 *
 * The public API (include/xury/engine.h) only exposes an opaque handle:
 *
 *   typedef struct xury_engine xury_engine_t;
 *
 * Everything in this header is private to the Xury build.
 *
 * Ownership:
 *   xury_create()   allocates the struct and returns a handle.
 *   xury_start()    initializes subsystems in a fixed order.
 *   xury_destroy()  tears subsystems down in reverse order and frees.
 *
 * Threading:
 *   One engine = one thread. The struct is NOT synchronized. The host
 *   must not share an engine across threads. BLITZ internally uses
 *   worker threads, but it coordinates them through the engine's own
 *   synchronization primitives declared below.
 *
 * Rules:
 *   - Never expose this struct in include/xury/.
 *   - Never let a public header include this file.
 *   - Never assume field order or layout outside the Xury build.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/types.h>
#include <xury/err.h>
#include <xury/config.h>
#include <xury/scan.h>
#include <xury/weapon.h>

#include "api/internal/config.h"
#include "api/internal/hooks.h"
#include "api/internal/weapon.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * FORWARD DECLARATIONS
 * ============================================================================
 *
 * Subsystem contexts are defined in their own internal headers. The
 * engine holds pointers to them, so a forward decl is enough here.
 */

struct xury_platform_ctx;   /* src/platform/platform.h   */
struct xury_scan_ctx;       /* src/scan/internal/...     */
struct xury_analysis_ctx;   /* src/analysis/internal/... */
struct xury_smart_ctx;      /* src/smart/internal/...    */
struct xury_weapon_ctx;     /* src/weapons/internal/...  */
struct xury_peer_ctx;       /* src/peer/internal/...     */
struct xury_sweet_ctx;      /* src/sweet/internal/...    */
struct xury_blitz_ctx;      /* src/blitz/internal/...    */
struct xury_opt_ctx;        /* src/opt/internal/...      */

/*
 * ============================================================================
 * ENGINE STATE
 * ============================================================================
 *
 * Explicit lifecycle. Transitions are monotonic in one direction:
 *
 *   CREATED -> STARTED -> CONNECTED -> STARTED -> STOPPED
 *                                \-> FAILED
 *
 * The engine never goes back to CREATED. After STOPPED, the handle is
 * invalid and must not be used.
 */

typedef enum {
    XURY_ENGINE_STATE_CREATED   = 0,
    XURY_ENGINE_STATE_STARTED   = 1,
    XURY_ENGINE_STATE_CONNECTED = 2,
    XURY_ENGINE_STATE_STOPPED   = 3,
    XURY_ENGINE_STATE_ERROR     = 4,
} xury_engine_state_t;

/*
 * ============================================================================
 * SESSION
 * ============================================================================
 *
 * A single connection attempt (or the active connection).
 *
 * Kept separate from the engine so that a failed connect does not
 * destroy the engine's prepared state.
 */

typedef struct {
    xury_endpoint_t     peer;             /* target endpoint           */
    xury_endpoint_t     local_bound;      /* our bound endpoint        */

    xury_sock_t         sock;             /* connected socket (or -1)  */
    bool                connected;

    xury_weapon_t       winning_weapon;   /* which weapon worked       */
    xury_phase_t        final_phase;      /* phase at completion       */

    uint64_t            started_ms;       /* monotonic, for metrics    */
    uint64_t            finished_ms;

    uint32_t            attempts;         /* weapons attempted         */
    uint32_t            cancelled;        /* weapons cancelled         */
} xury_session_t;

/*
 * ============================================================================
 * ENGINE STRUCT
 * ============================================================================
 *
 * Fields are grouped by purpose. Do not reorder without bumping
 * XURY_ENGINE_LAYOUT_VERSION.
 */

#define XURY_ENGINE_LAYOUT_VERSION 1u

struct xury_engine {
    /*
     * ----------------------------------------------------------------
     * IDENTITY
     * ----------------------------------------------------------------
     */
    uint32_t            layout_version;   /* XURY_ENGINE_LAYOUT_VERSION */
    xury_engine_state_t state;

    /*
     * ----------------------------------------------------------------
     * CONFIG (fully resolved — zero fields already replaced)
     * ----------------------------------------------------------------
     */
    xury_config_t       cfg;

    /*
     * ----------------------------------------------------------------
     * HOOKS
     * ----------------------------------------------------------------
     */
    xury_hook_set_t     hooks;

    /*
     * Reentrancy flag, per engine, shared across hook set.
     * Stored here so its address is stable.
     */
    volatile int        in_hook_flag;

    /*
     * ----------------------------------------------------------------
     * SUBSYSTEM CONTEXTS (owned by the engine)
     * ----------------------------------------------------------------
     */
    struct xury_platform_ctx *platform;
    struct xury_scan_ctx     *scan;
    struct xury_analysis_ctx *analysis;
    struct xury_smart_ctx    *smart;
    struct xury_weapon_ctx   *weapons;
    struct xury_peer_ctx     *peer;
    struct xury_sweet_ctx    *sweet;
    struct xury_blitz_ctx    *blitz;
    struct xury_opt_ctx      *opt;

    /*
     * ----------------------------------------------------------------
     * SESSION
     * ----------------------------------------------------------------
     */
    xury_session_t      session;

    /*
     * ----------------------------------------------------------------
     * LAST SCAN RESULT
     * ----------------------------------------------------------------
     * Owned by the engine. Returned to the host via
     * xury_get_last_scan() as a const pointer. Valid until the next
     * scan or connect.
     */
    xury_scan_result_t  last_scan;
    bool                last_scan_valid;

    /*
     * ----------------------------------------------------------------
     * PEER REGISTRY
     * ----------------------------------------------------------------
     * Peers are supplied by the host via xury_add_peer(). Xury does
     * not discover peers. The registry is a small open-addressed hash
     * keyed by peer id hash.
     */
    struct xury_peer_entry *peers;
    size_t              peer_count;
    size_t              peer_capacity;

    /*
     * ----------------------------------------------------------------
     * LAST ERROR
     * ----------------------------------------------------------------
     * Preserved across calls for diagnostics. Not part of the public
     * API; the host sees the return value of the failed call.
     */
    xury_err_t          last_error;
    int                 last_errno;

    /*
     * ----------------------------------------------------------------
     * RUNTIME STATISTICS
     * ----------------------------------------------------------------
     * Simple counters. Not synchronized; only the engine's thread
     * writes them.
     */
    uint64_t            stat_connects;
    uint64_t            stat_connects_ok;
    uint64_t            stat_connects_fail;
    uint64_t            stat_scans;
    uint64_t            stat_scans_cached;
    uint64_t            stat_weapons_tried;
    uint64_t            stat_weapons_ok;
};

/*
 * ============================================================================
 * LIFECYCLE HELPERS
 * ============================================================================
 *
 * These are the real implementations. Public xury_create() /
 * xury_start() / xury_destroy() call them.
 */

/*
 * Allocate and partially initialize an engine.
 *
 * Steps:
 *   1. validate cfg
 *   2. apply defaults -> internal resolved config
 *   3. normalize
 *   4. allocate engine struct
 *   5. init hook set
 *   6. init peer registry (empty)
 *   7. leave state = CREATED
 *
 * Platform and subsystem contexts are NOT created here. They are
 * created by xury_engine_start().
 *
 * Returns NULL on failure and sets *out_err if out_err is non-NULL.
 */
struct xury_engine *xury_engine_alloc(const xury_config_t *cfg,
                                      xury_err_t *out_err);

/*
 * Start an engine: initialize platform + subsystems in a fixed order.
 *
 * Order is important:
 *   platform -> core -> scan -> analysis -> smart -> weapons ->
 *   peer -> sweet -> blitz -> opt
 *
 * On failure, everything initialized so far is torn down and the
 * engine transitions to ERROR.
 */
xury_err_t xury_engine_start(struct xury_engine *e);

/*
 * Stop an engine: tear down subsystems in reverse order.
 *
 * Idempotent: calling on a stopped engine is a no-op.
 */
void xury_engine_stop(struct xury_engine *e);

/*
 * Free an engine.
 *
 * Calls xury_engine_stop() first if needed, then frees everything.
 * Safe with NULL.
 */
void xury_engine_free(struct xury_engine *e);

/*
 * ============================================================================
 * STATE HELPERS
 * ============================================================================
 */

/*
 * Set the engine state. Logs at DEBUG when a hook is present.
 * Returns XURY_OK, or XURY_ERR_INVAL if the transition is not allowed.
 */
xury_err_t xury_engine_set_state(struct xury_engine *e,
                                 xury_engine_state_t new_state);

/*
 * Short name for the state, for logs.
 * Never returns NULL.
 */
const char *xury_engine_state_name(xury_engine_state_t s);

/*
 * Record the last error for diagnostics.
 */
void xury_engine_set_last_error(struct xury_engine *e, xury_err_t rc);

/*
 * Return the last recorded error, or XURY_OK.
 */
xury_err_t xury_engine_last_error(const struct xury_engine *e);

/*
 * ============================================================================
 * SESSION HELPERS
 * ============================================================================
 */

/*
 * Reset the session to its initial state.
 * Closes any socket owned by the session.
 */
void xury_session_reset(struct xury_engine *e);

/*
 * Begin a new session. Sets started_ms and clears results.
 * Returns XURY_ERR_BUSY if a session is already active.
 */
xury_err_t xury_session_begin(struct xury_engine *e,
                              const xury_endpoint_t *peer);

/*
 * Mark the session as finished. Records finished_ms and the winning
 * weapon / final phase.
 */
void xury_session_finish(struct xury_engine *e,
                         xury_weapon_t weapon,
                         xury_phase_t phase);

/*
 * ============================================================================
 * PEER REGISTRY (INTERNAL)
 * ============================================================================
 *
 * The public API wraps these. The internal versions assume the engine
 * is started and arguments are non-NULL.
 */

/*
 * Insert or update a peer. Returns XURY_OK or an error code.
 */
xury_err_t xury_engine_peer_put(struct xury_engine *e,
                                const xury_peer_id_t *id,
                                const xury_endpoint_t *ep);

/*
 * Remove a peer. Returns XURY_OK even if absent.
 */
xury_err_t xury_engine_peer_remove(struct xury_engine *e,
                                   const xury_peer_id_t *id);

/*
 * Look up a peer. Returns XURY_ERR_NO_PEER if absent.
 */
xury_err_t xury_engine_peer_get(const struct xury_engine *e,
                                const xury_peer_id_t *id,
                                xury_endpoint_t *out);

/*
 * Remove all peers. Frees the hash table.
 */
void xury_engine_peer_clear(struct xury_engine *e);

/*
 * ============================================================================
 * QUERY ADAPTERS
 * ============================================================================
 *
 * Internal implementations of the public query functions. Public
 * functions in include/xury/engine.h call these after validating
 * arguments.
 */

/*
 * Internal implementation of xury_get_socket_fd().
 */
xury_err_t xury_engine_get_socket_fd(struct xury_engine *e, int *out);

/*
 * Internal implementation of xury_get_local_endpoint().
 */
xury_err_t xury_engine_get_local_endpoint(const struct xury_engine *e,
                                          xury_endpoint_t *out);

/*
 * Internal implementation of xury_get_peer_endpoint().
 */
xury_err_t xury_engine_get_peer_endpoint(const struct xury_engine *e,
                                         xury_endpoint_t *out);

/*
 * ============================================================================
 * VERSION SELF-CHECK
 * ============================================================================
 *
 * Called once by xury_engine_start(). If the header/library versions
 * mismatch, start fails with XURY_ERR_INTERNAL and logs a fatal
 * message through the hook (if installed).
 */
xury_err_t xury_engine_check_versions(void);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY INTERNAL ENGINE HEADER
 * ============================================================================
 */

#endif /* XURY_API_INTERNAL_ENGINE_H */
