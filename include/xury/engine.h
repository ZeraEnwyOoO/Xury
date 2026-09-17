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

#ifndef XURY_ENGINE_H
#define XURY_ENGINE_H

/*
 * ============================================================================
 * XURY ENGINE — MAIN API
 * ============================================================================
 *
 * The engine is the single entry point of Xury. It owns:
 *   - configuration (copied at create)
 *   - platform state
 *   - scan cache
 *   - learning state
 *   - the current socket (if any)
 *
 * Rules:
 *   - One engine = one thread. Do NOT share an engine across threads.
 *   - The engine is a library. It does NOT create a main loop.
 *     The host owns threading, event loop, and lifecycle of the app.
 *   - All calls are SYNC. Async is the host's responsibility:
 *       host wraps xury_connect() in its own worker thread.
 *   - The engine does NOT call the host back from its own threads
 *     except during BLITZ (weapon_result hook — see hooks.h).
 *
 * Lifecycle:
 *
 *   xury_create()  -> engine handle (created, not started)
 *   xury_start()   -> platform init, ready to scan / connect
 *   xury_connect() -> scan + strike (+ blitz if needed)
 *   xury_destroy() -> stop + free
 *
 * Typical host usage:
 *
 *   xury_config_t cfg = XURY_CONFIG_DEFAULT;
 *   cfg.on_log = my_log;
 *   cfg.log_userdata = &my_state;
 *
 *   xury_engine_t *e = xury_create(&cfg);
 *   if (!e) { 失败 }
 *
 *   if (xury_start(e) != XURY_OK) { 失败 }
 *
 *   xury_endpoint_t peer = { ... };
 *   if (xury_connect(e, &peer, 30000) == XURY_OK) {
 *       int fd = xury_get_socket(e);
 *       // host now owns the connected fd for data transfer
 *   }
 *
 *   xury_destroy(e);
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/version.h>
#include <xury/types.h>
#include <xury/err.h>
#include <xury/config.h>
#include <xury/hooks.h>
#include <xury/weapon.h>
#include <xury/scan.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Create a new engine.
 *
 * Arguments:
 *   cfg — configuration. May be NULL for defaults.
 *         The struct is copied; caller may free it immediately.
 *
 * Returns:
 *   A new engine handle on success.
 *   NULL on failure (invalid config, out of memory).
 *
 * Threading:
 *   Safe to call from any thread. The returned engine is bound to
 *   the thread that calls xury_start().
 */
xury_engine_t *xury_create(const xury_config_t *cfg);

/*
 * Start the engine.
 *
 * Initializes the platform layer (sockets, permissions on Android).
 * After this call, xury_scan() and xury_connect() may be used.
 *
 * Returns:
 *   XURY_OK                    — started
 *   XURY_ERR_INVAL             — engine is NULL
 *   XURY_ERR_ALREADY_STARTED   — start() called twice
 *   XURY_ERR_PLATFORM_INIT     — platform init failed
 *   XURY_ERR_PERMISSION_DENIED — Android: missing INTERNET permission
 *   XURY_ERR_NOMEM             — out of memory
 *
 * Threading:
 *   Must be called on the thread that will use the engine.
 *   Engine is bound to this thread until xury_destroy().
 */
xury_err_t xury_start(xury_engine_t *e);

/*
 * Stop and destroy the engine.
 *
 * Safe to call with NULL. Closes any socket owned by the engine.
 * After this call, the handle is invalid.
 *
 * Threading:
 *   Must be called on the engine's thread.
 */
void xury_destroy(xury_engine_t *e);

/*
 * True if xury_start() completed successfully.
 */
bool xury_is_started(const xury_engine_t *e);

/*
 * True if the engine currently holds a connected socket.
 */
bool xury_is_connected(const xury_engine_t *e);

/*
 * ============================================================================
 * CONNECT — SYNC
 * ============================================================================
 *
 * The primary function of Xury.
 *
 * Attempts to establish a NAT-traversed connection to the given peer.
 *
 * Internally:
 *   1. Scan (unless cached)
 *   2. Strike with the recommended weapon
 *   3. Blitz if strike fails and blitz is enabled
 *   4. Return the socket on success
 *
 * Arguments:
 *   e           — engine handle (must be started)
 *   peer        — target peer endpoint (must not be NULL)
 *   timeout_ms  — total budget across all phases.
 *                 0 means "use cfg.connect_timeout_ms".
 *
 * Returns:
 *   XURY_OK                   — connected. Call xury_get_socket().
 *   XURY_ERR_INVAL            — e or peer is NULL, or peer is malformed
 *   XURY_ERR_NOT_READY        — engine not started
 *   XURY_ERR_BUSY             — another connect() is running
 *   XURY_ERR_TIMEOUT          — budget exceeded
 *   XURY_ERR_NO_METHOD        — all enabled methods failed
 *   XURY_ERR_CGNAT_STRICT     — strict CGNAT, no viable path
 *   XURY_ERR_PEER_UNREACHABLE — peer endpoint unreachable
 *   XURY_ERR_PERMISSION       — runtime permission missing
 *   XURY_ERR_IO               — platform I/O error
 *   XURY_ERR_NOMEM            — out of memory
 *
 * Threading:
 *   BLOCKS the calling thread for up to timeout_ms.
 *   Not reentrant. Host must serialize calls per engine.
 *   Host may wrap this in its own worker thread for async behavior.
 */
xury_err_t xury_connect(xury_engine_t *e,
                        const xury_endpoint_t *peer,
                        uint32_t timeout_ms);

/*
 * Connect, forcing a specific strategy.
 *
 * Same as xury_connect() but overrides cfg.force_strategy for this
 * single call. Useful for tests and for hosts that want explicit
 * control.
 *
 * Returns: same as xury_connect().
 */
xury_err_t xury_connect_strategy(xury_engine_t *e,
                                 const xury_endpoint_t *peer,
                                 xury_strategy_t strategy,
                                 uint32_t timeout_ms);

/*
 * Connect using BLITZ only. Skips SCAN and STRIKE.
 *
 * Tries every enabled weapon in parallel. Returns as soon as one
 * succeeds. Costs bandwidth and CPU; use as a last resort or when
 * the host already knows the environment.
 *
 * Returns: same as xury_connect().
 */
xury_err_t xury_connect_blitz(xury_engine_t *e,
                              const xury_endpoint_t *peer,
                              uint32_t timeout_ms);

/*
 * Disconnect the current session.
 *
 * Closes any socket owned by the engine and returns to READY.
 * Safe to call when not connected.
 */
xury_err_t xury_disconnect(xury_engine_t *e);

/*
 * ============================================================================
 * SOCKET HANDOFF
 * ============================================================================
 */

/*
 * Get the socket file descriptor of the current connection.
 *
 * On success, the fd remains owned by the engine. The host may use
 * it for send()/recv() but MUST NOT close() it. Call xury_disconnect()
 * or xury_destroy() to close.
 *
 * Arguments:
 *   e   — engine handle
 *   out — receives the fd on success
 *
 * Returns:
 *   XURY_OK                — out filled with a valid fd
 *   XURY_ERR_INVAL         — e or out is NULL
 *   XURY_ERR_NOT_CONNECTED — no active connection
 *
 * Threading:
 *   Must be called on the engine's thread.
 */
xury_err_t xury_get_socket_fd(xury_engine_t *e, int *out);

/*
 * Detach the socket from the engine.
 *
 * On success, the engine no longer owns the fd. The host MUST close()
 * it when done. After detach, xury_is_connected() returns false.
 *
 * Returns:
 *   XURY_OK                — fd detached
 *   XURY_ERR_INVAL         — e or out is NULL
 *   XURY_ERR_NOT_CONNECTED — no active connection
 */
xury_err_t xury_detach_socket(xury_engine_t *e, int *out);

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

/*
 * Return the last scan result.
 *
 * Valid until the next scan or connect. The pointer is owned by the
 * engine; host must not free it.
 *
 * Returns NULL if no scan has been performed yet.
 */
const xury_scan_result_t *xury_get_last_scan(const xury_engine_t *e);

/*
 * Return the local endpoint currently bound by the engine.
 *
 * Valid after xury_start(). Useful for logging and for peers that
 * want to know our LAN address.
 *
 * Returns:
 *   XURY_OK        — out filled
 *   XURY_ERR_INVAL — e or out is NULL
 *   XURY_ERR_NOT_READY — engine not started
 */
xury_err_t xury_get_local_endpoint(const xury_engine_t *e,
                                   xury_endpoint_t *out);

/*
 * Return the peer endpoint of the current connection.
 *
 * Returns:
 *   XURY_OK                — out filled
 *   XURY_ERR_INVAL         — e or out is NULL
 *   XURY_ERR_NOT_CONNECTED — no active connection
 */
xury_err_t xury_get_peer_endpoint(const xury_engine_t *e,
                                  xury_endpoint_t *out);

/*
 * Return the NAT type last observed by the engine.
 *
 * XURY_NAT_UNKNOWN if no scan has been performed.
 */
xury_nat_type_t xury_get_nat_type(const xury_engine_t *e);

/*
 * Return the CGNAT type last observed.
 *
 * XURY_CGNAT_UNKNOWN if unknown, XURY_CGNAT_NONE if no CGNAT.
 */
xury_cgnat_type_t xury_get_cgnat_type(const xury_engine_t *e);

/*
 * Return the number of peers known to the engine.
 *
 * In Xury v0.1, peers are supplied by the host through
 * xury_add_peer(). Xury itself does not discover peers.
 */
size_t xury_get_peer_count(const xury_engine_t *e);

/*
 * ============================================================================
 * PEER REGISTRY
 * ============================================================================
 *
 * Xury does NOT discover peers. The host provides them.
 *
 * Peer info is used by:
 *   - MIRROR   (ask a peer what our public endpoint looks like)
 *   - RELAY    (ask a peer to forward traffic)
 *   - UPGRADE  (peer-assisted direct upgrade)
 *
 * Xury stores an opaque endpoint per peer id. The peer id is defined
 * by the host (e.g., a public key hash).
 */

/*
 * Add or update a peer.
 *
 * If the peer id already exists, its endpoint is updated.
 *
 * Returns:
 *   XURY_OK         — added / updated
 *   XURY_ERR_INVAL  — e, id or ep is NULL, or ep malformed
 *   XURY_ERR_NOMEM  — out of memory
 *   XURY_ERR_NOT_READY — engine not started
 */
xury_err_t xury_add_peer(xury_engine_t *e,
                         const xury_peer_id_t *id,
                         const xury_endpoint_t *ep);

/*
 * Remove a peer.
 *
 * Returns XURY_OK even if the peer was not known.
 */
xury_err_t xury_remove_peer(xury_engine_t *e,
                            const xury_peer_id_t *id);

/*
 * Look up a peer's endpoint.
 *
 * Returns:
 *   XURY_OK         — found, out filled
 *   XURY_ERR_NO_PEER— not found
 *   XURY_ERR_INVAL  — e, id or out is NULL
 */
xury_err_t xury_lookup_peer(const xury_engine_t *e,
                            const xury_peer_id_t *id,
                            xury_endpoint_t *out);

/*
 * Remove all peers.
 */
xury_err_t xury_clear_peers(xury_engine_t *e);

/*
 * ============================================================================
 * RUNTIME VERSION
 * ============================================================================
 */

/*
 * Return the Xury version string ("0.1.0").
 * Never returns NULL.
 */
const char *xury_version(void);

/*
 * Return the git commit the library was built from, or "unknown".
 */
const char *xury_build_commit(void);

/*
 * Return the build date ("YYYY-MM-DD"), or "unknown".
 */
const char *xury_build_date(void);

/*
 * Return the build type ("Debug", "Release", ...), or "unknown".
 */
const char *xury_build_type(void);

/*
 * Return the platform the library was built for
 * ("linux", "android", ...), or "unknown".
 */
const char *xury_build_platform(void);

/*
 * Return the public API version (integer).
 * Equal to XURY_API_VERSION.
 */
int xury_api_version(void);

/*
 * ============================================================================
 * CONVENIENCE — STRING HELPERS
 * ============================================================================
 *
 * Endpoint formatting is needed by every host. Provided here to avoid
 * duplication and to guarantee consistent output.
 */

/*
 * Format an endpoint as "ip:port" into buf.
 *
 * Examples:
 *   IPv4  ->  "203.0.113.5:8888"
 *   IPv6  ->  "[2001:db8::1]:8888"
 *
 * The port is always in host byte order.
 *
 * Returns:
 *   XURY_OK               — written, NUL-terminated
 *   XURY_ERR_INVAL        — ep or buf is NULL, or buflen == 0
 *   XURY_ERR_BAD_ENDPOINT — ep->family is not INET / INET6
 *   XURY_ERR_BUFFER_TOO_SMALL — buffer too small
 *
 * Recommended minimum buffer size: 64 bytes.
 */
xury_err_t xury_endpoint_to_string(const xury_endpoint_t *ep,
                                   char *buf,
                                   size_t buflen);

/*
 * Parse "ip:port" or "[ipv6]:port" into an endpoint.
 *
 * Returns:
 *   XURY_OK               — parsed
 *   XURY_ERR_INVAL        — str or out is NULL
 *   XURY_ERR_BAD_ENDPOINT — malformed input
 *   XURY_ERR_BAD_PORT     — port missing or out of range
 *   XURY_ERR_BAD_FAMILY   — address is neither IPv4 nor IPv6
 */
xury_err_t xury_endpoint_from_string(const char *str,
                                     xury_endpoint_t *out);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY ENGINE HEADER
 * ============================================================================
 */

#endif /* XURY_ENGINE_H */
