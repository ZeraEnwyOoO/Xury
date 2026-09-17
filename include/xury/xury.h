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

#ifndef XURY_H
#define XURY_H

/*
 * ============================================================================
 * XURY — UMBRELLA HEADER
 * ============================================================================
 *
 * Xury is a no-server P2P NAT traversal engine.
 *
 * It handles NAT only. Everything else (discovery, storage, transport,
 * application protocol, encryption) is the host's responsibility.
 *
 * Host products use Xury like this:
 *
 *   #include <xury/xury.h>
 *
 *   int main(void) {
 *       xury_engine_t *e = xury_create(NULL);
 *       xury_start(e);
 *
 *       xury_endpoint_t peer = {
 *           .ip     = "203.0.113.5",
 *           .port   = 8888,
 *           .family = XURY_AF_INET,
 *       };
 *
 *       if (xury_connect(e, &peer, 30000) == XURY_OK) {
 *           int fd;
 *           xury_get_socket_fd(e, &fd);
 *           // use fd
 *       }
 *
 *       xury_destroy(e);
 *       return 0;
 *   }
 *
 * ----------------------------------------------------------------------------
 *
 * SCOPE — what Xury does:
 *
 *   - NAT detection (scan)
 *   - NAT classification (type, label, CGNAT sub-type)
 *   - NAT traversal (weapons)
 *   - Hole punching
 *   - Port mapping (UPnP, NAT-PMP, PCP)
 *   - CGNAT persuasion (sweet)
 *   - Peer-as-mirror (no STUN server)
 *   - Peer relay (no TURN server)
 *   - Relay -> direct upgrade
 *
 * SCOPE — what Xury does NOT do:
 *
 *   - Peer discovery  (DHT, gossip, bootstrap) — host
 *   - Storage         (disk, database)         — host
 *   - Transport       (after handoff)          — host
 *   - Application protocol                     — host
 *   - Encryption / authentication              — host
 *   - Main loop / event loop                   — host
 *
 * ----------------------------------------------------------------------------
 *
 * PILLARS:
 *
 *   SCAN   — analyze network, classify NAT, pick weapon
 *   STRIKE — try the best weapon (single, fast)
 *   BLITZ  — try all weapons in parallel (last resort)
 *
 * PILLAR 3 (SWEET) is CGNAT persuasion, invoked automatically when
 * the scan detects CGNAT and the config allows it.
 *
 * ----------------------------------------------------------------------------
 *
 * PLATFORMS (v0.1):
 *
 *   - Linux    (first-class)
 *   - Android  (first-class)
 *
 *   Plug-in ready — other OSes added later without core change:
 *   - Windows, macOS, iOS, BSD
 *
 * ----------------------------------------------------------------------------
 *
 * THREADING:
 *
 *   One engine = one thread. Do NOT share an engine across threads.
 *   All calls are SYNC. Async is the host's responsibility:
 *     host wraps xury_connect() in its own worker thread.
 *
 * ----------------------------------------------------------------------------
 *
 * LICENSE:
 *
 *   GNU General Public License v3.0 or later (GPL-3.0-or-later).
 *   See the LICENSE file for the full text.
 *
 * ============================================================================
 */

/*
 * ----------------------------------------------------------------------------
 * STANDARD HEADERS
 * ----------------------------------------------------------------------------
 * Only the minimum needed to make every public type self-contained.
 * No OS-specific headers are ever included here.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * ----------------------------------------------------------------------------
 * XURY PUBLIC HEADERS
 * ----------------------------------------------------------------------------
 * Ordered so that each header's dependencies appear above it.
 *
 *   1. version  — no deps
 *   2. types    — needs version
 *   3. err      — needs types
 *   4. config   — needs version, types
 *   5. hooks    — needs version, types, err
 *   6. weapon   — needs version, types
 *   7. scan     — needs version, types, err, weapon
 *   8. engine   — needs version, types, err, config, hooks, weapon, scan
 *   9. peer     — needs version, types, err, engine
 */
#include <xury/version.h>
#include <xury/types.h>
#include <xury/err.h>
#include <xury/config.h>
#include <xury/hooks.h>
#include <xury/weapon.h>
#include <xury/scan.h>
#include <xury/engine.h>
#include <xury/peer.h>

/*
 * ============================================================================
 * COMPILE-TIME SANITY CHECKS
 * ============================================================================
 *
 * These catch misconfigurations at build time, not at runtime.
 * They are cheap and are compiled away in release builds if the
 * compiler optimizes them, but the static_asserts remain.
 */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ < 201112L
    #error "Xury requires C11 or later (__STDC_VERSION__ >= 201112L)."
#endif

#if defined(__cplusplus) && __cplusplus < 201103L
    #error "Xury requires C++11 or later when included from C++."
#endif

/*
 * The following constants must agree. If they ever drift, the build
 * fails loudly rather than corrupting memory at runtime.
 */
#if defined(XURY_API_VERSION) && (XURY_API_VERSION < 1)
    #error "Xury: XURY_API_VERSION must be >= 1."
#endif

/*
 * ============================================================================
 * CONVENIENCE MACROS
 * ============================================================================
 * Small helpers that hosts commonly need.
 */

/*
 * Mark a variable intentionally unused (for hooks that ignore args).
 */
#ifndef XURY_UNUSED
#  if defined(__GNUC__) || defined(__clang__)
#    define XURY_UNUSED(x)   ((void)(x))
#  else
#    define XURY_UNUSED(x)   ((void)(x))
#  endif
#endif

/*
 * Branch prediction hints. No effect on behavior.
 */
#ifndef XURY_LIKELY
#  if defined(__GNUC__) || defined(__clang__)
#    define XURY_LIKELY(x)   (__builtin_expect(!!(x), 1))
#    define XURY_UNLIKELY(x) (__builtin_expect(!!(x), 0))
#  else
#    define XURY_LIKELY(x)   (x)
#    define XURY_UNLIKELY(x) (x)
#  endif
#endif

/*
 * Array size.
 */
#ifndef XURY_ARRAY_SIZE
#  define XURY_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

/*
 * Version string helper for compile-time logging.
 */
#define XURY_VERSION_STRING_FULL \
    XURY_VERSION_STRING " (" XURY_BUILD_PLATFORM ", " XURY_BUILD_TYPE ")"

/*
 * ============================================================================
 * QUICK REFERENCE — PUBLIC API
 * ============================================================================
 *
 * Lifecycle:
 *   xury_create()                     create engine
 *   xury_start()                      start engine
 *   xury_destroy()                    stop and free
 *   xury_is_started()                 started?
 *   xury_is_connected()               connected?
 *
 * Connect:
 *   xury_connect()                    full auto connect
 *   xury_connect_strategy()           force strategy
 *   xury_connect_blitz()              blitz only
 *   xury_disconnect()                 disconnect
 *
 * Socket:
 *   xury_get_socket_fd()              borrow fd
 *   xury_detach_socket()              take ownership of fd
 *
 * Scan:
 *   xury_scan()                       full scan
 *   xury_scan_quick()                 sensing + cache only
 *   xury_scan_invalidate()            drop cache
 *
 * Query:
 *   xury_get_last_scan()              last scan result
 *   xury_get_local_endpoint()         local bind endpoint
 *   xury_get_peer_endpoint()          peer of current conn
 *   xury_get_nat_type()               observed NAT type
 *   xury_get_cgnat_type()             observed CGNAT type
 *   xury_get_peer_count()             number of known peers
 *
 * Peer registry:
 *   xury_add_peer()                   add/update peer
 *   xury_remove_peer()                remove peer
 *   xury_lookup_peer()                find peer
 *   xury_clear_peers()                clear all peers
 *
 * Mirror (peer-as-STUN, no server):
 *   xury_mirror_query()               ask one peer
 *   xury_mirror_query_any()           ask any of N
 *   xury_mirror_classify()            classify NAT via peers
 *   xury_mirror_set_enabled()         act as mirror for others
 *   xury_mirror_is_enabled()          mirror role status
 *   xury_mirror_answered_count()      probes answered
 *
 * Relay (peer-as-TURN, no server):
 *   xury_relay_request()              ask peer to relay
 *   xury_relay_accept()               act as relay for others
 *   xury_relay_close()                close relay
 *   xury_relay_active_count()         active relays
 *   xury_relay_upgrade()              relay -> direct
 *
 * Version:
 *   xury_version()                    "0.1.0"
 *   xury_build_commit()               git hash
 *   xury_build_date()                 build date
 *   xury_build_type()                 "Release" etc.
 *   xury_build_platform()             "linux", "android", ...
 *   xury_api_version()                public API version
 *
 * String helpers:
 *   xury_strerror()                   error string
 *   xury_err_tag()                    short error tag
 *   xury_nat_type_str()               NAT type string
 *   xury_nat_label_str()              NAT label string
 *   xury_cgnat_type_str()             CGNAT type string
 *   xury_weapon_name()                weapon name
 *   xury_weapon_tag()                 weapon tag
 *   xury_endpoint_to_string()         format endpoint
 *   xury_endpoint_from_string()       parse endpoint
 *
 * ============================================================================
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * UMBRELLA FUNCTIONS
 * ============================================================================
 *
 * A tiny set of helpers that are useful to every host but do not
 * belong to any specific subsystem. Implemented in src/core/util.c.
 */

/*
 * Return a NUL-terminated string describing the library:
 *
 *   "Xury 0.1.0 (linux, Release)"
 *
 * Never returns NULL.
 */
const char *xury_about(void);

/*
 * Print a one-line summary to the log hook if set, or to stderr if not.
 *
 * Example output:
 *   "Xury 0.1.0 | platform=linux | api=1 | connected=no"
 *
 * Returns XURY_OK on success.
 */
xury_err_t xury_print_info(const xury_engine_t *e);

/*
 * Zero an endpoint. Equivalent to:
 *
 *   memset(ep, 0, sizeof(*ep));
 *   ep->family = XURY_AF_UNSPEC;
 *
 * Useful for initialization.
 */
void xury_endpoint_clear(xury_endpoint_t *ep);

/*
 * True if two endpoints are exactly equal (ip, port, family).
 */
bool xury_endpoint_equal(const xury_endpoint_t *a,
                         const xury_endpoint_t *b);

/*
 * True if the endpoint is well-formed (family is INET or INET6,
 * ip string parses, port may be 0).
 */
bool xury_endpoint_valid(const xury_endpoint_t *ep);

/*
 * Zero a peer id.
 */
void xury_peer_id_clear(xury_peer_id_t *id);

/*
 * True if two peer ids are equal.
 */
bool xury_peer_id_equal(const xury_peer_id_t *a,
                        const xury_peer_id_t *b);

/*
 * True if the peer id is all zeros (i.e. unset).
 */
bool xury_peer_id_is_zero(const xury_peer_id_t *id);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY UMBRELLA HEADER
 * ============================================================================
 */

#endif /* XURY_H */
