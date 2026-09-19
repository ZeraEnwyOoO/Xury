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

#ifndef XURY_PLATFORM_H
#define XURY_PLATFORM_H

/*
 * ============================================================================
 * XURY PLATFORM INTERFACE
 * ============================================================================
 *
 * The platform layer is the ONLY place in Xury that talks to the
 * operating system. Everything above it (core, scan, weapons, sweet,
 * peer, engine) calls these functions and nothing else.
 *
 * Why an interface:
 *
 *   - Adding a new OS is adding a new directory under src/platform/
 *     that implements this header. No core change, no engine change.
 *
 *   - Tests can link a fake platform to exercise the layers above
 *     without a real network.
 *
 *   - The Core↔Platform cycle is broken here: the core DISPATCHES
 *     (declares weak symbols), the platform IMPLEMENTS. Neither
 *     includes the other's private headers.
 *
 * Contract rules:
 *   - Every function here must be implementable in plain C on the
 *     target OS with no external dependency.
 *   - Functions must be thread-safe unless the comment says otherwise.
 *   - Functions must not allocate unless the comment says otherwise.
 *   - On failure, functions return an xury_err_t from <xury/err.h>.
 *     Never a raw errno, never a bool, never a platform error code.
 *   - Functions must not call back into Xury.
 *
 * Link policy:
 *   The core declares these as weak symbols. If the platform is not
 *   linked, the core returns XURY_ERR_NOT_IMPLEMENTED. This is the
 *   documented contract, not a stub.
 *
 * Naming:
 *   Every function begins with xury_platform_. The core's forwarding
 *   wrappers use xury_sock_*, xury_time_*, xury_rand_*, xury_log_*.
 *
 * Namespace note:
 *   The platform layer has its OWN enum namespace
 *   (xury_platform_sock_type_t with XURY_PLATFORM_SOCK_*). The core
 *   has its own (xury_sock_type_t with XURY_SOCK_*). The two are
 *   intentionally separate: neither layer includes the other's
 *   header, and the core casts between them. The numeric values
 *   MUST match; a compile-time check enforces this in sock.c.
 *
 * File layout:
 *   platform.h            this file
 *   posix/sock.c          Linux + Android + macOS + BSD sockets
 *   posix/time.c          clock_gettime(CLOCK_MONOTONIC)
 *   posix/log.c           write to stderr (or /dev/null)
 *   linux/rand.c          getrandom(2) / /dev/urandom
 *   linux/netlink.c       rtnetlink queries
 *   android/jni.c         JNI bridge for permissions
 *   android/log.c         __android_log_write
 *   android/rand.c        JNI SecureRandom bridge
 *   android/permissions.c runtime INTERNET check
 *
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
 * LIFECYCLE
 * ============================================================================
 */

/*
 * One-time initialization.
 *
 * On POSIX this is a no-op. On Windows it will call WSAStartup.
 * On Android it will cache the JavaVM.
 *
 * Called by xury_global_init(). Idempotent.
 */
xury_err_t xury_platform_init(void);

/*
 * Release process-wide resources.
 *
 * Called by the last xury_global_shutdown(). Idempotent.
 */
void xury_platform_shutdown(void);

/*
 * Human-readable platform name: "linux", "android", "windows", ...
 * Never returns NULL.
 */
const char *xury_platform_name(void);

/*
 * Human-readable OS version string, or "" if unknown.
 * Never returns NULL.
 */
const char *xury_platform_version(void);

/*
 * ============================================================================
 * TIME
 * ============================================================================
 *
 * Monotonic time only. Wall-clock time is not exposed because Xury
 * never needs it; monotonic time cannot go backwards and is immune to
 * NTP adjustments.
 *
 * Units:
 *   xury_platform_time_ms()  milliseconds
 *   xury_platform_time_us()  microseconds
 */

uint64_t xury_platform_time_ms(void);
uint64_t xury_platform_time_us(void);

/*
 * Sleep for the given duration. Not exact; may overshoot.
 * sleep_ms(0) is a yield.
 */
void xury_platform_sleep_ms(uint32_t ms);

/*
 * ============================================================================
 * RANDOM (secure)
 * ============================================================================
 *
 * Fill buf with n cryptographically strong random bytes.
 *
 * On success, all n bytes are written. On failure, no partial fill.
 * Thread-safe.
 *
 * Linux:    getrandom(2) with /dev/urandom fallback.
 * Android:  JNI SecureRandom bridge.
 * Windows:  BCryptGenRandom.
 * macOS:    arc4random_buf or SecRandomCopyBytes.
 */
xury_err_t xury_platform_rand_secure(void *buf, size_t n);

/*
 * ============================================================================
 * SOCKETS
 * ============================================================================
 *
 * The platform layer owns the translation between xury_endpoint_t
 * and the OS sockaddr type. The core never sees a sockaddr.
 *
 * Namespace:
 *   xury_platform_sock_type_t and its enumerators XURY_PLATFORM_SOCK_*
 *   are PRIVATE to the platform layer. They must not be used outside
 *   src/platform/. The core has its own xury_sock_type_t in
 *   src/core/internal/sock.h with enumerators XURY_SOCK_*.
 *
 *   The numeric values of the two enums MUST match:
 *     XURY_PLATFORM_SOCK_UDP == XURY_SOCK_UDP == 0
 *     XURY_PLATFORM_SOCK_TCP == XURY_SOCK_TCP == 1
 *   sock.c enforces this with a compile-time assertion.
 */

typedef enum {
    XURY_PLATFORM_SOCK_UDP = 0,
    XURY_PLATFORM_SOCK_TCP = 1,
} xury_platform_sock_type_t;

xury_err_t xury_platform_sock_init(void);
void       xury_platform_sock_shutdown(void);

xury_err_t xury_platform_sock_create(xury_family_t family,
                                     xury_platform_sock_type_t type,
                                     xury_sock_t *out);
xury_err_t xury_platform_sock_close(xury_sock_t s);

xury_err_t xury_platform_sock_bind(xury_sock_t s,
                                   const xury_endpoint_t *ep);
xury_err_t xury_platform_sock_local(xury_sock_t s,
                                    xury_endpoint_t *out);

xury_err_t xury_platform_sock_set_reuseaddr(xury_sock_t s, bool on);
xury_err_t xury_platform_sock_set_nonblocking(xury_sock_t s, bool on);
xury_err_t xury_platform_sock_set_ttl(xury_sock_t s, uint8_t v);
xury_err_t xury_platform_sock_set_interface(xury_sock_t s,
                                            const char *ifname);

xury_err_t xury_platform_sock_sendto(xury_sock_t s,
                                     const void *buf,
                                     size_t len,
                                     const xury_endpoint_t *to,
                                     size_t *out_sent);

xury_err_t xury_platform_sock_recvfrom(xury_sock_t s,
                                       void *buf,
                                       size_t buf_cap,
                                       xury_endpoint_t *out_from,
                                       size_t *out_len,
                                       uint32_t timeout_ms);

xury_err_t xury_platform_sock_connect(xury_sock_t s,
                                      const xury_endpoint_t *to);
xury_err_t xury_platform_sock_wait_writable(xury_sock_t s,
                                            uint32_t timeout_ms);
xury_err_t xury_platform_sock_wait_readable(xury_sock_t s,
                                            uint32_t timeout_ms);

/*
 * ============================================================================
 * LOG
 * ============================================================================
 *
 * The platform layer provides a minimal sink. The host hook (see
 * <xury/hooks.h>) is preferred; this exists for the narrow case
 * where the engine must say something before the host has installed
 * a hook, or before the engine exists at all.
 *
 * Level is the raw integer from <xury/hooks.h> (0..4).
 * Message is a NUL-terminated line, already formatted.
 */
void xury_platform_log_write(int level, const char *msg);

/*
 * ============================================================================
 * INTERFACES (sensing)
 * ============================================================================
 *
 * Enumerate the host's network interfaces.
 *
 * The platform layer fills up to cap entries and reports how many it
 * wrote. Each entry carries its name, its family, its address, and
 * a flag indicating whether the address is usable for outbound
 * traffic.
 *
 * The caller-provided array must be large enough; if the real number
 * of interfaces exceeds cap, the platform writes cap and returns OK
 * with *out_count == cap. It is not an error.
 *
 * Used by the scan layer. Not needed by any other layer.
 */

typedef struct {
    char            name[32];
    xury_family_t   family;
    xury_endpoint_t addr;     /* port is 0 */
    bool            is_up;
    bool            is_loopback;
} xury_platform_iface_t;

xury_err_t xury_platform_ifaces_list(xury_platform_iface_t *out,
                                     size_t cap,
                                     size_t *out_count);

/*
 * Query the current default gateway (first hop).
 *
 * Returns XURY_ERR_NOT_CONNECTED if there is no route.
 */
xury_err_t xury_platform_gateway(xury_endpoint_t *out);

/*
 * ============================================================================
 * PERMISSIONS (Android only)
 * ============================================================================
 *
 * On non-Android platforms these return XURY_OK. On Android they map
 * to the runtime permission model. The names are the Android
 * permission strings ("android.permission.INTERNET").
 *
 * On Android, xury_platform_init() caches the JavaVM. The permission
 * check requires a valid JNIEnv for the current thread, which the
 * platform layer obtains internally.
 */

xury_err_t xury_platform_permission_check(const char *name);

/*
 * ============================================================================
 * END OF XURY PLATFORM INTERFACE
 * ============================================================================
 */

#endif /* XURY_PLATFORM_H */
