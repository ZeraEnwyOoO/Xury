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
 * XURY PLATFORM — POSIX INIT
 * ============================================================================
 *
 * Real implementation for Linux, macOS, and BSD.
 *
 * On Android, this file is NOT compiled. src/platform/android/jni.c
 * provides the same four symbols so that xury_platform_init verifies
 * the cached JavaVM is present.
 *
 * Why four symbols in one file:
 *   - They are all process-lifetime, no state, one-line each.
 *   - They belong together conceptually: "the platform's identity
 *     and lifecycle".
 *   - Keeping them in one file makes the Android override easy to
 *     reason about: one file replaced, not four.
 *
 * xury_platform_init is called by the first xury_global_init(). It
 * must be idempotent. On POSIX there is nothing to initialize, so it
 * returns XURY_OK every time.
 *
 * xury_platform_shutdown is called by the last xury_global_shutdown().
 * On POSIX there is nothing to release.
 *
 * xury_platform_name and xury_platform_version return stable strings.
 * The version is empty because the exact distribution is not
 * knowable from the C library alone, and Xury does not want to shell
 * out to uname(1). The host's log hook can enrich it if needed.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/types.h>
#include <xury/err.h>

#include "platform/platform.h"

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

xury_err_t xury_platform_init(void)
{
    /*
     * POSIX: nothing to initialize.
     *
     * Sockets, time, and random on Linux/macOS/BSD need no
     * process-wide setup. Android overrides this file and checks the
     * cached JavaVM instead.
     */
    return XURY_OK;
}

void xury_platform_shutdown(void)
{
    /*
     * POSIX: nothing to release.
     *
     * The cached /dev/urandom fd (see posix/rand.c) is owned by the
     * process and closed by the kernel at exit. We deliberately do
     * not close it here: a shutdown call may race with an in-flight
     * read on another thread, and the fd is harmless to keep.
     */
}

/*
 * ============================================================================
 * PLATFORM IDENTITY
 * ============================================================================
 *
 * The compiler tells us which POSIX flavour we are on. We do not run
 * uname(2) because it is slow and unnecessary: the caller only needs
 * a short tag for logs and cache keys.
 */

const char *xury_platform_name(void)
{
#if defined(__APPLE__) && defined(__MACH__)
    return "macos";
#elif defined(__FreeBSD__)
    return "freebsd";
#elif defined(__OpenBSD__)
    return "openbsd";
#elif defined(__NetBSD__)
    return "netbsd";
#elif defined(__linux__)
    return "linux";
#else
    return "posix";
#endif
}

const char *xury_platform_version(void)
{
    /*
     * Empty by design. The exact OS version is not needed by any
     * Xury layer and would require a syscall or a header-dependent
     * constant that ages badly. The host can supply it through its
     * own log hook.
     */
    return "";
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
