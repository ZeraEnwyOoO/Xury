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
 * XURY PLATFORM — POSIX SECURE RANDOM
 * ============================================================================
 *
 * Real implementation for Linux, Android, macOS, and BSD.
 *
 * Strategy, in order:
 *
 *   1. getrandom(2)         Linux 3.17+, Android 6+, glibc 2.25+
 *   2. /dev/urandom         everywhere POSIX, always present
 *
 * On macOS the getrandom symbol is absent; the preprocessor skips
 * step 1 and uses /dev/urandom directly, which is the correct and
 * recommended source on that platform.
 *
 * No external dependency. No <sys/random.h> required (we declare
 * getrandom ourselves with a weak symbol so the file links on systems
 * where glibc headers predate it).
 *
 * Thread-safety: getrandom and read are both thread-safe. We open
 * /dev/urandom once and cache the fd for the lifetime of the process.
 * A process that closes fd 0/1/2 without reopening will not affect
 * us: we open our own.
 *
 * Blocking: getrandom blocks until the kernel CSPRNG is initialized.
 * That is the intended behavior for a secure source.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <xury/types.h>
#include <xury/err.h>

#include "platform/platform.h"

/*
 * ============================================================================
 * getrandom(2) — weak declaration
 * ============================================================================
 *
 * glibc provides getrandom in <sys/random.h> from 2.25 (2017). musl
 * provides it from 1.1.20. bionic (Android) provides it from API 28.
 *
 * To support older toolchains without conditionals, we declare the
 * symbol ourselves with a weak attribute. If the libc provides it,
 * the linker resolves to the strong symbol. If not, the weak
 * reference is NULL and we fall through to /dev/urandom.
 *
 * The signature matches glibc exactly: ssize_t getrandom(void *buf,
 * size_t buflen, unsigned int flags).
 */

#if defined(__linux__) && (defined(__GNUC__) || defined(__clang__))
extern ssize_t getrandom(void *buf, size_t buflen, unsigned int flags)
    __attribute__((weak));
#  define XURY_HAVE_GETRANDOM 1
#else
#  define XURY_HAVE_GETRANDOM 0
#endif

#define XURY_GRND_NONBLOCK 0x0001u

/*
 * ============================================================================
 * /dev/urandom fd cache
 * ============================================================================
 *
 * Opened once on first use, kept for the process lifetime. We do NOT
 * close it in xury_platform_shutdown: the fd is owned by the process,
 * and closing it during shutdown could race with an in-flight read.
 * The kernel closes it at exit.
 */

static int g_urandom_fd = -1;

/*
 * Open /dev/urandom. Returns the fd or -1.
 * Not thread-safe on its own; guarded by the simple "first writer
 * wins" pattern below, which is benign because the loser closes its
 * own fd.
 */
static int urandom_open(void)
{
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    return fd;
}

static int urandom_get(void)
{
    int fd = g_urandom_fd;
    if (fd >= 0) {
        return fd;
    }
    fd = urandom_open();
    if (fd < 0) {
        return -1;
    }
    /*
     * Benign race: if another thread opened first, keep theirs and
     * close ours. Both are valid fds; we only need one.
     */
    if (g_urandom_fd >= 0) {
        close(fd);
        return g_urandom_fd;
    }
    g_urandom_fd = fd;
    return fd;
}

/*
 * ============================================================================
 * FILL FROM /DEV/URANDOM
 * ============================================================================
 *
 * Read exactly n bytes. On short read or EINTR, retry. Give up only
 * on a real error.
 */
static xury_err_t urandom_fill(void *buf, size_t n)
{
    int fd = urandom_get();
    if (fd < 0) {
        return XURY_ERR_IO;
    }

    uint8_t *p   = (uint8_t *)buf;
    size_t   off = 0u;

    while (off < n) {
        ssize_t r = read(fd, p + off, n - off);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return XURY_ERR_IO;
        }
        if (r == 0) {
            /* Should not happen for /dev/urandom. Treat as failure. */
            return XURY_ERR_IO;
        }
        off += (size_t)r;
    }
    return XURY_OK;
}

/*
 * ============================================================================
 * FILL FROM getrandom(2)
 * ============================================================================
 *
 * getrandom may return fewer bytes than requested when interrupted.
 * Loop. Blocking is intentional.
 */
#if XURY_HAVE_GETRANDOM
static xury_err_t getrandom_fill(void *buf, size_t n)
{
    if (getrandom == NULL) {
        return XURY_ERR_NOT_IMPLEMENTED;
    }

    uint8_t *p   = (uint8_t *)buf;
    size_t   off = 0u;

    while (off < n) {
        ssize_t r = getrandom(p + off, n - off, 0u);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == ENOSYS) {
                /* Kernel too old: signal caller to fall back. */
                return XURY_ERR_NOT_IMPLEMENTED;
            }
            return XURY_ERR_IO;
        }
        if (r == 0) {
            return XURY_ERR_IO;
        }
        off += (size_t)r;
    }
    return XURY_OK;
}
#endif

/*
 * ============================================================================
 * PUBLIC
 * ============================================================================
 */

xury_err_t xury_platform_rand_secure(void *buf, size_t n)
{
    if (n == 0u) {
        return XURY_OK;
    }
    if (buf == NULL) {
        return XURY_ERR_INVAL;
    }

#if XURY_HAVE_GETRANDOM
    xury_err_t rc = getrandom_fill(buf, n);
    if (rc == XURY_OK) {
        return XURY_OK;
    }
    if (rc != XURY_ERR_NOT_IMPLEMENTED) {
        /*
         * Real error from getrandom. Do not silently fall through to
         * a weaker source: return the error.
         */
        return rc;
    }
    /* Kernel has no getrandom: fall through. */
#endif

    return urandom_fill(buf, n);
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
