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
 * XURY PLATFORM — POSIX TIME
 * ============================================================================
 *
 * Real implementation for Linux, Android, macOS, and BSD.
 *
 * Monotonic time only. CLOCK_MONOTONIC never goes backwards and is
 * not affected by NTP or wall-clock changes.
 *
 * On Android, CLOCK_MONOTONIC pauses during deep sleep on some
 * kernels. Xury does not care: the timeouts it measures are
 * sub-second and never survive suspend. If that ever changes, switch
 * to CLOCK_BOOTTIME, which is Android-specific and monotonic across
 * suspend.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>

#include <xury/types.h>
#include <xury/err.h>

#include "platform/platform.h"

/*
 * ============================================================================
 * INTERNAL — one clock read
 * ============================================================================
 */

static bool clock_now(struct timespec *ts)
{
    if (ts == NULL) {
        return false;
    }
    if (clock_gettime(CLOCK_MONOTONIC, ts) != 0) {
        /*
         * CLOCK_MONOTONIC is guaranteed by POSIX. If it fails, the
         * process has bigger problems than a timing bug. Return false
         * so callers can decide; the Xury convention is to return 0
         * (a safe "no time has passed" value) rather than crash.
         */
        return false;
    }
    return true;
}

/*
 * ============================================================================
 * PUBLIC — time
 * ============================================================================
 */

uint64_t xury_platform_time_ms(void)
{
    struct timespec ts;
    if (!clock_now(&ts)) {
        return 0u;
    }
    return ((uint64_t)ts.tv_sec * 1000ull) +
           ((uint64_t)ts.tv_nsec / 1000000ull);
}

uint64_t xury_platform_time_us(void)
{
    struct timespec ts;
    if (!clock_now(&ts)) {
        return 0u;
    }
    return ((uint64_t)ts.tv_sec * 1000000ull) +
           ((uint64_t)ts.tv_nsec / 1000ull);
}

/*
 * ============================================================================
 * PUBLIC — sleep
 * ============================================================================
 *
 * nanosleep() can return early if a signal is delivered. POSIX
 * requires the remaining time to be written back into the second
 * argument. We loop until either the full duration has elapsed or a
 * non-EINTR error occurs.
 *
 * sleep_ms(0) returns immediately without entering the syscall.
 */

void xury_platform_sleep_ms(uint32_t ms)
{
    if (ms == 0u) {
        return;
    }

    struct timespec req;
    req.tv_sec  = (time_t)(ms / 1000u);
    req.tv_nsec = (long)((ms % 1000u) * 1000000ul);

    struct timespec rem;
    for (;;) {
        int rv = nanosleep(&req, &rem);
        if (rv == 0) {
            return;
        }
        if (errno != EINTR) {
            /* EINVAL would mean a malformed timespec; can't happen
             * with the computation above, but be defensive. */
            return;
        }
        req = rem;
    }
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
