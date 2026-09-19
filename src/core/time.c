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
 * XURY CORE — TIME IMPLEMENTATION
 * ============================================================================
 *
 * Real implementation of the internal time helpers.
 *
 * This file is a thin dispatch layer over the platform time functions.
 * The core never talks to clock_gettime() directly; it asks the
 * platform, which knows whether the target is POSIX, Windows, or
 * something else.
 *
 * All time in Xury is monotonic. Wall-clock time is intentionally
 * absent: monotonic time cannot go backwards and is immune to NTP
 * adjustments, which matters for timeouts, RTT estimates, and cache
 * TTLs.
 *
 * Thread-safety: the platform functions are thread-safe. Nothing here
 * adds state.
 *
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
 * INTERNAL HEADER (inline declarations)
 * ============================================================================
 *
 * The core layer uses these names. They are declared here rather than
 * in a separate time_internal.h because there are only two of them and
 * they never grow.
 *
 * If the set ever grows beyond a handful, split this into
 * src/core/internal/time.h. Until then, keep it local.
 */

uint64_t xury_time_now_ms(void);
uint64_t xury_time_now_us(void);
void     xury_time_sleep_ms(uint32_t ms);

/*
 * ============================================================================
 * PUBLIC — dispatch to platform
 * ============================================================================
 */

uint64_t xury_time_now_ms(void)
{
    return xury_platform_time_ms();
}

uint64_t xury_time_now_us(void)
{
    return xury_platform_time_us();
}

void xury_time_sleep_ms(uint32_t ms)
{
    xury_platform_sleep_ms(ms);
}

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 *
 * Small utilities built on the primitives above. They are used by the
 * scan layer (RTT measurement), the engine (timeout budget), and the
 * smart layer (cache TTL).
 */

/*
 * Return the number of milliseconds elapsed since `start_ms`,
 * clamped at 0 in case the clock source went backwards.
 *
 * Monotonic time should never go backwards; the clamp is defensive
 * against a buggy platform backend.
 */
uint64_t xury_time_elapsed_ms(uint64_t start_ms)
{
    uint64_t now = xury_time_now_ms();
    if (now < start_ms) {
        return 0u;
    }
    return now - start_ms;
}

/*
 * True if `deadline_ms` has passed.
 *
 * A deadline of 0 means "no deadline": this function returns false,
 * which lets callers use 0 as a sentinel for "wait forever".
 */
bool xury_time_deadline_passed(uint64_t deadline_ms)
{
    if (deadline_ms == 0u) {
        return false;
    }
    return xury_time_now_ms() >= deadline_ms;
}

/*
 * Compute an absolute deadline from a relative timeout.
 *
 * A timeout of 0 means "no deadline": returns 0.
 * A timeout of UINT32_MAX means "forever": returns UINT64_MAX.
 */
uint64_t xury_time_deadline_from(uint32_t timeout_ms)
{
    if (timeout_ms == 0u) {
        return 0u;
    }
    if (timeout_ms == UINT32_MAX) {
        return UINT64_MAX;
    }
    return xury_time_now_ms() + (uint64_t)timeout_ms;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
