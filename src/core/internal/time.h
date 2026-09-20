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

#ifndef XURY_CORE_INTERNAL_TIME_H
#define XURY_CORE_INTERNAL_TIME_H

/*
 * ============================================================================
 * XURY CORE — TIME
 * ============================================================================
 *
 * Monotonic time and sleep.
 *
 * This header is the INTERNAL time API used by every Xury module.
 * It is the dispatch layer that sits on top of the platform layer.
 *
 * Two layers:
 *
 *   core/time.c        dispatch  (this header)
 *   platform/posix/time.c   implementation (clock_gettime)
 *
 * Why a dispatch layer for time:
 *
 *   - The rest of Xury must not call clock_gettime directly.
 *     That would tie the engine to POSIX and make the Windows
 *     port a rewrite.
 *
 *   - Tests can drive the dispatch layer with a fake clock later,
 *     without touching the engine.
 *
 *   - A single place to enforce "monotonic only, no wall clock".
 *
 * What this header provides:
 *
 *   xury_time_now_ms()    monotonic milliseconds
 *   xury_time_now_us()    monotonic microseconds
 *   xury_time_sleep_ms()  sleep, EINTR-safe
 *   xury_time_elapsed_ms() helper for measuring a span
 *
 * Contract:
 *   - Time never goes backwards. Both functions return values that
 *     are non-decreasing across calls within one process.
 *   - The epoch is unspecified and process-local. Two processes on
 *     the same host cannot compare timestamps.
 *   - xury_time_now_ms() and xury_time_now_us() share the same
 *     epoch: now_ms() * 1000 is close to now_us().
 *
 * Dependencies:
 *   <xury/types.h> and "platform/platform.h".
 *
 * Never expose this header to hosts. Public time is not part of the
 * Xury API; the engine only needs it internally.
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
 * MONOTONIC CLOCK
 * ============================================================================
 */

/*
 * Return milliseconds since an unspecified monotonic epoch.
 *
 * Never goes backwards. Safe to call from any thread.
 *
 * Returns 0 if the platform clock is unavailable; the engine treats
 * 0 as "no time has passed" rather than crashing.
 */
uint64_t xury_time_now_ms(void);

/*
 * Return microseconds since the same monotonic epoch as
 * xury_time_now_ms().
 *
 * Never goes backwards. Safe to call from any thread.
 *
 * Returns 0 if the platform clock is unavailable.
 */
uint64_t xury_time_now_us(void);

/*
 * ============================================================================
 * SLEEP
 * ============================================================================
 */

/*
 * Sleep for at least the given number of milliseconds.
 *
 * sleep_ms(0) is a yield: it returns immediately without entering
 * the kernel, so a tight loop that calls it does not starve other
 * threads.
 *
 * The implementation must be EINTR-safe: a signal delivered during
 * the sleep must not cause the function to return early. The caller
 * is guaranteed that at least the requested wall-clock duration has
 * passed when the function returns.
 *
 * Not guaranteed to be exact. On a loaded system, or with a coarse
 * timer resolution, the sleep may overshoot. Callers that need a
 * precise deadline must re-check the clock.
 */
void xury_time_sleep_ms(uint32_t ms);

/*
 * ============================================================================
 * MEASUREMENT HELPER
 * ============================================================================
 *
 * A convenience for the common pattern:
 *
 *   uint64_t t0 = xury_time_now_ms();
 *   ... do work ...
 *   uint32_t dt = xury_time_elapsed_ms(t0);
 *
 * Returns 0 if start_ms is greater than the current time (which can
 * happen if the caller passed a bogus value or the clock wrapped,
 * which it does not, but we still guard against it).
 */

uint32_t xury_time_elapsed_ms(uint64_t start_ms);

/*
 * ============================================================================
 * DEADLINE
 * ============================================================================
 *
 * A deadline is a monotonic timestamp. Two helpers make it easy to
 * reason about "wait until t".
 *
 *   uint64_t deadline = xury_time_now_ms() + timeout_ms;
 *   while (!xury_time_deadline_passed(deadline)) {
 *       do_something();
 *   }
 *
 * The comparison is wrap-safe for the practical lifetime of a
 * process (uint64 milliseconds is ~584 million years).
 */

typedef uint64_t xury_time_deadline_t;

/*
 * Build a deadline timeout_ms from now.
 * timeout_ms == UINT32_MAX means "never expires".
 */
xury_time_deadline_t xury_time_deadline_in(uint32_t timeout_ms);

/*
 * True if the deadline has passed.
 * A deadline of UINT64_MAX is never reached.
 */
bool xury_time_deadline_passed(xury_time_deadline_t deadline);

/*
 * Milliseconds remaining until the deadline.
 * Returns 0 if the deadline has passed.
 * Returns UINT32_MAX if the deadline is UINT64_MAX.
 */
uint32_t xury_time_deadline_remaining_ms(xury_time_deadline_t deadline);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY CORE INTERNAL TIME HEADER
 * ============================================================================
 */

#endif /* XURY_CORE_INTERNAL_TIME_H */
