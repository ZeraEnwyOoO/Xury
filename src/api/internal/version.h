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

#ifndef XURY_API_INTERNAL_VERSION_H
#define XURY_API_INTERNAL_VERSION_H

/*
 * ============================================================================
 * XURY INTERNAL VERSION HELPERS
 * ============================================================================
 *
 * Internal helpers used by src/api/version.c and by the engine when it
 * needs a stable version string for logging or cache keys.
 *
 * This header is NOT installed. It is private to the Xury build.
 *
 * The public version API is declared in include/xury/version.h and
 * include/xury/engine.h:
 *
 *   xury_version()          -> "0.1.0"
 *   xury_build_commit()     -> git hash
 *   xury_build_date()       -> "YYYY-MM-DD"
 *   xury_build_type()       -> "Release"
 *   xury_build_platform()   -> "linux"
 *   xury_api_version()      -> 1
 *   xury_about()            -> "Xury 0.1.0 (linux, Release)"
 *
 * This header adds:
 *
 *   - a precomputed "about" string with no runtime formatting
 *   - a numeric composite for comparisons
 *   - a stable cache key prefix
 *
 * Rules:
 *   - Never expose these in include/xury/.
 *   - Never call them from public headers.
 *   - All functions are pure; no allocation, no I/O.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <xury/version.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * COMPOSITE VERSION
 * ============================================================================
 *
 * The public header already defines:
 *
 *   XURY_VERSION_CODE         compile-time composite
 *   XURY_VERSION_CODE_OF(m,n,p)  helper macro
 *
 * This header adds runtime accessors for the same value, useful when
 * the host wants to compare a runtime string against a known version.
 */

/*
 * Return the composite version as a 32-bit integer.
 *
 * Format: (MAJOR << 16) | (MINOR << 8) | PATCH
 *
 * Always equals XURY_VERSION_CODE at the time the library was built.
 */
uint32_t xury_version_code(void);

/*
 * Parse a version string of the form "MAJOR.MINOR.PATCH" into a
 * composite integer.
 *
 * Accepts optional leading 'v' ("v0.1.0"). Accepts missing minor or
 * patch ("1", "1.2").
 *
 * Returns:
 *   the composite value on success
 *   0 if str is NULL, empty, or malformed
 *
 * Pure: no allocation, no I/O.
 */
uint32_t xury_version_parse(const char *str);

/*
 * Compare two composite version codes.
 *
 * Returns:
 *   < 0  if a < b
 *   = 0  if a == b
 *   > 0  if a > b
 */
int xury_version_compare(uint32_t a, uint32_t b);

/*
 * ============================================================================
 * PRECOMPUTED STRINGS
 * ============================================================================
 *
 * These return pointers to static const strings that are computed once
 * at library load. They never allocate and never fail.
 *
 * Never returns NULL.
 */

/*
 * Full human-readable build string:
 *
 *   "Xury 0.1.0 (linux, Release)"
 *
 * Uses XURY_BUILD_PLATFORM and XURY_BUILD_TYPE if the build system
 * provided them. Otherwise "unknown".
 */
const char *xury_version_about(void);

/*
 * Short "Xury/<version>" tag, useful as a protocol banner or log tag:
 *
 *   "Xury/0.1.0"
 */
const char *xury_version_tag(void);

/*
 * Version + commit, for bug reports:
 *
 *   "0.1.0+abc1234"
 *
 * If the commit is unknown, the "+..." suffix is omitted.
 */
const char *xury_version_full(void);

/*
 * ============================================================================
 * CACHE KEY
 * ============================================================================
 *
 * A stable prefix for cache keys. Different Xury versions must never
 * share a cache, because scan semantics may change between versions.
 *
 * Format:
 *
 *   "xury:v<major>.<minor>.<patch>:"
 *
 * Example:
 *
 *   "xury:v0.1.0:"
 */
const char *xury_version_cache_prefix(void);

/*
 * ============================================================================
 * CONSISTENCY CHECK
 * ============================================================================
 *
 * Called once at engine startup. Verifies that the runtime composite
 * value matches the compile-time constant. Catches accidental mixing
 * of headers from one version with a library from another.
 *
 * Returns:
 *   XURY_OK         — consistent
 *   XURY_ERR_INVAL  — mismatch (headers/library out of sync)
 */
int xury_version_self_check(void);

#ifdef __cplusplus
}
#endif

/*
 * ============================================================================
 * END OF XURY INTERNAL VERSION HEADER
 * ============================================================================
 */

#endif /* XURY_API_INTERNAL_VERSION_H */
