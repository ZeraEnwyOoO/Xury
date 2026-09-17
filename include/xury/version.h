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

#ifndef XURY_VERSION_H
#define XURY_VERSION_H

/*
 * ============================================================================
 * XURY VERSION
 * ============================================================================
 *
 * Xury is a no-server P2P NAT traversal engine.
 *
 * Scope:
 *   - NAT detection
 *   - NAT traversal
 *   - Hole punching
 *   - Port mapping (UPnP / NAT-PMP / PCP)
 *   - CGNAT persuasion
 *   - Peer-as-mirror (no STUN server)
 *   - Peer relay (no TURN server)
 *
 * Non-scope (other products handle these):
 *   - DHT / discovery
 *   - Bootstrap
 *   - Storage
 *   - Application protocol
 *   - Encryption
 *
 * Platforms (first-class):
 *   - Linux
 *   - Android
 *
 * Platforms (plug-in ready, added later without core change):
 *   - Windows
 *   - macOS
 *   - iOS
 *   - BSD
 *
 * Protocol support:
 *   - UDP (primary — NAT traversal)
 *   - TCP (secondary — relay fallback)
 *
 * ============================================================================
 */

/*
 * ----------------------------------------------------------------------------
 * VERSION NUMBERS
 * ----------------------------------------------------------------------------
 *
 * Semantic Versioning 2.0.0
 *
 *   MAJOR — Incompatible API changes
 *   MINOR — Backward-compatible new features
 *   PATCH — Backward-compatible bug fixes
 *
 * Update rules:
 *   - Release:  update all three + XURY_VERSION_STRING
 *   - Hotfix:   update PATCH only
 *   - Feature:  update MINOR, reset PATCH
 *   - Breaking: update MAJOR, reset MINOR + PATCH
 */

#define XURY_VERSION_MAJOR       0
#define XURY_VERSION_MINOR       1
#define XURY_VERSION_PATCH       0

/*
 * ----------------------------------------------------------------------------
 * VERSION STRING
 * ----------------------------------------------------------------------------
 *
 * Human-readable version string.
 *
 * Format: "MAJOR.MINOR.PATCH"
 *
 * Must match XURY_VERSION_MAJOR/MINOR/PATCH above.
 * Used in logs, --version output, and package metadata.
 */

#define XURY_VERSION_STRING      "0.1.0"

/*
 * ----------------------------------------------------------------------------
 * VERSION COMPOSITE
 * ----------------------------------------------------------------------------
 *
 * Single integer representation for comparison.
 *
 * Format: (MAJOR << 16) | (MINOR << 8) | PATCH
 *
 * Example:
 *   0.1.0  ->  0x000100
 *   1.0.0  ->  0x010000
 *   1.2.3  ->  0x010203
 *
 * Usage:
 *   #if XURY_VERSION_CODE >= XURY_VERSION_CODE_OF(1, 0, 0)
 *       // feature available
 *   #endif
 */

#define XURY_VERSION_CODE \
    ((XURY_VERSION_MAJOR << 16) | \
     (XURY_VERSION_MINOR <<  8) | \
     (XURY_VERSION_PATCH))

/*
 * Helper macro to build a version code at compile time.
 *
 * Usage:
 *   XURY_VERSION_CODE_OF(1, 2, 3)  ->  0x010203
 */

#define XURY_VERSION_CODE_OF(major, minor, patch) \
    (((major) << 16) | ((minor) << 8) | (patch))

/*
 * ----------------------------------------------------------------------------
 * VERSION COMPARISON MACROS
 * ----------------------------------------------------------------------------
 *
 * Compile-time version checks.
 *
 * Usage:
 *   #if XURY_VERSION_AT_LEAST(0, 2, 0)
 *       // code that requires 0.2.0+
 *   #endif
 */

#define XURY_VERSION_AT_LEAST(major, minor, patch) \
    (XURY_VERSION_CODE >= XURY_VERSION_CODE_OF(major, minor, patch))

#define XURY_VERSION_LESS_THAN(major, minor, patch) \
    (XURY_VERSION_CODE <  XURY_VERSION_CODE_OF(major, minor, patch))

/*
 * ----------------------------------------------------------------------------
 * API VERSION
 * ----------------------------------------------------------------------------
 *
 * Public API stability marker.
 *
 * Incremented whenever the public API changes in a way that affects
 * source compatibility. Used by host products to detect mismatches.
 *
 * Current: 1
 *   - 1 = initial public API (Xury v0.1.0)
 *
 * Rules:
 *   - Bump on breaking API change.
 *   - Never reuse a number.
 *   - Document changes in CHANGELOG.md.
 */

#define XURY_API_VERSION         1

/*
 * ----------------------------------------------------------------------------
 * ABI VERSION
 * ----------------------------------------------------------------------------
 *
 * Shared library ABI marker.
 *
 * Used as the SONAME major version when building libxury.so.
 * Only relevant when XURY_BUILD_SHARED=ON.
 *
 * Current: 0 (pre-stable)
 *   - 0 = unstable ABI (v0.x)
 *   - 1 = first stable ABI (v1.0)
 *
 * Rules:
 *   - Must equal XURY_VERSION_MAJOR until v1.0.
 *   - After v1.0: bump only on ABI-breaking change.
 */

#define XURY_ABI_VERSION         XURY_VERSION_MAJOR

/*
 * ----------------------------------------------------------------------------
 * BUILD METADATA
 * ----------------------------------------------------------------------------
 *
 * Optional build-time metadata injected by the build system.
 *
 * CMake may define these via target_compile_definitions():
 *   XURY_BUILD_COMMIT    — git commit hash
 *   XURY_BUILD_DATE      — build date "YYYY-MM-DD"
 *   XURY_BUILD_TYPE      — "Debug", "Release", "RelWithDebInfo"
 *   XURY_BUILD_PLATFORM  — "linux", "android", ...
 *
 * If not defined, they default to "unknown".
 */

#ifndef XURY_BUILD_COMMIT
#define XURY_BUILD_COMMIT        "unknown"
#endif

#ifndef XURY_BUILD_DATE
#define XURY_BUILD_DATE          "unknown"
#endif

#ifndef XURY_BUILD_TYPE
#define XURY_BUILD_TYPE          "unknown"
#endif

#ifndef XURY_BUILD_PLATFORM
#define XURY_BUILD_PLATFORM      "unknown"
#endif

/*
 * ----------------------------------------------------------------------------
 * COMPILER / PLATFORM DETECTION (for version reporting only)
 * ----------------------------------------------------------------------------
 *
 * These are informational. They do NOT change behavior.
 * Actual platform logic lives in src/platform/.
 *
 * Note: Do not add #ifdef behavior here. Use platform layer instead.
 */

#if defined(__ANDROID__)
    #define XURY_PLATFORM_ANDROID   1
#elif defined(__linux__)
    #define XURY_PLATFORM_LINUX     1
#elif defined(_WIN32)
    #define XURY_PLATFORM_WINDOWS   1
#elif defined(__APPLE__)
    #include <TargetConditionals.h>
    #if TARGET_OS_IPHONE
        #define XURY_PLATFORM_IOS   1
    #else
        #define XURY_PLATFORM_MACOS 1
    #endif
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    #define XURY_PLATFORM_BSD       1
#else
    #define XURY_PLATFORM_UNKNOWN   1
#endif

/*
 * ----------------------------------------------------------------------------
 * RUNTIME VERSION FUNCTIONS
 * ----------------------------------------------------------------------------
 *
 * The actual function declarations live in xury.h, not here.
 * This header is macros-only so it can be included anywhere with no cost.
 *
 * See xury.h for:
 *   const char *xury_version(void);         // returns XURY_VERSION_STRING
 *   const char *xury_build_commit(void);    // returns XURY_BUILD_COMMIT
 *   const char *xury_build_date(void);      // returns XURY_BUILD_DATE
 *   const char *xury_build_type(void);      // returns XURY_BUILD_TYPE
 *   const char *xury_build_platform(void);  // returns XURY_BUILD_PLATFORM
 *   int         xury_api_version(void);     // returns XURY_API_VERSION
 */

/*
 * ============================================================================
 * END OF XURY VERSION HEADER
 * ============================================================================
 */

#endif /* XURY_VERSION_H */
