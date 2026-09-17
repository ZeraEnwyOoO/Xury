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
 * XURY VERSION — IMPLEMENTATION
 * ============================================================================
 *
 * Implements:
 *   - public API (include/xury/version.h, include/xury/engine.h)
 *   - internal helpers (src/api/internal/version.h)
 *
 * All functions in this file are pure:
 *   - no allocation
 *   - no I/O
 *   - no global mutable state
 *
 * The precomputed strings are built once at library load from the
 * XURY_BUILD_* macros. They are stored as static const char arrays so
 * that the compiler can place them in .rodata and so that no runtime
 * formatting is required.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/version.h>
#include <xury/engine.h>

#include "api/internal/version.h"
#include "api/internal/xury.h"

/*
 * ============================================================================
 * PRECOMPUTED STRING BUFFERS
 * ============================================================================
 *
 * These are filled once, at library load, by xury_version_ctor().
 *
 * Sizes are chosen to hold the largest possible value with a NUL.
 *
 *   about        : "Xury MMM.mmm.ppp (pppppppppp, tttttttttt)"
 *                  -> ~48 bytes; use 96 for safety
 *   tag          : "Xury/MMM.mmm.ppp"
 *                  -> ~20 bytes; use 32
 *   full         : "MMM.mmm.ppp+cccccccccccccccc"
 *                  -> ~40 bytes; use 64
 *   cache_prefix : "xury:vMMM.mmm.ppp:"
 *                  -> ~24 bytes; use 32
 */

#define XURY_VERSION_ABOUT_MAX  96
#define XURY_VERSION_TAG_MAX    32
#define XURY_VERSION_FULL_MAX   64
#define XURY_VERSION_PREFIX_MAX 32

static char g_about[XURY_VERSION_ABOUT_MAX];
static char g_tag[XURY_VERSION_TAG_MAX];
static char g_full[XURY_VERSION_FULL_MAX];
static char g_cache_prefix[XURY_VERSION_PREFIX_MAX];

static bool g_initialized = false;

/*
 * ============================================================================
 * INTERNAL FORMATTING PRIMITIVES
 * ============================================================================
 *
 * These are the small, allocation-free helpers used only inside this
 * file. They are declared static so they cannot leak.
 *
 * They are deliberately simple: they handle only the cases this file
 * needs (unsigned decimal, unsigned hex, string copy). Anything more
 * general lives in src/api/xury.c.
 */

/*
 * Append an unsigned 32-bit integer in decimal to buf at *pos.
 *
 * Writes at most buflen - *pos - 1 characters plus a NUL.
 * Updates *pos to the new write position (not counting the NUL).
 *
 * Returns the number of bytes written (excluding the NUL).
 * If the buffer is too small, the value is truncated and the return
 * value reflects what was actually written.
 */
static size_t ver_append_u32(char *buf,
                             size_t buflen,
                             size_t *pos,
                             uint32_t value)
{
    char tmp[12];   /* enough for UINT32_MAX (10 digits) + slack */
    size_t n = 0;

    if (value == 0) {
        tmp[n++] = '0';
    } else {
        char rev[12];
        size_t r = 0;
        while (value > 0 && r < sizeof(rev)) {
            rev[r++] = (char)('0' + (value % 10u));
            value /= 10u;
        }
        while (r > 0) {
            tmp[n++] = rev[--r];
        }
    }

    size_t written = 0;
    for (size_t i = 0; i < n; i++) {
        if (*pos + 1 < buflen) {
            buf[*pos] = tmp[i];
            (*pos)++;
            written++;
        } else {
            break;
        }
    }
    return written;
}

/*
 * Append a NUL-terminated string to buf at *pos.
 *
 * Returns the number of bytes written (excluding the NUL).
 */
static size_t ver_append_str(char *buf,
                             size_t buflen,
                             size_t *pos,
                             const char *str)
{
    if (str == NULL) {
        return 0;
    }

    size_t written = 0;
    while (*str != '\0') {
        if (*pos + 1 < buflen) {
            buf[*pos] = *str;
            (*pos)++;
            written++;
        } else {
            break;
        }
        str++;
    }
    return written;
}

/*
 * Append a single character to buf at *pos.
 */
static size_t ver_append_char(char *buf,
                              size_t buflen,
                              size_t *pos,
                              char c)
{
    if (*pos + 1 < buflen) {
        buf[*pos] = c;
        (*pos)++;
        return 1;
    }
    return 0;
}

/*
 * Terminate the buffer at *pos (in place), if there is room.
 */
static void ver_terminate(char *buf, size_t buflen, size_t pos)
{
    if (buflen > 0) {
        if (pos >= buflen) {
            pos = buflen - 1;
        }
        buf[pos] = '\0';
    }
}

/*
 * ============================================================================
 * CONSTRUCTOR — build precomputed strings once
 * ============================================================================
 *
 * Called on first use, not at load time, because C does not guarantee
 * a portable constructor mechanism across all supported platforms.
 *
 * Idempotent and thread-safe enough for a library: the worst case is
 * that two threads race and write the same bytes.
 */

static void ver_build_strings(void)
{
    if (g_initialized) {
        return;
    }

    /*
     * about: "Xury MMM.mmm.ppp (pppppppppp, tttttttttt)"
     */
    {
        size_t pos = 0;
        ver_append_str(g_about, sizeof(g_about), &pos, "Xury ");
        ver_append_u32(g_about, sizeof(g_about), &pos,
                       (uint32_t)XURY_VERSION_MAJOR);
        ver_append_char(g_about, sizeof(g_about), &pos, '.');
        ver_append_u32(g_about, sizeof(g_about), &pos,
                       (uint32_t)XURY_VERSION_MINOR);
        ver_append_char(g_about, sizeof(g_about), &pos, '.');
        ver_append_u32(g_about, sizeof(g_about), &pos,
                       (uint32_t)XURY_VERSION_PATCH);
        ver_append_str(g_about, sizeof(g_about), &pos, " (");
        ver_append_str(g_about, sizeof(g_about), &pos,
                       XURY_BUILD_PLATFORM);
        ver_append_str(g_about, sizeof(g_about), &pos, ", ");
        ver_append_str(g_about, sizeof(g_about), &pos,
                       XURY_BUILD_TYPE);
        ver_append_char(g_about, sizeof(g_about), &pos, ')');
        ver_terminate(g_about, sizeof(g_about), pos);
    }

    /*
     * tag: "Xury/MMM.mmm.ppp"
     */
    {
        size_t pos = 0;
        ver_append_str(g_tag, sizeof(g_tag), &pos, "Xury/");
        ver_append_u32(g_tag, sizeof(g_tag), &pos,
                       (uint32_t)XURY_VERSION_MAJOR);
        ver_append_char(g_tag, sizeof(g_tag), &pos, '.');
        ver_append_u32(g_tag, sizeof(g_tag), &pos,
                       (uint32_t)XURY_VERSION_MINOR);
        ver_append_char(g_tag, sizeof(g_tag), &pos, '.');
        ver_append_u32(g_tag, sizeof(g_tag), &pos,
                       (uint32_t)XURY_VERSION_PATCH);
        ver_terminate(g_tag, sizeof(g_tag), pos);
    }

    /*
     * full: "MMM.mmm.ppp+commit"
     *       or just "MMM.mmm.ppp" if commit is "unknown"
     */
    {
        size_t pos = 0;
        ver_append_u32(g_full, sizeof(g_full), &pos,
                       (uint32_t)XURY_VERSION_MAJOR);
        ver_append_char(g_full, sizeof(g_full), &pos, '.');
        ver_append_u32(g_full, sizeof(g_full), &pos,
                       (uint32_t)XURY_VERSION_MINOR);
        ver_append_char(g_full, sizeof(g_full), &pos, '.');
        ver_append_u32(g_full, sizeof(g_full), &pos,
                       (uint32_t)XURY_VERSION_PATCH);

        const char *commit = XURY_BUILD_COMMIT;
        if (commit != NULL && strcmp(commit, "unknown") != 0) {
            ver_append_char(g_full, sizeof(g_full), &pos, '+');
            ver_append_str(g_full, sizeof(g_full), &pos, commit);
        }
        ver_terminate(g_full, sizeof(g_full), pos);
    }

    /*
     * cache_prefix: "xury:vMMM.mmm.ppp:"
     */
    {
        size_t pos = 0;
        ver_append_str(g_cache_prefix, sizeof(g_cache_prefix), &pos,
                       "xury:v");
        ver_append_u32(g_cache_prefix, sizeof(g_cache_prefix), &pos,
                       (uint32_t)XURY_VERSION_MAJOR);
        ver_append_char(g_cache_prefix, sizeof(g_cache_prefix), &pos, '.');
        ver_append_u32(g_cache_prefix, sizeof(g_cache_prefix), &pos,
                       (uint32_t)XURY_VERSION_MINOR);
        ver_append_char(g_cache_prefix, sizeof(g_cache_prefix), &pos, '.');
        ver_append_u32(g_cache_prefix, sizeof(g_cache_prefix), &pos,
                       (uint32_t)XURY_VERSION_PATCH);
        ver_append_char(g_cache_prefix, sizeof(g_cache_prefix), &pos, ':');
        ver_terminate(g_cache_prefix, sizeof(g_cache_prefix), pos);
    }

    g_initialized = true;
}

/*
 * ============================================================================
 * PUBLIC API — version strings
 * ============================================================================
 */

const char *xury_version(void)
{
    return XURY_VERSION_STRING;
}

const char *xury_build_commit(void)
{
    return XURY_BUILD_COMMIT;
}

const char *xury_build_date(void)
{
    return XURY_BUILD_DATE;
}

const char *xury_build_type(void)
{
    return XURY_BUILD_TYPE;
}

const char *xury_build_platform(void)
{
    return XURY_BUILD_PLATFORM;
}

int xury_api_version(void)
{
    return (int)XURY_API_VERSION;
}

/*
 * ============================================================================
 * INTERNAL API — composite and parse
 * ============================================================================
 *
 * These are declared in src/api/internal/version.h and are not part
 * of the public ABI.
 */

uint32_t xury_version_code(void)
{
    return (uint32_t)XURY_VERSION_CODE;
}

/*
 * Parse "MAJOR.MINOR.PATCH", optional leading 'v'.
 *
 * Missing MINOR or PATCH default to 0.
 *
 * Returns 0 on any malformed input.
 *
 * This parser is intentionally strict: it does not accept spaces,
 * trailing garbage, non-digit characters, or empty components.
 */
uint32_t xury_version_parse(const char *str)
{
    if (str == NULL || *str == '\0') {
        return 0u;
    }

    const char *p = str;

    /* Optional leading 'v' or 'V'. */
    if (*p == 'v' || *p == 'V') {
        p++;
    }

    uint32_t parts[3] = {0u, 0u, 0u};
    int idx = 0;
    bool saw_digit = false;

    while (*p != '\0' && idx < 3) {
        if (*p >= '0' && *p <= '9') {
            saw_digit = true;
            uint32_t v = 0u;
            while (*p >= '0' && *p <= '9') {
                uint32_t d = (uint32_t)(*p - '0');
                /* overflow guard */
                if (v > (0xFFFFFFFFu - d) / 10u) {
                    return 0u;
                }
                v = v * 10u + d;
                p++;
            }
            parts[idx++] = v;

            if (*p == '.') {
                p++;
                saw_digit = false;
                continue;
            }
            break;
        } else {
            return 0u;
        }
    }

    if (!saw_digit) {
        return 0u;
    }
    if (*p != '\0') {
        return 0u;
    }

    return (parts[0] << 16) | (parts[1] << 8) | parts[2];
}

int xury_version_compare(uint32_t a, uint32_t b)
{
    if (a < b) {
        return -1;
    }
    if (a > b) {
        return 1;
    }
    return 0;
}

 /* ---- continued from part 1/2 ---- */

/*
 * ============================================================================
 * INTERNAL API — precomputed strings
 * ============================================================================
 *
 * These functions return pointers to the static buffers built by
 * ver_build_strings(). They never allocate, never fail, and never
 * return NULL.
 *
 * The first call triggers the lazy constructor. Subsequent calls are
 * a single pointer return.
 */

const char *xury_version_about(void)
{
    ver_build_strings();
    return g_about;
}

const char *xury_version_tag(void)
{
    ver_build_strings();
    return g_tag;
}

const char *xury_version_full(void)
{
    ver_build_strings();
    return g_full;
}

const char *xury_version_cache_prefix(void)
{
    ver_build_strings();
    return g_cache_prefix;
}

/*
 * ============================================================================
 * INTERNAL API — self-check
 * ============================================================================
 *
 * Verify that the runtime composite value matches the compile-time
 * constant. This catches the case where a host links against a
 * libxury built from different headers.
 *
 * How the mismatch can happen:
 *   - the host's include/xury/version.h is from v0.2.0
 *   - the linked libxury.a was built from v0.1.0
 *   - the host's headers say one thing, the library another
 *
 * The consequences of a mismatch are subtle and dangerous (wrong
 * struct layout, wrong enum values, wrong bitmask widths). This check
 * turns a silent corruption into a clear startup failure.
 *
 * Called once by xury_engine_start().
 */

xury_err_t xury_version_self_check(void)
{
    /*
     * Runtime: xury_version_code() returns the value the library was
     * built with.
     *
     * Compile-time: XURY_VERSION_CODE is what the headers say.
     *
     * If they differ, the host's headers and the linked library are
     * out of sync.
     */
    const uint32_t runtime_code   = xury_version_code();
    const uint32_t compile_code   = (uint32_t)XURY_VERSION_CODE;

    if (runtime_code != compile_code) {
        return XURY_ERR_INVAL;
    }

    /*
     * Also verify the string and the numeric value agree. If a release
     * changes one but not the other, this catches it.
     *
     * "0.1.0" must parse to (0 << 16) | (1 << 8) | 0.
     */
    const uint32_t parsed_code = xury_version_parse(XURY_VERSION_STRING);
    if (parsed_code == 0u) {
        /* The string is malformed at build time. */
        return XURY_ERR_INVAL;
    }
    if (parsed_code != compile_code) {
        return XURY_ERR_INVAL;
    }

    /*
     * Verify the API version is at least the minimum the library
     * requires.
     *
     * XURY_API_VERSION is a compile-time constant. The library was
     * built with one value; the host may have been built with another.
     * A mismatch means the host's header set is older or newer than
     * the library's.
     *
     * For now, any value >= 1 is acceptable. Future breaking changes
     * will raise the minimum.
     */
    if (XURY_API_VERSION < 1) {
        return XURY_ERR_INVAL;
    }

    return XURY_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
