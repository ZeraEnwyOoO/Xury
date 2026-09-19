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
 * XURY PLATFORM — ANDROID LOG
 * ============================================================================
 *
 * Android-specific log sink.
 *
 * On Android the fallback sink is logcat, not stderr. stderr is
 * routed to /dev/null for most apps and is useless for diagnostics.
 * __android_log_write is the correct primitive.
 *
 * Build selection:
 *   On Android, this file is compiled INSTEAD OF posix/log.c. Both
 *   define xury_platform_log_write; the CMake platform file chooses
 *   one. They are never linked together.
 *
 * Tag:
 *   logcat groups messages by tag. We use "xury" so that the user can
 *   filter with `adb logcat -s xury`.
 *
 * Level mapping:
 *   Xury level 0..4 -> ANDROID_LOG_VERBOSE..FATAL
 *
 *   Xury            Android             logcat tag
 *   XURY_LOG_TRACE  ANDROID_LOG_VERBOSE V
 *   XURY_LOG_DEBUG  ANDROID_LOG_DEBUG   D
 *   XURY_LOG_INFO   ANDROID_LOG_INFO    I
 *   XURY_LOG_WARN   ANDROID_LOG_WARN    W
 *   XURY_LOG_ERROR  ANDROID_LOG_ERROR   E
 *
 * The public header uses 0..4 to avoid depending on <android/log.h>
 * outside this file.
 *
 * Threading:
 *   __android_log_write is thread-safe.
 *
 * Dependency:
 *   Links against liblog, which is part of the NDK sysroot. The CMake
 *   platform file adds it to XURY_PLATFORM_LIBS.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <android/log.h>

#include <xury/types.h>
#include <xury/err.h>

#include "platform/platform.h"

/*
 * ============================================================================
 * PUBLIC — Android log sink
 * ============================================================================
 */

void xury_platform_log_write(int level, const char *msg)
{
    if (msg == NULL) {
        return;
    }

    int android_priority;
    switch (level) {
    case 0:  android_priority = ANDROID_LOG_VERBOSE; break;
    case 1:  android_priority = ANDROID_LOG_DEBUG;   break;
    case 2:  android_priority = ANDROID_LOG_INFO;    break;
    case 3:  android_priority = ANDROID_LOG_WARN;    break;
    case 4:  android_priority = ANDROID_LOG_ERROR;   break;
    default: android_priority = ANDROID_LOG_DEFAULT; break;
    }

    /*
     * __android_log_write takes the tag, the message, and returns the
     * number of bytes written (or negative on error). We ignore the
     * return value: a library must not fail because logging failed.
     *
     * logcat adds the newline itself, so we do not append one.
     */
    (void)__android_log_write(android_priority, "xury", msg);
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
