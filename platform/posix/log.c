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
 * XURY PLATFORM — POSIX LOG (fallback sink)
 * ============================================================================
 *
 * Real implementation for Linux, Android, macOS, and BSD.
 *
 * This is the FALLBACK sink. The preferred path is the host's log
 * hook (see <xury/hooks.h>). This file exists for the narrow case
 * where the engine must say something before the host has installed
 * a hook, or before the engine exists at all.
 *
 * On Android, __android_log_write (see src/platform/android/log.c)
 * overrides this by being linked first. The core dispatches to
 * xury_platform_log_write, and the Android translation unit provides
 * a strong definition of that symbol; this POSIX one is only used
 * when Android is not the target.
 *
 * Actually, on Android both translation units would define the same
 * symbol. The build selects exactly one: posix/log.c is used on
 * Linux/macOS/BSD, android/log.c is used on Android. The selection
 * happens in cmake/platforms/*.cmake.
 *
 * Behavior:
 *   - Writes a single line to stderr (fd 2).
 *   - Never allocates.
 *   - Never buffers beyond the caller's own line.
 *   - Best-effort: write errors are ignored. A library must not
 *     crash because its logger failed.
 *   - No timestamps, no prefixes, no locking. Formatting belongs to
 *     the caller.
 *
 * Why write(2) and not fputs(stderr):
 *   - write(2) does not touch FILE* state, so it is safe even if the
 *     host is manipulating stdio concurrently.
 *   - write(2) is async-signal-safe.
 *   - write(2) does not allocate a buffer.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <xury/types.h>
#include <xury/err.h>

#include "platform/platform.h"

/*
 * ============================================================================
 * INTERNAL — write-all helper
 * ============================================================================
 *
 * write(2) may write fewer bytes than requested when interrupted by a
 * signal, and it returns -1 with errno == EINTR. Loop until the whole
 * buffer is out, or a non-recoverable error occurs.
 *
 * Best-effort: on error we simply stop. The caller (a library) must
 * not fail because logging failed.
 */
static void write_all(int fd, const char *buf, size_t len)
{
    size_t off = 0u;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        if (n == 0) {
            /* Unexpected but possible on a closed pipe. */
            return;
        }
        off += (size_t)n;
    }
}

/*
 * ============================================================================
 * PUBLIC — fallback log sink
 * ============================================================================
 */

void xury_platform_log_write(int level, const char *msg)
{
    if (msg == NULL) {
        return;
    }

    /*
     * Prefix each line with a single-letter level tag and a space.
     * The tag uses the same mapping as <xury/hooks.h>:
     *
     *   0 TRACE -> 'T'
     *   1 DEBUG -> 'D'
     *   2 INFO  -> 'I'
     *   3 WARN  -> 'W'
     *   4 ERROR -> 'E'
     *
     * Unknown levels fall back to '?'.
     */
    char tag;
    switch (level) {
    case 0:  tag = 'T'; break;
    case 1:  tag = 'D'; break;
    case 2:  tag = 'I'; break;
    case 3:  tag = 'W'; break;
    case 4:  tag = 'E'; break;
    default: tag = '?'; break;
    }

    /*
     * We build the prefix in a small stack buffer and then write the
     * tag, the message, and a newline. We avoid a single big buffer
     * because the message may be long; three writes are simpler and
     * never allocate.
     */
    char prefix[3];
    prefix[0] = tag;
    prefix[1] = ' ';
    prefix[2] = '\0';

    write_all(STDERR_FILENO, prefix, 2u);

    size_t len = strlen(msg);
    if (len > 0u) {
        write_all(STDERR_FILENO, msg, len);
    }

    /* Ensure exactly one trailing newline. */
    if (len == 0u || msg[len - 1u] != '\n') {
        write_all(STDERR_FILENO, "\n", 1u);
    }
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
