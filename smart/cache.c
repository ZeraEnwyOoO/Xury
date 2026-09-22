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
 * XURY SMART — CACHE IMPLEMENTATION
 * ============================================================================
 *
 * Real implementation of src/smart/internal/cache.h.
 *
 * The cache persists a small, fixed-layout blob through the caller's
 * xury_storage_iface_t. Xury never opens a file, never chooses a
 * path, and never inspects the environment. The host decides where
 * the blob lives.
 *
 * ----------------------------------------------------------------------------
 * Blob layout (version 1)
 * ----------------------------------------------------------------------------
 *
 *   offset  size  field
 *   ------  ----  -----
 *   0       4     magic       "XCH1" (0x58 0x43 0x48 0x31)
 *   4       1     version     0x01
 *   5       1     nat_type    (0..6)
 *   6       1     nat_label   (0..4)
 *   7       1     cgnat_type  (0..5)
 *   8       4     success_weapons  bitmask, big-endian
 *   12      4     failed_weapons   bitmask, big-endian
 *   16      8     saved_at_ms      monotonic ms at save time,
 *                                  big-endian
 *   24      8     key              the network fingerprint, big-endian
 *   ------  ----
 *   total:  32 bytes
 *
 * The blob is fixed-width because every field is fixed-width. The
 * format is versioned and self-describing; an unknown version or a
 * wrong magic is treated as "no entry", not as an error.
 *
 * The key is stored inside the blob and re-checked on load. This
 * means a host that uses a single storage slot for multiple keys
 * cannot accidentally load another network's entry.
 *
 * The age is computed from saved_at_ms, which is a monotonic value
 * within the process. Across process restarts, monotonic time may
 * reset, in which case age_sec can be meaningless. The cache
 * therefore treats a saved_at_ms that is greater than the current
 * time as "age unknown, not fresh": loaded = true, valid = false.
 * This is the honest behavior; hosts that need wall-clock aging must
 * persist a wall-clock value themselves and key on it.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 * - src/core/internal/bytes.h    (cursor, big-endian encode/decode)
 * - src/core/internal/time.h     (monotonic now)
 * - <xury/scan.h>
 * - <xury/types.h>
 *
 * No allocation, no I/O beyond the storage callbacks, no global state.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/types.h>
#include <xury/err.h>
#include <xury/scan.h>

#include "core/internal/bytes.h"
#include "core/internal/time.h"
#include "smart/internal/cache.h"

/*
 * ============================================================================
 * FORMAT CONSTANTS
 * ============================================================================
 */

#define XCH_MAGIC_0 0x58u   /* 'X' */
#define XCH_MAGIC_1 0x43u   /* 'C' */
#define XCH_MAGIC_2 0x48u   /* 'H' */
#define XCH_MAGIC_3 0x31u   /* '1' */

#define XCH_VERSION 0x01u

#define XCH_BLOB_SIZE 32u

/*
 * The storage interface reports success as 0 and failure as non-zero.
 * It does not distinguish "no entry" from "I/O error". The cache
 * treats any non-zero result as "no entry"; see cache.h for why.
 */

/*
 * ============================================================================
 * INTERNAL HELPERS
 * ============================================================================
 */

static void memory_clear(xury_memory_result_t *r)
{
    memset(r, 0, sizeof(*r));
    r->loaded  = false;
    r->valid   = false;
    r->status  = XURY_SCAN_SUB_SKIPPED;
}

/*
 * Encode the cache blob.
 *
 * out_cap must be at least XCH_BLOB_SIZE.
 * Returns XURY_OK on success.
 */
static xury_err_t encode_blob(uint8_t *out,
                              size_t out_cap,
                              uint64_t key,
                              uint8_t nat_type,
                              uint8_t nat_label,
                              uint8_t cgnat_type,
                              uint32_t success_weapons,
                              uint32_t failed_weapons,
                              uint64_t saved_at_ms)
{
    if (out == NULL) {
        return XURY_ERR_INVAL;
    }
    if (out_cap < XCH_BLOB_SIZE) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }

    xury_cursor_t c;
    xury_cursor_init(&c, out, out_cap);

    uint8_t magic[4] = {
        XCH_MAGIC_0, XCH_MAGIC_1, XCH_MAGIC_2, XCH_MAGIC_3
    };
    (void)xury_bytes_put(&c, magic, 4u);
    (void)xury_bytes_put(&c, &(uint8_t){ XCH_VERSION }, 1u);
    (void)xury_bytes_put(&c, &nat_type, 1u);
    (void)xury_bytes_put(&c, &nat_label, 1u);
    (void)xury_bytes_put(&c, &cgnat_type, 1u);
    (void)xury_bytes_put_be32(&c, success_weapons);
    (void)xury_bytes_put_be32(&c, failed_weapons);
    (void)xury_bytes_put_be64(&c, saved_at_ms);
    (void)xury_bytes_put_be64(&c, key);

    return XURY_OK;
}

/*
 * Decode a cache blob.
 *
 * On success, all out parameters are written.
 *
 * Returns:
 *   XURY_OK                 decoded
 *   XURY_ERR_BAD_ENDPOINT   wrong magic or unknown version
 *   XURY_ERR_BUFFER_TOO_SMALL short blob
 *   XURY_ERR_INVAL          bad arguments
 */
static xury_err_t decode_blob(const uint8_t *buf,
                              size_t len,
                              uint64_t *out_key,
                              uint8_t *out_nat_type,
                              uint8_t *out_nat_label,
                              uint8_t *out_cgnat_type,
                              uint32_t *out_success_weapons,
                              uint32_t *out_failed_weapons,
                              uint64_t *out_saved_at_ms)
{
    if (buf == NULL ||
        out_key == NULL ||
        out_nat_type == NULL ||
        out_nat_label == NULL ||
        out_cgnat_type == NULL ||
        out_success_weapons == NULL ||
        out_failed_weapons == NULL ||
        out_saved_at_ms == NULL) {
        return XURY_ERR_INVAL;
    }
    if (len < XCH_BLOB_SIZE) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }
    if (buf[0] != XCH_MAGIC_0 ||
        buf[1] != XCH_MAGIC_1 ||
        buf[2] != XCH_MAGIC_2 ||
        buf[3] != XCH_MAGIC_3) {
        return XURY_ERR_BAD_ENDPOINT;
    }
    if (buf[4] != XCH_VERSION) {
        return XURY_ERR_BAD_ENDPOINT;
    }

    xury_cursor_t c;
    xury_cursor_init_read(&c, buf, len);

    /* Skip magic + version. */
    (void)xury_bytes_skip(&c, 5u);

    uint8_t nt = 0u, nl = 0u, ct = 0u;
    uint32_t sw = 0u, fw = 0u;
    uint64_t saved = 0u, key = 0u;

    if (xury_bytes_get(&c, &nt, 1u) != XURY_OK ||
        xury_bytes_get(&c, &nl, 1u) != XURY_OK ||
        xury_bytes_get(&c, &ct, 1u) != XURY_OK ||
        xury_bytes_get_be32(&c, &sw) != XURY_OK ||
        xury_bytes_get_be32(&c, &fw) != XURY_OK ||
        xury_bytes_get_be64(&c, &saved) != XURY_OK ||
        xury_bytes_get_be64(&c, &key) != XURY_OK) {
        return XURY_ERR_BUFFER_TOO_SMALL;
    }

    *out_nat_type        = nt;
    *out_nat_label       = nl;
    *out_cgnat_type      = ct;
    *out_success_weapons = sw;
    *out_failed_weapons  = fw;
    *out_saved_at_ms     = saved;
    *out_key             = key;

    return XURY_OK;
}

/*
 * ============================================================================
 * PUBLIC — LOAD
 * ============================================================================
 */

xury_err_t xury_smart_cache_load(const xury_storage_iface_t *storage,
                                 uint64_t key,
                                 uint32_t ttl_sec,
                                 xury_memory_result_t *out)
{
    if (out == NULL) {
        return XURY_ERR_INVAL;
    }

    memory_clear(out);

    /*
     * Inert cache: no storage, no key, or no load callback.
     * This is a valid configuration, not an error.
     */
    if (storage == NULL || storage->load == NULL ||
        storage->userdata == NULL || key == 0u) {
        return XURY_OK;
    }

    uint8_t blob[XURY_SMART_CACHE_BLOB_MAX];
    size_t  blob_len = sizeof(blob);
    memset(blob, 0, sizeof(blob));

    int rc = storage->load(storage->userdata, blob, &blob_len);
    if (rc != 0) {
        /*
         * No entry, or storage backend failure. Either way the
         * cache is a hint, not a source of truth; report "not
         * loaded" and move on.
         */
        return XURY_OK;
    }

    if (blob_len == 0u) {
        /* Explicitly invalidated entry. */
        return XURY_OK;
    }
    if (blob_len > sizeof(blob)) {
        /* Backend lied about how much it wrote. Refuse it. */
        return XURY_OK;
    }

    uint64_t stored_key = 0u;
    uint8_t  nt = 0u, nl = 0u, ct = 0u;
    uint32_t sw = 0u, fw = 0u;
    uint64_t saved_at_ms = 0u;

    xury_err_t drc = decode_blob(blob, blob_len,
                                 &stored_key,
                                 &nt, &nl, &ct,
                                 &sw, &fw,
                                 &saved_at_ms);
    if (drc != XURY_OK) {
        /* Corrupt or unknown-version entry. Treat as not loaded. */
        return XURY_OK;
    }

    if (stored_key != key) {
        /*
         * The host used the same storage slot for a different
         * network. Do not mix them.
         */
        return XURY_OK;
    }

    /*
     * Entry is structurally valid and belongs to this key.
     * Fill the diagnostic fields even if it turns out to be stale.
     */
    out->loaded              = true;
    out->cached_nat_type     = (xury_nat_type_t)nt;
    out->cached_nat_label    = (xury_nat_label_t)nl;
    out->cached_cgnat_type   = (xury_cgnat_type_t)ct;
    out->cached_success_weapons = sw;
    out->cached_failed_weapons  = fw;

    /*
     * Age computation.
     *
     * saved_at_ms is a monotonic value from a previous call. If the
     * process has not restarted, now >= saved and the subtraction is
     * meaningful. If the process restarted, monotonic time may have
     * reset, and now < saved. In that case we cannot know the age;
     * report it as 0 and treat the entry as not fresh.
     */
    uint64_t now_ms = xury_time_now_ms();
    if (now_ms >= saved_at_ms) {
        uint64_t age_ms = now_ms - saved_at_ms;
        uint64_t age_sec_64 = age_ms / 1000u;
        if (age_sec_64 > 0xFFFFFFFFu) {
            age_sec_64 = 0xFFFFFFFFu;
        }
        out->age_sec = (uint32_t)age_sec_64;

        if (ttl_sec == 0u) {
            out->valid  = true;
            out->status = XURY_SCAN_SUB_OK;
            return XURY_OK;
        }
        if (out->age_sec <= ttl_sec) {
            out->valid  = true;
            out->status = XURY_SCAN_SUB_OK;
            return XURY_OK;
        }
        /* Stale. */
        out->valid  = false;
        out->status = XURY_SCAN_SUB_SKIPPED;
        return XURY_OK;
    }

    /*
     * Clock went backwards (process restart or platform quirk).
     * The entry exists, but we cannot attest to its freshness.
     */
    out->age_sec = 0u;
    out->valid   = false;
    out->status  = XURY_SCAN_SUB_SKIPPED;
    return XURY_OK;
}

/*
 * ============================================================================
 * PUBLIC — STORE
 * ============================================================================
 */

xury_err_t xury_smart_cache_store(const xury_storage_iface_t *storage,
                                  uint64_t key,
                                  const xury_analysis_result_t *analysis)
{
    if (analysis == NULL) {
        return XURY_ERR_INVAL;
    }

    /* Inert cache: nothing to do, and that is fine. */
    if (storage == NULL || storage->save == NULL ||
        storage->userdata == NULL || key == 0u) {
        return XURY_OK;
    }

    uint8_t blob[XCH_BLOB_SIZE];
    memset(blob, 0, sizeof(blob));

    /*
     * The cached weapons bitmaps are not in the analysis struct; they
     * live in the caller's engine. Until the engine wires them in,
     * store zeroes for both bitmaps. This is an honest "no weapon
     * history yet", not a fabricated value.
     */
    uint32_t success_weapons = 0u;
    uint32_t failed_weapons  = 0u;

    uint64_t saved_at_ms = xury_time_now_ms();

    xury_err_t rc = encode_blob(blob, sizeof(blob),
                                key,
                                (uint8_t)analysis->nat_type,
                                (uint8_t)analysis->nat_label,
                                (uint8_t)analysis->cgnat_type,
                                success_weapons,
                                failed_weapons,
                                saved_at_ms);
    if (rc != XURY_OK) {
        return rc;
    }

    int s = storage->save(storage->userdata, blob, sizeof(blob));
    if (s != 0) {
        return XURY_ERR_IO;
    }
    return XURY_OK;
}

/*
 * ============================================================================
 * PUBLIC — INVALIDATE
 * ============================================================================
 */

xury_err_t xury_smart_cache_invalidate(const xury_storage_iface_t *storage,
                                       uint64_t key)
{
    if (storage == NULL) {
        /* Inert cache; nothing to invalidate. */
        return XURY_OK;
    }
    if (key == 0u) {
        /* The caller asked to invalidate "no key", which is misuse. */
        return XURY_ERR_INVAL;
    }
    if (storage->save == NULL || storage->userdata == NULL) {
        /* No persistence configured; nothing to do. */
        return XURY_OK;
    }

    /*
     * The storage interface has no delete callback. Writing a
     * zero-length blob is the documented way to mark an entry as
     * absent; both load and store treat zero length as "no entry".
     */
    int s = storage->save(storage->userdata, NULL, 0u);
    if (s != 0) {
        return XURY_ERR_IO;
    }
    return XURY_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
