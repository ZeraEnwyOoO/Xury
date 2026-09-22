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
 * TESTS — src/smart/cache.c
 * ============================================================================
 *
 * Exercise the persistent scan cache:
 *
 *   xury_smart_cache_load()
 *   xury_smart_cache_store()
 *   xury_smart_cache_invalidate()
 *
 * No file I/O, no system calls. The storage backend is a tiny in-
 * memory buffer driven by the test. This is the same
 * xury_storage_iface_t a host would implement over a file, but with
 * the persistence replaced by a struct the test can inspect.
 *
 * The goal is to verify the contract documented in cache.h:
 *
 *   - Inert cache: NULL storage / NULL save / key == 0 -> no-op
 *   - Round trip: store then load returns the same classification
 *   - TTL: fresh entries load, stale entries do not
 *   - Key mismatch: entries for another key are not loaded
 *   - Corruption: bad magic or version -> "not loaded"
 *   - Invalidation: zero-length write makes the entry absent
 *   - Honest failure: broken storage does not crash load
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "smart/internal/cache.h"
#include "test/test.h"

/*
 * ============================================================================
 * IN-MEMORY STORAGE
 * ============================================================================
 *
 * A single-slot storage backend. The host's real backend would be a
 * file or a key-value store; here it is a struct.
 *
 * "save" copies the blob into the slot.
 * "load" copies the slot into the caller's buffer.
 *
 * A "save" of length 0 clears the slot: that is how the cache
 * expresses invalidation (see cache.h).
 */

#define SLOT_CAP XURY_SMART_CACHE_BLOB_MAX

typedef struct {
    uint8_t  buf[SLOT_CAP];
    size_t   len;
    bool     fail_save;
    bool     fail_load;
} fake_storage_t;

static void fake_storage_reset(fake_storage_t *fs)
{
    memset(fs, 0, sizeof(*fs));
    fs->len = 0;
}

static int fake_load(void *userdata, uint8_t *buf, size_t *len)
{
    fake_storage_t *fs = (fake_storage_t *)userdata;
    if (fs->fail_load) {
        return -1;
    }
    if (fs->len == 0u) {
        /*
         * The cache contract says: a storage->load returning 0 with
         * *len unchanged means "no entry". The caller passes in a
         * capacity; we must not pretend to have written anything.
         */
        return 0;
    }
    if (*len < fs->len) {
        return -1;
    }
    memcpy(buf, fs->buf, fs->len);
    *len = fs->len;
    return 0;
}

static int fake_save(void *userdata, const uint8_t *buf, size_t len)
{
    fake_storage_t *fs = (fake_storage_t *)userdata;
    if (fs->fail_save) {
        return -1;
    }
    if (len == 0u) {
        fs->len = 0;
        return 0;
    }
    if (len > sizeof(fs->buf)) {
        return -1;
    }
    memcpy(fs->buf, buf, len);
    fs->len = len;
    return 0;
}

static xury_storage_iface_t make_iface(fake_storage_t *fs)
{
    xury_storage_iface_t s;
    s.userdata = fs;
    s.load     = fake_load;
    s.save     = fake_save;
    return s;
}

/*
 * ============================================================================
 * FIXTURES
 * ============================================================================
 */

static xury_analysis_result_t analysis_fixture(void)
{
    xury_analysis_result_t a;
    memset(&a, 0, sizeof(a));
    a.nat_type   = XURY_NAT_SYMMETRIC;
    a.nat_label  = XURY_NAT_LABEL_HARD;
    a.cgnat_type = XURY_CGNAT_RANDOM;
    return a;
}

/*
 * ============================================================================
 * SENTINEL
 * ============================================================================
 */

#define SENTINEL_BYTE 0x5Au

static void fill_mem_sentinel(xury_memory_result_t *r)
{
    unsigned char *b = (unsigned char *)r;
    for (size_t i = 0; i < sizeof(*r); i++) {
        b[i] = SENTINEL_BYTE;
    }
}

/*
 * ============================================================================
 * INERT CACHE
 * ============================================================================
 */

static void test_load_null_out(void)
{
    xury_err_t rc = xury_smart_cache_load(NULL, 0u, 0u, NULL);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_store_null_analysis(void)
{
    fake_storage_t fs;
    fake_storage_reset(&fs);
    xury_storage_iface_t s = make_iface(&fs);

    xury_err_t rc = xury_smart_cache_store(&s, 1u, NULL);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_load_with_null_storage(void)
{
    xury_memory_result_t m;
    fill_mem_sentinel(&m);

    xury_err_t rc = xury_smart_cache_load(NULL, 1u, 0u, &m);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT(!m.loaded);
    TEST_ASSERT(!m.valid);
    TEST_ASSERT_EQ(m.status, XURY_SCAN_SUB_SKIPPED);
}

static void test_load_with_zero_key(void)
{
    fake_storage_t fs;
    fake_storage_reset(&fs);
    xury_storage_iface_t s = make_iface(&fs);

    xury_memory_result_t m;
    fill_mem_sentinel(&m);

    xury_err_t rc = xury_smart_cache_load(&s, 0u, 0u, &m);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT(!m.loaded);
    TEST_ASSERT(!m.valid);
}

static void test_store_with_null_storage(void)
{
    xury_analysis_result_t a = analysis_fixture();
    xury_err_t rc = xury_smart_cache_store(NULL, 1u, &a);
    TEST_ASSERT_EQ(rc, XURY_OK);
}

static void test_store_with_zero_key(void)
{
    fake_storage_t fs;
    fake_storage_reset(&fs);
    xury_storage_iface_t s = make_iface(&fs);

    xury_analysis_result_t a = analysis_fixture();
    xury_err_t rc = xury_smart_cache_store(&s, 0u, &a);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(fs.len, 0u);
}

/*
 * ============================================================================
 * ROUND TRIP
 * ============================================================================
 */

static void test_round_trip_fresh_entry(void)
{
    fake_storage_t fs;
    fake_storage_reset(&fs);
    xury_storage_iface_t s = make_iface(&fs);

    xury_analysis_result_t a = analysis_fixture();
    const uint64_t key = 0x123456789ABCDEF0ull;

    TEST_ASSERT_EQ(xury_smart_cache_store(&s, key, &a), XURY_OK);
    TEST_ASSERT(fs.len > 0u);

    xury_memory_result_t m;
    fill_mem_sentinel(&m);

    TEST_ASSERT_EQ(xury_smart_cache_load(&s, key, 60u, &m), XURY_OK);
    TEST_ASSERT(m.loaded);
    TEST_ASSERT(m.valid);
    TEST_ASSERT_EQ(m.status, XURY_SCAN_SUB_OK);
    TEST_ASSERT_EQ(m.cached_nat_type, a.nat_type);
    TEST_ASSERT_EQ(m.cached_nat_label, a.nat_label);
    TEST_ASSERT_EQ(m.cached_cgnat_type, a.cgnat_type);
}

static void test_round_trip_with_ttl_zero(void)
{
    /*
     * TTL 0 means "never expire". A just-stored entry must be valid.
     */
    fake_storage_t fs;
    fake_storage_reset(&fs);
    xury_storage_iface_t s = make_iface(&fs);

    xury_analysis_result_t a = analysis_fixture();
    TEST_ASSERT_EQ(xury_smart_cache_store(&s, 42u, &a), XURY_OK);

    xury_memory_result_t m;
    fill_mem_sentinel(&m);
    TEST_ASSERT_EQ(xury_smart_cache_load(&s, 42u, 0u, &m), XURY_OK);
    TEST_ASSERT(m.loaded);
    TEST_ASSERT(m.valid);
}

/*
 * ============================================================================
 * KEY MISMATCH
 * ============================================================================
 */

static void test_load_with_wrong_key(void)
{
    fake_storage_t fs;
    fake_storage_reset(&fs);
    xury_storage_iface_t s = make_iface(&fs);

    xury_analysis_result_t a = analysis_fixture();
    TEST_ASSERT_EQ(xury_smart_cache_store(&s, 100u, &a), XURY_OK);

    xury_memory_result_t m;
    fill_mem_sentinel(&m);
    TEST_ASSERT_EQ(xury_smart_cache_load(&s, 200u, 0u, &m), XURY_OK);
    TEST_ASSERT(!m.loaded);
    TEST_ASSERT(!m.valid);
    TEST_ASSERT_EQ(m.status, XURY_SCAN_SUB_SKIPPED);
}

/*
 * ============================================================================
 * CORRUPTION
 * ============================================================================
 */

static void test_load_bad_magic(void)
{
    fake_storage_t fs;
    fake_storage_reset(&fs);
    xury_storage_iface_t s = make_iface(&fs);

    xury_analysis_result_t a = analysis_fixture();
    TEST_ASSERT_EQ(xury_smart_cache_store(&s, 7u, &a), XURY_OK);

    /* Corrupt the magic byte. */
    fs.buf[0] = 0x00u;

    xury_memory_result_t m;
    fill_mem_sentinel(&m);
    TEST_ASSERT_EQ(xury_smart_cache_load(&s, 7u, 0u, &m), XURY_OK);
    TEST_ASSERT(!m.loaded);
    TEST_ASSERT(!m.valid);
}

static void test_load_bad_version(void)
{
    fake_storage_t fs;
    fake_storage_reset(&fs);
    xury_storage_iface_t s = make_iface(&fs);

    xury_analysis_result_t a = analysis_fixture();
    TEST_ASSERT_EQ(xury_smart_cache_store(&s, 8u, &a), XURY_OK);

    /* Version byte is at offset 4. */
    fs.buf[4] = 0xFEu;

    xury_memory_result_t m;
    fill_mem_sentinel(&m);
    TEST_ASSERT_EQ(xury_smart_cache_load(&s, 8u, 0u, &m), XURY_OK);
    TEST_ASSERT(!m.loaded);
    TEST_ASSERT(!m.valid);
}

static void test_load_short_blob(void)
{
    fake_storage_t fs;
    fake_storage_reset(&fs);
    xury_storage_iface_t s = make_iface(&fs);

    /* Store a valid entry, then pretend the backend returned less. */
    xury_analysis_result_t a = analysis_fixture();
    TEST_ASSERT_EQ(xury_smart_cache_store(&s, 9u, &a), XURY_OK);
    fs.len = 4u;

    xury_memory_result_t m;
    fill_mem_sentinel(&m);
    TEST_ASSERT_EQ(xury_smart_cache_load(&s, 9u, 0u, &m), XURY_OK);
    TEST_ASSERT(!m.loaded);
    TEST_ASSERT(!m.valid);
}

/*
 * ============================================================================
 * INVALIDATION
 * ============================================================================
 */

static void test_invalidate_clears_entry(void)
{
    fake_storage_t fs;
    fake_storage_reset(&fs);
    xury_storage_iface_t s = make_iface(&fs);

    xury_analysis_result_t a = analysis_fixture();
    TEST_ASSERT_EQ(xury_smart_cache_store(&s, 55u, &a), XURY_OK);
    TEST_ASSERT(fs.len > 0u);

    TEST_ASSERT_EQ(xury_smart_cache_invalidate(&s, 55u), XURY_OK);
    TEST_ASSERT_EQ(fs.len, 0u);

    xury_memory_result_t m;
    fill_mem_sentinel(&m);
    TEST_ASSERT_EQ(xury_smart_cache_load(&s, 55u, 0u, &m), XURY_OK);
    TEST_ASSERT(!m.loaded);
    TEST_ASSERT(!m.valid);
}

static void test_invalidate_null_storage(void)
{
    TEST_ASSERT_EQ(xury_smart_cache_invalidate(NULL, 1u), XURY_OK);
}

static void test_invalidate_zero_key(void)
{
    fake_storage_t fs;
    fake_storage_reset(&fs);
    xury_storage_iface_t s = make_iface(&fs);

    TEST_ASSERT_EQ(xury_smart_cache_invalidate(&s, 0u), XURY_ERR_INVAL);
}

/*
 * ============================================================================
 * BROKEN STORAGE
 * ============================================================================
 */

static void test_load_broken_storage_is_not_fatal(void)
{
    fake_storage_t fs;
    fake_storage_reset(&fs);
    fs.fail_load = true;
    xury_storage_iface_t s = make_iface(&fs);

    xury_memory_result_t m;
    fill_mem_sentinel(&m);
    TEST_ASSERT_EQ(xury_smart_cache_load(&s, 1u, 0u, &m), XURY_OK);
    TEST_ASSERT(!m.loaded);
    TEST_ASSERT(!m.valid);
    TEST_ASSERT_EQ(m.status, XURY_SCAN_SUB_SKIPPED);
}

static void test_store_broken_storage_is_error(void)
{
    fake_storage_t fs;
    fake_storage_reset(&fs);
    fs.fail_save = true;
    xury_storage_iface_t s = make_iface(&fs);

    xury_analysis_result_t a = analysis_fixture();
    TEST_ASSERT_EQ(xury_smart_cache_store(&s, 1u, &a), XURY_ERR_IO);
}

/*
 * ============================================================================
 * FIELD CONSISTENCY
 * ============================================================================
 */

static void test_load_status_consistent_with_flags(void)
{
    fake_storage_t fs;
    fake_storage_reset(&fs);
    xury_storage_iface_t s = make_iface(&fs);

    xury_analysis_result_t a = analysis_fixture();

    /* Case 1: no entry. */
    {
        xury_memory_result_t m;
        fill_mem_sentinel(&m);
        TEST_ASSERT_EQ(xury_smart_cache_load(&s, 1u, 0u, &m), XURY_OK);
        TEST_ASSERT(!m.loaded);
        TEST_ASSERT(!m.valid);
        TEST_ASSERT_EQ(m.status, XURY_SCAN_SUB_SKIPPED);
    }

    /* Case 2: fresh entry. */
    {
        TEST_ASSERT_EQ(xury_smart_cache_store(&s, 2u, &a), XURY_OK);
        xury_memory_result_t m;
        fill_mem_sentinel(&m);
        TEST_ASSERT_EQ(xury_smart_cache_load(&s, 2u, 60u, &m), XURY_OK);
        TEST_ASSERT(m.loaded);
        TEST_ASSERT(m.valid);
        TEST_ASSERT_EQ(m.status, XURY_SCAN_SUB_OK);
    }

    /* Case 3: wrong key. */
    {
        xury_memory_result_t m;
        fill_mem_sentinel(&m);
        TEST_ASSERT_EQ(xury_smart_cache_load(&s, 3u, 60u, &m), XURY_OK);
        TEST_ASSERT(!m.loaded);
        TEST_ASSERT(!m.valid);
        TEST_ASSERT_EQ(m.status, XURY_SCAN_SUB_SKIPPED);
    }
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    /* Inert cache */
    TEST_RUN(test_load_null_out);
    TEST_RUN(test_store_null_analysis);
    TEST_RUN(test_load_with_null_storage);
    TEST_RUN(test_load_with_zero_key);
    TEST_RUN(test_store_with_null_storage);
    TEST_RUN(test_store_with_zero_key);

    /* Round trip */
    TEST_RUN(test_round_trip_fresh_entry);
    TEST_RUN(test_round_trip_with_ttl_zero);

    /* Key mismatch */
    TEST_RUN(test_load_with_wrong_key);

    /* Corruption */
    TEST_RUN(test_load_bad_magic);
    TEST_RUN(test_load_bad_version);
    TEST_RUN(test_load_short_blob);

    /* Invalidation */
    TEST_RUN(test_invalidate_clears_entry);
    TEST_RUN(test_invalidate_null_storage);
    TEST_RUN(test_invalidate_zero_key);

    /* Broken storage */
    TEST_RUN(test_load_broken_storage_is_not_fatal);
    TEST_RUN(test_store_broken_storage_is_error);

    /* Field consistency */
    TEST_RUN(test_load_status_consistent_with_flags);
}

TEST_MAIN()
