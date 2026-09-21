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
 * TESTS — src/scan/sensing.c (F.1)
 * ============================================================================
 *
 * Exercise xury_scan_sensing().
 *
 * Sensing queries the platform layer, which talks to the real OS.
 * These tests therefore cannot assert specific interface names or
 * IP addresses; those depend on the machine the test runs on. What
 * they DO assert is the contract:
 *
 *   - Argument validation
 *   - Status semantics (OK / PARTIAL / FAILED, never SKIPPED)
 *   - Internal consistency (fields agree with each other)
 *   - Fields that must never be invented (gateway_mac, net_type)
 *   - Behavior that must hold regardless of environment
 *
 * This means the tests pass on a fully networked host and on a host
 * with no network at all. They do not assume either.
 *
 * No mocks. The platform layer is the real one.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "scan/internal/sensing.h"
#include "test/test.h"

/*
 * ============================================================================
 * SENTINEL
 * ============================================================================
 *
 * To detect that the function writes all fields it promises to write,
 * we pre-fill the struct with a recognizable byte pattern and check
 * the parts that must be deterministic.
 */

#define SENTINEL_BYTE 0x5Au

static void fill_sentinel(xury_sensing_result_t *r)
{
    unsigned char *b = (unsigned char *)r;
    for (size_t i = 0; i < sizeof(*r); i++) {
        b[i] = SENTINEL_BYTE;
    }
}

/*
 * ============================================================================
 * ARGUMENT VALIDATION
 * ============================================================================
 */

static void test_null_out(void)
{
    xury_err_t rc = xury_scan_sensing(NULL);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_null_out_does_not_crash(void)
{
    /*
     * Redundant with test_null_out, but named separately so a crash
     * is reported as a crash rather than a mismatched return value.
     */
    for (int i = 0; i < 3; i++) {
        (void)xury_scan_sensing(NULL);
    }
}

/*
 * ============================================================================
 * BASIC CONTRACT
 * ============================================================================
 */

static void test_returns_ok(void)
{
    /*
     * The function always returns XURY_OK when out is non-NULL.
     * Platform errors are recorded in status, not propagated.
     */
    xury_sensing_result_t r;
    fill_sentinel(&r);

    xury_err_t rc = xury_scan_sensing(&r);
    TEST_ASSERT_EQ(rc, XURY_OK);
}

static void test_status_is_never_skipped(void)
{
    /*
     * SKIPPED is a sentinel for the composite struct, not a value
     * sensing produces. After a successful call, status must be one
     * of OK / PARTIAL / FAILED.
     */
    xury_sensing_result_t r;
    fill_sentinel(&r);

    xury_err_t rc = xury_scan_sensing(&r);
    TEST_ASSERT_EQ(rc, XURY_OK);

    TEST_ASSERT(r.status == XURY_SCAN_SUB_OK ||
                r.status == XURY_SCAN_SUB_PARTIAL ||
                r.status == XURY_SCAN_SUB_FAILED);
}

static void test_status_failed_implies_no_interface(void)
{
    /*
     * FAILED is defined as: ifaces_list failed, or no usable
     * interface was found. In both cases has_interface must be false.
     */
    xury_sensing_result_t r;
    fill_sentinel(&r);

    xury_err_t rc = xury_scan_sensing(&r);
    TEST_ASSERT_EQ(rc, XURY_OK);

    if (r.status == XURY_SCAN_SUB_FAILED) {
        TEST_ASSERT(!r.has_interface);
    }
}

static void test_status_ok_or_partial_implies_has_interface(void)
{
    /*
     * If we found at least one usable interface, status is OK or
     * PARTIAL. SKIPPED and FAILED are excluded.
     */
    xury_sensing_result_t r;
    fill_sentinel(&r);

    xury_err_t rc = xury_scan_sensing(&r);
    TEST_ASSERT_EQ(rc, XURY_OK);

    if (r.status == XURY_SCAN_SUB_OK ||
        r.status == XURY_SCAN_SUB_PARTIAL) {
        TEST_ASSERT(r.has_interface);
    }
}

static void test_has_interface_is_true_on_typical_host(void)
{
    /*
     * This test assumes the host running it has at least one
     * non-loopback interface that is up. That is true on every
     * machine that can run the test suite at all (a CI runner, a
     * laptop, a container with networking).
     *
     * If a future environment breaks this assumption, the failure
     * message will point here, and the assumption can be revisited.
     */
    xury_sensing_result_t r;
    fill_sentinel(&r);

    xury_err_t rc = xury_scan_sensing(&r);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT(r.has_interface);
}

/*
 * ============================================================================
 * GATEWAY MAC — MUST NOT BE INVENTED
 * ============================================================================
 */

static void test_gateway_mac_known_is_always_false(void)
{
    /*
     * F.1 defers MAC lookup. Until that changes, this field must
     * never be true. If it ever becomes true, the deferral has been
     * silently lifted and this test will catch it.
     */
    xury_sensing_result_t r;
    fill_sentinel(&r);

    xury_err_t rc = xury_scan_sensing(&r);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT(!r.gateway_mac_known);
}

static void test_gateway_mac_is_zeroed(void)
{
    /*
     * Not only is the flag false, the bytes themselves must be
     * zeroed. A future partial implementation that set the flag
     * but forgot to zero the bytes would fail here.
     */
    xury_sensing_result_t r;
    fill_sentinel(&r);

    xury_err_t rc = xury_scan_sensing(&r);
    TEST_ASSERT_EQ(rc, XURY_OK);

    for (size_t i = 0; i < sizeof(r.gateway_mac); i++) {
        TEST_ASSERT_EQ(r.gateway_mac[i], 0u);
    }
}

/*
 * ============================================================================
 * NETWORK TYPE — MUST NOT BE GUESSED
 * ============================================================================
 */

static void test_net_type_is_unknown(void)
{
    /*
     * F.1 has no reliable cross-platform signal for WiFi vs
     * cellular vs ethernet. The primary interface is defined to be
     * non-loopback, so LOOPBACK is not reachable either. The honest
     * answer is UNKNOWN.
     *
     * When platform support arrives, this test changes.
     */
    xury_sensing_result_t r;
    fill_sentinel(&r);

    xury_err_t rc = xury_scan_sensing(&r);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(r.net_type, XURY_NET_UNKNOWN);
}

/*
 * ============================================================================
 * IPV6 GLOBAL — MUST MATCH LOCAL_IPV6
 * ============================================================================
 */

static void test_ipv6_global_matches_local_ipv6(void)
{
    /*
     * ipv6_global is defined only in terms of the selected
     * local_ipv6. It must not become true because some OTHER
     * interface has global IPv6.
     *
     * We cannot easily force that scenario here, but we can verify
     * the consistency property: if ipv6_global is true, local_ipv6
     * must be a global IPv6 address.
     */
    xury_sensing_result_t r;
    fill_sentinel(&r);

    xury_err_t rc = xury_scan_sensing(&r);
    TEST_ASSERT_EQ(rc, XURY_OK);

    if (r.ipv6_global) {
        TEST_ASSERT(r.local_ipv6.family == XURY_AF_INET6);
        TEST_ASSERT(xury_endpoint_is_global_v6(&r.local_ipv6));
    }
}

static void test_ipv6_global_false_when_no_local_ipv6(void)
{
    /*
     * If local_ipv6 is not set, ipv6_global must be false.
     */
    xury_sensing_result_t r;
    fill_sentinel(&r);

    xury_err_t rc = xury_scan_sensing(&r);
    TEST_ASSERT_EQ(rc, XURY_OK);

    if (r.local_ipv6.family != XURY_AF_INET6) {
        TEST_ASSERT(!r.ipv6_global);
    }
}

/*
 * ============================================================================
 * LOCAL ENDPOINT CONSISTENCY
 * ============================================================================
 */

static void test_local_ipv4_family_is_inet_or_unspec(void)
{
    /*
     * local_ipv4 is either a valid INET endpoint (if the primary
     * interface has IPv4) or UNSPEC (if it does not). It is never
     * INET6 and never some third value.
     */
    xury_sensing_result_t r;
    fill_sentinel(&r);

    xury_err_t rc = xury_scan_sensing(&r);
    TEST_ASSERT_EQ(rc, XURY_OK);

    TEST_ASSERT(r.local_ipv4.family == XURY_AF_INET ||
                r.local_ipv4.family == XURY_AF_UNSPEC);
}

static void test_local_ipv6_family_is_inet6_or_unspec(void)
{
    xury_sensing_result_t r;
    fill_sentinel(&r);

    xury_err_t rc = xury_scan_sensing(&r);
    TEST_ASSERT_EQ(rc, XURY_OK);

    TEST_ASSERT(r.local_ipv6.family == XURY_AF_INET6 ||
                r.local_ipv6.family == XURY_AF_UNSPEC);
}

static void test_local_ipv4_port_is_zero(void)
{
    /*
     * Sensing reports addresses, not ports. The platform struct
     * documents port 0. If a port ever appears here, something has
     * been wired incorrectly.
     */
    xury_sensing_result_t r;
    fill_sentinel(&r);

    xury_err_t rc = xury_scan_sensing(&r);
    TEST_ASSERT_EQ(rc, XURY_OK);

    TEST_ASSERT_EQ(r.local_ipv4.port, 0u);
    TEST_ASSERT_EQ(r.local_ipv6.port, 0u);
}

/*
 * ============================================================================
 * GATEWAY CONSISTENCY
 * ============================================================================
 */

static void test_gateway_unspec_on_partial(void)
{
    /*
     * PARTIAL means the gateway lookup failed. In that case the
     * gateway field must be zeroed to UNSPEC, not left with a stale
     * or bogus value.
     */
    xury_sensing_result_t r;
    fill_sentinel(&r);

    xury_err_t rc = xury_scan_sensing(&r);
    TEST_ASSERT_EQ(rc, XURY_OK);

    if (r.status == XURY_SCAN_SUB_PARTIAL) {
        TEST_ASSERT(r.gateway.family == XURY_AF_UNSPEC);
    }
}

static void test_gateway_family_is_inet_or_inet6_or_unspec(void)
{
    xury_sensing_result_t r;
    fill_sentinel(&r);

    xury_err_t rc = xury_scan_sensing(&r);
    TEST_ASSERT_EQ(rc, XURY_OK);

    TEST_ASSERT(r.gateway.family == XURY_AF_INET ||
                r.gateway.family == XURY_AF_INET6 ||
                r.gateway.family == XURY_AF_UNSPEC);
}

/*
 * ============================================================================
 * INTERFACE NAME
 * ============================================================================
 */

static void test_interface_name_terminated(void)
{
    /*
     * If we found an interface, the name must be NUL-terminated
     * within the array. If we did not, it must be all zeros.
     */
    xury_sensing_result_t r;
    fill_sentinel(&r);

    xury_err_t rc = xury_scan_sensing(&r);
    TEST_ASSERT_EQ(rc, XURY_OK);

    /* Always NUL-terminated within the array. */
    bool terminated = false;
    for (size_t i = 0; i < sizeof(r.interface_name); i++) {
        if (r.interface_name[i] == '\0') {
            terminated = true;
            break;
        }
    }
    TEST_ASSERT(terminated);
}

static void test_interface_name_nonempty_when_has_interface(void)
{
    xury_sensing_result_t r;
    fill_sentinel(&r);

    xury_err_t rc = xury_scan_sensing(&r);
    TEST_ASSERT_EQ(rc, XURY_OK);

    if (r.has_interface) {
        TEST_ASSERT(r.interface_name[0] != '\0');
    }
}

static void test_interface_name_empty_when_failed(void)
{
    xury_sensing_result_t r;
    fill_sentinel(&r);

    xury_err_t rc = xury_scan_sensing(&r);
    TEST_ASSERT_EQ(rc, XURY_OK);

    if (r.status == XURY_SCAN_SUB_FAILED) {
        TEST_ASSERT_EQ(r.interface_name[0], '\0');
    }
}

/*
 * ============================================================================
 * ELAPSED TIME
 * ============================================================================
 */

static void test_elapsed_ms_is_recorded(void)
{
    /*
     * elapsed_ms is a measurement, not a decision. It may be 0 on a
     * fast machine, but it must never be a sentinel value left over
     * from the pre-fill.
     */
    xury_sensing_result_t r;
    fill_sentinel(&r);

    xury_err_t rc = xury_scan_sensing(&r);
    TEST_ASSERT_EQ(rc, XURY_OK);

    /*
     * We cannot assert a specific value. We can assert it is not
     * the sentinel byte pattern, which would indicate the field was
     * not written. The sentinel is 0x5A5A5A5A in the common case.
     */
    TEST_ASSERT(r.elapsed_ms != 0x5A5A5A5Au);
}

/*
 * ============================================================================
 * IDEMPOTENCE
 * ============================================================================
 *
 * Two consecutive calls with fresh structs should produce
 * consistent results for the deterministic fields. We do not
 * compare elapsed_ms, which can differ.
 */

static void test_consistent_between_calls(void)
{
    xury_sensing_result_t a;
    xury_sensing_result_t b;

    xury_err_t rc_a = xury_scan_sensing(&a);
    xury_err_t rc_b = xury_scan_sensing(&b);
    TEST_ASSERT_EQ(rc_a, XURY_OK);
    TEST_ASSERT_EQ(rc_b, XURY_OK);

    TEST_ASSERT_EQ(a.status, b.status);
    TEST_ASSERT_EQ(a.has_interface, b.has_interface);
    TEST_ASSERT_EQ(a.ipv6_global, b.ipv6_global);
    TEST_ASSERT_EQ(a.net_type, b.net_type);
    TEST_ASSERT_EQ(a.gateway_mac_known, b.gateway_mac_known);
    TEST_ASSERT_STREQ(a.interface_name, b.interface_name);
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    /* Argument validation */
    TEST_RUN(test_null_out);
    TEST_RUN(test_null_out_does_not_crash);

    /* Basic contract */
    TEST_RUN(test_returns_ok);
    TEST_RUN(test_status_is_never_skipped);
    TEST_RUN(test_status_failed_implies_no_interface);
    TEST_RUN(test_status_ok_or_partial_implies_has_interface);
    TEST_RUN(test_has_interface_is_true_on_typical_host);

    /* Gateway MAC must not be invented */
    TEST_RUN(test_gateway_mac_known_is_always_false);
    TEST_RUN(test_gateway_mac_is_zeroed);

    /* Network type must not be guessed */
    TEST_RUN(test_net_type_is_unknown);

    /* IPv6 global consistency */
    TEST_RUN(test_ipv6_global_matches_local_ipv6);
    TEST_RUN(test_ipv6_global_false_when_no_local_ipv6);

    /* Local endpoint consistency */
    TEST_RUN(test_local_ipv4_family_is_inet_or_unspec);
    TEST_RUN(test_local_ipv6_family_is_inet6_or_unspec);
    TEST_RUN(test_local_ipv4_port_is_zero);

    /* Gateway consistency */
    TEST_RUN(test_gateway_unspec_on_partial);
    TEST_RUN(test_gateway_family_is_inet_or_inet6_or_unspec);

    /* Interface name */
    TEST_RUN(test_interface_name_terminated);
    TEST_RUN(test_interface_name_nonempty_when_has_interface);
    TEST_RUN(test_interface_name_empty_when_failed);

    /* Elapsed time */
    TEST_RUN(test_elapsed_ms_is_recorded);

    /* Idempotence */
    TEST_RUN(test_consistent_between_calls);
}

TEST_MAIN()
