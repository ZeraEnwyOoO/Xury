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
 * TESTS — weapons/upnp_xml.c
 * ============================================================================
 *
 * Exercises the minimal XML text extractor.
 *
 * The XML fixtures in this file are drawn from two sources:
 *
 *   - The UPnP Device Architecture specification's own examples of
 *     device descriptions and SOAP envelopes (structure, element
 *     names, and namespace declarations match the published form).
 *
 *   - The published SOAP 1.1 envelope structure for the
 *     AddPortMapping action, as documented in the UPnP IGD service
 *     templates.
 *
 * No fixture is invented to make a test pass. Where the extractor
 * is expected to fail (malformed input), the failure is the point
 * of the test.
 *
 * No mocks. The extractor is a pure function of its input.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <xury/xury.h>
#include "weapons/internal/upnp_xml.h"
#include "test/test.h"

/*
 * ============================================================================
 * FIXTURES
 * ============================================================================
 */

/*
 * A trimmed device description with the shape produced by UPnP IGD
 * gateways. It has the XML declaration, the root <root> element
 * with the standard namespace, and a <serviceList> with one
 * <service> whose <serviceType> and <controlURL> we need.
 */
static const char *DEVICE_DESC =
    "<?xml version=\"1.0\"?>\n"
    "<root xmlns=\"urn:schemas-upnp-org:device-1-0\">\n"
    "  <specVersion><major>1</major><minor>0</minor></specVersion>\n"
    "  <device>\n"
    "    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>\n"
    "    <friendlyName>Test Router</friendlyName>\n"
    "    <serviceList>\n"
    "      <service>\n"
    "        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\n"
    "        <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>\n"
    "        <controlURL>/upnp/control/WANIPConn1</controlURL>\n"
    "        <eventSubURL>/upnp/event/WANIPConn1</eventSubURL>\n"
    "        <SCPDURL>/WANIPConn1.xml</SCPDURL>\n"
    "      </service>\n"
    "    </serviceList>\n"
    "  </device>\n"
    "  <URLBase>http://192.168.1.1:80</URLBase>\n"
    "</root>\n";

/*
 * The same document, but with a namespace prefix on the elements we
 * care about. Real gateways sometimes emit this form.
 */
static const char *DEVICE_DESC_PREFIXED =
    "<?xml version=\"1.0\"?>\n"
    "<root xmlns=\"urn:schemas-upnp-org:device-1-0\">\n"
    "  <device>\n"
    "    <serviceList>\n"
    "      <service>\n"
    "        <u:serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</u:serviceType>\n"
    "        <u:controlURL>/upnp/control/WANIPConn1</u:controlURL>\n"
    "      </service>\n"
    "    </serviceList>\n"
    "  </device>\n"
    "</root>\n";

/*
 * A trimmed SOAP success response for AddPortMapping. The action
 * response is empty by definition; a successful AddPortMapping
 * returns no output arguments.
 */
static const char *SOAP_SUCCESS =
    "<?xml version=\"1.0\"?>\n"
    "<s:Envelope "
    "xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
    "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n"
    "  <s:Body>\n"
    "    <u:AddPortMappingResponse "
    "xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"/>\n"
    "  </s:Body>\n"
    "</s:Envelope>\n";

/*
 * A trimmed SOAP fault response for AddPortMapping. Contains the
 * canonical UPnPError element that distinguishes a fault from a
 * success.
 */
static const char *SOAP_FAULT =
    "<?xml version=\"1.0\"?>\n"
    "<s:Envelope "
    "xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
    "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n"
    "  <s:Body>\n"
    "    <s:Fault>\n"
    "      <faultcode>s:Client</faultcode>\n"
    "      <faultstring>UPnPError</faultstring>\n"
    "      <detail>\n"
    "        <UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">\n"
    "          <errorCode>725</errorCode>\n"
    "          <errorDescription>OnlyPermanentLeasesSupported</errorDescription>\n"
    "        </UPnPError>\n"
    "      </detail>\n"
    "    </s:Fault>\n"
    "  </s:Body>\n"
    "</s:Envelope>\n";

/*
 * A document containing an XML comment between two elements. The
 * comment must be skipped, and a following element found.
 */
static const char *WITH_COMMENT =
    "<root>\n"
    "  <!-- this is a comment, ignore me -->\n"
    "  <controlURL>/foo/bar</controlURL>\n"
    "</root>\n";

/*
 * An empty element with no body.
 */
static const char *EMPTY_ELEMENT =
    "<root><URLBase/></root>\n";

/*
 * A malformed document: an open tag with no matching end.
 */
static const char *MALFORMED =
    "<root><controlURL>/missing-end</root>\n";

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

static void expect_find(const char *xml,
                        const char *name,
                        const char *want)
{
    xury_upnp_xml_text_t t;
    xury_err_t rc = xury_upnp_xml_find(xml, strlen(xml), name, &t);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_NOT_NULL(t.start);
    TEST_ASSERT_EQ(t.len, strlen(want));
    TEST_ASSERT(memcmp(t.start, want, t.len) == 0);
}

/*
 * ============================================================================
 * BASIC FIND
 * ============================================================================
 */

static void test_find_simple(void)
{
    expect_find("<root><a>hello</a></root>", "a", "hello");
}

static void test_find_nested(void)
{
    expect_find("<root><s><a>deep</a></s></root>", "a", "deep");
}

static void test_find_first_only(void)
{
    /* Two <a> elements: the first wins. */
    expect_find("<r><a>one</a><a>two</a></r>", "a", "one");
}

static void test_find_control_url(void)
{
    expect_find(DEVICE_DESC, "controlURL", "/upnp/control/WANIPConn1");
}

static void test_find_service_type(void)
{
    expect_find(DEVICE_DESC, "serviceType",
                "urn:schemas-upnp-org:service:WANIPConnection:1");
}

static void test_find_url_base(void)
{
    expect_find(DEVICE_DESC, "URLBase", "http://192.168.1.1:80");
}

static void test_find_prefix_stripped(void)
{
    expect_find(DEVICE_DESC_PREFIXED, "controlURL",
                "/upnp/control/WANIPConn1");
}

static void test_find_prefix_service_type(void)
{
    expect_find(DEVICE_DESC_PREFIXED, "serviceType",
                "urn:schemas-upnp-org:service:WANIPConnection:1");
}

static void test_find_skips_comment(void)
{
    expect_find(WITH_COMMENT, "controlURL", "/foo/bar");
}

static void test_find_empty_element(void)
{
    xury_upnp_xml_text_t t;
    xury_err_t rc = xury_upnp_xml_find(EMPTY_ELEMENT,
                                       strlen(EMPTY_ELEMENT),
                                       "URLBase", &t);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_NOT_NULL(t.start);
    TEST_ASSERT_EQ(t.len, 0u);
}

/*
 * ============================================================================
 * NOT FOUND / MALFORMED
 * ============================================================================
 */

static void test_not_found(void)
{
    const char *xml = "<root><a>x</a></root>";
    xury_upnp_xml_text_t t;
    xury_err_t rc = xury_upnp_xml_find(xml, strlen(xml), "b", &t);
    TEST_ASSERT_EQ(rc, XURY_ERR_BAD_ENDPOINT);
}

static void test_malformed_missing_end(void)
{
    xury_upnp_xml_text_t t;
    xury_err_t rc = xury_upnp_xml_find(MALFORMED, strlen(MALFORMED),
                                       "controlURL", &t);
    TEST_ASSERT_EQ(rc, XURY_ERR_BAD_ENDPOINT);
}

static void test_null_xml(void)
{
    xury_upnp_xml_text_t t;
    xury_err_t rc = xury_upnp_xml_find(NULL, 0u, "a", &t);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_null_name(void)
{
    xury_upnp_xml_text_t t;
    xury_err_t rc = xury_upnp_xml_find("<a>x</a>", 8u, NULL, &t);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_null_out(void)
{
    xury_err_t rc = xury_upnp_xml_find("<a>x</a>", 8u, "a", NULL);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_empty_name(void)
{
    xury_upnp_xml_text_t t;
    xury_err_t rc = xury_upnp_xml_find("<a>x</a>", 8u, "", &t);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

/*
 * ============================================================================
 * FIND_STR
 * ============================================================================
 */

static void test_find_str_copies(void)
{
    char buf[32];
    size_t n = 0u;
    xury_err_t rc = xury_upnp_xml_find_str(DEVICE_DESC,
                                           strlen(DEVICE_DESC),
                                           "controlURL",
                                           buf, sizeof(buf), &n);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(n, strlen("/upnp/control/WANIPConn1"));
    TEST_ASSERT_STREQ(buf, "/upnp/control/WANIPConn1");
}

static void test_find_str_truncates(void)
{
    char buf[8];
    size_t n = 0u;
    xury_err_t rc = xury_upnp_xml_find_str(DEVICE_DESC,
                                           strlen(DEVICE_DESC),
                                           "controlURL",
                                           buf, sizeof(buf), &n);
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(n, sizeof(buf) - 1u);
    TEST_ASSERT(buf[sizeof(buf) - 1u] == '\0');
}

static void test_find_str_zero_cap(void)
{
    char buf[1];
    size_t n = 0u;
    xury_err_t rc = xury_upnp_xml_find_str(DEVICE_DESC,
                                           strlen(DEVICE_DESC),
                                           "controlURL",
                                           buf, 0u, &n);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_find_str_not_found(void)
{
    char buf[32];
    size_t n = 0u;
    xury_err_t rc = xury_upnp_xml_find_str(DEVICE_DESC,
                                           strlen(DEVICE_DESC),
                                           "noSuchElement",
                                           buf, sizeof(buf), &n);
    TEST_ASSERT_EQ(rc, XURY_ERR_BAD_ENDPOINT);
    TEST_ASSERT(buf[0] == '\0');
}

/*
 * ============================================================================
 * PRESENT
 * ============================================================================
 */

static void test_present_yes(void)
{
    TEST_ASSERT(xury_upnp_xml_present(DEVICE_DESC,
                                      strlen(DEVICE_DESC),
                                      "controlURL"));
}

static void test_present_no(void)
{
    TEST_ASSERT(!xury_upnp_xml_present(DEVICE_DESC,
                                       strlen(DEVICE_DESC),
                                       "noSuchElement"));
}

static void test_present_fault(void)
{
    TEST_ASSERT(xury_upnp_xml_present(SOAP_FAULT,
                                      strlen(SOAP_FAULT),
                                      "UPnPError"));
}

static void test_present_success_has_no_fault(void)
{
    TEST_ASSERT(!xury_upnp_xml_present(SOAP_SUCCESS,
                                       strlen(SOAP_SUCCESS),
                                       "UPnPError"));
}

static void test_present_fault_error_code(void)
{
    expect_find(SOAP_FAULT, "errorCode", "725");
}

static void test_present_fault_error_description(void)
{
    expect_find(SOAP_FAULT, "errorDescription",
                "OnlyPermanentLeasesSupported");
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    TEST_RUN(test_find_simple);
    TEST_RUN(test_find_nested);
    TEST_RUN(test_find_first_only);
    TEST_RUN(test_find_control_url);
    TEST_RUN(test_find_service_type);
    TEST_RUN(test_find_url_base);
    TEST_RUN(test_find_prefix_stripped);
    TEST_RUN(test_find_prefix_service_type);
    TEST_RUN(test_find_skips_comment);
    TEST_RUN(test_find_empty_element);

    TEST_RUN(test_not_found);
    TEST_RUN(test_malformed_missing_end);
    TEST_RUN(test_null_xml);
    TEST_RUN(test_null_name);
    TEST_RUN(test_null_out);
    TEST_RUN(test_empty_name);

    TEST_RUN(test_find_str_copies);
    TEST_RUN(test_find_str_truncates);
    TEST_RUN(test_find_str_zero_cap);
    TEST_RUN(test_find_str_not_found);

    TEST_RUN(test_present_yes);
    TEST_RUN(test_present_no);
    TEST_RUN(test_present_fault);
    TEST_RUN(test_present_success_has_no_fault);
    TEST_RUN(test_present_fault_error_code);
    TEST_RUN(test_present_fault_error_description);
}

TEST_MAIN()
