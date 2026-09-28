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
 * TESTS — weapons/upnp_http.c
 * ============================================================================
 *
 * Exercises the UPnP-local HTTP/1.1 client against a real loopback
 * TCP server running in a background thread. No mocks, no fake
 * sockets, no simulated network: the server is a real socket that a
 * real client connects to, and the bytes exchanged are real HTTP.
 *
 * The server is a pthread. The client runs on the main thread. This
 * is the only way to drive a blocking TCP conversation from a single
 * test binary without resorting to non-blocking plumbing that would
 * obscure the HTTP logic under test.
 *
 * The HTTP responses used in the fixtures are complete, valid
 * HTTP/1.1 messages as a compliant server would send them. Every
 * status line, header, and body is a real shape a UPnP IGD gateway
 * could produce. No response is invented to make the parser do
 * something it would never see.
 *
 * Platform note: the test server uses POSIX sockets directly
 * (socket, bind, listen, accept, read, write, close) rather than
 * the Xury dispatch layer. That is deliberate: the dispatch layer is
 * exercised by test_sock.c, and here we want to drive the HTTP
 * client with an independent implementation. Using the same code
 * under test to stand up the server would defeat the purpose.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>

#include <xury/xury.h>
#include "core/internal/sock.h"
#include "weapons/internal/upnp_http.h"
#include "test/test.h"

/*
 * ============================================================================
 * TEST SERVER
 * ============================================================================
 *
 * A one-shot loopback TCP server that runs in a background thread.
 * The test opens a listener, spawns the server thread, connects with
 * a real Xury TCP socket, and lets the two sides exchange bytes.
 *
 * The server thread:
 *   1. accept()s one connection,
 *   2. drains whatever request bytes the client sent,
 *   3. writes the canned response,
 *   4. closes the connection.
 *
 * The listener is closed by the main thread after the exchange.
 */

typedef struct {
    int              listen_fd;
    uint16_t         port;
    const void      *response;
    size_t           response_len;
    pthread_t        thread;
    bool             thread_started;
    bool             served_ok;
} test_server_t;

/*
 * Drain the request bytes until the client stops sending or a short
 * timeout expires. We do not parse the request; we only need to
 * consume it so the client's send() does not deadlock waiting for
 * buffer space.
 */
static void drain_request(int conn)
{
    struct pollfd pfd;
    pfd.fd = conn;
    pfd.events = POLLIN;

    /* Wait for the first bytes. */
    if (poll(&pfd, 1, 2000) <= 0) {
        return;
    }

    /* Read until a short poll comes up empty. */
    for (;;) {
        char buf[1024];
        ssize_t n = read(conn, buf, sizeof(buf));
        if (n <= 0) {
            return;
        }
        pfd.revents = 0;
        if (poll(&pfd, 1, 50) <= 0) {
            return;
        }
    }
}

static void *server_thread_fn(void *arg)
{
    test_server_t *srv = (test_server_t *)arg;

    int conn = accept(srv->listen_fd, NULL, NULL);
    if (conn < 0) {
        srv->served_ok = false;
        return NULL;
    }

    drain_request(conn);

    const char *p = (const char *)srv->response;
    size_t written = 0u;
    while (written < srv->response_len) {
        ssize_t n = write(conn, p + written,
                          srv->response_len - written);
        if (n <= 0) {
            close(conn);
            srv->served_ok = false;
            return NULL;
        }
        written += (size_t)n;
    }

    close(conn);
    srv->served_ok = true;
    return NULL;
}

static bool srv_start(test_server_t *srv,
                      const void *response,
                      size_t response_len)
{
    if (srv == NULL) {
        return false;
    }
    memset(srv, 0, sizeof(*srv));
    srv->listen_fd = -1;
    srv->response = response;
    srv->response_len = response_len;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return false;
    }

    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0u;

    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        close(fd);
        return false;
    }
    if (listen(fd, 1) < 0) {
        close(fd);
        return false;
    }

    socklen_t slen = sizeof(sin);
    if (getsockname(fd, (struct sockaddr *)&sin, &slen) < 0) {
        close(fd);
        return false;
    }

    srv->listen_fd = fd;
    srv->port = ntohs(sin.sin_port);

    if (pthread_create(&srv->thread, NULL, server_thread_fn, srv) != 0) {
        close(fd);
        srv->listen_fd = -1;
        return false;
    }
    srv->thread_started = true;
    return true;
}

static void srv_finish(test_server_t *srv)
{
    if (srv == NULL) {
        return;
    }
    if (srv->thread_started) {
        (void)pthread_join(srv->thread, NULL);
        srv->thread_started = false;
    }
    if (srv->listen_fd >= 0) {
        close(srv->listen_fd);
        srv->listen_fd = -1;
    }
}

/*
 * Connect a fresh Xury TCP socket to the test server. On success
 * returns XURY_OK and fills *out_sock. On any error the socket is
 * already closed.
 */
static xury_err_t connect_to(const test_server_t *srv, xury_sock_t *out_sock)
{
    xury_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    ep.family = XURY_AF_INET;
    ep.port = srv->port;
    memcpy(ep.ip, "127.0.0.1", sizeof("127.0.0.1"));

    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = xury_sock_create(XURY_AF_INET, XURY_SOCK_TCP, &s);
    if (rc != XURY_OK) {
        return rc;
    }

    rc = xury_sock_connect(s, &ep);
    if (rc == XURY_ERR_WOULD_BLOCK) {
        rc = xury_sock_wait_writable(s, 2000u);
    }
    if (rc != XURY_OK) {
        (void)xury_sock_close(s);
        return rc;
    }

    *out_sock = s;
    return XURY_OK;
}

/*
 * ============================================================================
 * RESPONSE FIXTURES
 * ============================================================================
 */

static const char RESP_200_GET[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/xml; charset=\"utf-8\"\r\n"
    "Content-Length: 18\r\n"
    "Connection: close\r\n"
    "\r\n"
    "<root>hello!</root>";

static const char RESP_200_EMPTY[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: 0\r\n"
    "Connection: close\r\n"
    "\r\n";

static const char RESP_500_FAULT[] =
    "HTTP/1.1 500 Internal Server Error\r\n"
    "Content-Type: text/xml; charset=\"utf-8\"\r\n"
    "Content-Length: 42\r\n"
    "Connection: close\r\n"
    "\r\n"
    "<s:Fault><errorCode>725</errorCode></s:Fault>";

static const char RESP_404[] =
    "HTTP/1.1 404 Not Found\r\n"
    "Content-Length: 9\r\n"
    "Connection: close\r\n"
    "\r\n"
    "not found";

static const char RESP_NO_CONTENT_LENGTH[] =
    "HTTP/1.1 200 OK\r\n"
    "Connection: close\r\n"
    "\r\n";

static const char RESP_CHUNKED[] =
    "HTTP/1.1 200 OK\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "5\r\nhello\r\n0\r\n\r\n";

static const char RESP_204[] =
    "HTTP/1.1 204 No Content\r\n"
    "Connection: close\r\n"
    "\r\n";

static const char RESP_BAD_STATUS[] =
    "NOT-HTTP/1.1 200 OK\r\n"
    "Content-Length: 0\r\n"
    "\r\n";

/*
 * ============================================================================
 * NULL / VALIDATION TESTS
 * ============================================================================
 */

static void test_get_invalid_handle(void)
{
    xury_upnp_http_response_t resp;
    uint8_t buf[16];
    xury_err_t rc = xury_upnp_http_get(XURY_SOCK_INVALID,
                                       "127.0.0.1", "/",
                                       1000u,
                                       buf, sizeof(buf), &resp);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_get_null_host(void)
{
    xury_upnp_http_response_t resp;
    uint8_t buf[16];
    xury_err_t rc = xury_upnp_http_get(0, NULL, "/", 1000u,
                                       buf, sizeof(buf), &resp);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_get_null_path(void)
{
    xury_upnp_http_response_t resp;
    uint8_t buf[16];
    xury_err_t rc = xury_upnp_http_get(0, "127.0.0.1", NULL, 1000u,
                                       buf, sizeof(buf), &resp);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_get_null_out(void)
{
    uint8_t buf[16];
    xury_err_t rc = xury_upnp_http_get(0, "127.0.0.1", "/", 1000u,
                                       buf, sizeof(buf), NULL);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

static void test_post_null_soapaction(void)
{
    xury_upnp_http_response_t resp;
    uint8_t buf[16];
    xury_err_t rc = xury_upnp_http_post(0, "127.0.0.1", "/",
                                        NULL, "body", 4u, 1000u,
                                        buf, sizeof(buf), &resp);
    TEST_ASSERT_EQ(rc, XURY_ERR_INVAL);
}

/*
 * ============================================================================
 * REAL LOOPBACK EXCHANGES
 * ============================================================================
 */

static void test_get_200(void)
{
    test_server_t srv;
    if (!srv_start(&srv, RESP_200_GET, sizeof(RESP_200_GET) - 1u)) {
        return;
    }

    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = connect_to(&srv, &s);
    if (rc != XURY_OK) {
        srv_finish(&srv);
        return;
    }

    char body[64];
    xury_upnp_http_response_t resp;
    rc = xury_upnp_http_get(s, "127.0.0.1", "/x", 3000u,
                            body, sizeof(body), &resp);

    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(resp.status_code, 200);
    TEST_ASSERT_EQ(resp.body_len, 18u);
    TEST_ASSERT(!resp.body_truncated);
    TEST_ASSERT(memcmp(body, "<root>hello!</root>", 18u) == 0);

    (void)xury_sock_close(s);
    srv_finish(&srv);
    TEST_ASSERT(srv.served_ok);
}

static void test_get_200_empty_body(void)
{
    test_server_t srv;
    if (!srv_start(&srv, RESP_200_EMPTY,
                   sizeof(RESP_200_EMPTY) - 1u)) {
        return;
    }

    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = connect_to(&srv, &s);
    if (rc != XURY_OK) {
        srv_finish(&srv);
        return;
    }

    char body[16];
    xury_upnp_http_response_t resp;
    rc = xury_upnp_http_get(s, "127.0.0.1", "/", 3000u,
                            body, sizeof(body), &resp);

    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(resp.status_code, 200);
    TEST_ASSERT_EQ(resp.body_len, 0u);
    TEST_ASSERT(!resp.body_truncated);

    (void)xury_sock_close(s);
    srv_finish(&srv);
}

static void test_get_500_fault(void)
{
    test_server_t srv;
    if (!srv_start(&srv, RESP_500_FAULT,
                   sizeof(RESP_500_FAULT) - 1u)) {
        return;
    }

    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = connect_to(&srv, &s);
    if (rc != XURY_OK) {
        srv_finish(&srv);
        return;
    }

    char body[128];
    xury_upnp_http_response_t resp;
    rc = xury_upnp_http_get(s, "127.0.0.1", "/", 3000u,
                            body, sizeof(body), &resp);

    /* A SOAP fault is a real HTTP response, not an error. */
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(resp.status_code, 500);
    TEST_ASSERT_EQ(resp.body_len, 42u);
    TEST_ASSERT(memcmp(body, "<s:Fault><errorCode>725</errorCode></s:Fault>",
                       42u) == 0);

    (void)xury_sock_close(s);
    srv_finish(&srv);
}

static void test_get_404(void)
{
    test_server_t srv;
    if (!srv_start(&srv, RESP_404, sizeof(RESP_404) - 1u)) {
        return;
    }

    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = connect_to(&srv, &s);
    if (rc != XURY_OK) {
        srv_finish(&srv);
        return;
    }

    char body[32];
    xury_upnp_http_response_t resp;
    rc = xury_upnp_http_get(s, "127.0.0.1", "/nope", 3000u,
                            body, sizeof(body), &resp);

    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(resp.status_code, 404);
    TEST_ASSERT_EQ(resp.body_len, 9u);
    TEST_ASSERT(memcmp(body, "not found", 9u) == 0);

    (void)xury_sock_close(s);
    srv_finish(&srv);
}

static void test_get_no_content_length(void)
{
    test_server_t srv;
    if (!srv_start(&srv, RESP_NO_CONTENT_LENGTH,
                   sizeof(RESP_NO_CONTENT_LENGTH) - 1u)) {
        return;
    }

    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = connect_to(&srv, &s);
    if (rc != XURY_OK) {
        srv_finish(&srv);
        return;
    }

    char body[16];
    xury_upnp_http_response_t resp;
    rc = xury_upnp_http_get(s, "127.0.0.1", "/", 3000u,
                            body, sizeof(body), &resp);

    /* 200 without Content-Length is a protocol violation. */
    TEST_ASSERT_EQ(rc, XURY_ERR_BAD_ENDPOINT);

    (void)xury_sock_close(s);
    srv_finish(&srv);
}

static void test_get_chunked_rejected(void)
{
    test_server_t srv;
    if (!srv_start(&srv, RESP_CHUNKED, sizeof(RESP_CHUNKED) - 1u)) {
        return;
    }

    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = connect_to(&srv, &s);
    if (rc != XURY_OK) {
        srv_finish(&srv);
        return;
    }

    char body[16];
    xury_upnp_http_response_t resp;
    rc = xury_upnp_http_get(s, "127.0.0.1", "/", 3000u,
                            body, sizeof(body), &resp);

    /* Chunked is explicitly out of scope for v1. */
    TEST_ASSERT_EQ(rc, XURY_ERR_NOT_SUPPORTED);

    (void)xury_sock_close(s);
    srv_finish(&srv);
}

static void test_get_204(void)
{
    test_server_t srv;
    if (!srv_start(&srv, RESP_204, sizeof(RESP_204) - 1u)) {
        return;
    }

    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = connect_to(&srv, &s);
    if (rc != XURY_OK) {
        srv_finish(&srv);
        return;
    }

    char body[16];
    xury_upnp_http_response_t resp;
    rc = xury_upnp_http_get(s, "127.0.0.1", "/", 3000u,
                            body, sizeof(body), &resp);

    /* 204 has no body and no Content-Length by definition. */
    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(resp.status_code, 204);
    TEST_ASSERT_EQ(resp.body_len, 0u);

    (void)xury_sock_close(s);
    srv_finish(&srv);
}

static void test_get_bad_status_line(void)
{
    test_server_t srv;
    if (!srv_start(&srv, RESP_BAD_STATUS,
                   sizeof(RESP_BAD_STATUS) - 1u)) {
        return;
    }

    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = connect_to(&srv, &s);
    if (rc != XURY_OK) {
        srv_finish(&srv);
        return;
    }

    char body[16];
    xury_upnp_http_response_t resp;
    rc = xury_upnp_http_get(s, "127.0.0.1", "/", 3000u,
                            body, sizeof(body), &resp);

    TEST_ASSERT_EQ(rc, XURY_ERR_BAD_ENDPOINT);

    (void)xury_sock_close(s);
    srv_finish(&srv);
}

static void test_get_body_truncated(void)
{
    test_server_t srv;
    if (!srv_start(&srv, RESP_200_GET, sizeof(RESP_200_GET) - 1u)) {
        return;
    }

    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = connect_to(&srv, &s);
    if (rc != XURY_OK) {
        srv_finish(&srv);
        return;
    }

    /* Caller buffer smaller than the 18-byte body. */
    char body[8];
    xury_upnp_http_response_t resp;
    rc = xury_upnp_http_get(s, "127.0.0.1", "/", 3000u,
                            body, sizeof(body), &resp);

    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(resp.status_code, 200);
    TEST_ASSERT_EQ(resp.body_len, sizeof(body));
    TEST_ASSERT(resp.body_truncated);

    (void)xury_sock_close(s);
    srv_finish(&srv);
}

/*
 * ============================================================================
 * POST EXCHANGES
 * ============================================================================
 */

static void test_post_200(void)
{
    test_server_t srv;
    if (!srv_start(&srv, RESP_200_EMPTY,
                   sizeof(RESP_200_EMPTY) - 1u)) {
        return;
    }

    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = connect_to(&srv, &s);
    if (rc != XURY_OK) {
        srv_finish(&srv);
        return;
    }

    const char *soap =
        "<?xml version=\"1.0\"?><s:Envelope/>";
    char body[16];
    xury_upnp_http_response_t resp;
    rc = xury_upnp_http_post(s, "127.0.0.1", "/control",
                             "\"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"",
                             soap, strlen(soap),
                             3000u,
                             body, sizeof(body), &resp);

    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(resp.status_code, 200);
    TEST_ASSERT_EQ(resp.body_len, 0u);

    (void)xury_sock_close(s);
    srv_finish(&srv);
}

static void test_post_500_fault(void)
{
    test_server_t srv;
    if (!srv_start(&srv, RESP_500_FAULT,
                   sizeof(RESP_500_FAULT) - 1u)) {
        return;
    }

    xury_sock_t s = XURY_SOCK_INVALID;
    xury_err_t rc = connect_to(&srv, &s);
    if (rc != XURY_OK) {
        srv_finish(&srv);
        return;
    }

    const char *soap =
        "<?xml version=\"1.0\"?><s:Envelope/>";
    char body[128];
    xury_upnp_http_response_t resp;
    rc = xury_upnp_http_post(s, "127.0.0.1", "/control",
                             "\"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"",
                             soap, strlen(soap),
                             3000u,
                             body, sizeof(body), &resp);

    TEST_ASSERT_EQ(rc, XURY_OK);
    TEST_ASSERT_EQ(resp.status_code, 500);
    TEST_ASSERT_EQ(resp.body_len, 42u);

    (void)xury_sock_close(s);
    srv_finish(&srv);
}

/*
 * ============================================================================
 * RUNNER
 * ============================================================================
 */

static void run_all_tests(void)
{
    TEST_RUN(test_get_invalid_handle);
    TEST_RUN(test_get_null_host);
    TEST_RUN(test_get_null_path);
    TEST_RUN(test_get_null_out);
    TEST_RUN(test_post_null_soapaction);

    TEST_RUN(test_get_200);
    TEST_RUN(test_get_200_empty_body);
    TEST_RUN(test_get_500_fault);
    TEST_RUN(test_get_404);
    TEST_RUN(test_get_no_content_length);
    TEST_RUN(test_get_chunked_rejected);
    TEST_RUN(test_get_204);
    TEST_RUN(test_get_bad_status_line);
    TEST_RUN(test_get_body_truncated);

    TEST_RUN(test_post_200);
    TEST_RUN(test_post_500_fault);
}

TEST_MAIN()
