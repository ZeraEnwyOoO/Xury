 
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
 * XURY PLATFORM — LINUX NETLINK
 * ============================================================================
 *
 * Linux-specific rtnetlink queries.
 *
 * Scope:
 *   xury_platform_gateway()   — find the default gateway
 *
 * Non-scope (handled elsewhere):
 *   xury_platform_ifaces_list() lives in src/platform/posix/sock.c and
 *   uses getifaddrs(3), which is POSIX and portable. There is no
 *   reason to reimplement it with netlink.
 *
 * Future:
 *   Route change notification (RTMGRP_IPV4_ROUTE / RTMGRP_IPV6_ROUTE)
 *   will be added here when the engine needs it. Until then this file
 *   stays small and single-purpose.
 *
 * Why rtnetlink for the gateway:
 *   /proc/net/route is IPv4-only and racy. RTM_GETROUTE asks the
 *   kernel for the route it would actually use, atomically, for any
 *   destination. That is the correct primitive.
 *
 * Android note:
 *   This file is not compiled on Android. Android's ConnectivityManager
 *   is queried through JNI instead (src/platform/android/jni.c).
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <xury/types.h>
#include <xury/err.h>
#include <xury/xury.h>  

#include "platform/platform.h"

/*
 * ============================================================================
 * INTERNAL — netlink request/response
 * ============================================================================
 */

#define NL_BUFSIZE 8192

static int nl_open(void)
{
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

typedef int (*nl_cb_t)(struct nlmsghdr *nlh, void *userdata);

static int nl_request(int fd, struct nlmsghdr *req, nl_cb_t cb, void *ud)
{
    struct sockaddr_nl kernel;
    memset(&kernel, 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;

    struct iovec iov;
    iov.iov_base = req;
    iov.iov_len  = req->nlmsg_len;

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name    = &kernel;
    msg.msg_namelen = sizeof(kernel);
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;

    if (sendmsg(fd, &msg, 0) < 0) {
        return -errno;
    }

    uint8_t buf[NL_BUFSIZE];

    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -errno;
        }
        if (n == 0) {
            return -ECONNRESET;
        }

        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        for (; NLMSG_OK(nlh, (unsigned)n);
             nlh = NLMSG_NEXT(nlh, n)) {

            if (nlh->nlmsg_type == NLMSG_DONE) {
                return 0;
            }
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = NLMSG_DATA(nlh);
                return (err->error != 0) ? err->error : 0;
            }

            if (cb != NULL) {
                int rv = cb(nlh, ud);
                if (rv != 0) {
                    return rv;
                }
            }
        }
    }
}

/*
 * ============================================================================
 * GATEWAY
 * ============================================================================
 *
 * RTM_GETROUTE with a destination asks the kernel for the route it
 * would use to reach that destination. We ask about 1.1.1.1 (a public
 * anycast used only as a target; no packets are sent).
 *
 * The kernel fills RTA_GATEWAY. We copy it out.
 */

typedef struct {
    xury_endpoint_t *out;
    bool             found;
} gateway_ctx_t;

static int gateway_cb(struct nlmsghdr *nlh, void *ud)
{
    gateway_ctx_t *ctx = (gateway_ctx_t *)ud;
    if (nlh->nlmsg_type != RTM_NEWROUTE) {
        return 0;
    }

    struct rtmsg *rtm = NLMSG_DATA(nlh);
    int len = (int)(nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*rtm)));
    if (len < 0) {
        return 0;
    }

    struct rtattr *rta = RTM_RTA(rtm);
    for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        if (rta->rta_type != RTA_GATEWAY) {
            continue;
        }
        void *addr = RTA_DATA(rta);

        if (rtm->rtm_family == AF_INET) {
            struct in_addr *in = (struct in_addr *)addr;
            ctx->out->family = XURY_AF_INET;
            ctx->out->port = 0;
            if (inet_ntop(AF_INET, in, ctx->out->ip,
                          sizeof(ctx->out->ip)) != NULL) {
                ctx->found = true;
            }
        } else if (rtm->rtm_family == AF_INET6) {
            struct in6_addr *in6 = (struct in6_addr *)addr;
            ctx->out->family = XURY_AF_INET6;
            ctx->out->port = 0;
            if (inet_ntop(AF_INET6, in6, ctx->out->ip,
                          sizeof(ctx->out->ip)) != NULL) {
                ctx->found = true;
            }
        }
        return 0;
    }
    return 0;
}

xury_err_t xury_platform_gateway(xury_endpoint_t *out)
{
    if (out == NULL) {
        return XURY_ERR_INVAL;
    }
    xury_endpoint_clear(out);

    int fd = nl_open();
    if (fd < 0) {
        return XURY_ERR_IO;
    }

    struct {
        struct nlmsghdr nlh;
        struct rtmsg    rtm;
        char            attrs[64];
    } req;
    memset(&req, 0, sizeof(req));

    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type  = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.nlh.nlmsg_seq   = 1;
    req.rtm.rtm_family  = AF_INET;
    req.rtm.rtm_dst_len = 32;

    struct rtattr *rta = (struct rtattr *)
        ((char *)&req + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = RTA_DST;
    rta->rta_len  = (unsigned short)(RTA_LENGTH(4));
    uint8_t dst[4] = {1, 1, 1, 1};
    memcpy(RTA_DATA(rta), dst, 4);
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) +
                        RTA_ALIGN(rta->rta_len);

    gateway_ctx_t ctx;
    ctx.out   = out;
    ctx.found = false;

    int rv = nl_request(fd, &req.nlh, gateway_cb, &ctx);
    close(fd);

    if (rv != 0) {
        return XURY_ERR_IO;
    }
    if (!ctx.found) {
        return XURY_ERR_NOT_CONNECTED;
    }
    return XURY_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
