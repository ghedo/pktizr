/*
 * Scriptable, asynchronous network packet generator/analyzer.
 *
 * Copyright (c) 2015, Alessandro Ghedini
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef __linux__

#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>

#include <linux/rtnetlink.h>

#include "routes.h"
#include "printf.h"
#include "util.h"

#define BUF_LEN 8192

static int rtnl_parse_route(struct nlmsghdr *nlh, struct route *r);

int routes_get_default(struct route *r) {
    int rc;

    char req[BUF_LEN];
    char rsp[BUF_LEN];

    struct nlmsghdr *req_hdr, *rsp_hdr;

    _close_ int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (fd < 0)
        sysf_printf("socket(AF_NETLINK)");

    memset(&req, 0, BUF_LEN);
    req_hdr = (struct nlmsghdr *) req;

    req_hdr->nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    req_hdr->nlmsg_type  = RTM_GETROUTE;
    req_hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req_hdr->nlmsg_seq   = 1;
    req_hdr->nlmsg_pid   = getpid();

    rc = send(fd, req_hdr, req_hdr->nlmsg_len, 0);
    if (rc < 0)
        sysf_printf("send()");

    while (1) {
        memset(&rsp, 0, BUF_LEN);

        rc = recv(fd, rsp, BUF_LEN, 0);
        if (rc < 0)
            sysf_printf("recv()");

        for (rsp_hdr = (struct nlmsghdr *) rsp; NLMSG_OK(rsp_hdr, rc);
             rsp_hdr = NLMSG_NEXT(rsp_hdr, rc))
        {
            if (rsp_hdr->nlmsg_seq != 1)
                continue;

            if (rsp_hdr->nlmsg_pid != getpid())
                continue;

            if (rsp_hdr->nlmsg_type == NLMSG_DONE)
                return -1;

            if (rsp_hdr->nlmsg_type != RTM_NEWROUTE)
                continue;

            if (!rtnl_parse_route(rsp_hdr, r))
                return 0;
        }
    }

    return -1;
}

static int rtnl_parse_route(struct nlmsghdr *nlh, struct route *r) {
    struct  rtmsg  *rtmsg;
    struct  rtattr *rtattr;
    int     rtattr_len = 0;

    rtmsg = (struct rtmsg *) NLMSG_DATA(nlh);

    if (rtmsg->rtm_table != RT_TABLE_MAIN)
        return -1;

    rtattr_len = RTM_PAYLOAD(nlh);

    for (rtattr = RTM_RTA(rtmsg); RTA_OK(rtattr, rtattr_len);
         rtattr = RTA_NEXT(rtattr, rtattr_len))
    {
        switch (rtattr->rta_type) {
        case RTA_GATEWAY:
            r->gate_addr = *(uint32_t *) RTA_DATA(rtattr);
            break;

        case RTA_PREFSRC:
            r->pref_addr = *(uint32_t *) RTA_DATA(rtattr);
            break;

        case RTA_OIF:
            r->if_index = *(uint32_t *) RTA_DATA(rtattr);
            if_indextoname(r->if_index, r->if_name);
            break;
        }
    }

    return 0;
}

#endif /* __linux__ */
