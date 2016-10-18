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

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <netdb.h>

#include <arpa/inet.h>

#include "ut/utlist.h"

#include "netdev.h"
#include "queue.h"
#include "pkt.h"
#include "printf.h"
#include "util.h"

#define ETH_PKTLEN 14
#define ARP_PKTLEN (8 + 2 * 6 + 2 * 4)

int resolv_name_to_addr(const char *name, uint32_t *addr) {
    int rc;
    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;

    rc = getaddrinfo(name, NULL, &hints, &res);
    if (rc != 0)
        fail_printf("Error resolving '%s': %s", name, gai_strerror(rc));

    *addr = ((struct sockaddr_in *) res->ai_addr)->sin_addr.s_addr;

    freeaddrinfo(res);

    return 0;
}

int resolv_addr_to_mac(struct netdev *netdev,
                       uint8_t *shost, uint32_t saddr,
                       uint8_t *dhost, uint32_t daddr) {
    uint8_t *buf;
    size_t  blen;

    struct pkt *pkt = NULL;

    uint16_t tries = 5;
    uint64_t start, timeout = 1000000;

    saddr = htonl(saddr);
    daddr = htonl(daddr);

    struct pkt *arp = pkt_new(TYPE_ARP);
    DL_APPEND(pkt, arp);

    pkt_build_arp(arp, ARPHRD_ETHER, ETHERTYPE_IP, ARPOP_REQUEST,
                  shost, (uint8_t *) &saddr,
                  (uint8_t *) "\x00\x00\x00\x00\x00\x00", (uint8_t*)&daddr);

    struct pkt *eth = pkt_new(TYPE_ETH);
    DL_APPEND(pkt, eth);

    pkt_build_eth(eth, shost, (uint8_t *) "\xff\xff\xff\xff\xff\xff", 0);

    buf = netdev_get_buf(netdev, &blen);

    int len = pkt_pack(buf, blen, pkt);
    pkt_free_all(arp);

    if (len < 0)
        fail_printf("Error packing ARP packet");

again:
    if (tries-- <= 0)
        return -1;

    netdev_inject(netdev, buf, len);

    start = time_now();

    while (1) {
        int rsp_len, n;
        struct pkt *rsp_pkt = NULL;

        const uint8_t *rsp = netdev_capture(netdev, &rsp_len);
        if ((time_now() - start) > timeout)
            goto again;

        if (rsp == NULL)
            continue;

        n = pkt_unpack((uint8_t *) rsp, rsp_len, &rsp_pkt);
        if (n < 2)
            goto done;

        if (rsp_pkt->next && rsp_pkt->next->type == TYPE_ARP) {
            struct pkt *arp_pkt = rsp_pkt->next;

            if (memcmp(&daddr, arp_pkt->p.arp.psrc, 4) != 0)
                goto done;

            if (memcmp(&saddr, arp_pkt->p.arp.pdst, 4) != 0)
                goto done;

            memcpy(dhost, arp_pkt->p.arp.hwsrc, 6);

            pkt_free_all(rsp_pkt);

            netdev_release(netdev);
            break;
        }

done:
        pkt_free_all(rsp_pkt);
        netdev_release(netdev);
    }

    return 0;
}
