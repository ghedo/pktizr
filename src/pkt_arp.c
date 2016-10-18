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

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <arpa/inet.h>

#include "queue.h"
#include "pkt.h"

void pkt_build_arp(struct pkt *p, uint16_t hwtype, uint16_t ptype, uint16_t op,
                  uint8_t *hwsrc, uint8_t *psrc, uint8_t *hwdst, uint8_t *pdst) {
    if (p == NULL)
        return;

    p->p.arp.hwtype = hwtype;
    switch (p->p.arp.hwtype) {
    case ARPHRD_ETHER:
        p->p.arp.hwlen = 6;
        break;

    default:
        p->p.arp.hwlen = 0;
        break;
    }

    p->p.arp.ptype = ptype;
    switch (p->p.arp.ptype) {
    case ETHERTYPE_IP:
        p->p.arp.plen = 4;
        break;

    case ETHERTYPE_IPV6:
        p->p.arp.plen = 16;
        break;

    default:
        p->p.arp.plen = 0;
        break;
    }

    p->p.arp.op = op;

    p->p.arp.hwsrc = malloc(p->p.arp.hwlen);
    memcpy(p->p.arp.hwsrc, hwsrc, p->p.arp.hwlen);

    p->p.arp.psrc = malloc(p->p.arp.plen);
    memcpy(p->p.arp.psrc, psrc, p->p.arp.plen);

    p->p.arp.hwdst = malloc(p->p.arp.hwlen);
    memcpy(p->p.arp.hwdst, hwdst, p->p.arp.hwlen);

    p->p.arp.pdst = malloc(p->p.arp.plen);
    memcpy(p->p.arp.pdst, pdst, p->p.arp.plen);

    p->type   = TYPE_ARP;
    p->length = 8 + p->p.arp.hwlen * 2 + p->p.arp.plen * 2;
}

void pkt_pack_arp(struct pkt *p, uint8_t *buf,size_t len) {
    size_t i = 0;
    struct arp_hdr *out = (struct arp_hdr *) buf;

    out->hwlen  = p->p.arp.hwlen;
    out->plen   = p->p.arp.plen;
    out->hwtype = htons(p->p.arp.hwtype);
    out->ptype  = htons(p->p.arp.ptype);
    out->op     = htons(p->p.arp.op);

    i += 8;

    memcpy(buf + i, p->p.arp.hwsrc, p->p.arp.hwlen);
    i += p->p.arp.hwlen;

    memcpy(buf + i, p->p.arp.psrc,  p->p.arp.plen);
    i += p->p.arp.plen;

    memcpy(buf + i, p->p.arp.hwdst, p->p.arp.hwlen);
    i += p->p.arp.hwlen;

    memcpy(buf + i, p->p.arp.pdst,  p->p.arp.plen);
    i += p->p.arp.plen;
}

int pkt_unpack_arp(struct pkt *p, uint8_t *buf, size_t len) {
    size_t i = 0;

    if (len < 8)
        return -1;

    memcpy(&p->p.arp, buf + i, 8);
    i += 8;

    p->p.arp.hwtype = ntohs(p->p.arp.hwtype);
    p->p.arp.ptype  = ntohs(p->p.arp.ptype);
    p->p.arp.op     = ntohs(p->p.arp.op);

    if (len < (8 + p->p.arp.hwlen * 2 + p->p.arp.plen * 2))
        return -1;

    p->p.arp.hwsrc = malloc(p->p.arp.hwlen);
    p->p.arp.hwdst = malloc(p->p.arp.hwlen);

    p->p.arp.psrc = malloc(p->p.arp.plen);
    p->p.arp.pdst = malloc(p->p.arp.plen);

    memcpy(p->p.arp.hwsrc, buf + i, p->p.arp.hwlen);
    i += p->p.arp.hwlen;

    memcpy(p->p.arp.psrc, buf + i, p->p.arp.plen);
    i += p->p.arp.plen;

    memcpy(p->p.arp.hwdst, buf + i, p->p.arp.hwlen);
    i += p->p.arp.hwlen;

    memcpy(p->p.arp.pdst, buf + i, p->p.arp.plen);
    i += p->p.arp.plen;

    p->type   = TYPE_ARP;
    p->length = 8 + p->p.arp.hwlen * 2 + p->p.arp.plen * 2;

    return TYPE_NONE;
}
