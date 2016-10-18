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

#include <arpa/inet.h>

#include "queue.h"
#include "pkt.h"

void pkt_pack_ip4(struct pkt *p, uint8_t *buf, size_t len) {
    struct ip4_hdr *out = (struct ip4_hdr *) buf;

    out->version  = p->p.ip4.version;
    out->ihl      = p->p.ip4.ihl;
    out->tos      = p->p.ip4.tos;
    out->len      = htons(p->p.ip4.len);
    out->id       = htons(p->p.ip4.id);
    out->frag_off = htons(p->p.ip4.frag_off);
    out->ttl      = p->p.ip4.ttl;
    out->proto    = p->p.ip4.proto;;
    out->chksum   = 0;
    out->src      = p->p.ip4.src;
    out->dst      = p->p.ip4.dst;

    out->chksum   = pkt_chksum(buf, sizeof(*out), 0);
}

int pkt_unpack_ip4(struct pkt *p, uint8_t *buf, size_t len) {
    if (len < 20)
        return -1;

    memcpy(&p->p.ip4, buf, sizeof(p->p.ip4));

    if (p->p.ip4.version != 4)
        return -1;

    p->p.ip4.version  = p->p.ip4.version;
    p->p.ip4.ihl      = p->p.ip4.ihl;
    p->p.ip4.tos      = p->p.ip4.tos;
    p->p.ip4.len      = ntohs(p->p.ip4.len);
    p->p.ip4.id       = ntohs(p->p.ip4.id);
    p->p.ip4.frag_off = ntohs(p->p.ip4.frag_off);
    p->p.ip4.ttl      = p->p.ip4.ttl;
    p->p.ip4.proto    = p->p.ip4.proto;
    p->p.ip4.chksum   = ntohs(p->p.ip4.chksum);
    p->p.ip4.src      = p->p.ip4.src;
    p->p.ip4.dst      = p->p.ip4.dst;

    /* TODO: unpack IP options */

    p->type   = TYPE_IP4;
    p->length = p->p.ip4.ihl * 4;

    switch (p->p.ip4.proto) {
    case PROTO_ICMP:
        return TYPE_ICMP;

    case PROTO_UDP:
        return TYPE_UDP;

    case PROTO_TCP:
        return TYPE_TCP;
    }

    return TYPE_NONE;
}
