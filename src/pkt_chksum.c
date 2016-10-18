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

static uint32_t sum(uint8_t *buf, size_t len) {
    uint32_t csum = 0;

    for (size_t i = 0; i < len - 1; i += 2)
        csum += *(uint16_t *) &buf[i];

    if (len & 1)
        csum += (uint16_t) buf[len - 1];

    return csum;
}

uint16_t pkt_chksum(uint8_t *buf, size_t len, uint32_t csum) {
    csum += sum(buf, len);

    while (csum >> 16)
        csum = (csum >> 16) + (csum & 0xFFFF);

    return ~csum;
}

uint32_t pkt_pseudo_chksum(struct ip4_hdr *h) {
    struct pseudo_hdr {
        uint32_t saddr;
        uint32_t daddr;
        uint8_t  zero;
        uint8_t  proto;
        uint16_t length;
    } hdr;

    uint16_t len = h->len - (h->ihl * 4);

    hdr.saddr  = h->src;
    hdr.daddr  = h->dst;
    hdr.zero   = 0;
    hdr.proto  = h->proto;
    hdr.length = htons(len);

    return sum((uint8_t *) &hdr, sizeof(hdr));
}
