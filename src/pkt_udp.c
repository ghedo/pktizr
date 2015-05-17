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

void pkt_pack_udp(struct pkt *p, uint8_t *buf, size_t len) {
	uint32_t csum = 0;
	struct udp_hdr *out = (struct udp_hdr *) buf;

	out->sport  = htons(p->p.udp.sport);
	out->dport  = htons(p->p.udp.dport);
	out->len    = htons(p->p.udp.len);
	out->chksum = 0;

	if (p->next && (p->next->type == TYPE_IP4))
		csum = pkt_pseudo_chksum(&p->next->p.ip4);

	out->chksum = pkt_chksum(buf, len, csum);
}

int pkt_unpack_udp(struct pkt *p, uint8_t *buf, size_t len) {
	if (len < 8)
		return -1;

	memcpy(&p->p.udp, buf, sizeof(p->p.udp));

	p->p.udp.sport  = htons(p->p.udp.sport);
	p->p.udp.dport  = htons(p->p.udp.dport);
	p->p.udp.len    = htons(p->p.udp.len);
	p->p.udp.chksum = htons(p->p.udp.chksum);

	p->type   = TYPE_UDP;
	p->length = 8;

	return TYPE_RAW;
}
