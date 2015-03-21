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

void pkt_pack_tcp(struct pkt *p, uint8_t *buf, size_t len) {
	uint32_t csum = 0;
	struct tcp_hdr *out = (struct tcp_hdr *) buf;

	memset(out, 0, sizeof(*out));

	out->sport   = htons(p->p.tcp.sport);
	out->dport   = htons(p->p.tcp.dport);
	out->seq     = htonl(p->p.tcp.seq);
	out->ack_seq = htonl(p->p.tcp.ack_seq);
	out->doff    = p->p.tcp.doff;
	out->fin     = p->p.tcp.fin;
	out->syn     = p->p.tcp.syn;
	out->rst     = p->p.tcp.rst;
	out->psh     = p->p.tcp.psh;
	out->ack     = p->p.tcp.ack;
	out->urg     = p->p.tcp.urg;
	out->ece     = p->p.tcp.ece;
	out->cwr     = p->p.tcp.cwr;
	out->ns      = p->p.tcp.ns;
	out->window  = htons(p->p.tcp.window);
	out->chksum  = 0;
	out->urg_ptr = htons(p->p.tcp.urg_ptr);

	if (p->next && (p->next->type == TYPE_IP4))
		csum = pkt_pseudo_chksum(&p->next->p.ip4);

	out->chksum  = pkt_chksum(buf, len, csum);
}

int pkt_unpack_tcp(struct pkt *p, uint8_t *buf, size_t len) {
	if (len < 20)
		return -1;

	memcpy(&p->p.tcp, buf, sizeof(p->p.tcp));

	p->p.tcp.sport   = ntohs(p->p.tcp.sport);
	p->p.tcp.dport   = ntohs(p->p.tcp.dport);
	p->p.tcp.seq     = ntohl(p->p.tcp.seq);
	p->p.tcp.ack_seq = ntohl(p->p.tcp.ack_seq);
	p->p.tcp.doff    = p->p.tcp.doff;
	p->p.tcp.fin     = p->p.tcp.fin;
	p->p.tcp.syn     = p->p.tcp.syn;
	p->p.tcp.rst     = p->p.tcp.rst;
	p->p.tcp.psh     = p->p.tcp.psh;
	p->p.tcp.ack     = p->p.tcp.ack;
	p->p.tcp.urg     = p->p.tcp.urg;
	p->p.tcp.window  = ntohs(p->p.tcp.window);
	p->p.tcp.chksum  = ntohs(p->p.tcp.chksum);
	p->p.tcp.urg_ptr = ntohs(p->p.tcp.urg_ptr);

	/* TODO: unpack TCP extensions */

	p->type   = TYPE_TCP;
	p->length = p->p.tcp.doff * 4;

	return TYPE_RAW;
}
