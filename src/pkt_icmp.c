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

void pkt_pack_icmp(struct pkt *p, uint8_t *buf, size_t len) {
	struct icmp_hdr *out = (struct icmp_hdr *) buf;

	memset(out, 0, sizeof(*out));

	out->type   = p->p.icmp.type;
	out->code   = p->p.icmp.code;
	out->chksum = 0;
	out->id     = htons(p->p.icmp.id);
	out->seq    = htons(p->p.icmp.seq);

	out->chksum = pkt_chksum(buf, len, 0);
}

int pkt_unpack_icmp(struct pkt *p, uint8_t *buf, size_t len) {
	if (len < 8)
		return -1;

	memcpy(&p->p.icmp, buf, sizeof(p->p.icmp));

	p->p.icmp.type   = p->p.icmp.type;
	p->p.icmp.code   = p->p.icmp.code;
	p->p.icmp.chksum = htons(p->p.icmp.chksum);
	p->p.icmp.id     = htons(p->p.icmp.id);
	p->p.icmp.seq    = htons(p->p.icmp.seq);

	p->type   = TYPE_ICMP;
	p->length = 8;

	if ((p->p.icmp.type == 3) ||
	    (p->p.icmp.type == 4) ||
	    (p->p.icmp.type == 5) ||
	    (p->p.icmp.type == 11))
		return TYPE_IP4;

	return TYPE_RAW;
}
