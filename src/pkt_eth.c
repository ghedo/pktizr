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

void pkt_build_eth(struct pkt *p, uint8_t *src, uint8_t *dst, uint16_t type) {
	if (p == NULL)
		return;

	memcpy(p->p.eth.src, src, 6);
	memcpy(p->p.eth.dst, dst, 6);

	p->p.eth.type = type;

	p->type   = TYPE_ETH;
	p->length = 14;
}

void pkt_pack_eth(struct pkt *p, uint8_t *buf, size_t len) {
	struct eth_hdr out;
	uint16_t type = p->p.eth.type;

	if (p->prev) {
		switch (p->prev->type) {
		case TYPE_ARP:
			type = ETHERTYPE_ARP;
			break;

		case TYPE_IP4:
			type = ETHERTYPE_IP;
			break;
		}
	}

	out.type = htons(type);
	memcpy(out.src, p->p.eth.src, 6);
	memcpy(out.dst, p->p.eth.dst, 6);

	memcpy(buf, &out, sizeof(out));
}

int pkt_unpack_eth(struct pkt *p, uint8_t *buf, size_t len) {
	if (len < 14)
		return -1;

	memcpy(&p->p.eth, buf, sizeof(p->p.eth));
	p->p.eth.type = ntohs(p->p.eth.type);

	p->type   = TYPE_ETH;
	p->length = 14;

	switch (p->p.eth.type) {
	case ETHERTYPE_ARP:
		return TYPE_ARP;

	case ETHERTYPE_IP:
		return TYPE_IP4;
	}

	return TYPE_NONE;
}
