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
#include <string.h>

#include <arpa/inet.h>

#include "ut/utlist.h"

#include "pkt.h"
#include "printf.h"
#include "util.h"

struct pkt *pkt_new(void *ta, enum pkt_type type) {
	struct pkt *p = calloc(1, sizeof(*p));

	p->type = type;

	switch (type) {
	case TYPE_ETH:
		pkt_build_eth(p, (uint8_t *) "\x0\x0\x0\x0\x0\x0",
		                 (uint8_t *) "\x0\x0\x0\x0\x0\x0", 0);
		break;

	case TYPE_ARP:
		p->length = 8;
		break;

	case TYPE_IP4:
		p->length = 20;
		break;

	case TYPE_ICMP:
		p->length = 8;
		break;

	case TYPE_UDP:
		p->length = 8;
		break;

	case TYPE_TCP:
		p->length = 20;
		break;

	case TYPE_RAW:
		p->length = 0;
		break;

	case TYPE_NONE:
		p->length = 0;
		break;

	default:
		fail_printf("Invalid packet type: %d", type);
	}

	cds_wfcq_node_init(&p->queue);

	return p;
}

int pkt_pack(uint8_t *buf, size_t len, struct pkt *p) {
	struct pkt *cur;
	size_t plen = 0, i = 0;

	DL_FOREACH(p, cur) {
		plen += cur->length;

		switch (cur->type) {
		case TYPE_IP4:
			if (cur->prev) {
				switch (cur->prev->type) {
				case TYPE_ICMP:
					cur->p.ip4.proto = PROTO_ICMP;
					break;

				case TYPE_UDP:
					cur->p.ip4.proto = PROTO_UDP;
					break;

				case TYPE_TCP:
					cur->p.ip4.proto = PROTO_TCP;
					break;
				}
			}

			cur->p.ip4.len = plen;
			break;

		case TYPE_UDP:
			cur->p.udp.len = plen;
			break;

		case TYPE_TCP:
			break;
		}
	}

	if (len < plen)
		return -1;

	i = plen;

	DL_FOREACH(p, cur) {
		i -= cur->length;

		switch (cur->type) {
		case TYPE_ETH:
			pkt_pack_eth(cur, buf + i, plen - i);
			break;

		case TYPE_ARP:
			pkt_pack_arp(cur, buf + i, plen - i);
			break;

		case TYPE_IP4:
			pkt_pack_ip4(cur, buf + i, plen - i);
			break;

		case TYPE_ICMP:
			pkt_pack_icmp(cur, buf + i, plen - i);
			break;

		case TYPE_UDP:
			pkt_pack_udp(cur, buf + i, plen - i);
			break;

		case TYPE_TCP:
			pkt_pack_tcp(cur, buf + i, plen - i);
			break;

		case TYPE_RAW:
			pkt_pack_raw(cur, buf + i, plen - i);
			break;
		}
	}

	return plen;
}

int pkt_unpack(void *ta, uint8_t *buf, size_t len, struct pkt **p) {
	int n = 0;
	size_t i = 0;

	if (len < 14)
		return 0;

	struct pkt *pkt = NULL;
	int next_type = TYPE_ETH;

	while ((i < len) && (next_type != TYPE_NONE)) {
		struct pkt *new = pkt_new(NULL, next_type);
		DL_APPEND(pkt, new);

		switch (next_type) {
		case TYPE_ARP:
			next_type = pkt_unpack_arp(new, (buf + i), (len - i));
			break;

		case TYPE_ETH:
			next_type = pkt_unpack_eth(new, (buf + i), (len - i));
			break;

		case TYPE_IP4:
			next_type = pkt_unpack_ip4(new, (buf + i), (len - i));
			break;

		case TYPE_ICMP:
			next_type = pkt_unpack_icmp(new, (buf + i), (len - i));
			break;

		case TYPE_UDP:
			next_type = pkt_unpack_udp(new, (buf + i), (len - i));
			break;

		case TYPE_TCP:
			next_type = pkt_unpack_tcp(new, (buf + i), (len - i));
			break;

		case TYPE_RAW:
			next_type = pkt_unpack_raw(new, (buf + i), (len - i));
			break;

		default:
			fail_printf("Unknown packet type: %u", next_type);
		}

		if (next_type < 0) {
			pkt_free(pkt);
			return 0;
		}

		i += new->length;
		n++;
	}

	*p = pkt;

	return n;
}

void pkt_free(struct pkt *pkt) {
	struct pkt *cur, *tmp;

	DL_FOREACH_SAFE(pkt, cur, tmp) {
		DL_DELETE(pkt, cur);

		switch (cur->type) {
		case TYPE_ARP:
			if (cur->p.arp.hwsrc)
				free(cur->p.arp.hwsrc);

			if (cur->p.arp.hwdst)
				free(cur->p.arp.hwdst);

			if (cur->p.arp.psrc)
				free(cur->p.arp.psrc);

			if (cur->p.arp.pdst)
				free(cur->p.arp.pdst);

			break;

		case TYPE_RAW:
			if (cur->p.raw.payload)
				free(cur->p.raw.payload);

			break;
		}

		free(cur);
	}
}
