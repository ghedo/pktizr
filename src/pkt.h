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

enum pkt_type {
	TYPE_NONE,
	TYPE_ETH,
	TYPE_ARP,
	TYPE_IP4,
	TYPE_ICMP,
	TYPE_UDP,
	TYPE_TCP,
	TYPE_RAW,
};

enum {
	ETHERTYPE_IP   = 0x0800,
	ETHERTYPE_ARP  = 0x0806,
	ETHERTYPE_VLAN = 0x8100,
	ETHERTYPE_IPV6 = 0x86dd,
};

enum {
	ARPHRD_ETHER   = 1,
};

enum {
	ARPOP_REQUEST    = 1,
	ARPOP_REPLY      = 2,
	ARPOP_REVREQUEST = 3,
	ARPOP_REVREPLY   = 4,
	ARPOP_INVREQUEST = 8,
	ARPOP_INVREPLY   = 9,
};

enum {
	PROTO_ICMP = 0x01,
	PROTO_TCP  = 0x06,
	PROTO_UDP  = 0x11,
};

enum {
	ICMPOP_ECHOREPLY      = 0,
	ICMPOP_DEST_UNREACH   = 3,
	ICMPOP_SOURCE_QUENCH  = 4,
	ICMPOP_REDIRECT       = 5,
	ICMPOP_ECHO           = 8,
	ICMPOP_TIME_EXCEEDED  = 11,
	ICMPOP_PARAMETERPROB  = 12,
	ICMPOP_TIMESTAMP      = 13,
	ICMPOP_TIMESTAMPREPLY = 14,
	ICMPOP_INFO_REQUEST   = 15,
	ICMPOP_INFO_REPLY     = 16,
	ICMPOP_ADDRESS        = 17,
	ICMPOP_ADDRESSREPLY   = 18,
};

struct eth_hdr {
	uint8_t  dst[6];
	uint8_t  src[6];
	uint16_t type;
};

struct arp_hdr {
	uint16_t hwtype;
	uint16_t ptype;
	uint8_t  hwlen;
	uint8_t  plen;
	uint16_t op;
	uint8_t  *hwsrc;
	uint8_t  *psrc;
	uint8_t  *hwdst;
	uint8_t  *pdst;
};

struct ip4_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t ihl:4;
	uint16_t version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t version:4;
	uint16_t ihl:4;
#else
# error "Please fix <bits/endian.h>"
#endif
	uint8_t  tos;
	uint16_t len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t  ttl;
	uint8_t  proto;
	uint16_t chksum;
	uint32_t src;
	uint32_t dst;
};

struct icmp_hdr {
	uint8_t  type;
	uint8_t  code;
	uint16_t chksum;
	uint16_t id;
	uint16_t seq;
};

struct udp_hdr {
	uint16_t sport;
	uint16_t dport;
	uint16_t len;
	uint16_t chksum;
};

struct tcp_hdr {
	uint16_t sport;
	uint16_t dport;
	uint32_t seq;
	uint32_t ack_seq;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t ns:1;
	uint16_t res:3;
	uint16_t doff:4;
	uint16_t fin:1;
	uint16_t syn:1;
	uint16_t rst:1;
	uint16_t psh:1;
	uint16_t ack:1;
	uint16_t urg:1;
	uint16_t ece:1;
	uint16_t cwr:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t doff:4;
	uint16_t res:3;
	uint16_t ns:1;
	uint16_t cwr:1;
	uint16_t ece:1;
	uint16_t urg:1;
	uint16_t ack:1;
	uint16_t psh:1;
	uint16_t rst:1;
	uint16_t syn:1;
	uint16_t fin:1;
#else
# error "Please fix <bits/endian.h>"
#endif
	uint16_t window;
	uint16_t chksum;
	uint16_t urg_ptr;
};

struct raw_hdr {
	uint8_t *payload;
	size_t  len;
};

struct pkt {
	uint16_t type;
	size_t   length;
	bool     probe;

	union {
		struct eth_hdr  eth;
		struct arp_hdr  arp;
		struct ip4_hdr  ip4;
		struct icmp_hdr icmp;
		struct udp_hdr  udp;
		struct tcp_hdr  tcp;
		struct raw_hdr  raw;
	} p;

	struct pkt *prev, *next;

	struct queue_node queue;
};

struct pkt *pkt_new(void *ta, enum pkt_type type);

uint16_t pkt_chksum(uint8_t *buf, size_t len, uint32_t csum);
uint32_t pkt_pseudo_chksum(struct ip4_hdr *h);
uint64_t pkt_cookie(uint32_t saddr, uint32_t daddr,
                    uint16_t sport, uint16_t dport,
                    uint64_t seed);

void pkt_build_eth(struct pkt *p, uint8_t *src, uint8_t *dst, uint16_t type);
void pkt_build_arp(struct pkt *p, uint16_t hwtype, uint16_t ptype, uint16_t op,
                  uint8_t *hwsrc, uint8_t *psrc, uint8_t *hwdst, uint8_t *pdst);

void pkt_pack_arp(struct pkt *p, uint8_t *buf, size_t len);
void pkt_pack_eth(struct pkt *p, uint8_t *buf, size_t len);
void pkt_pack_ip4(struct pkt *p, uint8_t *buf, size_t len);
void pkt_pack_icmp(struct pkt *p, uint8_t *buf, size_t len);
void pkt_pack_udp(struct pkt *p, uint8_t *buf, size_t len);
void pkt_pack_tcp(struct pkt *p, uint8_t *buf, size_t len);
void pkt_pack_raw(struct pkt *p, uint8_t *buf, size_t len);

int pkt_unpack_arp(struct pkt *p, uint8_t *buf, size_t len);
int pkt_unpack_eth(struct pkt *p, uint8_t *buf, size_t len);
int pkt_unpack_ip4(struct pkt *p, uint8_t *buf, size_t len);
int pkt_unpack_icmp(struct pkt *p, uint8_t *buf, size_t len);
int pkt_unpack_udp(struct pkt *p, uint8_t *buf, size_t len);
int pkt_unpack_tcp(struct pkt *p, uint8_t *buf, size_t len);
int pkt_unpack_raw(struct pkt *p, uint8_t *buf, size_t len);

int pkt_pack(uint8_t *buf, size_t len, struct pkt *p);
int pkt_unpack(void *ta, uint8_t *buf, size_t len, struct pkt **p);
void pkt_free(struct pkt *pkt);
