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

#include <assert.h>
#include <stdint.h>

#include <pcap/pcap.h>

#include "netdev.h"
#include "printf.h"

static void netdev_inject_pcap(struct netdev *n, uint8_t *buf, size_t len) {
	int rc = pcap_sendpacket(n->p, buf, len);
	if (rc < 0)
		fail_printf("Error sending packet: %s", pcap_geterr(n->p));
}

static const uint8_t *netdev_capture_pcap(struct netdev *n, int *len) {
	const uint8_t *buf;
	struct pcap_pkthdr *pkt_hdr;

	int rc = pcap_next_ex(n->p, &pkt_hdr, &buf);
	switch (rc) {
	case -2:
		return NULL;

	case -1:
		fail_printf("Error capturing packet: %s",
			    pcap_geterr(n->p));

	case 0:
		return NULL;

	case 1:
		*len = pkt_hdr->len;
		return buf;
	}

	assert(1);
	return NULL;
}

static void netdev_close_pcap(struct netdev *n) {
	pcap_close(n->p);
}

static struct netdev netdev_pcap = {
	.p       = NULL,
	.inject  = netdev_inject_pcap,
	.capture = netdev_capture_pcap,
	.close   = netdev_close_pcap,
};

struct netdev *netdev_open_pcap(const char *dev_name) {
	char err[PCAP_ERRBUF_SIZE];

	pcap_t *pcap = pcap_open_live(dev_name, 262144, 0, 10, err);
	if (pcap == NULL)
		fail_printf("Error opening pcap: %s", err);

	netdev_pcap.p = pcap;

	return &netdev_pcap;
}
