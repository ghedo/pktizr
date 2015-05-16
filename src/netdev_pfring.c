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
#include <stdlib.h>
#include <unistd.h>

#include <pfring.h>

#include <urcu/uatomic.h>

#include "netdev.h"
#include "printf.h"
#include "util.h"

static uint8_t *pfring_buf     = NULL;
static size_t   pfring_buf_len = 0;

static uint8_t *netdev_get_buf_pfring(struct netdev *n, size_t *len) {
	*len = pfring_buf_len;
	return pfring_buf;
}

static void netdev_inject_pfring(struct netdev *n, uint8_t *buf, size_t len) {
	while (pfring_send(n->p, (char *) buf, len, 1) < 0)
		caa_cpu_relax();
}

static const uint8_t *netdev_capture_pfring(struct netdev *n, int *len) {
	const uint8_t *buf;
	struct pfring_pkthdr pkt_hdr;

	int rc = pfring_recv(n->p, (unsigned char **) &buf, 0, &pkt_hdr, 0);
	switch (rc) {
	case -1:
		fail_printf("Error capturing packet");

	case 0:
		return NULL;

	case 1:
		*len = pkt_hdr.len;
		return buf;
	}

	assert(1);
	return NULL;
}

static void netdev_release_pfring(struct netdev *n) {
}

static void netdev_close_pfring(struct netdev *n) {
	pfring_close(n->p);

	freep(&pfring_buf);
	pfring_buf_len = 0;
}

static struct netdev netdev_pfring = {
	.p       = NULL,

	.get_buf = netdev_get_buf_pfring,
	.inject  = netdev_inject_pfring,

	.capture = netdev_capture_pfring,
	.release = netdev_release_pfring,

	.close   = netdev_close_pfring,
};

struct netdev *netdev_open_pfring(const char *dev_name) {
	pfring *ring = pfring_open(dev_name, 1500, 0);
	if (ring == NULL)
		fail_printf("Error opening pfring");

	pfring_set_application_name(ring, "pktizr");
	pfring_enable_ring(ring);

	pfring_buf_len = 65535;
	pfring_buf     = malloc(pfring_buf_len);

	netdev_pfring.p = ring;

	return &netdev_pfring;
}
