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
#include <stdlib.h>
#include <string.h>

#include "netdev.h"
#include "printf.h"
#include "util.h"

extern const struct netdev_driver netdev_pfring;
extern const struct netdev_driver netdev_pcap;
extern const struct netdev_driver netdev_sock;

static const struct netdev_driver * const netdev_drivers[] = {
#ifdef HAVE_PFRING_H
	&netdev_pfring,
#endif

#ifdef HAVE_PCAP_H
	&netdev_pcap,
#endif

#ifdef HAVE_LINUX_IF_PACKET_H
	&netdev_sock,
#endif
	NULL,
};

struct netdev *netdev_open(const char *name, const char *dev_name) {
	struct netdev *dev = malloc(sizeof(*dev));

	for (size_t i = 0; netdev_drivers[i] != NULL; i++) {
		const struct netdev_driver *cur = netdev_drivers[i];

		if (!name || !strcmp(cur->name, name)) {
			dev->driver = cur;
			dev->priv   = calloc(1, cur->priv_size);

			dev->driver->open(dev->priv, dev_name);
			return dev;
		}
	}

	fail_printf("No netdev implementation supported");
	return NULL;
}

uint8_t *netdev_get_buf(struct netdev *dev, size_t *len) {
	return dev->driver->get_buf(dev->priv, len);
}

void netdev_inject(struct netdev *dev, uint8_t *buf, size_t len) {
	dev->driver->inject(dev->priv, buf, len);
}

const uint8_t *netdev_capture(struct netdev *dev, int *len) {
	return dev->driver->capture(dev->priv, len);
}

void netdev_release(struct netdev *dev) {
	dev->driver->release(dev->priv);
}

void netdev_close(struct netdev *dev) {
	dev->driver->close(dev->priv);

	freep(&dev->priv);
	freep(&dev);
}
