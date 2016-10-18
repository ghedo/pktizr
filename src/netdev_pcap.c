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

#include <pcap/pcap.h>

#include "netdev.h"
#include "printf.h"
#include "util.h"

struct priv {
    pcap_t  *p;
    uint8_t *buf;
    size_t   buf_len;
};

static void netdev_open_pcap(void *p, const char *dev_name) {
    struct priv *priv = p;

    char err[PCAP_ERRBUF_SIZE];

    priv->p = pcap_open_live(dev_name, 1500, 0, 10, err);
    if (priv->p == NULL)
        fail_printf("Error opening pcap: %s", err);

    priv->buf_len = 65535;
    priv->buf     = malloc(priv->buf_len);
}

static uint8_t *netdev_get_buf_pcap(void *p, size_t *len) {
    struct priv *priv = p;
    *len = priv->buf_len;
    return priv->buf;
}

static void netdev_inject_pcap(void *p, uint8_t *buf, size_t len) {
    struct priv *priv = p;

    int rc = pcap_sendpacket(priv->p, buf, len);
    if (rc < 0)
        fail_printf("Error sending packet: %s", pcap_geterr(priv->p));
}

static const uint8_t *netdev_capture_pcap(void *p, int *len) {
    const uint8_t *buf;
    struct pcap_pkthdr *pkt_hdr;

    struct priv *priv = p;

    int rc = pcap_next_ex(priv->p, &pkt_hdr, &buf);
    switch (rc) {
    case -2:
        return NULL;

    case -1:
        fail_printf("Error capturing packet: %s",
                pcap_geterr(priv->p));

    case 0:
        return NULL;

    case 1:
        *len = pkt_hdr->len;
        return buf;
    }

    fail_printf("Should be here...");
    return NULL;
}

static void netdev_release_pcap(void *p) {
}

static void netdev_close_pcap(void *p) {
    struct priv *priv = p;

    pcap_close(priv->p);

    freep(&priv->buf);
    priv->buf_len = 0;
}

const struct netdev_driver netdev_pcap = {
    .name    = "pcap",

    .priv_size = sizeof(struct priv),

    .open    = netdev_open_pcap,

    .get_buf = netdev_get_buf_pcap,
    .inject  = netdev_inject_pcap,

    .capture = netdev_capture_pcap,
    .release = netdev_release_pcap,

    .close   = netdev_close_pcap,
};
