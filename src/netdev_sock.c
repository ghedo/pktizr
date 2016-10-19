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

#include <string.h>
#include <errno.h>

#include <sys/mman.h>
#include <sys/poll.h>

#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>

#include "netdev.h"
#include "printf.h"
#include "util.h"

#define RING_FRAME_SIZE (1 << 11)
#define RING_FRAME_NR   (1 << 9)

#define RING_BLOCK_SIZE (1 << 12)

struct priv {
    int fd;

    uint8_t *rx_ring;
    uint8_t *tx_ring;

    int rx_ring_off;
    int tx_ring_off;

    int ring_hdrlen;
};

static void netdev_open_sock(void *p, const char *dev_name) {
    int rc, fd;

    struct priv *priv = p;

    int vers = TPACKET_V2;

    struct tpacket_req tp;
    struct sockaddr_ll dev_addr;

    priv->ring_hdrlen = sizeof(struct tpacket2_hdr);

    fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0)
        sysf_printf("socket()");

    memset(&dev_addr, 0, sizeof(dev_addr));
    dev_addr.sll_family   = AF_PACKET;
    dev_addr.sll_protocol = htons(ETH_P_ALL);
    dev_addr.sll_ifindex  = if_nametoindex(dev_name);

    rc = bind(fd, (struct sockaddr *) &dev_addr, sizeof(dev_addr));
    if (rc < 0)
        sysf_printf("bind()");

    memset(&tp, 0, sizeof(tp));
    tp.tp_frame_size = RING_FRAME_SIZE;
    tp.tp_frame_nr   = RING_FRAME_NR;
    tp.tp_block_size = RING_BLOCK_SIZE;
    tp.tp_block_nr   = tp.tp_frame_nr /
                       (tp.tp_block_size / tp.tp_frame_size);

    rc = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &vers, sizeof(vers));
    if (rc < 0)
        sysf_printf("setsockopt(PACKET_VERSION)");

    rc = setsockopt(fd, SOL_PACKET, PACKET_RX_RING,
                    (void *) &tp, sizeof(tp));
    if (rc < 0)
        sysf_printf("setsockopt(PACKET_RX_RING)");

    rc = setsockopt(fd, SOL_PACKET, PACKET_TX_RING,
                    (void *) &tp, sizeof(tp));
    if (rc < 0)
        sysf_printf("setsockopt(PACKET_TX_RING)");

    unsigned int len = sizeof(vers);
    rc = getsockopt(fd, SOL_PACKET, PACKET_HDRLEN, &vers, &len);
    if (rc < 0)
        sysf_printf("getsockopt(PACKET_HDRLEN)");

    priv->ring_hdrlen = vers;

    priv->rx_ring = mmap(0, tp.tp_block_size * tp.tp_block_nr * 2,
                             PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (!priv->rx_ring)
        fail_printf("EOF");

    priv->tx_ring = priv->rx_ring + tp.tp_block_size * tp.tp_block_nr;

    priv->fd = fd;
}

static uint8_t *netdev_get_buf_sock(void *p, size_t *len) {
    int rc;

    struct pollfd pfd;

    struct priv *priv = p;

    uint8_t *base = priv->tx_ring + (priv->tx_ring_off * RING_FRAME_SIZE);
    struct tpacket2_hdr *hdr = (struct tpacket2_hdr *) base;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd      = priv->fd;
    pfd.events  = POLLIN | POLLERR;
    pfd.revents = 0;

    while (hdr->tp_status != TP_STATUS_AVAILABLE) {
        rc = poll(&pfd, 1, 10);
        if ((rc < 0) && (errno != EINTR))
            sysf_printf("poll()");
    }

    priv->tx_ring_off = (priv->tx_ring_off + 1) % RING_FRAME_NR;

    *len = RING_FRAME_SIZE;

    return base + TPACKET_ALIGN(priv->ring_hdrlen);
}

static void netdev_inject_sock(void *p, uint8_t *buf, size_t len) {
    int rc;

    struct priv *priv = p;

    uint8_t *base = buf - TPACKET_ALIGN(priv->ring_hdrlen);
    struct tpacket2_hdr *hdr = (struct tpacket2_hdr *) base;

    hdr->tp_len    = len;
    hdr->tp_status = TP_STATUS_SEND_REQUEST;

    rc = sendto(priv->fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    if ((rc < 0) && (errno != EAGAIN))
        sysf_printf("sendto()");
}

static const uint8_t *netdev_capture_sock(void *p, int *len) {
    int rc;

    struct pollfd pfd;

    struct priv *priv = p;

    uint8_t *base = priv->rx_ring + (priv->rx_ring_off * RING_FRAME_SIZE);
    struct tpacket2_hdr *hdr = (struct tpacket2_hdr *) base;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd      = priv->fd;
    pfd.events  = POLLIN | POLLERR;
    pfd.revents = 0;

    while (!(hdr->tp_status & TP_STATUS_USER)) {
        rc = poll(&pfd, 1, 10);
        if ((rc < 0) && (errno != EINTR))
            sysf_printf("poll()");

        if (rc == 0)
            return NULL;
    }

    if (hdr->tp_status & TP_STATUS_COPY)
        return NULL;

    if (hdr->tp_status & TP_STATUS_LOSING)
        return NULL;

    *len = hdr->tp_len;

    return base + hdr->tp_mac;
}

static void netdev_release_sock(void *p) {
    struct priv *priv = p;

    uint8_t *base = priv->rx_ring + (priv->rx_ring_off * RING_FRAME_SIZE);
    struct tpacket2_hdr *hdr = (struct tpacket2_hdr *) base;

    hdr->tp_status = TP_STATUS_KERNEL;

    priv->rx_ring_off = (priv->rx_ring_off + 1) & (RING_FRAME_NR - 1);
}

static void netdev_close_sock(void *p) {
    struct priv *priv = p;
    closep(&priv->fd);
}

const struct netdev_driver netdev_sock = {
    .name    = "sock",

    .priv_size = sizeof(struct priv),

    .open    = netdev_open_sock,

    .get_buf = netdev_get_buf_sock,
    .inject  = netdev_inject_sock,

    .capture = netdev_capture_sock,
    .release = netdev_release_sock,

    .close   = netdev_close_sock,
};
