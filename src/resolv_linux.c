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

#ifdef __linux__

#include <string.h>
#include <unistd.h>

#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <talloc.h>

#include "printf.h"
#include "util.h"

int resolve_ifname_to_mac(char *ifname, uint8_t *mac) {
	int rc;
	struct ifreq ifr;

	_close_ int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		sysf_printf("socket(AF_INET");

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	rc = ioctl(fd, SIOCGIFHWADDR, &ifr);
	if (rc < 0)
		sysf_printf("ioctl(SIOCGIFHWADDR)");

	memcpy(mac, ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);

	return 0;
}

int resolve_ifname_to_ip(char *ifname, uint32_t *ip) {
	int rc;
	struct ifreq ifr;
	struct sockaddr_in *sa;

	_close_ int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		sysf_printf("socket(AF_INET");

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	rc = ioctl(fd, SIOCGIFADDR, &ifr);
	if (rc < 0)
		sysf_printf("ioctl(SIOCGIFADDR)");

	sa = (struct sockaddr_in *) &ifr.ifr_addr;

	*ip = ntohl(sa->sin_addr.s_addr);

	return 0;
}

#endif /* __linux__ */
