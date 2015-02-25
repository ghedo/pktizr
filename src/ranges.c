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
#include <string.h>

#include <arpa/inet.h>

#include <utlist.h>

#include "ranges.h"
#include "netif.h"
#include "resolv.h"
#include "printf.h"
#include "util.h"

struct range *range_parse_targets(void *ta, char *spec) {
	_free_ char **ranges = NULL;
	size_t c = validate_optlist("<targets>", spec);

	_free_ char *tmp = strdup(spec);
	if (tmp == NULL) fail_printf("OOM");

	c = split_str(tmp, &ranges, ",");
	if (c == 0) fail_printf("Invalid targets spec '%s'", spec);

	struct range *list = NULL;

	for (int i = 0; i < c; i++) {
		struct in_addr a;

		int bits = inet_net_pton(AF_INET, ranges[i], &a, sizeof(a));
		if (bits < 0) {
			int rc = resolv_name_to_addr(ranges[i], &a.s_addr);
			if (rc < 0)
				sysf_printf("Invalid address '%s'", ranges[i]);

			bits = 32;
		}

		uint32_t mask = 0xffffffff00000000ull >> bits;

		uint32_t start = ntohl(a.s_addr) & mask;
		uint32_t end   = start | ~mask;

		range_list_add(ta, &list, start, end);
	}

	return list;
}

struct range *range_parse_ports(void *ta, char *spec) {
	_free_ char **ranges = NULL;

	_free_ char *tmp = strdup(spec);
	if (tmp == NULL) fail_printf("OOM");

	size_t c = split_str(tmp, &ranges, ",");
	if (c == 0) fail_printf("Invalid ports spec '%s'", spec);

	struct range *list = NULL;

	for (int i = 0; i < c; i++) {
		int x, y;
		char *s = ranges[i], *e;

		if (!(x = strtol(s, &e, 10), e != s) || (x < 0))
			fail_printf("Invalid port range: %s", s);
		s = e;

		if (*s == '\0') {
			range_list_add(ta, &list, x, x);
			continue;
		}

		if (*s != '-')
			fail_printf("Invalid port range: %s", s);
		s = e;

		s++;

		if (!(y = strtol(s, &e, 10), e != s) || (y < 0))
			fail_printf("Invalid port range: %s", s);

		range_list_add(ta, &list, x, y);
	}

	return list;
}

uint32_t range_list_pick(struct range *list, uint32_t index) {
	struct range *cur;

	LL_FOREACH(list, cur) {
		size_t cnt = (cur->end - cur->start) + 1;

		if (index < cnt)
			return cur->start + index;

		index -= cnt;
	}

	assert(1);
	return 0;
}

uint32_t range_list_min(struct range *list) {
	return range_list_pick(list, 0);
}

size_t range_list_count(struct range *list) {
	size_t count = 0;
	struct range *cur;

	LL_FOREACH(list, cur) {
		count += (cur->end - cur->start) + 1;
	}

	return count;
}

void range_list_add(void *ta, struct range **list, uint32_t start, uint32_t end) {
	struct range *cur, *tmp;

	LL_FOREACH_SAFE(*list, cur, tmp) {
		if ((start >= cur->start) && (end <= cur->end))
			return; /* skip */

		if ((start < cur->start) && (end >= cur->start)) {
			cur->start = start;
			return;
		}

		if ((start < cur->end) && (end >= cur->end)) {
			cur->end = end;
			return;
		}
	}

	struct range *new = malloc(sizeof(*new));

	new->start = start;
	new->end   = end;

	LL_FOREACH_SAFE(*list, cur, tmp) {
		if (end < cur->start) {
			LL_PREPEND_ELEM(*list, cur, new);
			return;
		}
	}

	LL_APPEND(*list, new);
}

void range_list_dump(struct range *list) {
	struct range *cur;

	LL_FOREACH(list, cur) {
		ok_printf("[ %u - %u ]", cur->start, cur->end);
	}
}

void range_list_free(struct range *list) {
	struct range *cur, *tmp;

	LL_FOREACH_SAFE(list, cur, tmp) {
		LL_DELETE(list, cur);

		free(cur);
	}
}
