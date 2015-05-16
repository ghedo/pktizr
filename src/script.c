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
#include <stdbool.h>

#include <arpa/inet.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <urcu/uatomic.h>

#include "lua-compat-5.3/c-api/compat-5.3.h"
#include "ut/utlist.h"

#include "netdev.h"
#include "queue.h"
#include "pkt.h"
#include "printf.h"
#include "util.h"
#include "pktizr.h"

static void push_pkt(lua_State *L, enum pkt_type type, struct pkt *p);
static struct pkt *pop_pkt(lua_State *L, struct pktizr_args *args);

static int get_ip4(lua_State *L, const char *key, struct ip4_hdr *ip4);
static int set_ip4(lua_State *L, const char *key, struct ip4_hdr *ip4);

static int get_icmp(lua_State *L, const char *key, struct icmp_hdr *icmp);
static int set_icmp(lua_State *L, const char *key, struct icmp_hdr *icmp);

static int get_udp(lua_State *L, const char *key, struct udp_hdr *udp);
static int set_udp(lua_State *L, const char *key, struct udp_hdr *udp);

static int get_tcp(lua_State *L, const char *key, struct tcp_hdr *tcp);
static int set_tcp(lua_State *L, const char *key, struct tcp_hdr *tcp);

static int get_raw(lua_State *L, const char *key, struct raw_hdr *raw);
static int set_raw(lua_State *L, const char *key, struct raw_hdr *raw);

LUALIB_API int luaopen_bit(lua_State *L);
LUALIB_API int luaopen_compat53_string(lua_State *L);
LUALIB_API int luaopen_pkt(lua_State *L);
LUALIB_API int luaopen_std(lua_State *L);

static const luaL_Reg pktizr_libs[] = {
	{ "pktizr.bin", luaopen_compat53_string },
	{ "pktizr.bit", luaopen_bit             },
	{ "pktizr.pkt", luaopen_pkt             },
	{ "pktizr.std", luaopen_std             },
	{ NULL,         NULL                    }
};


void *script_load(struct pktizr_args *args) {
	int rc;

	lua_State *L = luaL_newstate();
	if (L == NULL)
		fail_printf("Error creating Lua state");

	luaL_openlibs(L);

	for (int i = 0; pktizr_libs[i].name; i++) {
		luaL_requiref(L, pktizr_libs[i].name, pktizr_libs[i].func, 1);
		lua_pop(L, 1);
	}

	lua_pushlightuserdata(L, args);
	lua_setfield(L, LUA_REGISTRYINDEX, "args");

	assert(lua_gettop(L) == 0);

	rc = luaL_loadfile(L, args->script);
	if (rc != 0) {
		const char *err = "unknown error";
		if (lua_type(L, -1) == LUA_TSTRING)
			err = lua_tostring(L, -1);

		fail_printf("Error loading script: %s", err);
	}

	rc = lua_pcall(L, 0, 0, 0);
	if (rc != 0) {
		const char *err = "unknown error";
		if (lua_type(L, -1) == LUA_TSTRING)
			err = lua_tostring(L, -1);

		fail_printf("Error running script: %s", err);
	}

	assert(lua_gettop(L) == 0);

	return L;
}

void script_close(void *L) {
	lua_close(L);
}

int script_loop(void *L, struct pktizr_args *args, struct pkt **pkt,
                uint32_t daddr, uint16_t dport) {
	int rc;

	char dst_addr[INET_ADDRSTRLEN];
	daddr = htonl(daddr);
	inet_ntop(AF_INET, &daddr, dst_addr, sizeof(dst_addr));

	assert(lua_gettop(L) == 0);

	luaL_checkstack(L, 1, "OOM");
	lua_getglobal(L, "loop");

	if (caa_unlikely(lua_isnil(L, -1)))
		goto error;

	luaL_checkstack(L, 1, "OOM");
	lua_pushstring(L, dst_addr);

	luaL_checkstack(L, 1, "OOM");
	lua_pushinteger(L, dport);

	rc = lua_pcall(L, 2, LUA_MULTRET, 0);
	if (caa_unlikely(rc != 0)) {
		const char *err = "unknown error";
		if (lua_type(L, -1) == LUA_TSTRING)
			err = lua_tostring(L, -1);

		fail_printf("Error running script: %s", err);
	}

	*pkt = pop_pkt(L, args);

	assert(lua_gettop(L) == 0);

	return 0;

error:
	lua_settop(L, 0);
	return -1;
}

int script_recv(void *L, struct pktizr_args *args, struct pkt *pkt) {
	int rc, n = 1;

	struct pkt *cur, *tmp;

	assert(lua_gettop(L) == 0);

	luaL_checkstack(L, 1, "OOM");
	lua_getglobal(L, "recv");

	if (lua_isnil(L, -1))
		goto error;

	luaL_checkstack(L, 1, "OOM");
	lua_newtable(L);

	DL_FOREACH_SAFE(pkt, cur, tmp) {
		luaL_checkstack(L, 1, "OOM");

		switch (cur->type) {
		case TYPE_ETH:
		case TYPE_ARP:
			DL_DELETE(pkt, cur);
			pkt_free(cur);
			break;

		case TYPE_IP4:
		case TYPE_ICMP:
		case TYPE_UDP:
		case TYPE_TCP:
		case TYPE_RAW:
			push_pkt(L, cur->type, cur);
			lua_rawseti(L, -2, n++);
			break;
		}
	}

	assert(lua_gettop(L) == 2);

	rc = lua_pcall(L, 1, 1, 0);
	if (rc != 0) {
		const char *err = "unknown error";
		if (lua_type(L, -1) == LUA_TSTRING)
			err = lua_tostring(L, -1);

		fail_printf("Error running script: %s", err);
	}

	int status = lua_toboolean(L, -1);
	lua_pop(L, 1);

	assert(lua_gettop(L) == 0);

	return (status ? 0 : -1);

error:
	lua_settop(L, 0);
	return -1;
}

static int pktizr_IP(lua_State *L) {
	if (lua_gettop(L) != 0)
		luaL_error(L, "Invalid argument");

	struct pkt *p = pkt_new(TYPE_IP4);

	p->p.ip4.version = 4;
	p->p.ip4.ihl     = 5;
	p->p.ip4.ttl     = 64;

	push_pkt(L, TYPE_IP4, p);
	return 1;
}

static int pktizr_ICMP(lua_State *L) {
	if (lua_gettop(L) != 0)
		luaL_error(L, "Invalid argument");

	struct pkt *p = pkt_new(TYPE_ICMP);

	p->p.icmp.type = 8;

	push_pkt(L, TYPE_ICMP, p);
	return 1;
}

static int pktizr_UDP(lua_State *L) {
	if (lua_gettop(L) != 0)
		luaL_error(L, "Invalid argument");

	push_pkt(L, TYPE_UDP, NULL);
	return 1;
}

static int pktizr_TCP(lua_State *L) {
	if (lua_gettop(L) != 0)
		luaL_error(L, "Invalid argument");

	struct pkt *p = pkt_new(TYPE_TCP);

	p->p.tcp.doff   = 5;
	p->p.tcp.window = 5840;

	push_pkt(L, TYPE_TCP, p);
	return 1;
}

static int pktizr_Raw(lua_State *L) {
	if (lua_gettop(L) != 0)
		luaL_error(L, "Invalid argument");

	struct pkt *p = pkt_new(TYPE_RAW);

	p->p.raw.payload = NULL;

	push_pkt(L, TYPE_RAW, p);
	return 1;
}

static int pktizr_get_time(lua_State *L) {
	double now = (double) time_now() / 1e6;
	lua_pushnumber(L, now);

	return 1;
}

static uint64_t pktizr_cookie(lua_State *L) {
	struct pktizr_args *args;

	uint16_t dport, sport;
	struct in_addr daddr, saddr;

	if (lua_gettop(L) != 4)
		luaL_error(L, "Invalid number of arguments");

	dport = (uint16_t) lua_tonumber(L, -1);
	lua_pop(L, 1);

	sport = (uint16_t) lua_tonumber(L, -1);
	lua_pop(L, 1);

	if (lua_isnil(L, -1))
		luaL_error(L, "Invalid argument 'daddr': nil value");

	if (!inet_aton(lua_tostring(L, -1), &daddr))
		luaL_error(L, "Invalid argument 'daddr': not an IP address");

	lua_pop(L, 1);

	if (lua_isnil(L, -1))
		luaL_error(L, "Invalid argument 'saddr': nil value");

	if (!inet_aton(lua_tostring(L, -1), &saddr))
		luaL_error(L, "Invalid argument 'saddr': not an IP address");

	lua_pop(L, 1);

	lua_getfield(L, LUA_REGISTRYINDEX, "args");
	args = lua_touserdata(L, -1);

	return pkt_cookie(saddr.s_addr, daddr.s_addr, sport, dport, args->seed);
}

static int pktizr_cookie16(lua_State *L) {
	uint64_t cookie = pktizr_cookie(L);
	lua_pushnumber(L, (uint16_t) cookie);

	return 1;
}

static int pktizr_cookie32(lua_State *L) {
	uint64_t cookie = pktizr_cookie(L);
	lua_pushnumber(L, (uint32_t) cookie);

	return 1;
}

static int pktizr_get_addr(lua_State *L) {
	struct pktizr_args *args;

	char local_addr_str[INET_ADDRSTRLEN];
	uint32_t laddr;

	lua_getfield(L, LUA_REGISTRYINDEX, "args");
	args = lua_touserdata(L, -1);

	laddr = htonl(args->local_addr);
	inet_ntop(AF_INET, &laddr, local_addr_str, sizeof(local_addr_str));

	lua_pushstring(L, local_addr_str);

	return 1;

}

static int pktizr_print(lua_State *L) {
	luaL_checkstack(L, 1, "OOM");
	lua_getglobal(L, "string");
	lua_getfield(L, -1, "format");
	lua_insert(L, 1);

	lua_call(L, lua_gettop(L) - 1, 1);

	ok_printf("%s", lua_tostring(L, -1));
	return 0;
}

static int pktizr_send(lua_State *L) {
	struct pktizr_args *args = NULL;

	lua_getfield(L, LUA_REGISTRYINDEX, "args");
	args = lua_touserdata(L, -1);
	lua_pop(L, 1);

	struct pkt *pkt = pop_pkt(L, args);
	assert(lua_gettop(L) == 0);

	queue_enqueue(&args->queue, &pkt->queue);

	lua_pushboolean(L, 1);

	return 1;
}

static int pktizr_pkt_gc(lua_State* L) {
	void *u = lua_touserdata(L, -1);

	if (u == NULL)
		return 0;

	struct pkt *p = *(struct pkt **) u;
	pkt_free(p);

	return 0;
}

static int pktizr_pkt_newindex(lua_State* L) {
	struct pkt *p   = *(struct pkt **) lua_touserdata(L, -3);
	const char *key = lua_tostring(L, -2);

	switch (p->type) {
	case TYPE_IP4:
		p->length = set_ip4(L, key, &p->p.ip4);
		return 0;

	case TYPE_ICMP:
		p->length = set_icmp(L, key, &p->p.icmp);
		return 0;

	case TYPE_UDP:
		p->length = set_udp(L, key, &p->p.udp);
		return 0;

	case TYPE_TCP:
		p->length = set_tcp(L, key, &p->p.tcp);
		return 0;

	case TYPE_RAW:
		p->length = set_raw(L, key, &p->p.raw);
		return 0;
	}

	return 0;
}

static int pktizr_pkt_index(lua_State* L) {
	struct pkt *p   = *(struct pkt **) lua_touserdata(L, -2);
	const char *key = lua_tostring(L, -1);

	if (!strncmp("_type", key, sizeof("_type"))) {
		switch (p->type) {
		case TYPE_IP4:
			lua_pushstring(L, "ip4");
			return 1;

		case TYPE_ICMP:
			lua_pushstring(L, "icmp");
			return 1;

		case TYPE_UDP:
			lua_pushstring(L, "udp");
			return 1;

		case TYPE_TCP:
			lua_pushstring(L, "tcp");
			return 1;

		case TYPE_RAW:
			lua_pushstring(L, "raw");
			return 1;
		}
	}

	switch (p->type) {
	case TYPE_IP4:
		return get_ip4(L, key, &p->p.ip4);

	case TYPE_ICMP:
		return get_icmp(L, key, &p->p.icmp);

	case TYPE_UDP:
		return get_udp(L, key, &p->p.udp);

	case TYPE_TCP:
		return get_tcp(L, key, &p->p.tcp);

	case TYPE_RAW:
		return get_raw(L, key, &p->p.raw);
	}

	return 0;
}

LUALIB_API int luaopen_pkt(lua_State *L) {
	luaL_Reg const funcs[] = {
		{ "IP",       pktizr_IP       },
		{ "ICMP",     pktizr_ICMP     },
		{ "UDP",      pktizr_UDP      },
		{ "TCP",      pktizr_TCP      },
		{ "Raw",      pktizr_Raw      },
		{ "cookie16", pktizr_cookie16 },
		{ "cookie32", pktizr_cookie32 },
		{ "send",     pktizr_send     },
		{ NULL,       NULL            }
	};

	luaL_Reg const pkt_meta[] = {
		{ "__gc",       pktizr_pkt_gc       },
		{ "__index",    pktizr_pkt_index    },
		{ "__newindex", pktizr_pkt_newindex },
		{ NULL,         NULL                }
	};

	luaL_newlib(L, funcs);

	luaL_newmetatable(L, "pktizr.pkt");
	luaL_setfuncs(L, pkt_meta, 0);
	lua_setmetatable(L, -2);

	return 1;
}

LUALIB_API int luaopen_std(lua_State *L) {
	luaL_Reg const funcs[] = {
		{ "get_time", pktizr_get_time },
		{ "get_addr", pktizr_get_addr },
		{ "print",    pktizr_print    },
		{ NULL,       NULL            }
	};

	luaL_newlib(L, funcs);
	return 1;
}

static struct pkt *pop_pkt(lua_State *L, struct pktizr_args *args) {
	struct pkt *pkt = NULL;

	while (lua_gettop(L) != 0) {
		struct pkt *p = NULL;

		if (!lua_isuserdata(L, -1))
			luaL_error(L, "Invalid packet type");

		p = *(struct pkt **) lua_touserdata(L, -1);
		DL_APPEND(pkt, p);

		p->refcnt++;

		lua_pop(L, 1);
	}

	struct pkt *eth = pkt_new(TYPE_ETH);
	DL_APPEND(pkt, eth);

	pkt_build_eth(eth, args->local_mac, args->gateway_mac, 0);

	return pkt;
}

static void push_pkt(lua_State *L, enum pkt_type type, struct pkt *p) {
	struct pkt **pkt = lua_newuserdata(L, sizeof(*pkt));

	if (p == NULL)
		p = pkt_new(type);

	*pkt = p;

	luaL_setmetatable(L, "pktizr.pkt");
}

#define MATCH_KEY(NAME, KEY)				\
	(!strncmp(NAME, KEY, sizeof(NAME)))

#define MATCH_KEY_TYPE(NAME, KEY, TYPE)			\
	(MATCH_KEY(NAME, KEY) && lua_is##TYPE(L, -1))

static int get_ip4(lua_State *L, const char *key, struct ip4_hdr *ip4) {
	luaL_checkstack(L, 1, "OOM");

	if (MATCH_KEY("version", key)) {
		lua_pushnumber(L, ip4->version);
		goto done;
	}

	if (MATCH_KEY("ihl", key)) {
		lua_pushnumber(L, ip4->ihl);
		goto done;
	}

	if (MATCH_KEY("tos", key)) {
		lua_pushnumber(L, ip4->tos);
		goto done;
	}

	if (MATCH_KEY("len", key)) {
		lua_pushnumber(L, ip4->len);
		goto done;
	}

	if (MATCH_KEY("id", key)) {
		lua_pushnumber(L, ip4->id);
		goto done;
	}

	if (MATCH_KEY("frag", key)) {
		lua_pushnumber(L, ip4->frag_off);
		goto done;
	}

	if (MATCH_KEY("ttl", key)) {
		lua_pushnumber(L, ip4->ttl);
		goto done;
	}

	if (MATCH_KEY("proto", key)) {
		lua_pushnumber(L, ip4->proto);
		goto done;
	}

	if (MATCH_KEY("chksum", key)) {
		lua_pushnumber(L, ip4->chksum);
		goto done;
	}

	if (MATCH_KEY("src", key)) {
		struct in_addr saddr = { .s_addr = ip4->src };

		lua_pushstring(L, inet_ntoa(saddr));
		goto done;
	}

	if (MATCH_KEY("dst", key)) {
		struct in_addr daddr = { .s_addr = ip4->dst };

		lua_pushstring(L, inet_ntoa(daddr));
		goto done;
	}

	return luaL_error(L, "Invalid field '%s'", key);

done:
	return 1;
}

static int set_ip4(lua_State *L, const char *key, struct ip4_hdr *ip4) {
	if (MATCH_KEY_TYPE("version", key, number)) {
		ip4->version = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("ihl", key, number)) {
		ip4->ihl = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("tos", key, number)) {
		ip4->tos = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("len", key, number)) {
		ip4->len = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("id", key, number)) {
		ip4->id = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("frag", key, number)) {
		ip4->frag_off = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("ttl", key, number)) {
		ip4->ttl = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("proto", key, number)) {
		ip4->proto = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("chksum", key, number)) {
		ip4->version = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("src", key, string)) {
		inet_aton(lua_tostring(L, -1), (struct in_addr *) &ip4->src);
		goto done;
	}

	if (MATCH_KEY_TYPE("dst", key, string)) {
		inet_aton(lua_tostring(L, -1), (struct in_addr *) &ip4->dst);
		goto done;
	}

	return luaL_error(L, "Invalid field '%s'", key);

done:
	return 20;
}

static int get_icmp(lua_State *L, const char *key, struct icmp_hdr *icmp) {
	luaL_checkstack(L, 1, "OOM");

	if (MATCH_KEY("type", key)) {
		lua_pushnumber(L, icmp->type);
		goto done;
	}

	if (MATCH_KEY("code", key)) {
		lua_pushnumber(L, icmp->code);
		goto done;
	}

	if (MATCH_KEY("chksum", key)) {
		lua_pushnumber(L, icmp->chksum);
		goto done;
	}

	if (MATCH_KEY("id", key)) {
		lua_pushnumber(L, icmp->id);
		goto done;
	}

	if (MATCH_KEY("seq", key)) {
		lua_pushnumber(L, icmp->seq);
		goto done;
	}

	return luaL_error(L, "Invalid field '%s'", key);

done:
	return 1;
}

static int set_icmp(lua_State *L, const char *key, struct icmp_hdr *icmp) {
	if (MATCH_KEY_TYPE("type", key, number)) {
		icmp->type = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("code", key, number)) {
		icmp->code = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("chksum", key, number)) {
		icmp->chksum = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("id", key, number)) {
		icmp->id = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("seq", key, number)) {
		icmp->seq = lua_tonumber(L, -1);
		goto done;
	}

	return luaL_error(L, "Invalid field '%s'", key);

done:
	return 8;
}

static int get_udp(lua_State *L, const char *key, struct udp_hdr *udp) {
	luaL_checkstack(L, 1, "OOM");

	if (MATCH_KEY("sport", key)) {
		lua_pushnumber(L, udp->sport);
		goto done;
	}

	if (MATCH_KEY("dport", key)) {
		lua_pushnumber(L, udp->dport);
		goto done;
	}

	if (MATCH_KEY("len", key)) {
		lua_pushnumber(L, udp->len);
		goto done;
	}

	if (MATCH_KEY("chksum", key)) {
		lua_pushnumber(L, udp->chksum);
		goto done;
	}

	return luaL_error(L, "Invalid field '%s'", key);

done:
	return 1;
}

static int set_udp(lua_State *L, const char *key, struct udp_hdr *udp) {
	if (MATCH_KEY_TYPE("sport", key, number)) {
		udp->sport = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("dport", key, number)) {
		udp->dport = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("len", key, number)) {
		udp->len = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("chksum", key, number)) {
		udp->chksum = lua_tonumber(L, -1);
		goto done;
	}

	return luaL_error(L, "Invalid field '%s'", key);

done:
	return 8;
}

static int get_tcp(lua_State *L, const char *key, struct tcp_hdr *tcp) {
	luaL_checkstack(L, 1, "OOM");

	if (MATCH_KEY("sport", key)) {
		lua_pushnumber(L, tcp->sport);
		goto done;
	}

	if (MATCH_KEY("dport", key)) {
		lua_pushnumber(L, tcp->dport);
		goto done;
	}

	if (MATCH_KEY("seq", key)) {
		lua_pushnumber(L, tcp->seq);
		goto done;
	}

	if (MATCH_KEY("ack_seq", key)) {
		lua_pushnumber(L, tcp->ack_seq);
		goto done;
	}

	if (MATCH_KEY("doff", key)) {
		lua_pushnumber(L, tcp->doff);
		goto done;
	}

	if (MATCH_KEY("fin", key)) {
		lua_pushboolean(L, tcp->fin);
		goto done;
	}

	if (MATCH_KEY("syn", key)) {
		lua_pushboolean(L, tcp->syn);
		goto done;
	}

	if (MATCH_KEY("rst", key)) {
		lua_pushboolean(L, tcp->rst);
		goto done;
	}

	if (MATCH_KEY("psh", key)) {
		lua_pushboolean(L, tcp->psh);
		goto done;
	}

	if (MATCH_KEY("ack", key)) {
		lua_pushboolean(L, tcp->ack);
		goto done;
	}

	if (MATCH_KEY("urg", key)) {
		lua_pushboolean(L, tcp->urg);
		goto done;
	}

	if (MATCH_KEY("ece", key)) {
		lua_pushboolean(L, tcp->ece);
		goto done;
	}

	if (MATCH_KEY("cwr", key)) {
		lua_pushboolean(L, tcp->cwr);
		goto done;
	}

	if (MATCH_KEY("ns", key)) {
		lua_pushboolean(L, tcp->ns);
		goto done;
	}

	if (MATCH_KEY("window", key)) {
		lua_pushnumber(L, tcp->window);
		goto done;
	}

	if (MATCH_KEY("chksum", key)) {
		lua_pushnumber(L, tcp->chksum);
		goto done;
	}

	if (MATCH_KEY("urg_ptr", key)) {
		lua_pushnumber(L, tcp->urg_ptr);
		goto done;
	}

	return luaL_error(L, "Invalid field '%s'", key);

done:
	return 1;
}

static int set_tcp(lua_State *L, const char *key, struct tcp_hdr *tcp) {
	if (MATCH_KEY_TYPE("sport", key, number)) {
		tcp->sport = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("dport", key, number)) {
		tcp->dport = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("seq", key, number)) {
		tcp->seq = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("ack_seq", key, number)) {
		tcp->ack_seq = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("doff", key, number)) {
		tcp->doff = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("fin", key, boolean)) {
		tcp->fin = lua_toboolean(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("syn", key, boolean)) {
		tcp->syn = lua_toboolean(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("rst", key, boolean)) {
		tcp->rst = lua_toboolean(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("psh", key, boolean)) {
		tcp->psh = lua_toboolean(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("ack", key, boolean)) {
		tcp->ack = lua_toboolean(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("urg", key, boolean)) {
		tcp->urg = lua_toboolean(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("ece", key, boolean)) {
		tcp->ece = lua_toboolean(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("cwr", key, boolean)) {
		tcp->cwr = lua_toboolean(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("ns", key, boolean)) {
		tcp->ns = lua_toboolean(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("window", key, number)) {
		tcp->window = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("chksum", key, number)) {
		tcp->chksum = lua_tonumber(L, -1);
		goto done;
	}

	if (MATCH_KEY_TYPE("urg_ptr", key, number)) {
		tcp->urg_ptr = lua_tonumber(L, -1);
		goto done;
	}

	return luaL_error(L, "Invalid field '%s'", key);

done:
	return 20;
}

static int get_raw(lua_State *L, const char *key, struct raw_hdr *raw) {
	luaL_checkstack(L, 1, "OOM");

	if (MATCH_KEY("payload", key)) {
		lua_pushlstring(L, (const char *) raw->payload, raw->len);
		goto done;
	}

	return luaL_error(L, "Invalid field '%s'", key);

done:
	return 1;
}

static int set_raw(lua_State *L, const char *key, struct raw_hdr *raw) {
	if (MATCH_KEY_TYPE("payload", key, string)) {
		const char *payload = lua_tolstring(L, -1, &raw->len);

		if (raw->payload)
			free(raw->payload);

		raw->payload = malloc(raw->len);
		memcpy(raw->payload, payload, raw->len);

		goto done;
	}

	return luaL_error(L, "Invalid field '%s'", key);

done:
	return raw->len;
}
