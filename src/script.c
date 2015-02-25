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

#include <utlist.h>

#include "c-api/compat-5.3.h"

#include "hype.h"
#include "netif.h"
#include "pkt.h"
#include "printf.h"
#include "util.h"

static struct pkt *get_pkt(lua_State *L, struct hype_args *args);

static int get_type(lua_State *L);

static int get_ip4(lua_State *L, struct ip4_hdr *ip4);
static int set_ip4(lua_State *L, struct ip4_hdr *ip4);

static int get_icmp(lua_State *L, struct icmp_hdr *icmp);
static int set_icmp(lua_State *L, struct icmp_hdr *icmp);

static int get_udp(lua_State *L, struct udp_hdr *udp);
static int set_udp(lua_State *L, struct udp_hdr *udp);

static int get_tcp(lua_State *L, struct tcp_hdr *tcp);
static int set_tcp(lua_State *L, struct tcp_hdr *tcp);

static int get_raw(lua_State *L, struct raw_hdr *raw);
static int set_raw(lua_State *L, struct raw_hdr *raw);

static int hype_IP(lua_State *L);
static int hype_ICMP(lua_State *L);
static int hype_UDP(lua_State *L);
static int hype_TCP(lua_State *L);
static int hype_Raw(lua_State *L);
static int hype_cookie16(lua_State *L);
static int hype_cookie32(lua_State *L);
static int hype_print(lua_State *L);
static int hype_send(lua_State *L);

static const luaL_Reg hype_fns[] = {
	{ "IP",       hype_IP       },
	{ "ICMP",     hype_ICMP     },
	{ "UDP",      hype_UDP      },
	{ "TCP",      hype_TCP      },
	{ "Raw",      hype_Raw      },
	{ "cookie16", hype_cookie16 },
	{ "cookie32", hype_cookie32 },
	{ "print",    hype_print    },
	{ "send",     hype_send     },
	{ NULL,       NULL          }
};

static const luaL_Reg loadedlibs[] = {
  {"_G", luaopen_base},
  {LUA_LOADLIBNAME, luaopen_package},
  /* {LUA_COLIBNAME, luaopen_coroutine}, */
  {LUA_TABLIBNAME, luaopen_table},
  {LUA_IOLIBNAME, luaopen_io},
  {LUA_OSLIBNAME, luaopen_os},
  {LUA_STRLIBNAME, luaopen_string},
  {LUA_MATHLIBNAME, luaopen_math},
  /* {LUA_UTF8LIBNAME, luaopen_utf8}, */
  {LUA_DBLIBNAME, luaopen_debug},
#if defined(LUA_COMPAT_BITLIB)
  {LUA_BITLIBNAME, luaopen_bit32},
#endif
  {NULL, NULL}
};

void *script_load(struct hype_args *args) {
	int rc;

	lua_State *L = luaL_newstate();
	if (L == NULL)
		fail_printf("Error creating Lua state");

	luaL_openlibs(L);

	/* luaL_getsubtable(L, LUA_REGISTRYINDEX, "_LOADED"); */
	/* lua_pop(L, 1); */

	/* for (const luaL_Reg *lib = loadedlibs; lib->func; lib++) { */
	/* 	luaL_requiref(L, lib->name, lib->func, 1); */
	/* 	lua_pop(L, 1); */
	/* } */

	lua_newtable(L);

	luaL_setfuncs(L, hype_fns, 0);

	luaopen_compat53_string(L);
	lua_setfield(L, -2, "string");

	char local_addr_str[INET_ADDRSTRLEN];
	uint32_t laddr = htonl(args->local_addr);
	inet_ntop(AF_INET, &laddr, local_addr_str, sizeof(local_addr_str));

	lua_pushstring(L, local_addr_str);
	lua_setfield(L, -2, "local_addr");

	lua_pushlightuserdata(L, args);
	lua_setfield(L, LUA_REGISTRYINDEX, "args");

	lua_setglobal(L, "hype");

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

int script_loop(void *L, struct hype_args *args,
                    uint32_t daddr, uint16_t dport) {
	int rc;

	char dst_addr[INET_ADDRSTRLEN];
	daddr = htonl(daddr);
	inet_ntop(AF_INET, &daddr, dst_addr, sizeof(dst_addr));

	assert(lua_gettop(L) == 0);

	luaL_checkstack(L, 1, "OOM");
	lua_getglobal(L, "loop");

	if (lua_isnil(L, -1))
		goto error;

	luaL_checkstack(L, 1, "OOM");
	lua_pushstring(L, dst_addr);

	luaL_checkstack(L, 1, "OOM");
	lua_pushinteger(L, dport);

	rc = lua_pcall(L, 2, LUA_MULTRET, 0);
	if (rc != 0) {
		const char *err = "unknown error";
		if (lua_type(L, -1) == LUA_TSTRING)
			err = lua_tostring(L, -1);

		fail_printf("Error running script: %s", err);
	}

	struct pkt *pkt = get_pkt(L, args);
	pkt->probe = true;

	assert(lua_gettop(L) == 0);

	cds_wfcq_enqueue(&args->queue_head, &args->queue_tail, &pkt->queue);

	return 0;

error:
	lua_settop(L, 0);
	return -1;
}

int script_recv(void *L, struct hype_args *args, struct pkt *pkt) {
	int rc, n = 1;

	struct pkt *cur;

	assert(lua_gettop(L) == 0);

	luaL_checkstack(L, 1, "OOM");
	lua_getglobal(L, "recv");

	if (lua_isnil(L, -1))
		goto error;

	luaL_checkstack(L, 1, "OOM");
	lua_newtable(L);

	DL_FOREACH(pkt, cur) {
		luaL_checkstack(L, 1, "OOM");

		switch (cur->type) {
		case TYPE_ETH:
		case TYPE_ARP:
			break;

		case TYPE_IP4:
			lua_newtable(L);

			set_ip4(L, &cur->p.ip4);
			lua_rawseti(L, -2, n++);
			break;

		case TYPE_ICMP:
			lua_newtable(L);

			set_icmp(L, &cur->p.icmp);
			lua_rawseti(L, -2, n++);
			break;

		case TYPE_UDP:
			lua_newtable(L);

			set_udp(L, &cur->p.udp);
			lua_rawseti(L, -2, n++);
			break;

		case TYPE_TCP:
			lua_newtable(L);

			set_tcp(L, &cur->p.tcp);
			lua_rawseti(L, -2, n++);
			break;

		case TYPE_RAW:
			lua_newtable(L);

			set_raw(L, &cur->p.raw);
			lua_rawseti(L, -2, n++);
			break;

		default:
			fail_printf("Invalid packet type: %u", cur->type);
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

static int hype_IP(lua_State *L) {
	if ((lua_gettop(L) == 0) || !lua_istable(L, -1))
		luaL_error(L, "Invalid argument");

	struct ip4_hdr ip4 = {
		.version = 4,
		.ihl     = 5,
		.ttl     = 64,
	};

	get_ip4(L, &ip4);
	set_ip4(L, &ip4);

	return 1;
}

static int hype_ICMP(lua_State *L) {
	if ((lua_gettop(L) != 1) || !lua_istable(L, -1))
		luaL_error(L, "Invalid argument");

	struct icmp_hdr icmp = {
		.type = 8,
	};

	get_icmp(L, &icmp);
	set_icmp(L, &icmp);

	return 1;
}

static int hype_UDP(lua_State *L) {
	if ((lua_gettop(L) != 1) || !lua_istable(L, -1))
		luaL_error(L, "Invalid argument");

	struct udp_hdr udp = { 0 };

	get_udp(L, &udp);
	set_udp(L, &udp);

	return 1;
}

static int hype_TCP(lua_State *L) {
	if ((lua_gettop(L) != 1) || !lua_istable(L, -1))
		luaL_error(L, "Invalid argument");

	struct tcp_hdr tcp = {
		.doff   = 5,
		.window = 5840,
	};

	get_tcp(L, &tcp);
	set_tcp(L, &tcp);

	return 1;
}

static int hype_Raw(lua_State *L) {
	if ((lua_gettop(L) != 1) || !lua_istable(L, -1))
		luaL_error(L, "Invalid argument");

	struct raw_hdr raw = {
		.payload = NULL,
	};

	get_raw(L, &raw);
	set_raw(L, &raw);

	return 1;
}

static uint64_t hype_cookie(lua_State *L) {
	struct hype_args *args;

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

static int hype_cookie16(lua_State *L) {
	uint64_t cookie = hype_cookie(L);
	lua_pushnumber(L, (uint16_t) cookie);

	return 1;
}

static int hype_cookie32(lua_State *L) {
	uint64_t cookie = hype_cookie(L);
	lua_pushnumber(L, (uint32_t) cookie);

	return 1;
}

static int hype_print(lua_State *L) {
	luaL_checkstack(L, 1, "OOM");
	lua_getglobal(L, "string");
	lua_getfield(L, -1, "format");
	lua_insert(L, 1);

	lua_call(L, lua_gettop(L) - 1, 1);

	ok_printf("%s", lua_tostring(L, -1));
	return 0;
}

static int hype_send(lua_State *L) {
	struct hype_args *args = NULL;

	lua_getfield(L, LUA_REGISTRYINDEX, "args");
	args = lua_touserdata(L, -1);
	lua_pop(L, 1);

	struct pkt *pkt = get_pkt(L, args);
	assert(lua_gettop(L) == 0);

	cds_wfcq_enqueue(&args->queue_head, &args->queue_tail, &pkt->queue);

	lua_pushboolean(L, 1);

	return 1;
}

static struct pkt *get_pkt(lua_State *L, struct hype_args *args) {
	struct pkt *pkt = NULL;

	while (lua_gettop(L) != 0) {
		if (!lua_istable(L, -1))
			luaL_error(L, "Invalid packet type");

		uint16_t type = get_type(L);

		struct pkt *p = pkt_new(NULL, type);
		DL_APPEND(pkt, p);

		switch (type) {
		case TYPE_IP4:
			p->length = get_ip4(L, &p->p.ip4);
			break;

		case TYPE_ICMP:
			p->length = get_icmp(L, &p->p.icmp);
			break;

		case TYPE_UDP:
			p->length = get_udp(L, &p->p.udp);
			break;

		case TYPE_TCP:
			p->length = get_tcp(L, &p->p.tcp);
			break;

		case TYPE_RAW:
			p->length = get_raw(L, &p->p.raw);
			break;

		default:
			luaL_error(L, "Invalid packet type: %u", type);
		}

		lua_pop(L, 1);
	}

	struct pkt *eth = pkt_new(NULL, TYPE_ETH);
	DL_APPEND(pkt, eth);

	pkt_build_eth(eth, args->local_mac, args->gateway_mac, 0);

	return pkt;
}

#define luaH_getfield(STATE, FIELD, TYPE, OUT)				\
do {									\
	luaL_checkstack(STATE, 1, "OOM");				\
	lua_getfield(STATE, -1, FIELD);					\
									\
	if (!lua_isnil(STATE, -1)) {					\
		if (!lua_is##TYPE(STATE, -1))				\
			fail_printf("Invalid value for field '%s'", FIELD); \
									\
		OUT = lua_to##TYPE(STATE, -1);				\
	}								\
									\
	lua_pop(STATE, 1);						\
} while (0);

#define luaH_setfield(STATE, FIELD, TYPE, IN)				\
do {									\
	luaL_checkstack(STATE, 1, "OOM");				\
	lua_push##TYPE(STATE, IN);					\
	lua_setfield(STATE, -2, FIELD);					\
} while (0);

static int get_type(lua_State *L) {
	const char *type = NULL;

	luaH_getfield(L, "_type", string, type);
	if (type == NULL)
		return TYPE_NONE;

	if (strcmp(type, "ip4") == 0)
		return TYPE_IP4;
	else if (strcmp(type, "icmp") == 0)
		return TYPE_ICMP;
	else if (strcmp(type, "udp") == 0)
		return TYPE_UDP;
	else if (strcmp(type, "tcp") == 0)
		return TYPE_TCP;
	else if (strcmp(type, "raw") == 0)
		return TYPE_RAW;

	return TYPE_NONE;
}

static int get_ip4(lua_State *L, struct ip4_hdr *ip4) {
	luaH_getfield(L, "version", number, ip4->version);
	luaH_getfield(L, "ihl", number, ip4->ihl);
	luaH_getfield(L, "tos", number, ip4->tos);

	luaH_getfield(L, "len", number, ip4->len);
	luaH_getfield(L, "id", number, ip4->id);
	luaH_getfield(L, "frag", number, ip4->frag_off);

	luaH_getfield(L, "ttl", number, ip4->ttl);
	luaH_getfield(L, "proto", number, ip4->proto);

	luaH_getfield(L, "chksum", number, ip4->chksum);

	const char *saddr = NULL;
	luaH_getfield(L, "src", string, saddr);
	if (saddr)
		inet_aton(saddr, (struct in_addr *) &ip4->src);

	const char *daddr = NULL;
	luaH_getfield(L, "dst", string, daddr);
	if (daddr)
		inet_aton(daddr, (struct in_addr *) &ip4->dst);

	return 20;
}

static int set_ip4(lua_State *L, struct ip4_hdr *ip4) {
	luaH_setfield(L, "_type", string, "ip4");

	luaH_setfield(L, "version", number, ip4->version);
	luaH_setfield(L, "ihl", number, ip4->ihl);
	luaH_setfield(L, "tos", number, ip4->tos);

	luaH_setfield(L, "len", number, ip4->len);
	luaH_setfield(L, "id", number, ip4->id);
	luaH_setfield(L, "frag", number, ip4->frag_off);

	luaH_setfield(L, "ttl", number, ip4->ttl);

	if (ip4->proto != 0)
		luaH_setfield(L, "proto", number, ip4->proto);

	luaH_setfield(L, "chksum", number, ip4->chksum);

	struct in_addr saddr = { .s_addr = ip4->src };
	luaH_setfield(L, "src", string, inet_ntoa(saddr));

	struct in_addr daddr = { .s_addr = ip4->dst };
	luaH_setfield(L, "dst", string, inet_ntoa(daddr));

	return 20;
}

static int get_icmp(lua_State *L, struct icmp_hdr *icmp) {
	luaH_getfield(L, "type", number, icmp->type);
	luaH_getfield(L, "code", number, icmp->code);
	luaH_getfield(L, "chksum", number, icmp->chksum);

	luaH_getfield(L, "id", number, icmp->id);
	luaH_getfield(L, "seq", number, icmp->seq);

	return 8;
}

static int set_icmp(lua_State *L, struct icmp_hdr *icmp) {
	luaH_setfield(L, "_type", string, "icmp");

	luaH_setfield(L, "type", number, icmp->type);
	luaH_setfield(L, "code", number, icmp->code);
	luaH_setfield(L, "chksum", number, icmp->chksum);

	luaH_setfield(L, "id", number, icmp->id);
	luaH_setfield(L, "seq", number, icmp->seq);

	return 8;
}

static int get_udp(lua_State *L, struct udp_hdr *udp) {
	luaH_getfield(L, "sport", number, udp->sport);
	luaH_getfield(L, "dport", number, udp->dport);

	luaH_getfield(L, "len", number, udp->len);
	luaH_getfield(L, "chksum", number, udp->chksum);

	return 8;
}

static int set_udp(lua_State *L, struct udp_hdr *udp) {
	luaH_setfield(L, "_type", string, "udp");

	luaH_setfield(L, "sport", number, udp->sport);
	luaH_setfield(L, "dport", number, udp->dport);

	luaH_setfield(L, "len", number, udp->len);
	luaH_setfield(L, "chksum", number, udp->chksum);

	return 8;
}

static int get_tcp(lua_State *L, struct tcp_hdr *tcp) {
	luaH_getfield(L, "sport", number, tcp->sport);
	luaH_getfield(L, "dport", number, tcp->dport);
	luaH_getfield(L, "seq", number, tcp->seq);
	luaH_getfield(L, "ack_seq", number, tcp->ack_seq);

	luaH_getfield(L, "doff", number, tcp->doff);

	luaH_getfield(L, "fin", boolean, tcp->fin);
	luaH_getfield(L, "syn", boolean, tcp->syn);
	luaH_getfield(L, "rst", boolean, tcp->rst);
	luaH_getfield(L, "psh", boolean, tcp->psh);
	luaH_getfield(L, "ack", boolean, tcp->ack);
	luaH_getfield(L, "urg", boolean, tcp->urg);
	luaH_getfield(L, "ece", boolean, tcp->ece);
	luaH_getfield(L, "cwr", boolean, tcp->cwr);
	luaH_getfield(L, "ns", boolean, tcp->ns);

	luaH_getfield(L, "window", number, tcp->window);
	luaH_getfield(L, "chksum", number, tcp->chksum);
	luaH_getfield(L, "urg_ptr", number, tcp->urg_ptr);

	return 20;
}

static int set_tcp(lua_State *L, struct tcp_hdr *tcp) {
	luaH_setfield(L, "_type", string, "tcp");

	luaH_setfield(L, "sport", number, tcp->sport);
	luaH_setfield(L, "dport", number, tcp->dport);
	luaH_setfield(L, "seq", number, tcp->seq);
	luaH_setfield(L, "ack_seq", number, tcp->ack_seq);

	luaH_setfield(L, "doff", number, tcp->doff);

	luaH_setfield(L, "fin", boolean, tcp->fin);
	luaH_setfield(L, "syn", boolean, tcp->syn);
	luaH_setfield(L, "rst", boolean, tcp->rst);
	luaH_setfield(L, "psh", boolean, tcp->psh);
	luaH_setfield(L, "ack", boolean, tcp->ack);
	luaH_setfield(L, "urg", boolean, tcp->urg);
	luaH_setfield(L, "ece", boolean, tcp->ece);
	luaH_setfield(L, "cwr", boolean, tcp->cwr);
	luaH_setfield(L, "ns", boolean, tcp->ns);

	luaH_setfield(L, "window", number, tcp->window);
	luaH_setfield(L, "chksum", number, tcp->chksum);
	luaH_setfield(L, "urg_ptr", number, tcp->urg_ptr);

	return 20;
}

static int get_raw(lua_State *L, struct raw_hdr *raw) {
	luaL_checkstack(L, 1, "OOM");
	lua_getfield(L, -1, "payload");

	if (!lua_isnil(L, -1)) {
		if (!lua_isstring(L, -1))
			fail_printf("Invalid value for field 'payload'");

		const char *payload = lua_tolstring(L, -1, &raw->len);

		if (raw->payload)
			free(raw->payload);

		raw->payload = malloc(raw->len);
		memcpy(raw->payload, payload, raw->len);
	}

	lua_pop(L, 1);
	return raw->len;
}

static int set_raw(lua_State *L, struct raw_hdr *raw) {
	luaH_setfield(L, "_type", string, "raw");

	luaL_checkstack(L, 1, "OOM");
	lua_pushlstring(L, (const char *) raw->payload, raw->len);
	lua_setfield(L, -2, "payload");

	return raw->len;
}
