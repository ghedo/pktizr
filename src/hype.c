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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>
#include <fcntl.h>

#include <pthread.h>

#include <arpa/inet.h>
#include <net/if.h>

#include <talloc.h>

#include "bucket.h"
#include "hype.h"
#include "netif.h"
#include "ranges.h"
#include "resolv.h"
#include "routes.h"
#include "script.h"
#include "printf.h"
#include "util.h"

static const char *short_opts = "S:p:r:s:w:c:qh?";

static struct option long_opts[] = {
	{ "script",      required_argument, NULL, 'S' },
	{ "ports",       required_argument, NULL, 'p' },
	{ "rate",        required_argument, NULL, 'r' },
	{ "seed",        required_argument, NULL, 's' },
	{ "wait",        required_argument, NULL, 'w' },
	{ "count",       required_argument, NULL, 'c' },

	{ "quiet",       no_argument,       NULL, 'q' },

	{ "help",        no_argument,       NULL, 'h' },
	{ 0, 0, 0, 0 }
};

static void start_send(struct hype_args *args);
static void start_recv(struct hype_args *args);

static void *send_cb(void *p);
static void *recv_cb(void *p);

static void status_line(struct hype_args *args);

static uint64_t get_entropy(void);

static inline void help(void);

int main(int argc, char *argv[]) {
	int rc, i;

	_ta_free_ struct hype_args *args = NULL;

	if (argc < 4) {
		help();
		return 0;
	}

	args = talloc_ptrtype(NULL, args);

	/* TODO: add --exclude option */

	args->targets = range_parse_targets(args, argv[1]);
	args->ports   = range_parse_ports(args, "0");
	args->rate    = 100;
	args->seed    = get_entropy();
	args->wait    = 5;
	args->count   = 1;
	args->quiet   = false;
	args->done    = false;

	while ((rc = getopt_long(argc, argv, short_opts, long_opts, &i)) !=-1) {
		char *end;

		switch (rc) {
		case 'S':
			args->script = talloc_strdup(args, optarg);
			break;

		case 'p':
			validate_optlist("--ports", optarg);
			talloc_free(args->ports);

			args->ports = range_parse_ports(args, optarg);
			break;

		case 'r':
			args->rate = strtoull(optarg, &end, 10);
			if (*end != '\0')
				fail_printf("Invalid rate value");
			break;

		case 's':
			args->seed = strtoull(optarg, &end, 10);
			if (*end != '\0')
				fail_printf("Invalid seed value");
			break;

		case 'w':
			args->wait = strtoull(optarg, &end, 10);
			if (*end != '\0')
				fail_printf("Invalid wait value");
			break;

		case 't':
			args->count = strtoull(optarg, &end, 10);
			if (*end != '\0')
				fail_printf("Invalid wait value");
			break;

		case 'q':
			args->quiet = true;
			break;

		case '?':
		case 'h':
			help();
			return 0;
		}
	}

	/* TODO: make local_addr/mac, gateway_addr/mac configurable */

	struct route route;
	rc = routes_get_default(&route);
	if (rc < 0)
		fail_printf("Error getting routes");

	args->local_addr   = ntohl(route.pref_addr);
	args->gateway_addr = ntohl(route.gate_addr);

	rc = resolve_ifname_to_mac(route.if_name, args->local_mac);
	if (rc < 0)
		fail_printf("Error resolving local MAC");

	args->netif = netif_open_pcap(route.if_name);
	if (!args->netif)
		fail_printf("Error opening netif");

	rc = resolv_addr_to_mac(args->netif,
	                        args->local_mac, args->local_addr,
	                        args->gateway_mac, args->gateway_addr);
	if (rc < 0)
		fail_printf("Error resolving local MAC");

	start_recv(args);
	start_send(args);

	status_line(args);

	pthread_join(args->send_thread, NULL);

	time_sleep(args->wait * 1e6);

	args->done = true;

	pthread_join(args->recv_thread, NULL);

	args->netif->close(args->netif);

	return 0;
}

static void start_send(struct hype_args *args) {
	pthread_mutex_init(&args->send_mutex, NULL);
	pthread_cond_init(&args->send_started, NULL);
	pthread_create(&args->send_thread, NULL, send_cb, args);

	pthread_mutex_lock(&args->send_mutex);
	pthread_cond_wait(&args->send_started, &args->send_mutex);
	pthread_mutex_unlock(&args->send_mutex);
}

static void start_recv(struct hype_args *args) {
	pthread_mutex_init(&args->recv_mutex, NULL);
	pthread_cond_init(&args->recv_started, NULL);
	pthread_create(&args->recv_thread, NULL, recv_cb, args);

	pthread_mutex_lock(&args->recv_mutex);
	pthread_cond_wait(&args->recv_started, &args->recv_mutex);
	pthread_mutex_unlock(&args->recv_mutex);
}

static void *send_cb(void *p) {
	struct hype_args *args = p;

	void *L   = script_load(args);
	void *mem = talloc_new(args);

	struct bucket bucket;
	bucket_init(&bucket, args->rate);

	size_t tgt_cnt = range_list_count(args->targets);
	size_t prt_cnt = range_list_count(args->ports);
	size_t tot_cnt = tgt_cnt * prt_cnt * args->count;

	uint8_t *buf = talloc_size(args, 65535);
	size_t   len = 65535;

	args->pkt_sent  = 0;
	args->pkt_count = tot_cnt;

	printf("Scanning %zu ports on %zu hosts...\n", prt_cnt, tgt_cnt);

	pthread_cond_signal(&args->send_started);

	/* TODO: randomize targets */
	for (size_t i = 0; i < tot_cnt; i++) {
		int pkt_len;

		bucket_consume(&bucket);

		uint32_t daddr = range_list_pick(args->targets,
		                              (i % tgt_cnt) / args->count);
		uint16_t dport = range_list_pick(args->ports,
		                              (i / tgt_cnt) / args->count);

		pkt_len = script_assemble(L, mem, args, buf, len, daddr, dport);
		if (pkt_len < 0)
			continue;

		args->netif->inject(args->netif, buf, pkt_len);

		args->pkt_sent++;
	}

	script_close(L);

	return NULL;
}

static void *recv_cb(void *p) {
	struct hype_args *args = p;

	void *L   = script_load(args);
	void *mem = talloc_new(args);

	args->pkt_recv = 0;

	pthread_cond_signal(&args->recv_started);

	while (!args->done) {
		int rc, len;

		const uint8_t *buf = args->netif->capture(args->netif, &len);
		if (buf == NULL)
			continue;

		rc = script_analyze(L, mem, args, (uint8_t *) buf, len);
		if (rc < 0)
			continue;

		args->pkt_recv++;
	}

	script_close(L);

	return NULL;
}

static void status_line(struct hype_args *args) {
	/* TODO: handle ctrl+c */
	uint64_t tot      = args->pkt_count;
	uint64_t now_old  = time_now();
	uint64_t sent_old = args->pkt_sent;

	while (1) {
		uint64_t now   = time_now();
		uint64_t sent  = args->pkt_sent;

		double rate    = (sent - sent_old) / ((now - now_old) / 1e6);
		double percent = (double) sent * 100 / tot;

		if (!args->quiet) {
			fprintf(stderr, "\033[K");
			fprintf(stderr, "Progress: %3.2f%% ", percent);
			fprintf(stderr, "Rate: %3.2fkpps ", rate / 1000);
			fprintf(stderr, "Sent: %zu ", sent);
			fprintf(stderr, "Replies: %zu ", args->pkt_recv);
			fprintf(stderr, "\r");
		}

		now_old  = now;
		sent_old = sent;

		if (sent == tot)
			break;

		time_sleep(250000);
	}
}

static uint64_t get_entropy(void) {
	uint64_t entropy;

	_close_ int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		sysf_printf("open(/dev/urandom)");

	int rc = read(fd, &entropy, sizeof(entropy));
	if (rc != sizeof(entropy))
		sysf_printf("read(/dev/urandom)");

	return entropy;
}

static inline void help(void) {
	#define CMD_HELP(CMDL, CMDS, MSG) printf("  %s, %-15s \t%s.\n", COLOR_YELLOW CMDS, CMDL COLOR_OFF, MSG);

	printf(COLOR_RED "Usage: " COLOR_OFF);
	printf(COLOR_GREEN "hype " COLOR_OFF);
	puts("<targets> [options]\n");

	puts(COLOR_RED " Options:" COLOR_OFF);

	CMD_HELP("--script", "-S", "Load and run the given script");

	puts("");

	CMD_HELP("--ports", "-p", "Use the specified port ranges");
	CMD_HELP("--rate",  "-r", "Send packets no faster than the specified rate");
	CMD_HELP("--seed",  "-s", "Use the given number as seed value");
	CMD_HELP("--wait",  "-w", "Wait the given amount of seconds after the scan is complete");
	CMD_HELP("--count", "-c", "Send the given amount of duplicate packets");
	CMD_HELP("--quiet", "-q", "Don't show the status line");

	puts("");

	CMD_HELP("--help", "-h", "Show this help");

	puts("");
}
