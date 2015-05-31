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
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>
#include <fcntl.h>

#include <pthread.h>
#include <signal.h>

#include <arpa/inet.h>
#include <net/if.h>

#include <urcu/uatomic.h>

#include "bucket.h"
#include "netdev.h"
#include "shuffle.h"
#include "ranges.h"
#include "resolv.h"
#include "routes.h"
#include "queue.h"
#include "pkt.h"
#include "printf.h"
#include "util.h"
#include "pktizr.h"
#include "script.h"

static const char *short_opts = "S:p:r:s:w:c:l:g:n:Rqh?";

static bool stop = false;

static struct option long_opts[] = {
	{ "script",      required_argument, NULL, 'S' },
	{ "ports",       required_argument, NULL, 'p' },
	{ "rate",        required_argument, NULL, 'r' },
	{ "seed",        required_argument, NULL, 's' },
	{ "wait",        required_argument, NULL, 'w' },
	{ "count",       required_argument, NULL, 'c' },

	{ "local-addr",  required_argument, NULL, 'l' },
	{ "gateway-addr",required_argument, NULL, 'g' },

	{ "netdev",      required_argument, NULL, 'n' },

	{ "shuffle",     required_argument, NULL, 'R' },

	{ "quiet",       no_argument,       NULL, 'q' },

	{ "help",        no_argument,       NULL, 'h' },
	{ 0, 0, 0, 0 }
};

static void *recv_cb(void *p);
static void *loop_cb(void *p);

static void status_line(struct pktizr_args *args);
static void setup_signals(void);

static uint64_t get_entropy(void);

static inline void help(void);

#define START_THREAD(MUTEX, COND, THREAD, FUNC, ARGS)	\
	pthread_mutex_init(&ARGS->MUTEX, NULL);		\
	pthread_cond_init(&ARGS->COND, NULL);		\
	pthread_mutex_lock(&ARGS->MUTEX);		\
	pthread_create(&ARGS->THREAD, NULL, FUNC, ARGS);\
	pthread_cond_wait(&ARGS->COND, &ARGS->MUTEX);	\
	pthread_mutex_unlock(&ARGS->MUTEX);		\

int main(int argc, char *argv[]) {
	int rc, i;

	_free_ struct pktizr_args *args = NULL;

	_free_ char *local_addr = NULL;
	_free_ char *gateway_addr = NULL;

	_free_ char *netdev = NULL;

	if (argc < 4) {
		help();
		return 0;
	}

	args = malloc(sizeof(*args));

	/* TODO: add --exclude option */

	args->targets = range_parse_targets(args, argv[1]);
	args->ports   = range_parse_ports(args, "1");
	args->rate    = 100;
	args->seed    = get_entropy();
	args->wait    = 5;
	args->count   = 1;
	args->script  = NULL;
	args->quiet   = !isatty(STDERR_FILENO);
	args->done    = false;
	args->stop    = false;

	while ((rc = getopt_long(argc, argv, short_opts, long_opts, &i)) !=-1) {
		char *end;

		switch (rc) {
		case 'S':
			args->script = strdup(optarg);
			break;

		case 'p':
			validate_optlist("--ports", optarg);
			free(args->ports);

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

		case 'c':
			args->count = strtoull(optarg, &end, 10);
			if (*end != '\0')
				fail_printf("Invalid wait value");
			break;

		case 'R':
			args->shuffle = true;
			break;

		case 'l':
			freep(&local_addr);
			local_addr = strdup(optarg);
			break;

		case 'g':
			freep(&gateway_addr);
			gateway_addr = strdup(optarg);
			break;

		case 'n':
			freep(&netdev);
			netdev = strdup(optarg);
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

	if (!args->script)
		fail_printf("No script provided");

	struct route route;
	rc = routes_get_default(&route);
	if (rc < 0)
		fail_printf("Error getting routes");

	if (gateway_addr)
		args->local_addr = ntohl(inet_addr(gateway_addr));
	else
		args->gateway_addr = ntohl(route.gate_addr);

	rc = resolve_ifname_to_mac(route.if_name, args->local_mac);
	if (rc < 0)
		fail_printf("Error resolving local MAC");

	if (local_addr) {
		args->local_addr = ntohl(inet_addr(local_addr));
	} else {
		rc = resolve_ifname_to_ip(route.if_name, &args->local_addr);
		if (rc < 0)
			fail_printf("Error resolving local IP");
	}

	args->netdev = netdev_open(netdev, route.if_name);
	if (!args->netdev)
		fail_printf("Error opening netdev");

	rc = resolv_addr_to_mac(args->netdev,
	                        args->local_mac, args->local_addr,
	                        args->gateway_mac, args->gateway_addr);
	if (rc < 0)
		fail_printf("Error resolving local MAC");

	queue_init(&args->queue);

	START_THREAD(recv_mutex, recv_started, recv_thread, recv_cb, args);
	START_THREAD(loop_mutex, loop_started, loop_thread, loop_cb, args);

	setup_signals();

	status_line(args);

	args->done = true;

	pthread_join(args->recv_thread, NULL);
	pthread_join(args->loop_thread, NULL);

	netdev_close(args->netdev);

	range_list_free(args->targets);
	range_list_free(args->ports);
	free(args->script);

	return 0;
}

static void *recv_cb(void *p) {
	struct pktizr_args *args = p;

	void *L = script_load(args);

	args->pkt_recv = 0;

	if (pthread_setname_np(pthread_self(), "pktizr: recv"))
		fail_printf("Error setting thread name");

	pthread_mutex_lock(&args->recv_mutex);
	pthread_cond_signal(&args->recv_started);
	pthread_mutex_unlock(&args->recv_mutex);

	while (!args->done) {
		int rc, len;
		struct pkt *pkt = NULL;

		const uint8_t *buf = netdev_capture(args->netdev, &len);
		if (buf == NULL)
			continue;

		rc = pkt_unpack((uint8_t *) buf, len, &pkt);
		if (!rc)
			goto done;

		rc = script_recv(L, args, pkt);
		if (rc < 0)
			goto done;

		args->pkt_recv++;

done:
		netdev_release(args->netdev);
	}

	script_close(L);

	return NULL;
}

int pkt_send(struct pktizr_args *args, struct pkt *pkt) {
	uint8_t *buf;
	size_t   len;

	buf = netdev_get_buf(args->netdev, &len);

	int pkt_len = pkt_pack(buf, len, pkt);
	if (pkt_len < 0)
		return -1;

	netdev_inject(args->netdev, buf, pkt_len);
	args->pkt_sent++;

	return 0;
}

static void *loop_cb(void *p) {
	struct pktizr_args *args = p;

	int rc;

	size_t i = 0;

	struct pkt *pkt;
	struct queue_node *node;

	void *L = script_load(args);

	size_t tgt_cnt = range_list_count(args->targets);
	size_t prt_cnt = range_list_count(args->ports);
	size_t tot_cnt = tgt_cnt * prt_cnt * args->count;

	struct bucket bucket;
	bucket_init(&bucket, args->rate);

	struct shuffle rnd;
	shuffle_init(&rnd, tot_cnt, args->seed);

	args->pkt_count = tot_cnt;
	args->pkt_sent  = 0;
	args->pkt_probe = 0;

	if (pthread_setname_np(pthread_self(), "pktizr: loop"))
		fail_printf("Error setting thread name");

	if (!args->quiet)
		printf("Scanning %zu ports on %zu hosts...\n",
		       prt_cnt, tgt_cnt);

	pthread_mutex_lock(&args->loop_mutex);
	pthread_cond_signal(&args->loop_started);
	pthread_mutex_unlock(&args->loop_mutex);

	while (!args->done) {
		uint64_t tgt;

		uint32_t daddr;
		uint16_t dport;

		bucket_consume(&bucket);

		node = queue_dequeue(&args->queue);
		if (!node)
			goto script;

		pkt = caa_container_of(node, struct pkt, queue);

		pkt_send(args, pkt);

		bucket.tokens--;
		goto done;

script:
		if (caa_unlikely((i >= tot_cnt) || args->stop))
			continue;

		tgt = (args->shuffle) ? shuffle(&rnd, i) : i;

		daddr = range_list_pick(args->targets,
		                        (tgt % tgt_cnt) / args->count);
		dport = range_list_pick(args->ports,
		                        (tgt / tgt_cnt) / args->count);

		i++;

		rc = script_loop(L, args, &pkt, daddr, dport);
		if (caa_unlikely(rc < 0))
			continue;

		pkt_send(args, pkt);

		args->pkt_probe++;
		bucket.tokens--;

done:
		pkt_free_all(pkt);
	}

	script_close(L);

	return NULL;
}

static void status_line(struct pktizr_args *args) {
	uint64_t tot      = args->pkt_count;
	uint64_t now_old  = time_now();
	uint64_t sent_old = args->pkt_sent;

	stop = false;

	if (!args->quiet)
		fprintf(stderr, CURSOR_HIDE);

	while (1) {
		uint64_t now   = time_now();
		uint64_t sent  = args->pkt_sent;
		uint64_t probe = args->pkt_probe;

		double rate    = (sent - sent_old) / ((now - now_old) / 1e6);
		double percent = (double) probe * 100 / tot;

		if (!args->quiet) {
			fprintf(stderr, LINE_CLEAR);
			fprintf(stderr, "Progress: %3.2f%% ", percent);
			fprintf(stderr, "Rate: %3.2fkpps ", rate / 1000);
			fprintf(stderr, "Sent: %zu ", sent);
			fprintf(stderr, "Replies: %zu ", args->pkt_recv);
			fprintf(stderr, "\r");
		}

		now_old  = now;
		sent_old = sent;

		if (probe == tot)
			break;

		if (stop) {
			args->stop = true;
			break;
		}

		time_sleep(250000);
	}

	args->stop = stop = false;

	for (; args->wait > 0 && !stop; args->wait--) {
		if (!args->quiet) {
			fprintf(stderr, LINE_CLEAR);
			fprintf(stderr, "Waiting for %zu seconds...",
			        args->wait);
		}

		time_sleep(1e6);

		if (!args->quiet)
			fprintf(stderr, "\r");
	}

	args->stop = true;

	if (!args->quiet)
		fprintf(stderr, "\r" LINE_CLEAR CURSOR_SHOW);
}

static void handle_term_sig(int sig) {
	stop = true;
}

static void setup_signals(void) {
	struct sigaction sa;

	sa.sa_handler   = NULL;
	sa.sa_flags     = SA_RESTART;
	sa.sa_sigaction = NULL;

	sigemptyset(&sa.sa_mask);

	sa.sa_handler = handle_term_sig;
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
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
	printf(COLOR_GREEN "pktizr " COLOR_OFF);
	puts("<targets> [options]\n");

	puts(COLOR_RED " Options:" COLOR_OFF);

	CMD_HELP("--script", "-S", "Load and run the given script");

	puts("");

	CMD_HELP("--ports", "-p", "Use the specified port ranges");
	CMD_HELP("--rate",  "-r", "Send packets no faster than the specified rate");
	CMD_HELP("--seed",  "-s", "Use the given number as seed value");
	CMD_HELP("--wait",  "-w", "Wait the given amount of seconds after the scan is complete");
	CMD_HELP("--count", "-c", "Send the given amount of duplicate packets");

	CMD_HELP("--local-addr", "-l", "Use the given IP address as source");
	CMD_HELP("--gateway-addr", "-g", "Route the packets to the given gateway");

	CMD_HELP("--netdev", "-n", "Use the specified netdev driver");

	CMD_HELP("--shuffle", "-R", "Shuffle the target address/port order");

	CMD_HELP("--quiet", "-q", "Don't show the status line");

	puts("");

	CMD_HELP("--help", "-h", "Show this help");

	puts("");
}
