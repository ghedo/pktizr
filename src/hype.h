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

struct hype_args {
	struct range *targets;
	struct range *ports;

	struct netif *netif;

	char *script;

	uint64_t pkt_count;
	uint64_t pkt_probe;
	uint64_t pkt_recv;
	uint64_t pkt_sent;

	uint64_t rate;
	uint64_t seed;
	uint64_t wait;
	uint64_t count;

	pthread_t       send_thread;
	pthread_mutex_t send_mutex;
	pthread_cond_t  send_started;

	pthread_t       recv_thread;
	pthread_mutex_t recv_mutex;
	pthread_cond_t  recv_started;

	pthread_t       loop_thread;
	pthread_mutex_t loop_mutex;
	pthread_cond_t  loop_started;

	struct queue_head queue_head;
	struct queue_tail queue_tail;

	uint32_t local_addr;
	uint32_t gateway_addr;

	uint8_t local_mac[6];
	uint8_t gateway_mac[6];

	bool done, stop, quiet;
};
