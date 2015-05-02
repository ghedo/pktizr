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
#include <stdbool.h>

#include <urcu/uatomic.h>

#include "bucket.h"
#include "printf.h"
#include "util.h"

void bucket_init(struct bucket *t, uint64_t rate) {
	t->rate      = rate;
	t->tokens    = rate;
	t->timestamp = time_now();
}

bool bucket_consume(struct bucket *t) {
	uint64_t now;
	double tokens;

	if (!t->rate)
		return true;

	do {
		now    = time_now();
		tokens = ((now - t->timestamp) / 1e6) * t->rate;

		if (tokens >= 1.0)
			break;

		caa_cpu_relax();
	} while (1);

	t->tokens += tokens;

	if (t->tokens > t->rate)
		t->tokens = t->rate;

	t->timestamp = now;

	return true;
}
