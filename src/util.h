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
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define _free_ __attribute__((cleanup(freep)))
#define _ta_free_ __attribute__((cleanup(ta_freep)))
#define _close_ __attribute__((cleanup(closep)))

static inline void freep(void *p) {
	if (p == NULL)
		return;

	free(*(void **) p);

	*(void **)p = NULL;
}

static inline void ta_freep(void *p) {
	if (p == NULL)
		return;

	talloc_free(*(void **) p);

	*(void **)p = NULL;
}

static inline void closep(int *p) {
	int rc;

	if (*p == -1)
		return;

	rc = close(*p);
	if (rc < 0) sysf_printf("close()");

	*p = -1;
}

static inline uint64_t time_now(void) {
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC_RAW, &now);
	return (now.tv_sec * 1000000) + (now.tv_nsec / 1000);
}

static inline void time_sleep(uint64_t us) {
	usleep(us);
}

size_t split_str(char *orig, char ***dest, char *needle);
size_t validate_optlist(char *name, char *opts);
