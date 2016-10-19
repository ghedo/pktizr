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

/*
 * Python randomized hash implementation as described at
 * https://www.python.org/dev/peps/pep-0456/#current-implementation-with-modified-fnv
 *
 * It is *not* a cryptographic hash function, but it doesn't really matter as
 * far as pktizr is concerned and it's faster than siphash.
 */
static inline uint64_t pyrhash(const uint8_t *k, const uint8_t *m,
                               const uint64_t n) {
    register int64_t len;
    register uint64_t x;
    register uint64_t prefix;
    register uint64_t suffix;
    register const unsigned char *p;

    prefix = *(uint64_t *) (k + 0);
    suffix = *(uint64_t *) (k + 8);

    len = n;

    if (len == 0)
        return 0;

    p = m;
    x = prefix;
    x ^= *p << 7;

    while (--len >= 0)
        x = (1000003 * x) ^ *p++;

    x ^= n;
    x ^= suffix;

    return x;
}
