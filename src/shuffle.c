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

/*
 * Generalized-Feistel Cipher implementation as described in the paper
 * "Ciphers with Arbitrary Finite Domains" by John Black and Phillip Rogaway
 * http://www.cs.ucdavis.edu/~rogaway/papers/subset.pdf
 */

#include <stdint.h>
#include <math.h>

#include "hash.h"
#include "shuffle.h"

#define ROUNDS 4

static inline uint64_t do_shuffle(unsigned r, uint64_t a, uint64_t b,
                                  uint64_t m, uint64_t seed);

void shuffle_init(struct shuffle *r, uint64_t range, uint64_t seed) {
    double root = sqrt(range);

    r->a = (uint64_t) (root - 1);
    r->b = (uint64_t) (root + 1);

    while ((r->a * r->b) <= range)
        r->b++;

    r->range  = range;
    r->seed   = seed;
    r->rounds = ROUNDS;
}

uint64_t shuffle(struct shuffle *r, uint64_t m) {
    uint64_t c = m;

    do {
        c = do_shuffle(r->rounds, r->a, r->b,  c, r->seed);
    } while (c >= r->range);

    return c;
}

static inline uint64_t F(uint64_t r, uint64_t R, uint64_t seed) {
    uint64_t buf[2];
    uint64_t key[2];

    key[0] = seed;
    key[1] = seed;

    buf[0] = r;
    buf[1] = R;

    return pyrhash((const uint8_t *)key, (const uint8_t *)buf, sizeof(buf));
}

static inline uint64_t do_shuffle(unsigned r, uint64_t a, uint64_t b,
                                  uint64_t m, uint64_t seed) {
    uint64_t tmp;

    uint64_t L = m % a;
    uint64_t R = m / a;

    for (unsigned j = 1; j <= r; j++) {
        tmp = (j & 1) ? (L + F(j, R, seed)) % a :
                        (L + F(j, R, seed)) % b;

        L = R;
        R = tmp;
    }

    return (r & 1) ? a * L + R :
                     a * R + L;
}
