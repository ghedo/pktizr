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

const unsigned char sbox[256] = {
    0x91, 0x58, 0xb3, 0x31, 0x6c, 0x33, 0xda, 0x88,
    0x57, 0xdd, 0x8c, 0xf2, 0x29, 0x5a, 0x08, 0x9f,
    0x49, 0x34, 0xce, 0x99, 0x9e, 0xbf, 0x0f, 0x81,
    0xd4, 0x2f, 0x92, 0x3f, 0x95, 0xf5, 0x23, 0x00,
    0x0d, 0x3e, 0xa8, 0x90, 0x98, 0xdd, 0x20, 0x00,
    0x03, 0x69, 0x0a, 0xca, 0xba, 0x12, 0x08, 0x41,
    0x6e, 0xb9, 0x86, 0xe4, 0x50, 0xf0, 0x84, 0xe2,
    0xb3, 0xb3, 0xc8, 0xb5, 0xb2, 0x2d, 0x18, 0x70,

    0x0a, 0xd7, 0x92, 0x90, 0x9e, 0x1e, 0x0c, 0x1f,
    0x08, 0xe8, 0x06, 0xfd, 0x85, 0x2f, 0xaa, 0x5d,
    0xcf, 0xf9, 0xe3, 0x55, 0xb9, 0xfe, 0xa6, 0x7f,
    0x44, 0x3b, 0x4a, 0x4f, 0xc9, 0x2f, 0xd2, 0xd3,
    0x8e, 0xdc, 0xae, 0xba, 0x4f, 0x02, 0xb4, 0x76,
    0xba, 0x64, 0x2d, 0x07, 0x9e, 0x08, 0xec, 0xbd,
    0x52, 0x29, 0x07, 0xbb, 0x9f, 0xb5, 0x58, 0x6f,
    0x07, 0x55, 0xb0, 0x34, 0x74, 0x9f, 0x05, 0xb2,

    0xdf, 0xa9, 0xc6, 0x2a, 0xa3, 0x5d, 0xff, 0x10,
    0x40, 0xb3, 0xb7, 0xb4, 0x63, 0x6e, 0xf4, 0x3e,
    0xee, 0xf6, 0x49, 0x52, 0xe3, 0x11, 0xb3, 0xf1,
    0xfb, 0x60, 0x48, 0xa1, 0xa4, 0x19, 0x7a, 0x2e,
    0x90, 0x28, 0x90, 0x8d, 0x5e, 0x8c, 0x8c, 0xc4,
    0xf2, 0x4a, 0xf6, 0xb2, 0x19, 0x83, 0xea, 0xed,
    0x6d, 0xba, 0xfe, 0xd8, 0xb6, 0xa3, 0x5a, 0xb4,
    0x48, 0xfa, 0xbe, 0x5c, 0x69, 0xac, 0x3c, 0x8f,

    0x63, 0xaf, 0xa4, 0x42, 0x25, 0x50, 0xab, 0x65,
    0x80, 0x65, 0xb9, 0xfb, 0xc7, 0xf2, 0x2d, 0x5c,
    0xe3, 0x4c, 0xa4, 0xa6, 0x8e, 0x07, 0x9c, 0xeb,
    0x41, 0x93, 0x65, 0x44, 0x4a, 0x86, 0xc1, 0xf6,
    0x2c, 0x97, 0xfd, 0xf4, 0x6c, 0xdc, 0xe1, 0xe0,
    0x28, 0xd9, 0x89, 0x7b, 0x09, 0xe2, 0xa0, 0x38,
    0x74, 0x4a, 0xa6, 0x5e, 0xd2, 0xe2, 0x4d, 0xf3,
    0xf4, 0xc6, 0xbc, 0xa2, 0x51, 0x58, 0xe8, 0xae,
};

static inline uint64_t F(uint64_t r, uint64_t R, uint64_t seed) {
#define GETBYTE(R, n) ((((R) >> (n * 8)) ^ seed ^ r) & 0xFF)

    uint64_t r0, r1, r2, r3;

    R ^= (seed << r) ^ (seed >> (64 - r));

    r0 = sbox[GETBYTE(R, 0)] << 0 |
         sbox[GETBYTE(R, 1)] << 8;

    r1 = (sbox[GETBYTE(R, 2)] << 16UL |
          sbox[GETBYTE(R, 3)] << 24UL) & 0x0ffffFFFFUL;

    r2 = sbox[GETBYTE(R, 4)] << 0 |
         sbox[GETBYTE(R, 5)] << 8;

    r3 = (sbox[GETBYTE(R, 6)] << 16UL |
          sbox[GETBYTE(R, 7)] << 24UL) & 0x0ffffFFFFUL;

    R = r0 ^ r1 ^ r2 << 23UL ^ r3 << 33UL;

    return R;
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
