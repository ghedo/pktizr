#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "clar/clar.h"

#include "shuffle.h"

void test_shuffle__simple(void) {
    struct shuffle r;

    shuffle_init(&r, 100, 500);

    for (uint64_t i = 0; i < 100; i++) {
        uint64_t res  = shuffle(&r, i);
        uint64_t res2 = unshuffle(&r, res);

        cl_assert_equal_i(i, res2);
    }
}

void test_shuffle__verify(void) {
    struct shuffle r;

    for (unsigned i = 1; i <= 1000; i++) {
        uint64_t *results = calloc(i, sizeof(uint64_t));

        shuffle_init(&r, i, time(NULL));

        for (unsigned j = 0; j < i; j++) {
            uint64_t res = shuffle(&r, j);
            uint64_t res2 = unshuffle(&r, res);

            cl_assert_equal_i(j, res2);

            results[j]++;
        }

        for (unsigned j = 0; j < i; j++) {
            cl_assert_equal_i(results[j], 1);
        }

        free(results);
    }
}
