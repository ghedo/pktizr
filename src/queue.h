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

#include <urcu/compiler.h>
#include <urcu/uatomic.h>

struct queue_node {
    struct queue_node *next;
};

struct queue {
    struct queue_node node;
    struct queue_node *p;
};

static inline void queue_node_init(struct queue_node *node) {
    node->next = NULL;
}

static inline void queue_init(struct queue *q) {
    queue_node_init(&q->node);
    q->p = &q->node;
}

static inline bool queue_empty(struct queue *q) {
    return CMM_LOAD_SHARED(q->node.next) == NULL &&
           CMM_LOAD_SHARED(q->p) == &q->node;
}

static inline bool queue_enqueue(struct queue *q, struct queue_node *node) {
    struct queue_node *old_tail = uatomic_xchg(&q->p, node);
    CMM_STORE_SHARED(old_tail->next, node);

    return old_tail != &q->node;
}

static inline struct queue_node *queue_node_next(struct queue_node *node) {
    struct queue_node *next;

    while ((next = CMM_LOAD_SHARED(node->next)) == NULL)
        caa_cpu_relax();

    return next;
}

static inline struct queue_node *queue_dequeue(struct queue *q) {
    struct queue_node *node, *next;

    if (queue_empty(q))
        return NULL;

    node = queue_node_next(&q->node);

    if ((next = CMM_LOAD_SHARED(node->next)) == NULL) {
        queue_node_init(&q->node);

        if (uatomic_cmpxchg(&q->p, node, &q->node) == node)
            return node;

        next = queue_node_next(node);
    }

    q->node.next = next;

    cmm_smp_read_barrier_depends();
    return node;
}
