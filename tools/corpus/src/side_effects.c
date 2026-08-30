/* SPDX-License-Identifier: 0BSD */
#include "fixture.h"

volatile int corpus_side_effect_sink;

CORPUS_KEEP int corpus_side_effect_helper(int value)
{
    corpus_side_effect_sink += value;
    return value * 2 + 1;
}

CORPUS_KEEP int corpus_side_effects(int x)
{
    corpus_u32 state = 0xb72308d1u;
    int acc = 0;

    for (;;) {
        if (state == 0xb72308d1u) {
            acc = corpus_side_effect_helper(x);
            state = (acc & 1) ? 0x4ef16a93u : 0xd805c27bu;
        } else if (state == 0x4ef16a93u) {
            corpus_side_effect_sink ^= 0x55;
            acc += corpus_side_effect_sink;
            state = 0x219d74e8u;
        } else if (state == 0xd805c27bu) {
            corpus_side_effect_sink += 3;
            acc -= corpus_side_effect_sink;
            state = 0x219d74e8u;
        } else if (state == 0x219d74e8u) {
            return acc;
        } else {
            return -1;
        }
    }
}

static int reference_side_effects(int x)
{
    int acc = corpus_side_effect_helper(x);
    if (acc & 1) {
        corpus_side_effect_sink ^= 0x55;
        acc += corpus_side_effect_sink;
    } else {
        corpus_side_effect_sink += 3;
        acc -= corpus_side_effect_sink;
    }
    return acc;
}

static int check_side_effects(int x)
{
    int got;
    int expected;
    int got_sink;
    int expected_sink;

    corpus_side_effect_sink = 0;
    got = corpus_side_effects(x);
    got_sink = corpus_side_effect_sink;
    corpus_side_effect_sink = 0;
    expected = reference_side_effects(x);
    expected_sink = corpus_side_effect_sink;
    return got != expected || got_sink != expected_sink;
}

int main(void)
{
    return check_side_effects(-2) || check_side_effects(0) ||
           check_side_effects(6);
}
