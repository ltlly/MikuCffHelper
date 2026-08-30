/* SPDX-License-Identifier: 0BSD */
#include "fixture.h"

#define CORPUS_ALIAS_MASK 0x5a5a5a5au

CORPUS_KEEP int corpus_encoded_alias(int x)
{
    corpus_u32 state = 0x7c109ea3u;
    int acc = x;

    for (;;) {
        corpus_u32 alias = state ^ CORPUS_ALIAS_MASK;
        if (alias == (0x7c109ea3u ^ CORPUS_ALIAS_MASK)) {
            acc += 9;
            state = (x & 1) ? 0xd82641f0u : 0x13b795ceu;
        } else if (alias == (0xd82641f0u ^ CORPUS_ALIAS_MASK)) {
            acc *= 3;
            state = 0xa46ce218u;
        } else if (alias == (0x13b795ceu ^ CORPUS_ALIAS_MASK)) {
            acc ^= 0x99;
            state = 0xa46ce218u;
        } else if (alias == (0xa46ce218u ^ CORPUS_ALIAS_MASK)) {
            return acc;
        } else {
            return -1;
        }
    }
}

static int reference_encoded_alias(int x)
{
    int acc = x + 9;
    if (x & 1)
        acc *= 3;
    else
        acc ^= 0x99;
    return acc;
}

int main(void)
{
    return corpus_encoded_alias(-2) != reference_encoded_alias(-2) ||
           corpus_encoded_alias(3) != reference_encoded_alias(3) ||
           corpus_encoded_alias(12) != reference_encoded_alias(12);
}
