/* SPDX-License-Identifier: 0BSD */
#include "fixture.h"

CORPUS_KEEP int corpus_single_switch(int x)
{
    corpus_u32 state = 0xa341316cu;
    int acc = x * 3 + 1;

    for (;;) {
        switch (state) {
        case 0xa341316cu:
            state = (x & 1) ? 0xd7287a91u : 0x1964c22fu;
            break;
        case 0x1964c22fu:
            acc ^= 0x55;
            state = 0x83e19b47u;
            break;
        case 0xd7287a91u:
            acc += 7;
            state = 0x83e19b47u;
            break;
        case 0x83e19b47u:
            state = (acc & 4) ? 0xf21805b3u : 0x2ca6de78u;
            break;
        case 0xf21805b3u:
            acc -= 3;
            state = 0x65bd44eau;
            break;
        case 0x2ca6de78u:
            acc += 11;
            state = 0x65bd44eau;
            break;
        case 0x65bd44eau:
            return acc;
        default:
            return -1;
        }
    }
}

static int reference_single_switch(int x)
{
    int acc = x * 3 + 1;
    if (x & 1)
        acc += 7;
    else
        acc ^= 0x55;
    if (acc & 4)
        acc -= 3;
    else
        acc += 11;
    return acc;
}

int main(void)
{
    return corpus_single_switch(-3) != reference_single_switch(-3) ||
           corpus_single_switch(0) != reference_single_switch(0) ||
           corpus_single_switch(7) != reference_single_switch(7);
}
