/* SPDX-License-Identifier: 0BSD */
#include "fixture.h"

CORPUS_KEEP int corpus_if_chain(int x)
{
    corpus_u32 state = 0xc71f294du;
    int acc = x - 2;

    for (;;) {
        if (state == 0xc71f294du) {
            state = x < 0 ? 0x15ac8ee3u : 0xe849307bu;
        } else if (state == 0x15ac8ee3u) {
            acc = -acc + 9;
            state = 0x731c4af2u;
        } else if (state == 0xe849307bu) {
            acc = acc * 2 + 1;
            state = 0x731c4af2u;
        } else if (state == 0x731c4af2u) {
            state = (acc & 1) ? 0xad325b60u : 0x46f98117u;
        } else if (state == 0xad325b60u) {
            acc ^= 0x1234;
            state = 0x90e4c83au;
        } else if (state == 0x46f98117u) {
            acc += 0x33;
            state = 0x90e4c83au;
        } else if (state == 0x90e4c83au) {
            return acc;
        } else {
            return -1;
        }
    }
}

static int reference_if_chain(int x)
{
    int acc = x - 2;
    if (x < 0)
        acc = -acc + 9;
    else
        acc = acc * 2 + 1;
    if (acc & 1)
        acc ^= 0x1234;
    else
        acc += 0x33;
    return acc;
}

int main(void)
{
    return corpus_if_chain(-5) != reference_if_chain(-5) ||
           corpus_if_chain(2) != reference_if_chain(2) ||
           corpus_if_chain(11) != reference_if_chain(11);
}
