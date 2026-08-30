/* SPDX-License-Identifier: 0BSD */
#include "fixture.h"

CORPUS_KEEP int corpus_conditional_state(int x)
{
    corpus_u32 state = 0x91d34b28u;
    int acc = x;

    for (;;) {
        if (state == 0x91d34b28u) {
            state = x < 0 ? 0x24e8a5f1u : 0xcd617903u;
        } else if (state == 0x24e8a5f1u) {
            acc = -x + 4;
            state = (acc & 1) ? 0x7a053ce6u : 0xe4821b59u;
        } else if (state == 0xcd617903u) {
            acc = x + 4;
            state = (acc & 1) ? 0x7a053ce6u : 0xe4821b59u;
        } else if (state == 0x7a053ce6u) {
            acc += 5;
            state = 0x368fb2c4u;
        } else if (state == 0xe4821b59u) {
            acc ^= 0x2d;
            state = 0x368fb2c4u;
        } else if (state == 0x368fb2c4u) {
            return acc;
        } else {
            return -1;
        }
    }
}

static int reference_conditional_state(int x)
{
    int acc = x < 0 ? -x + 4 : x + 4;
    if (acc & 1)
        acc += 5;
    else
        acc ^= 0x2d;
    return acc;
}

int main(void)
{
    return corpus_conditional_state(-8) != reference_conditional_state(-8) ||
           corpus_conditional_state(0) != reference_conditional_state(0) ||
           corpus_conditional_state(7) != reference_conditional_state(7);
}
