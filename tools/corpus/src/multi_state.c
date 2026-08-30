/* SPDX-License-Identifier: 0BSD */
#include "fixture.h"

CORPUS_KEEP int corpus_multi_state(int x)
{
    corpus_u32 state_a = 0x19a2c7d4u;
    corpus_u32 state_b = 0xe3104b6fu;
    int acc = x * 3;

    for (;;) {
        if (state_a == 0x19a2c7d4u && state_b == 0xe3104b6fu) {
            state_a = 0x82d9531bu;
            state_b = 0x47af208du;
        } else if (state_a == 0x82d9531bu && state_b == 0x47af208du) {
            if (acc & 1) {
                state_a = 0xf63c8410u;
                state_b = 0x2b718ed9u;
            } else {
                state_a = 0x3de709a2u;
                state_b = 0xc59416f8u;
            }
        } else if (state_a == 0xf63c8410u && state_b == 0x2b718ed9u) {
            acc += 3;
            state_a = 0xab40d275u;
            state_b = 0x58e31c06u;
        } else if (state_a == 0x3de709a2u && state_b == 0xc59416f8u) {
            acc ^= 0x44;
            state_a = 0xab40d275u;
            state_b = 0x58e31c06u;
        } else if (state_a == 0xab40d275u && state_b == 0x58e31c06u) {
            return acc;
        } else {
            return -1;
        }
    }
}

static int reference_multi_state(int x)
{
    int acc = x * 3;
    if (acc & 1)
        acc += 3;
    else
        acc ^= 0x44;
    return acc;
}

int main(void)
{
    return corpus_multi_state(-3) != reference_multi_state(-3) ||
           corpus_multi_state(2) != reference_multi_state(2) ||
           corpus_multi_state(9) != reference_multi_state(9);
}
