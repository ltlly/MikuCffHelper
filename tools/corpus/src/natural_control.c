/* SPDX-License-Identifier: 0BSD */
#include "fixture.h"

/* Negative control: structured code with a natural loop and switch, no dispatcher. */
CORPUS_KEEP int corpus_natural_control(int x)
{
    int i;
    int acc = 1;
    for (i = 0; i < 5; ++i) {
        if ((x + i) & 1)
            acc += x ^ i;
        else
            acc -= x + i;
    }
    switch (x & 3) {
    case 0:
        return acc + 3;
    case 1:
        return acc - 7;
    case 2:
        return acc ^ 0x31;
    default:
        return acc * 2;
    }
}

int main(void)
{
    return corpus_natural_control(-2) == corpus_natural_control(9);
}
