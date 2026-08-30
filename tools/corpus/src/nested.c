/* SPDX-License-Identifier: 0BSD */
#include "fixture.h"

CORPUS_KEEP int corpus_nested(int x)
{
    corpus_u32 outer = 0x8ac41237u;
    int acc = x;

    for (;;) {
        switch (outer) {
        case 0x8ac41237u: {
            corpus_u32 inner = 0xdd382a61u;
            acc += 1;
            for (;;) {
                if (inner == 0xdd382a61u) {
                    acc *= 2;
                    inner = (x & 2) ? 0x3f95b8ceu : 0xb2074d19u;
                } else if (inner == 0x3f95b8ceu) {
                    acc += 5;
                    inner = 0x62e1c743u;
                } else if (inner == 0xb2074d19u) {
                    acc ^= 0x2a;
                    inner = 0x62e1c743u;
                } else if (inner == 0x62e1c743u) {
                    break;
                } else {
                    return -1;
                }
            }
            outer = 0xf46b9d02u;
            break;
        }
        case 0xf46b9d02u:
            acc -= 7;
            outer = 0x174e53b8u;
            break;
        case 0x174e53b8u:
            return acc;
        default:
            return -1;
        }
    }
}

static int reference_nested(int x)
{
    int acc = (x + 1) * 2;
    if (x & 2)
        acc += 5;
    else
        acc ^= 0x2a;
    return acc - 7;
}

int main(void)
{
    return corpus_nested(-1) != reference_nested(-1) ||
           corpus_nested(2) != reference_nested(2) ||
           corpus_nested(8) != reference_nested(8);
}
