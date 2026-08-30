/* SPDX-License-Identifier: 0BSD */
#ifndef MIKU_CFF_CORPUS_FIXTURE_H
#define MIKU_CFF_CORPUS_FIXTURE_H

#ifdef CORPUS_WITH_TIGRESS
#include <tigress.h>
#endif

typedef unsigned int corpus_u32;

#if defined(__GNUC__) || defined(__clang__)
#define CORPUS_KEEP __attribute__((noinline, used))
#else
#define CORPUS_KEEP
#endif

#endif
