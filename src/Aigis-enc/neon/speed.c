/* Copyright (c) 2025 LiuRuikang
 * School Of Cyber Engineering, Xidian University
 *
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 * http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include "speed.h"

#define CPU_CLOCK 3400000

static int cmp_llu(const void *a, const void*b)
{
	if (*(unsigned long long *)a < *(unsigned long long *)b) return -1;
	if (*(unsigned long long *)a > *(unsigned long long *)b) return 1;
	return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen)
{
	qsort(l, llen, sizeof(unsigned long long), cmp_llu);

	if (llen % 2) return l[llen / 2];
	else return (l[llen / 2 - 1] + l[llen / 2]) / 2;
}

static unsigned long long average(unsigned long long *t, size_t tlen)
{
	unsigned long long acc = 0;
	size_t i;
	for (i = 0; i<tlen; i++)
		acc += t[i];
	return acc / (tlen);
}
static double mtime(unsigned long long *t, size_t tlen)
{
  double acc=0;
  size_t i;
  for(i=0;i<tlen;i++)
    acc += t[i];
  acc = acc/tlen;
  return acc/CPU_CLOCK;//acc/CPU_CLOCK;
}
void print_results(const char *s, unsigned long long *t, size_t tlen)
{
	printf("%s\n", s);
	printf("median: %llu\n", median(t, tlen));
	printf("average: %llu\n", average(t, tlen - 1));
printf("ms: %3f\n", mtime(t, tlen - 1));
  printf("times: %3f\n", 1000/mtime(t, tlen - 1));
	printf("\n");
}
