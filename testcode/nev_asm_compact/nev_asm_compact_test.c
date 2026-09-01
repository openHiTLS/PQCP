/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of the license at http://license.coscl.org.cn/MulanPSL2.
 */

/*
 * White-box regression test for PR #57 review comment #4:
 *   "NEON compaction scratch buffer is too small"
 *   (src/nev/src/asm/asm_nev_sample.c, NEV_REJ_COMPACT_BUF)
 *
 * NEV_Ternary3Ext() compacts the bias3 rejection stream through
 * NEV_RejTernaryCompactAsm() into a stack buffer cbuf[NEV_REJ_COMPACT_BUF].
 * The ARMv8 kernel contract (nev_sample_armv8.S) requires dst capacity of
 * len + 8 bytes, where len is the bufLen argument.  The caller in
 * nev_sample.c passes bufLen = Bias3InitialBlocks(n, rate) * rate, and the
 * documented custom-backend contract (nev_symmetric_backend.h) allows any
 * NEV_KdfRate() in [1, NEV_KDF_RATE_MAX=168] for every parameter set.
 *
 * With NEV_REJ_COMPACT_BUF sized 504 + 8 = 512, contract-legal rates whose
 * initial squeeze exceeds 504 bytes (29 rates, worst case 584 bytes at
 * n=2048/rate=146) overflow cbuf.  The shipped backends (rate 32/72/136/168
 * on their coupled parameter sets) top out at exactly 504 bytes and are
 * safe, which is why the constant looked correct.
 *
 * The test drives NEV_Ternary3Ext() directly over both boundary-safe and
 * overflow-triggering (n, rate) combinations with an all-accepted input
 * stream (every byte < 243), so the kernel writes exactly bufLen (+ tail
 * slack) bytes.  A buffer overflow smashes the caller stack frame; the
 * driver is compiled with -fstack-protector-all so the corruption aborts
 * the process deterministically instead of passing silently.
 *
 * Bit-exactness assertion: for an all-0x01 input every byte is accepted,
 * and NEV_TERNARY5[1] = {0, 1, 1, 1, 1} (5 coefficients + 3 padding lanes
 * that are always overwritten when 5 * acc >= n).  Hence the expected
 * output polynomial is r[k] = (k % 5 == 0) ? 0 : 1 for every k < n and
 * NEV_Ternary3Ext() returns n.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Defined in src/nev/src/asm/asm_nev_sample.c (ARMv8 compaction driver). */
extern int32_t NEV_Ternary3Ext(int16_t *r, const uint8_t *buf, int32_t n, int32_t bufLen);

/* Maximum parameter set (nev_local.h). */
#define TEST_N_MAX 2048

/* Mirror of Bias3InitialBlocks() in src/nev/src/nev_sample.c.  Keep in
 * sync: minBytes = ceil(n/5), one extra block only when the whole-block
 * prefix has an uncomfortable acceptance margin. */
static int32_t Bias3InitialBlocks(int32_t n, int32_t rate)
{
    int32_t minBytes = (n + 4) / 5;
    int32_t blocks = (minBytes + rate - 1) / rate;
    uint64_t expected = (uint64_t)blocks * (uint64_t)rate * 243U;
    uint64_t margin = (uint64_t)(minBytes + 8) * 256U;

    return blocks + (expected < margin ? 1 : 0);
}

typedef struct {
    const char *name;
    int32_t n;
    int32_t rate;
    int32_t squeezeLen; /* expected initial squeeze: blocks * rate */
} CompactCase;

/* Cases verified against Bias3InitialBlocks(n, rate):
 *   (2048,  72) -> 7 *  72 = 504  builtin SHA3-512, boundary fit (504+8=512)
 *   (2048, 168) -> 3 * 168 = 504  builtin SHA3-128, boundary fit
 *   (2048, 136) -> 4 * 136 = 544  builtin SHA3-256 rate, over on a set that
 *                                 a custom backend may legally pair it with
 *   (512,  168) -> 1 * 168 = 168  builtin SHA3-128, small
 *   (512,   32) -> 4 *  32 = 128  builtin SM3, small
 *   (2048,  88) -> 6 *  88 = 528  custom-contract legal, OVERFLOWS 512
 *   (2048, 146) -> 4 * 146 = 584  custom-contract legal, worst case, 592
 *                                 bytes needed vs 512 provided            */
static const CompactCase g_cases[] = {
    { "n=2048 rate= 72 (builtin, squeeze=504, boundary fit)", 2048,  72, 504 },
    { "n=2048 rate=168 (builtin, squeeze=504, boundary fit)", 2048, 168, 504 },
    { "n=2048 rate=136 (builtin rate, squeeze=544, OVERFLOW)", 2048, 136, 544 },
    { "n=512  rate=168 (builtin, squeeze=168)",                 512, 168, 168 },
    { "n=512  rate= 32 (builtin SM3, squeeze=128)",             512,  32, 128 },
    { "n=2048 rate= 88 (custom legal, squeeze=528, OVERFLOW)", 2048,  88, 528 },
    { "n=2048 rate=146 (custom legal, squeeze=584, WORST)",    2048, 146, 584 },
};

static int RunCase(const CompactCase *c)
{
    uint8_t buf[768];
    int16_t r[TEST_N_MAX];
    int32_t nblocks = Bias3InitialBlocks(c->n, c->rate);
    int32_t bufLen = nblocks * c->rate;
    int32_t ret, i;
    int failed = 0;

    if (bufLen != c->squeezeLen) {
        printf("    [FAIL] Bias3InitialBlocks(%d,%d) = %d blocks, squeeze %d, expected %d\n",
            c->n, c->rate, nblocks, bufLen, c->squeezeLen);
        return 1;
    }
    if (bufLen > (int32_t)sizeof(buf)) {
        printf("    [FAIL] test buffer too small for squeeze %d\n", bufLen);
        return 1;
    }

    /* Every byte < 243 is accepted, so the kernel copies exactly bufLen
     * bytes into cbuf and needs bufLen + 8 bytes of capacity. */
    memset(buf, 0x01, sizeof(buf));
    memset(r, 0x55, sizeof(r));

    ret = NEV_Ternary3Ext(r, buf, c->n, bufLen);

    if (ret != c->n) {
        printf("    [FAIL] returned %d, expected %d\n", ret, c->n);
        failed = 1;
    }
    for (i = 0; i < c->n; i++) {
        int16_t expect = (int16_t)((i % 5 == 0) ? 0 : 1);
        if (r[i] != expect) {
            printf("    [FAIL] r[%d] = %d, expected %d (stack corruption)\n",
                i, r[i], expect);
            failed = 1;
            break;
        }
    }
    if (!failed) {
        printf("    [PASS] squeeze=%d bytes, %d coefficients, stream intact\n",
            bufLen, ret);
    }
    return failed;
}

int main(void)
{
    size_t i;
    int failed = 0;

    for (i = 0; i < sizeof(g_cases) / sizeof(g_cases[0]); i++) {
        printf("[case %zu] %s\n", i, g_cases[i].name);
        fflush(stdout);
        failed |= RunCase(&g_cases[i]);
    }

    if (failed) {
        printf("NEV asm compaction buffer test: FAILED\n");
        return 1;
    }
    printf("NEV asm compaction buffer test: PASSED\n");
    return 0;
}
