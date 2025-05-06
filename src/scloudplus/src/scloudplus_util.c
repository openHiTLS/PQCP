/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include "securec.h"
#include "scloudplus_local.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "crypt_errno.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_md.h"
#include "pqcp_err.h"

static inline Complex ComplexAdd(const Complex a, const Complex b)
{
    return (Complex){a.real + b.real, a.imag + b.imag};
}

static inline Complex ComplexSub(const Complex a, const Complex b)
{
    return (Complex){a.real - b.real, a.imag - b.imag};
}

static inline Complex ComplexMul(const Complex a, const Complex b)
{
    return (Complex){
        a.real * b.real - a.imag * b.imag,
        a.real * b.imag + a.imag * b.real};
}
// a/(1+i) = a*(1-i)/2
static inline Complex ComplexDivPhi(const Complex a)
{
    return (Complex){
        (a.real + a.imag) >> 1,
        (a.imag - a.real) >> 1};
}

static inline int32_t Round(const int32_t in, const uint8_t logq, const uint8_t tau)
{
    const int32_t mod = 1 << (logq - tau);
    const int32_t mod2 = mod >> 1;
    const int32_t r = in % mod;
    int32_t q = in / mod;

    if (in >= 0) {
        if (r >= mod2) {
            q += 1;
        }
    } else {
        if (r <= -mod2) {
            q -= 1;
        }
    }

    return q * mod;
}

static inline uint32_t U16ToU32(const uint16_t *ptr)
{
    return ((uint32_t)ptr[0]) | ((uint32_t)ptr[1] << 16);
}

static inline uint32_t U8ToU24(const uint8_t *ptr)
{
    return ((uint32_t)ptr[0] << 0) | ((uint32_t)ptr[1] << 8) |
           ((uint32_t)ptr[2] << 16);
}

static inline uint32_t U8ToU32(const uint8_t *ptr)
{
    return ((uint32_t)ptr[0]) | ((uint32_t)ptr[1] << 8) |
           ((uint32_t)ptr[2] << 16) | ((uint32_t)ptr[3] << 24);
}

static inline uint64_t U8ToU56(const uint8_t *ptr)
{
    return ((uint64_t)ptr[0] << 0) | ((uint64_t)ptr[1] << 8) |
           ((uint64_t)ptr[2] << 16) | ((uint64_t)ptr[3] << 24) |
           ((uint64_t)ptr[4] << 32) | ((uint64_t)ptr[5] << 40) |
           ((uint64_t)ptr[6] << 48);
}

static inline void U8ToN(uint8_t *in, const int inLen, const SCLOUDPLUS_Para *para, uint16_t *out,
                         int *outLen)
{
    uint8_t *ptrIn = in;
    uint16_t *ptrOut = out;
    *outLen = 0;
    if (para->ss == 16) {
        const uint32_t n1 = 600;
        const uint32_t n2 = 360000;
        const uint32_t n3 = 216000000;

        for (int i = 0; i < inLen; i = i + 7) { // 7 bytes to get 6 values
            // 28 bits for 3 values in [0,599] i1 =[y]n, i2 = [(y-i1)/n]n, i3 = [(y-i1-i2*n)/n^2]n.
            uint32_t tmp = U8ToU32(ptrIn) & 0xFFFFFFF;
            if (tmp < n3) {
                *ptrOut = tmp % n1;
                *(ptrOut + 1) = tmp / n1 % n1;
                *(ptrOut + 2) = tmp / n2 % n1;
                ptrOut = ptrOut + 3;
                *outLen += 3;
            }
            tmp = (U8ToU32(ptrIn + 3) >> 4) & 0xFFFFFFF;
            if (tmp < n3) {
                *ptrOut = tmp % n1;
                *(ptrOut + 1) = tmp / n1 % n1;
                *(ptrOut + 2) = tmp / n2 % n1;
                ptrOut = ptrOut + 3;
                *outLen += 3;
            }
            ptrIn = ptrIn + 7;
        }
    } else if (para->ss == 24) {
        uint16_t tmp[8] = {0};
        for (int i = 0; i < inLen; i = i + 11) {  // 11 bytes to get 8 values 
            tmp[0] = *(uint16_t *)ptrIn & 0x7FF; // normal reject sample.n = 896 is near to 2^11.
            tmp[1] = (*(uint16_t *)(ptrIn + 1) >> 3) & 0x7FF;
            tmp[2] = (*(uint32_t *)(ptrIn + 2) >> 6) & 0x7FF;
            tmp[3] = (*(uint16_t *)(ptrIn + 4) >> 1) & 0x7FF;
            tmp[4] = (*(uint16_t *)(ptrIn + 5) >> 4) & 0x7FF;
            tmp[5] = (*(uint32_t *)(ptrIn + 6) >> 7) & 0x7FF;
            tmp[6] = (*(uint16_t *)(ptrIn + 8) >> 2) & 0x7FF;
            tmp[7] = (*(uint16_t *)(ptrIn + 9) >> 5) & 0x7FF;
            for (int j = 0; j < 8; j++) {
                if (tmp[j] < para->n) {
                    *ptrOut = tmp[j];
                    ptrOut = ptrOut + 1;
                    *outLen += 1;
                }
            }
            ptrIn = ptrIn + 11;
        }
    } else if (para->ss == 32) {
        const uint64_t n1 = 1120;
        const uint64_t n2 = 1254400;
        const uint64_t n3 = 1404928000;
        const uint64_t n4 = 1573519360000;
        const uint64_t n5 = 1762341683200000;

        uint64_t A[8] = {0};
        for (int i = 0; i < 13; i++) {
            A[0] = *(uint64_t *)ptrIn & 0x7FFFFFFFFFFFF; // 51 bits for 5 values.
            A[1] = (*(uint64_t *)(ptrIn + 6) >> 3) & 0x7FFFFFFFFFFFF;
            A[2] = (*(uint64_t *)(ptrIn + 12) >> 6) & 0x7FFFFFFFFFFFF;
            A[3] = (*(uint64_t *)(ptrIn + 19) >> 1) & 0x7FFFFFFFFFFFF;
            A[4] = (*(uint64_t *)(ptrIn + 25) >> 4) & 0x7FFFFFFFFFFFF;
            A[5] = (*(uint64_t *)(ptrIn + 31) >> 7) & 0x7FFFFFFFFFFFF;
            A[6] = (*(uint64_t *)(ptrIn + 38) >> 2) & 0x7FFFFFFFFFFFF;
            A[7] = (*(uint64_t *)(ptrIn + 44) >> 5) & 0x7FFFFFFFFFFFF;
            for (int j = 0; j < 8; j++) { // 51 bytes for 8*5 values.
                if (A[j] < n5) {
                    *ptrOut = A[j] % n1;
                    *(ptrOut + 1) = A[j] / n1 % n1;
                    *(ptrOut + 2) = A[j] / n2 % n1;
                    *(ptrOut + 3) = A[j] / n3 % n1;
                    *(ptrOut + 4) = A[j] / n4 % n1;
                    ptrOut = ptrOut + 5;
                    *outLen += 5;
                }
            }
            ptrIn = ptrIn + 51;
        }
        // 663 bytes used,17 bytes left to get 10 values.
        A[0] = *(uint64_t *)ptrIn & 0x7FFFFFFFFFFFF;
        A[1] = (*(uint64_t *)(ptrIn + 6) >> 3) & 0x7FFFFFFFFFFFF;
        for (int j = 0; j < 2; j++) {
            if (A[j] < n5) {
                *ptrOut = A[j] % n1;
                *(ptrOut + 1) = A[j] / n1 % n1;
                *(ptrOut + 2) = A[j] / n2 % n1;
                *(ptrOut + 3) = A[j] / n3 % n1;
                *(ptrOut + 4) = A[j] / n4 % n1;
                ptrOut = ptrOut + 5;
                *outLen += 5;
            }
        }
    }
}

static inline void U8ToM(uint8_t *in, const int inLen, const SCLOUDPLUS_Para *para, uint16_t *out, int *outLen)
{
    uint8_t *ptrIn = in;
    uint16_t *ptrOut = out;
    *outLen = 0;
    if (para->ss == 16) {
        const uint32_t m1 = 600;
        const uint32_t m2 = 360000;
        const uint32_t m3 = 216000000;
        for (int i = 0; i < inLen; i = i + 7) { // 7 bytes to get 6 values
            uint32_t tmp = U8ToU32(ptrIn) & 0xFFFFFFF; // 28 bits for 3 values in [0,599] i1 =[y]n, i2 = [(y-i1)/n]n, i3 = [(y-i1-i2*n)/n^2]n.
            if (tmp < m3) {
                *ptrOut = tmp % m1;
                *(ptrOut + 1) = tmp / m1 % m1;
                *(ptrOut + 2) = tmp / m2 % m1;
                ptrOut = ptrOut + 3;
                *outLen += 3;
            }
            tmp = (U8ToU32(ptrIn + 3) >> 4) & 0xFFFFFFF;
            if (tmp < m3) {
                *ptrOut = tmp % m1;
                *(ptrOut + 1) = tmp / m1 % m1;
                *(ptrOut + 2) = tmp / m2 % m1;
                ptrOut = ptrOut + 3;
                *outLen += 3;
            }
            ptrIn = ptrIn + 7;
        }
    } else if (para->ss == 24) {
        uint16_t tmp[8] = {0};
        for (int i = 0; i < inLen; i = i + 11) { // 11 bytes to get 8 values
            tmp[0] = *(uint16_t *)ptrIn & 0x7FF; // normal reject sample.n = 928 is near to 2^11.
            tmp[1] = (*(uint16_t *)(ptrIn + 1) >> 3) & 0x7FF;
            tmp[2] = (*(uint32_t *)(ptrIn + 2) >> 6) & 0x7FF;
            tmp[3] = (*(uint16_t *)(ptrIn + 4) >> 1) & 0x7FF;
            tmp[4] = (*(uint16_t *)(ptrIn + 5) >> 4) & 0x7FF;
            tmp[5] = (*(uint32_t *)(ptrIn + 6) >> 7) & 0x7FF;
            tmp[6] = (*(uint16_t *)(ptrIn + 8) >> 2) & 0x7FF;
            tmp[7] = (*(uint16_t *)(ptrIn + 9) >> 5) & 0x7FF;
            for (int j = 0; j < 8; j++) {
                if (tmp[j] < para->m) {
                    *ptrOut = tmp[j];
                    ptrOut = ptrOut + 1;
                    *outLen += 1;
                }
            }
            ptrIn = ptrIn + 11;
        }
    } else if (para->ss == 32) {
        const uint64_t m1 = 1120;
        const uint64_t m2 = 1254400;
        const uint64_t m3 = 1404928000;
        const uint64_t m4 = 1573519360000;
        const uint64_t m5 = 1762341683200000;

        uint64_t A[8] = {0};
        for (int i = 0; i < 13; i++) {
            A[0] = *(uint64_t *)ptrIn & 0x7FFFFFFFFFFFF; // 51 bits for 5 values
            A[1] = (*(uint64_t *)(ptrIn + 6) >> 3) & 0x7FFFFFFFFFFFF;
            A[2] = (*(uint64_t *)(ptrIn + 12) >> 6) & 0x7FFFFFFFFFFFF;
            A[3] = (*(uint64_t *)(ptrIn + 19) >> 1) & 0x7FFFFFFFFFFFF;
            A[4] = (*(uint64_t *)(ptrIn + 25) >> 4) & 0x7FFFFFFFFFFFF;
            A[5] = (*(uint64_t *)(ptrIn + 31) >> 7) & 0x7FFFFFFFFFFFF;
            A[6] = (*(uint64_t *)(ptrIn + 38) >> 2) & 0x7FFFFFFFFFFFF;
            A[7] = (*(uint64_t *)(ptrIn + 44) >> 5) & 0x7FFFFFFFFFFFF;
            for (int j = 0; j < 8; j++) { // 51 bytes for 8*5 values.
                if (A[j] < m5) {
                    *ptrOut = A[j] % m1;
                    *(ptrOut + 1) = A[j] / m1 % m1;
                    *(ptrOut + 2) = A[j] / m2 % m1;
                    *(ptrOut + 3) = A[j] / m3 % m1;
                    *(ptrOut + 4) = A[j] / m4 % m1;
                    ptrOut = ptrOut + 5;
                    *outLen += 5;
                }
            }
            ptrIn = ptrIn + 51;
        }
        // 663 bytes used,17 bytes left to get 10 values.
        A[0] = *(uint64_t *)ptrIn & 0x7FFFFFFFFFFFF;
        A[1] = (*(uint64_t *)(ptrIn + 6) >> 3) & 0x7FFFFFFFFFFFF;
        for (int j = 0; j < 2; j++) {
            if (A[j] < m5) {
                *ptrOut = A[j] % m1;
                *(ptrOut + 1) = A[j] / m1 % m1;
                *(ptrOut + 2) = A[j] / m2 % m1;
                *(ptrOut + 3) = A[j] / m3 % m1;
                *(ptrOut + 4) = A[j] / m4 % m1;
                ptrOut = ptrOut + 5;
                *outLen += 5;
            }
        }
    }
}
/**
 * LabelingComputeV 函数（对应论文 Algorithm 2 的步骤1-3）
 * 功能：将输入消息 m 映射到复数向量 v ∈ Z[i]^16（Barnes-Wall 格 BW32 的预编码向量）
 *
 * 参数说明：
 * - m：输入消息字节流（长度由 τ 决定，τ=3 时为 8 字节，τ=4 时为 12 字节）
 * - tau：模数参数（论文中的 τ，控制格基缩放）
 * - v：输出的复数向量（长度 16，对应 32 维格的复数表示）
 *
 * 论文对应关系（τ=3/4 时的消息分割）：
 * - A/B/C 数组对应论文中消息 m 的分块编码（Algorithm 2 步骤2）：
 *     u_j ∈ {0, 1}^(2τ−wH(j))
 *     v_j = f_(2τ−wH(j))(uj)
 *     fl : {0, 1}^l → Z[i] such that f_l(u) = a + bi, where 0 ≤ a < 2^⌈l/2⌉, 0 ≤ b < 2^⌊l/2⌋
 *     tau = 3 时：2τ−wH(j) 结果可能为2,3,4,5,6 ⌈l/2⌉可能为1,2,3 ⌊l/2⌋可能为1,2,3
 *     tau = 4 时：2τ−wH(j) 结果可能为4,5,6,7,8 ⌈l/2⌉可能为2,3,4 ⌊l/2⌋可能为2,3,4
 * 具体分割规则遵循论文中 μ = τ·2^k − (2^k/4)(k−1) 的约束（k=5 对应 BW32）
 * https://eprint.iacr.org/2024/1306
 */
static inline int32_t LabelingComputeV(const uint8_t *m, const uint8_t tau, Complex v[SCLOUDPLUS_BW_COMPLEX_LEN])
{
    uint8_t A[6] = {0};
    uint8_t B[20] = {0};
    uint8_t C[6] = {0};
    if (tau == 3) {
        A[0] = (m[0] >> 0) & 0x07;
        A[1] = (m[0] >> 3) & 0x07;
        A[2] = ((m[0] >> 6) & 0x03) | ((m[1] << 2) & 0x04);
        A[3] = (m[1] >> 1) & 0x07;
        A[4] = (m[1] >> 4) & 0x07;
        A[5] = ((m[1] >> 7) & 0x01) | ((m[2] << 1) & 0x06);

        for (int i = 0; i < 3; ++i) {
            B[i] = (m[2] >> (2 + 2 * i)) & 0x03;
        }

        for (int i = 0; i < 4; ++i) {
            B[3 + i] = (m[3] >> (2 * i)) & 0x03;
            B[7 + i] = (m[4] >> (2 * i)) & 0x03;
            B[11 + i] = (m[5] >> (2 * i)) & 0x03;
            B[15 + i] = (m[6] >> (2 * i)) & 0x03;
        }
        B[19] = m[7] & 0x03;
        C[0] = (m[7] >> 2) & 0x01;
        C[1] = (m[7] >> 3) & 0x01;
        C[2] = (m[7] >> 4) & 0x01;
        C[3] = (m[7] >> 5) & 0x01;
        C[4] = (m[7] >> 6) & 0x01;
        C[5] = (m[7] >> 7) & 0x01;
    } else if (tau == 4) {
        A[0] = m[0] & 0x0F;
        A[1] = (m[0] >> 4) & 0x0F;
        A[2] = m[1] & 0x0F;
        A[3] = (m[1] >> 4) & 0x0F;
        A[4] = m[2] & 0x0F;
        A[5] = (m[2] >> 4) & 0x0F;

        B[0] = m[3] & 0x07;
        B[1] = (m[3] >> 3) & 0x07;
        B[2] = ((m[3] >> 6) & 0x03) | ((m[4] << 2) & 0x04);
        B[3] = (m[4] >> 1) & 0x07;
        B[4] = (m[4] >> 4) & 0x07;
        B[5] = ((m[4] >> 7) & 0x01) | ((m[5] << 1) & 0x06);
        B[6] = (m[5] >> 2) & 0x07;
        B[7] = (m[5] >> 5) & 0x07;

        B[8] = m[6] & 0x07;
        B[9] = (m[6] >> 3) & 0x07;
        B[10] = ((m[6] >> 6) & 0x03) | ((m[7] << 2) & 0x04);
        B[11] = (m[7] >> 1) & 0x07;
        B[12] = (m[7] >> 4) & 0x07;
        B[13] = ((m[7] >> 7) & 0x01) | ((m[8] << 1) & 0x06);
        B[14] = (m[8] >> 2) & 0x07;
        B[15] = (m[8] >> 5) & 0x07;

        B[16] = m[9] & 0x07;
        B[17] = (m[9] >> 3) & 0x07;
        B[18] = ((m[9] >> 6) & 0x03) | ((m[10] << 2) & 0x04);
        B[19] = (m[10] >> 1) & 0x07;

        C[0] = (m[10] >> 4) & 0x03;
        C[1] = (m[10] >> 6) & 0x03;
        C[2] = m[11] & 0x03;
        C[3] = (m[11] >> 2) & 0x03;
        C[4] = (m[11] >> 4) & 0x03;
        C[5] = (m[11] >> 6) & 0x03;
    } else {
        return PQCP_SCLOUDPLUS_INVALID_ARG;
    }
    uint8_t D[32] = {
        A[0], A[1], A[2], B[0], A[3], B[1], B[2], B[3],
        A[4], B[4], B[5], B[6], B[7], B[8], B[9], C[0],
        A[5], B[10], B[11], B[12], B[13], B[14], B[15], C[1],
        B[16], B[17], B[18], C[2], B[19], C[3], C[4], C[5]};

    for (int i = 0; i < SCLOUDPLUS_BW_COMPLEX_LEN; ++i) {
        v[i].real = D[2 * i];
        v[i].imag = D[2 * i + 1];
    }
    return PQCP_SUCCESS;
}

/**
 * LabelingComputeW 函数（对应论文 Algorithm 2 的步骤4-8）
 * 功能：通过递归矩阵乘法构造 Barnes-Wall 格向量，并进行模数调整
 *
 * 参数说明：
 * - v：输入的复数向量（来自 LabelingComputeV）
 * - logq：模数 q 的对数值（用于缩放）
 * - tau：模数参数（控制格基缩放）
 * - w：输出的格向量（长度 32，对应 32 维整型格点）
 *
 * 论文对应关系：
 * - tmp 的递归计算对应 Wn 矩阵的 Kronecker 积乘法（论文式(4)）
 * - base = 1+i 对应 Barnes-Wall 格构造中的 ϕ 参数（论文定义6）
 * - 最终缩放操作对应论文中的模数调整 [·]_{2^τ}（Algorithm 2 步骤8）
 * - 然后将结果转到Q域上
 */
static inline int32_t LabelingComputeW(const Complex v[SCLOUDPLUS_BW_COMPLEX_LEN], const uint8_t logq,
    const uint8_t tau, uint16_t w[SCLOUDPLUS_BW_COMPLEX_LEN << 1])
{
    const Complex base = (Complex){1, 1};
    Complex tmp[SCLOUDPLUS_BW_COMPLEX_LEN];

    for (int i = 0; i < SCLOUDPLUS_BW_COMPLEX_LEN; i++) {
        tmp[i] = v[i];
    }

    for (int i = 0; i < 8; i++) {
        tmp[2 * i + 1] = ComplexAdd(tmp[2 * i], ComplexMul(tmp[2 * i + 1], base));
    }

    for (int i = 0; i < 4; i++) {
        tmp[4 * i + 2] = ComplexAdd(tmp[4 * i], ComplexMul(tmp[4 * i + 2], base));
        tmp[4 * i + 3] = ComplexAdd(tmp[4 * i + 1], ComplexMul(tmp[4 * i + 3], base));
    }

    for (int i = 0; i < 2; i++) {
        tmp[8 * i + 4] = ComplexAdd(tmp[8 * i], ComplexMul(tmp[8 * i + 4], base));
        tmp[8 * i + 5] = ComplexAdd(tmp[8 * i + 1], ComplexMul(tmp[8 * i + 5], base));
        tmp[8 * i + 6] = ComplexAdd(tmp[8 * i + 2], ComplexMul(tmp[8 * i + 6], base));
        tmp[8 * i + 7] = ComplexAdd(tmp[8 * i + 3], ComplexMul(tmp[8 * i + 7], base));
    }

    for (int i = 0; i < 8; i++) {
        tmp[8 + i] = ComplexAdd(tmp[i], ComplexMul(tmp[8 + i], base));
    }

    if (tau == 3) {
        for (int i = 0; i < 16; i++) {
            w[2 * i] = ((uint16_t)(tmp[i].real & 0x7) * (1 << (logq - tau))) & SCLOUDPLUS_MOD_Q;

            w[2 * i + 1] = ((uint16_t)(tmp[i].imag & 0x7) * (1 << (logq - tau))) & SCLOUDPLUS_MOD_Q;
        }
    } else if (tau == 4) {
        for (int i = 0; i < 16; i++) {
            w[2 * i] = ((uint16_t)(tmp[i].real & 0xF) * (1 << (logq - tau))) & SCLOUDPLUS_MOD_Q;

            w[2 * i + 1] = ((uint16_t)(tmp[i].imag & 0xF) * (1 << (logq - tau))) & SCLOUDPLUS_MOD_Q;
        }
    } else {
        return PQCP_SCLOUDPLUS_INVALID_ARG;
    }
    return PQCP_SUCCESS;
}

/**
 * DelabelingReduceW 函数（对应论文 Algorithm 3 的步骤6-10）
 * 功能：调整解码后的复数向量，确保其分量落在 S_{2τ - w_H(j)} 范围内
 * 
 * 参数说明：
 * - in：输入的复数向量（经过上述LabelingComputeW的逆变换的结果）
 * - tau：模数参数（τ=3 或 4，控制格基缩放）
 * - out：调整后的复数向量（满足 S_{2τ - w_H(j)} 约束）
 * 
 * 论文对应关系：
 * - 实现论文 Algorithm 3 的步骤8-9，通过模数调整确保：
 *   - 实部 a' = [a - (b - b')]_{2^{τ - ⌊w_H(j)/2⌋}}
 *   - 虚部 b' = [b]_{2^{τ - ⌈w_H(j)/2⌉}}
 * - 每个索引 j 的掩码值（如 0x7, 0x3 等）对应论文中 w_H(j) 的权重
 */

static inline int32_t DelabelingReduceW(const Complex in[SCLOUDPLUS_BW_COMPLEX_LEN], const uint8_t tau,
    Complex out[SCLOUDPLUS_BW_COMPLEX_LEN])
{
    int32_t mod, sub;
    if (tau == 3) {
        out[0] = (Complex){in[0].real & 0x7, in[0].imag & 0x7};
        out[3] = (Complex){in[3].real & 0x3, in[3].imag & 0x3};
        out[5] = (Complex){in[5].real & 0x3, in[5].imag & 0x3};
        out[6] = (Complex){in[6].real & 0x3, in[6].imag & 0x3};
        out[9] = (Complex){in[9].real & 0x3, in[9].imag & 0x3};
        out[10] = (Complex){in[10].real & 0x3, in[10].imag & 0x3};
        out[12] = (Complex){in[12].real & 0x3, in[12].imag & 0x3};
        out[15] = (Complex){in[15].real & 0x1, in[15].imag & 0x1};

        mod = in[1].imag & 0x3;
        sub = mod - in[1].imag;
        out[1] = (Complex){(in[1].real + sub) & 0x7, mod};

        mod = in[2].imag & 0x3;
        sub = mod - in[2].imag;
        out[2] = (Complex){(in[2].real + sub) & 0x7, mod};

        mod = in[4].imag & 0x3;
        sub = mod - in[4].imag;
        out[4] = (Complex){(in[4].real + sub) & 0x7, mod};

        mod = in[8].imag & 0x3;
        sub = mod - in[8].imag;
        out[8] = (Complex){(in[8].real + sub) & 0x7, mod};

        mod = in[7].imag & 0x1;
        sub = mod - in[7].imag;
        out[7] = (Complex){(in[7].real + sub) & 0x3, mod};

        mod = in[11].imag & 0x1;
        sub = mod - in[11].imag;
        out[11] = (Complex){(in[11].real + sub) & 0x3, mod};

        mod = in[13].imag & 0x1;
        sub = mod - in[13].imag;
        out[13] = (Complex){(in[13].real + sub) & 0x3, mod};

        mod = in[14].imag & 0x1;
        sub = mod - in[14].imag;
        out[14] = (Complex){(in[14].real + sub) & 0x3, mod};
    } else if (tau == 4) {
        out[0] = (Complex){in[0].real & 0xF, in[0].imag & 0xF};
        out[3] = (Complex){in[3].real & 0x7, in[3].imag & 0x7};
        out[5] = (Complex){in[5].real & 0x7, in[5].imag & 0x7};
        out[6] = (Complex){in[6].real & 0x7, in[6].imag & 0x7};
        out[9] = (Complex){in[9].real & 0x7, in[9].imag & 0x7};
        out[10] = (Complex){in[10].real & 0x7, in[10].imag & 0x7};
        out[12] = (Complex){in[12].real & 0x7, in[12].imag & 0x7};
        out[15] = (Complex){in[15].real & 0x3, in[15].imag & 0x3};

        mod = in[1].imag & 0x7;
        sub = mod - in[1].imag;
        out[1] = (Complex){(in[1].real + sub) & 0xF, mod};

        mod = in[2].imag & 0x7;
        sub = mod - in[2].imag;
        out[2] = (Complex){(in[2].real + sub) & 0xF, mod};

        mod = in[4].imag & 0x7;
        sub = mod - in[4].imag;
        out[4] = (Complex){(in[4].real + sub) & 0xF, mod};

        mod = in[8].imag & 0x7;
        sub = mod - in[8].imag;
        out[8] = (Complex){(in[8].real + sub) & 0xF, mod};

        mod = in[7].imag & 0x3;
        sub = mod - in[7].imag;
        out[7] = (Complex){(in[7].real + sub) & 0x7, mod};

        mod = in[11].imag & 0x3;
        sub = mod - in[11].imag;
        out[11] = (Complex){(in[11].real + sub) & 0x7, mod};

        mod = in[13].imag & 0x3;
        sub = mod - in[13].imag;
        out[13] = (Complex){(in[13].real + sub) & 0x7, mod};

        mod = in[14].imag & 0x3;
        sub = mod - in[14].imag;
        out[14] = (Complex){(in[14].real + sub) & 0x7, mod};
    } else {
        return PQCP_SCLOUDPLUS_INVALID_ARG;
    }
    return PQCP_SUCCESS;
}

/**
 * DelabelingComputeU 函数（对应论文 Algorithm 3 的步骤11-12）
 * 功能：将调整后的复数向量还原为原始消息比特
 * 
 * 参数说明：
 * - v：调整后的复数向量（来自 DelabelingReduceW）
 * - tau：模数参数
 * - m：输出的原始消息字节流
 * 
 * LabelingComputeV函数的逆变换
 */
static inline int32_t DelabelingComputeU(const Complex v[SCLOUDPLUS_BW_COMPLEX_LEN], const uint8_t tau, uint8_t *m)
{
    const int A[6] = {0, 1, 2, 4, 8, 16};
    const int B[20] = {
        3, 5, 6, 7, 9, 10, 11, 12, 13, 14,
        17, 18, 19, 20, 21, 22, 24, 25, 26, 28
    };
    const int C[6] = {15, 23, 27, 29, 30, 31};
    uint32_t bwNLen = SCLOUDPLUS_BW_COMPLEX_LEN << 1;
    uint16_t vecV[bwNLen];
    for (int i = 0; i < SCLOUDPLUS_BW_COMPLEX_LEN; i++) {
        vecV[2 * i] = v[i].real;
        vecV[2 * i + 1] = v[i].imag;
    }
    if (tau == 3) {
        memset_s(m, 8, 0, 8);
        for (int i = 5; i >= 0; i--) {
            m[7] = (m[7] << 1 | vecV[C[i]]);
        }
        m[7] = (m[7] << 2) | vecV[B[19]];
        m[6] = (m[6] | vecV[B[18]]) << 2;
        m[6] = (m[6] | vecV[B[17]]) << 2;
        m[6] = (m[6] | vecV[B[16]]) << 2;
        m[6] = (m[6] | vecV[B[15]]) << 0;
        m[5] = (m[5] | vecV[B[14]]) << 2;
        m[5] = (m[5] | vecV[B[13]]) << 2;
        m[5] = (m[5] | vecV[B[12]]) << 2;
        m[5] = (m[5] | vecV[B[11]]) << 0;
        m[4] = (m[4] | vecV[B[10]]) << 2;
        m[4] = (m[4] | vecV[B[9]]) << 2;
        m[4] = (m[4] | vecV[B[8]]) << 2;
        m[4] = (m[4] | vecV[B[7]]) << 0;
        m[3] = (m[3] | vecV[B[6]]) << 2;
        m[3] = (m[3] | vecV[B[5]]) << 2;
        m[3] = (m[3] | vecV[B[4]]) << 2;
        m[3] = (m[3] | vecV[B[3]]) << 0;
        m[2] = (m[2] | vecV[B[2]]) << 2;
        m[2] = (m[2] | vecV[B[1]]) << 2;
        m[2] = (m[2] | vecV[B[0]]) << 2;
        m[2] = m[2] | (vecV[A[5]] >> 1);
        m[1] = m[1] | (vecV[A[5]] << 7);
        m[1] = m[1] | (vecV[A[4]] << 4);
        m[1] = m[1] | (vecV[A[3]] << 1);
        m[1] = m[1] | (vecV[A[2]] >> 2);
        m[0] = m[0] | (vecV[A[2]] << 6);
        m[0] = m[0] | (vecV[A[1]] << 3);
        m[0] = m[0] | (vecV[A[0]] << 0);
    } else if (tau == 4) {
        memset_s(m, 12, 0, 12);
        m[11] = (vecV[C[5]] << 6) | (vecV[C[4]] << 4) | (vecV[C[3]] << 2) | (vecV[C[2]]);
        m[10] = (vecV[C[1]] << 6) | (vecV[C[0]] << 4) | (vecV[B[19]] << 1) | ((vecV[B[18]]) >> 2);
        m[9] = (vecV[B[18]] << 6) | (vecV[B[17]] << 3) | vecV[B[16]];
        m[8] = (vecV[B[15]] << 5) | (vecV[B[14]] << 2) | (vecV[B[13]] >> 1);
        m[7] = (vecV[B[13]] << 7) | (vecV[B[12]] << 4) | (vecV[B[11]] << 1) |
               (vecV[B[10]] >> 2);
        m[6] = (vecV[B[10]] << 6) | (vecV[B[9]] << 3) | vecV[B[8]];
        m[5] = (vecV[B[7]] << 5) | (vecV[B[6]] << 2) | (vecV[B[5]] >> 1);
        m[4] = (vecV[B[5]] << 7) | (vecV[B[4]] << 4) | (vecV[B[3]] << 1) |
               (vecV[B[2]] >> 2);
        m[3] = (vecV[B[2]] << 6) | (vecV[B[1]] << 3) | vecV[B[0]];
        m[2] = (vecV[A[5]] << 4) | (vecV[A[4]]);
        m[1] = (vecV[A[3]] << 4) | (vecV[A[2]]);
        m[0] = (vecV[A[1]] << 4) | (vecV[A[0]]);
    } else {
        return PQCP_SCLOUDPLUS_INVALID_ARG;
    }
    return PQCP_SUCCESS;
}
/**
 * DelabelingRecoverW 函数（对应论文 Algorithm 3 的步骤1-5）
 * 功能：逆向递归矩阵乘法，恢复原始复数向量 v'
 * 
 * 参数说明：
 * - w：输入的格向量（来自密文解码）
 * - logq：模数 q 的对数值（用于逆向缩放）
 * - tau：模数参数
 * - v：输出的原始复数向量
 * 
 * 论文对应关系：
 * - 逆向应用 Wn 矩阵的 Kronecker 积（Algorithm 1 的逆操作）
 * - ComplexDivPhi 实现 ϕ^{-1} = (1-i)/2 的乘法（论文式 ϕ^{-1} = 1/2 * \bar{ϕ}）
 */
static inline int32_t DelabelingRecoverW(const Complex w[SCLOUDPLUS_BW_COMPLEX_LEN], const uint8_t logq,
    const uint8_t tau, Complex v[SCLOUDPLUS_BW_COMPLEX_LEN])
{
    Complex tmp[SCLOUDPLUS_BW_COMPLEX_LEN];
    for (int i = 0; i < SCLOUDPLUS_BW_COMPLEX_LEN; i++) {
        tmp[i] = (Complex){w[i].real >> (logq - tau), w[i].imag >> (logq - tau)};
    }
    for (int i = 0; i < 8; i++) {
        tmp[8 + i] = ComplexDivPhi(ComplexSub(tmp[8 + i], tmp[i]));
    }
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 4; j++) {
            tmp[8 * i + 4 + j] = ComplexDivPhi(ComplexSub(tmp[8 * i + 4 + j], tmp[8 * i + j]));
        }
    }
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 2; j++) {
            tmp[4 * i + 2 + j] = ComplexDivPhi(ComplexSub(tmp[4 * i + 2 + j], tmp[4 * i + j]));
        }
    }
    for (int i = 0; i < 8; i++) {
        tmp[2 * i + 1] = ComplexDivPhi(ComplexSub(tmp[2 * i + 1], tmp[2 * i]));
    }
    return DelabelingReduceW(tmp, tau, v);
}

static inline int32_t EuclideanDistanceNoSqrt(const Complex *set1, const Complex *set2, int32_t set_size)
{
    int32_t sum = 0;
    for (int i = 0; i < set_size; i++) {
        const int32_t realDiff = set1[i].real - set2[i].real;
        const int32_t imagDiff = set1[i].imag - set2[i].imag;

        sum += realDiff * realDiff + imagDiff * imagDiff;
    }
    return sum;
}

static inline int32_t BDDForBWn(const Complex *t, const int32_t BWn, const uint8_t logq, const uint8_t tau, Complex *y)
{
    const int32_t tLen = BWn >> 1;
    const int32_t halfOftLen = tLen >> 1;
    const Complex phi = {1, 1};

    if (BWn == 2) {
        y[0] = (Complex){Round(t[0].real, logq, tau), Round(t[0].imag, logq, tau)};
        return 0;
    }
    Complex t1[halfOftLen], t2[halfOftLen], y1[halfOftLen], y2[halfOftLen];
    for (int i = 0; i < halfOftLen; i++) {
        t1[i] = t[i];
        t2[i] = t[i + halfOftLen];
    }
    BDDForBWn(t1, tLen, logq, tau, y1);
    BDDForBWn(t2, tLen, logq, tau, y2);

    Complex z1[halfOftLen], z2[halfOftLen], z1in[halfOftLen], z2in[halfOftLen];
    for (int i = 0; i < halfOftLen; i++) {
        z1in[i] = ComplexDivPhi(ComplexSub(t2[i], y1[i]));
        z2in[i] = ComplexDivPhi(ComplexSub(t1[i], y2[i]));
    }
    BDDForBWn(z1in, tLen, logq, tau, z1);
    BDDForBWn(z2in, tLen, logq, tau, z2);

    for (int i = 0; i < halfOftLen; i++) {
        z1[i] = ComplexMul(z1[i], phi);
        z2[i] = ComplexMul(z2[i], phi);
    }
    Complex out1[tLen], out2[tLen];
    for (int i = 0; i < halfOftLen; i++) {
        out1[i] = y1[i];
        out1[halfOftLen + i] = ComplexAdd(y1[i], z1[i]);
        out2[i] = ComplexAdd(y2[i], z2[i]);
        out2[halfOftLen + i] = y2[i];
    }
    const int32_t d1 = EuclideanDistanceNoSqrt(out1, t, tLen);
    const int32_t d2 = EuclideanDistanceNoSqrt(out2, t, tLen);

    if (d1 < d2) {
        for (int i = 0; i < tLen; i++) {
            y[i] = out1[i];
        }
    } else {
        for (int i = 0; i < tLen; i++) {
            y[i] = out2[i];
        }
    }
    return 0;
}

void SCLOUDPLUS_MsgEncode(const uint8_t *msg, const SCLOUDPLUS_Para *para, uint16_t *matrixM)
{
    uint8_t *msgPtr = (uint8_t *)msg;
    uint16_t *matMPtr = matrixM;
    uint32_t bwNLen = SCLOUDPLUS_BW_COMPLEX_LEN << 1;
    (void)memset_s(matrixM, para->mbar * para->nbar * sizeof(uint16_t), 0, para->mbar * para->nbar * sizeof(uint16_t));
    for (int i = 0; i < para->muConut; i++) {
        Complex v[SCLOUDPLUS_BW_COMPLEX_LEN];
        LabelingComputeV(msgPtr, para->tau, v);
        LabelingComputeW(v, para->logq, para->tau, matMPtr);
        msgPtr += (para->mu >> 3);
        matMPtr += bwNLen;
    }
}

void SCLOUDPLUS_MsgDecode(const uint16_t *matrixM, const SCLOUDPLUS_Para *para, uint8_t *msg)
{
    uint8_t *msgPtr = msg;
    Complex encMsg[SCLOUDPLUS_BW_COMPLEX_LEN], w[SCLOUDPLUS_BW_COMPLEX_LEN], u[SCLOUDPLUS_BW_COMPLEX_LEN];
    uint32_t bwNLen = SCLOUDPLUS_BW_COMPLEX_LEN << 1;
    for (int i = 0; i < para->muConut; i++) {
        for (int j = 0; j < SCLOUDPLUS_BW_COMPLEX_LEN; j++) {
            encMsg[j] = (Complex){matrixM[bwNLen * i + 2 * j], matrixM[bwNLen * i + 2 * j + 1]};
            w[j] = (Complex){0, 0};
            u[j] = (Complex){0, 0};
        }
        BDDForBWn(encMsg, bwNLen, para->logq, para->tau, w);
        DelabelingRecoverW(w, para->logq, para->tau, u);
        DelabelingComputeU(u, para->tau, msgPtr);
        msgPtr += (para->mu >> 3);
    }
}

void SCLOUDPLUS_PackPK(const uint16_t *B, const SCLOUDPLUS_Para *para, uint8_t *pk)
{
    const uint16_t *ptrIn = B;
    uint8_t *ptrOut = pk;
    uint32_t temp = 0;

    for (int i = 0; i < para->m * para->nbar; i = i + 2) {
        temp = U16ToU32(ptrIn);
        temp = (temp & 0xFFF) ^ ((temp >> 4) & 0xFFF000);
        *(uint32_t *)ptrOut = temp;
        ptrIn = ptrIn + 2;
        ptrOut = ptrOut + 3;
    }
}

void SCLOUDPLUS_UnPackPK(const uint8_t *pk, const SCLOUDPLUS_Para *para, uint16_t *B)
{
    const uint8_t *ptrIn = pk;
    uint16_t *ptrOut = B;
    for (int i = 0; i < para->m * para->nbar; i = i + 2) {
        *ptrOut = *(uint16_t *)ptrIn & SCLOUDPLUS_MOD_Q;
        *(ptrOut + 1) = (*(uint16_t *)(ptrIn + 1) >> 4) & SCLOUDPLUS_MOD_Q;
        ptrIn = ptrIn + 3;
        ptrOut = ptrOut + 2;
    }
}

void SCLOUDPLUS_PackSK(const uint16_t *S, const SCLOUDPLUS_Para *para, uint8_t *sk)
{
    const uint16_t *ptrIn = S;
    uint8_t *ptrOut = sk;
    uint8_t temp = 0;
    for (int i = 0; i < para->n * para->nbar; i = i + 4) {
        temp = (*ptrIn & 0x03);
        temp = ((*(ptrIn + 1) << 2) & 0x0C) ^ temp;
        temp = ((*(ptrIn + 2) << 4) & 0x30) ^ temp;
        temp = ((*(ptrIn + 3) << 6) & 0xC0) ^ temp;
        *ptrOut = temp;
        ptrIn = ptrIn + 4;
        ptrOut = ptrOut + 1;
    }
}

void SCLOUDPLUS_UnPackSK(const uint8_t *sk, const SCLOUDPLUS_Para *para, uint16_t *S)
{
    const uint8_t *ptrIn = sk;
    uint16_t *ptrOut = S;
    uint8_t temp = 0;
    for (int i = 0; i < para->n * para->nbar; i = i + 4) {
        temp = *ptrIn;
        *ptrOut = (int16_t)((temp & 0x03) << 14) >> 14;
        *(ptrOut + 1) = (int16_t)(((temp >> 2) & 0x03) << 14) >> 14;
        *(ptrOut + 2) = (int16_t)(((temp >> 4) & 0x03) << 14) >> 14;
        *(ptrOut + 3) = (int16_t)(((temp >> 6) & 0x03) << 14) >> 14;
        ptrIn = ptrIn + 1;
        ptrOut = ptrOut + 4;
    }
}

//compress函数类似于KYBER
void SCLOUDPLUS_CompressC1(const uint16_t *C, const SCLOUDPLUS_Para *para, uint16_t *out)
{
    if (para->ss == 16) {
        for (int i = 0; i < para->mbar * para->n; i++) {
            out[i] = ((((uint32_t)(C[i] & SCLOUDPLUS_MOD_Q) << 9) + 2048) >> 12) & 0x1FF;
        }
    } else if (para->ss == 24) {
        memcpy_s(out, para->mbar * para->n * sizeof(uint16_t), C, para->mbar * para->n * sizeof(uint16_t));
    } else if (para->ss == 32) {
        for (int i = 0; i < para->mbar * para->n; i++) {
            out[i] = ((((uint32_t)(C[i] & SCLOUDPLUS_MOD_Q) << 10) + 2048) >> 12) & 0x3FF;
        }
    }
}

void SCLOUDPLUS_DeCompressC1(const uint16_t *in, const SCLOUDPLUS_Para *para, uint16_t *C)
{
    if (para->ss == 16) {
        for (int i = 0; i < para->mbar * para->n; i++) {
            C[i] = ((uint32_t)((in[i] & 0x1FF) << 12) + 256) >> 9;
        }
    } else if (para->ss == 24) {
        memcpy_s(C, para->mbar * para->n * sizeof(uint16_t), in, para->mbar * para->n * sizeof(uint16_t));
    } else if (para->ss == 32) {
        for (int i = 0; i < para->mbar * para->n; i++) {
            C[i] = ((uint32_t)((in[i] & 0x3FF) << 12) + 512) >> 10;
        }
    }
}

//此函数对应论文算法5的C_2压缩时的四舍五入,针对0.5的情况要进行向奇数位的舍入,如0.5得到1, 3.5也是得到3.其他值仍为正常的四舍五入
void SCLOUDPLUS_CompressC2(const uint16_t *C, const SCLOUDPLUS_Para *para, uint16_t *out)
{
    if (para->ss == 16 || para->ss == 32) {
        for (int i = 0; i < para->mbar * para->nbar; i++) {
            const uint32_t temp = ((((uint32_t)(C[i] & SCLOUDPLUS_MOD_Q) << 7) + 2048) >> 12);
            const uint32_t remainder = (((uint32_t)(C[i] & SCLOUDPLUS_MOD_Q) << 7) + 2048) % 6144;
            out[i] = (temp - ((!remainder) && 1)) & 0x7F;
        }
    } else if (para->ss == 24) {
        for (int i = 0; i < para->mbar * para->nbar; i++) {
            const uint32_t temp = ((((uint32_t)(C[i] & SCLOUDPLUS_MOD_Q) << 10) + 2048) >> 12);
            const uint32_t remainder = (((uint32_t)(C[i] & SCLOUDPLUS_MOD_Q) << 10) + 2048) % 6144;
            out[i] = (temp - ((!remainder) && 1)) & 0x3FF;
        }
    }
}

void SCLOUDPLUS_DeCompressC2(const uint16_t *in, const SCLOUDPLUS_Para *para, uint16_t *C)
{
    if (para->ss == 16 || para->ss == 32) {
        for (int i = 0; i < para->mbar * para->nbar; i++) {
            C[i] = ((uint32_t)((in[i] & 0x7F) << 12) + 64) >> 7;
        }
    } else if (para->ss == 24) {
        for (int i = 0; i < para->mbar * para->nbar; i++) {
            C[i] = ((uint32_t)((in[i] & 0x3FF) << 12) + 512) >> 10;
        }
    }
}

void SCLOUDPLUS_PackC1(const uint16_t *C, const SCLOUDPLUS_Para *para, uint8_t *out)
{
    if (para->ss == 16) {
        const int inLen = para->mbar * para->n;
        const uint8_t *ptrIn = (uint8_t *)C;
        for (int i = 0; i < inLen; i++) {
            out[i] = ptrIn[2 * i];
        }
        for (int i = 0; i < (inLen >> 3); i++) {
            for (int j = 0; j < 8; j++) {
                out[inLen + i] = (out[inLen + i] << 1) | ptrIn[16 * i + 2 * j + 1];
            }
        }
    } else if (para->ss == 24) {
        const uint16_t *ptrIn = C;
        uint8_t *ptrOut = out;
        uint32_t temp = 0;
        for (int i = 0; i < para->mbar * para->n; i = i + 2) {
            temp = U16ToU32(ptrIn);
            temp = (temp & 0xFFF) ^ ((temp >> 4) & 0xFFF000);
            *(uint32_t *)ptrOut = temp;
            ptrIn = ptrIn + 2;
            ptrOut = ptrOut + 3;
        }
    } else if (para->ss == 32) {
        const int inLen = para->mbar * para->n;
        const uint8_t *ptrIn = (uint8_t *)C;
        for (int i = 0; i < inLen; i++) {
            out[i] = ptrIn[2 * i];
        }
        for (int i = 0; i < (inLen >> 2); i++) {
            for (int j = 0; j < 4; j++) {
                out[inLen + i] = (out[inLen + i] << 2) | ptrIn[8 * i + 2 * j + 1];
            }
        }
    }
}

void SCLOUDPLUS_UnPackC1(const uint8_t *in, const SCLOUDPLUS_Para *para, uint16_t *C)
{
    if (para->ss == 16) {
        const int outLen = para->mbar * para->n;
        for (int i = 0; i < outLen; i++) {
            C[i] = (uint16_t)in[i];
        }
        for (int i = 0; i < (outLen >> 3); i++) {
            C[8 * i] = C[8 * i] | (((uint16_t)in[outLen + i] << 1) & 0x100);
            C[8 * i + 1] = C[8 * i + 1] | (((uint16_t)in[outLen + i] << 2) & 0x100);
            C[8 * i + 2] = C[8 * i + 2] | (((uint16_t)in[outLen + i] << 3) & 0x100);
            C[8 * i + 3] = C[8 * i + 3] | (((uint16_t)in[outLen + i] << 4) & 0x100);
            C[8 * i + 4] = C[8 * i + 4] | (((uint16_t)in[outLen + i] << 5) & 0x100);
            C[8 * i + 5] = C[8 * i + 5] | (((uint16_t)in[outLen + i] << 6) & 0x100);
            C[8 * i + 6] = C[8 * i + 6] | (((uint16_t)in[outLen + i] << 7) & 0x100);
            C[8 * i + 7] = C[8 * i + 7] | (((uint16_t)in[outLen + i] << 8) & 0x100);
        }
    } else if (para->ss == 24) {
        const uint8_t *ptrIn = in;
        uint16_t *ptrOut = C;
        for (int i = 0; i < para->mbar * para->n; i = i + 2) {
            *ptrOut = *(uint16_t *)ptrIn & SCLOUDPLUS_MOD_Q;
            *(ptrOut + 1) = (*(uint16_t *)(ptrIn + 1) >> 4) & SCLOUDPLUS_MOD_Q;
            ptrIn = ptrIn + 3;
            ptrOut = ptrOut + 2;
        }
    } else if (para->ss == 32) {
        const int outLen = para->mbar * para->n;
        for (int i = 0; i < outLen; i++) {
            C[i] = (uint16_t)in[i];
        }
        for (int i = 0; i < (outLen >> 2); i++) {
            C[4 * i] = C[4 * i] | (((uint16_t)in[outLen + i] << 2) & 0x300);
            C[4 * i + 1] = C[4 * i + 1] | (((uint16_t)in[outLen + i] << 4) & 0x300);
            C[4 * i + 2] = C[4 * i + 2] | (((uint16_t)in[outLen + i] << 6) & 0x300);
            C[4 * i + 3] = C[4 * i + 3] | (((uint16_t)in[outLen + i] << 8) & 0x300);
        }
    }
}

void SCLOUDPLUS_PackC2(const uint16_t *C, const SCLOUDPLUS_Para *para, uint8_t *out)
{
    if (para->ss == 16) {
        const int inLen = para->mbar * para->nbar;
        const uint16_t *ptrIn = C;
        uint8_t *ptrOut = out;
        for (int i = 0; i < inLen; i = i + 8) {
            *ptrOut = ((*ptrIn) & 0x7F) | (*(ptrIn + 1) << 7);                  // 7+1
            *(ptrOut + 1) = ((*(ptrIn + 1) >> 1) & 0x3F) | (*(ptrIn + 2) << 6); // 6+2
            *(ptrOut + 2) = ((*(ptrIn + 2) >> 2) & 0x1F) | (*(ptrIn + 3) << 5); // 5+3
            *(ptrOut + 3) = ((*(ptrIn + 3) >> 3) & 0x0F) | (*(ptrIn + 4) << 4); // 4+4
            *(ptrOut + 4) = ((*(ptrIn + 4) >> 4) & 0x07) | (*(ptrIn + 5) << 3); // 3+5
            *(ptrOut + 5) = ((*(ptrIn + 5) >> 5) & 0x03) | (*(ptrIn + 6) << 2); // 2+6
            *(ptrOut + 6) = ((*(ptrIn + 6) >> 6) & 0x01) | (*(ptrIn + 7) << 1); // 1+7
            ptrIn = ptrIn + 8;
            ptrOut = ptrOut + 7;
        }
    } else if (para->ss == 24) {
        const int inLen = para->mbar * para->nbar;
        const uint8_t *ptrIn = (uint8_t *)C;
        for (int i = 0; i < inLen; i++) {
            out[i] = ptrIn[2 * i];
        }
        for (int i = 0; i < (inLen >> 2); i++) {
            for (int j = 0; j < 4; j++) {
                out[inLen + i] = (out[inLen + i] << 2) | ptrIn[8 * i + 2 * j + 1];
            }
        }
    } else if (para->ss == 32) {
        const int inLen = para->mbar * para->nbar - ((para->mbar * para->nbar) & 0x7);

        const uint16_t *ptrIn = C;
        uint8_t *ptrOut = out;
        for (int i = 0; i < inLen; i = i + 8) {
            *ptrOut = ((*ptrIn) & 0x7F) | (*(ptrIn + 1) << 7);                  // 7+1
            *(ptrOut + 1) = ((*(ptrIn + 1) >> 1) & 0x3F) | (*(ptrIn + 2) << 6); // 6+2
            *(ptrOut + 2) = ((*(ptrIn + 2) >> 2) & 0x1F) | (*(ptrIn + 3) << 5); // 5+3
            *(ptrOut + 3) = ((*(ptrIn + 3) >> 3) & 0x0F) | (*(ptrIn + 4) << 4); // 4+4
            *(ptrOut + 4) = ((*(ptrIn + 4) >> 4) & 0x07) | (*(ptrIn + 5) << 3); // 3+5
            *(ptrOut + 5) = ((*(ptrIn + 5) >> 5) & 0x03) | (*(ptrIn + 6) << 2); // 2+6
            *(ptrOut + 6) = ((*(ptrIn + 6) >> 6) & 0x01) | (*(ptrIn + 7) << 1); // 1+7
            ptrIn = ptrIn + 8;
            ptrOut = ptrOut + 7;
        }
        *ptrOut = ((*ptrIn) & 0x7F) | (*(ptrIn + 1) << 7);
        *(ptrOut + 1) = ((*(ptrIn + 1) >> 1) & 0x3F) | (*(ptrIn + 2) << 6);
        *(ptrOut + 2) = ((*(ptrIn + 2) >> 2) & 0x1F) | (*(ptrIn + 3) << 5);
        *(ptrOut + 3) = ((*(ptrIn + 3) >> 3) & 0x0F);
    }
}

void SCLOUDPLUS_UnPackC2(const uint8_t *in, const SCLOUDPLUS_Para *para, uint16_t *C)
{
    if (para->ss == 16) {
        const uint8_t *ptrIn = in;
        uint16_t *ptrOut = C;
        const int outLen = para->mbar * para->nbar;
        for (int i = 0; i < outLen; i = i + 8) {
            *ptrOut = *ptrIn & 0x7F;
            *(ptrOut + 1) = (*(uint16_t *)ptrIn >> 7) & 0x7F;
            *(ptrOut + 2) = (*(uint16_t *)(ptrIn + 1) >> 6) & 0x7F;
            *(ptrOut + 3) = (*(uint16_t *)(ptrIn + 2) >> 5) & 0x7F;
            *(ptrOut + 4) = (*(uint16_t *)(ptrIn + 3) >> 4) & 0x7F;
            *(ptrOut + 5) = (*(uint16_t *)(ptrIn + 4) >> 3) & 0x7F;
            *(ptrOut + 6) = (*(uint16_t *)(ptrIn + 5) >> 2) & 0x7F;
            *(ptrOut + 7) = (*(ptrIn + 6) >> 1) & 0x7F;
            ptrIn = ptrIn + 7;
            ptrOut = ptrOut + 8;
        }
    } else if (para->ss == 24) {
        const int outLen = para->mbar * para->nbar;
        for (int i = 0; i < outLen; i++) {
            C[i] = (uint16_t)in[i];
        }
        for (int i = 0; i < (outLen >> 2); i++) {
            C[4 * i] = C[4 * i] | (((uint16_t)in[outLen + i] << 2) & 0x300);
            C[4 * i + 1] = C[4 * i + 1] | (((uint16_t)in[outLen + i] << 4) & 0x300);
            C[4 * i + 2] = C[4 * i + 2] | (((uint16_t)in[outLen + i] << 6) & 0x300);
            C[4 * i + 3] = C[4 * i + 3] | (((uint16_t)in[outLen + i] << 8) & 0x300);
        }
    } else if (para->ss == 32) {
        const int outLen = para->mbar * para->nbar - ((para->mbar * para->nbar) & 0x7);
        const uint8_t *ptrIn = in;
        uint16_t *ptrOut = C;
        for (int i = 0; i < outLen; i = i + 8) {
            *ptrOut = *ptrIn & 0x7F;
            *(ptrOut + 1) = (*(uint16_t *)ptrIn >> 7) & 0x7F;
            *(ptrOut + 2) = (*(uint16_t *)(ptrIn + 1) >> 6) & 0x7F;
            *(ptrOut + 3) = (*(uint16_t *)(ptrIn + 2) >> 5) & 0x7F;
            *(ptrOut + 4) = (*(uint16_t *)(ptrIn + 3) >> 4) & 0x7F;
            *(ptrOut + 5) = (*(uint16_t *)(ptrIn + 4) >> 3) & 0x7F;
            *(ptrOut + 6) = (*(uint16_t *)(ptrIn + 5) >> 2) & 0x7F;
            *(ptrOut + 7) = (*(ptrIn + 6) >> 1) & 0x7F;
            ptrIn = ptrIn + 7;
            ptrOut = ptrOut + 8;
        }
        *ptrOut = *ptrIn & 0x7F;
        *(ptrOut + 1) = (*(uint16_t *)ptrIn >> 7) & 0x7F;
        *(ptrOut + 2) = (*(uint16_t *)(ptrIn + 1) >> 6) & 0x7F;
        *(ptrOut + 3) = (*(uint16_t *)(ptrIn + 2) >> 5) & 0x7F;
    }
}

int8_t SCLOUDPLUS_Verify(const uint8_t *a, const uint8_t *b, const int Len)
{
    uint8_t r = 0;
    for (int i = 0; i < Len; i++) {
        r |= a[i] ^ b[i];
    }

    r = (-(int8_t)(r >> 1) | -(int8_t)(r & 1)) >> (8 * sizeof(uint8_t) - 1);
    return (int8_t)r;
}

void SCLOUDPLUS_CMov(uint8_t *r, const uint8_t *a, const uint8_t *b, const int Len, const int8_t bl)
{
    for (int i = 0; i < Len; i++) {
        r[i] = (~bl & a[i]) | (bl & b[i]);
    }
}

void SCLOUDPLUS_Add(const uint16_t *in0, const uint16_t *in1, const int len, uint16_t *out)
{
    for (int i = 0; i < len; i++) {
        out[i] = (in0[i] + in1[i]) & SCLOUDPLUS_MOD_Q;
    }
}

void SCLOUDPLUS_Sub(const uint16_t *in0, const uint16_t *in1, const int len, uint16_t *out)
{
    for (int i = 0; i < len; i++) {
        out[i] = (in0[i] - in1[i]) & SCLOUDPLUS_MOD_Q;
    }
}

void SCLOUDPLUS_CS(const uint16_t *C, const uint16_t *S, const SCLOUDPLUS_Para *para, uint16_t *out)
{
    memset_s(out, para->mbar * para->nbar * 2, 0, para->mbar * para->nbar * 2);
    for (int i = 0; i < para->mbar; i++) {
        for (int j = 0; j < para->nbar; j++) {
            for (int k = 0; k < para->n; k++) {
                out[i * para->nbar + j] += C[i * para->n + k] * (uint16_t)S[j * para->n + k];
            }
        }
    }
}

void SCLOUDPLUS_SB_E(const uint16_t *S, const uint16_t *B, const uint16_t *E, const SCLOUDPLUS_Para *para, uint16_t *out)
{
    memcpy_s(out, para->mbar * para->nbar * 2, E, para->mbar * para->nbar * 2);
    for (int i = 0; i < para->mbar; i++) {
        for (int j = 0; j < para->nbar; j++) {
            for (int k = 0; k < para->m; k++) {
                out[i * para->nbar + j] += (uint16_t)S[i * para->m + k] * B[k * para->nbar + j];
            }
        }
    }
}

int32_t SCLOUDPLUS_AS_E(const uint8_t *seedA, const uint16_t *S, const uint16_t *E, const SCLOUDPLUS_Para *para,
                        uint16_t *B)
{
    int32_t ret = 0;
    memcpy_s(B, para->m * para->nbar * 2, E, para->m * para->nbar * 2);
    CRYPT_EAL_CipherCtx *RandCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_ECB);
    if (RandCtx == NULL) {
        return PQCP_MALLOC_FAIL;
    }
    uint32_t outLen = 4 * para->n * sizeof(uint16_t);
    const int blockRowLen = para->h1 * 2;
    const int blockNumber = para->h1 >> 1;
    uint32_t aRowIn[4 * blockRowLen];
    uint16_t aRowOut[4 * para->n];
    memset_s(aRowIn, 4 * blockRowLen * sizeof(uint32_t), 0, 4 * blockRowLen * sizeof(uint32_t));
    ret = CRYPT_EAL_CipherInit(RandCtx, seedA, 16, NULL, 0, true);
    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }
    ret = CRYPT_EAL_CipherSetPadding(RandCtx, CRYPT_PADDING_NONE);
    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }

    for (int i = 0; i < para->m; i = i + 4) {
        for (int j = 0; j < blockNumber; j++) {
            aRowIn[4 * j + 0 * blockRowLen] = i * blockNumber + j;
            aRowIn[4 * j + 1 * blockRowLen] = (i + 1) * blockNumber + j;
            aRowIn[4 * j + 2 * blockRowLen] = (i + 2) * blockNumber + j;
            aRowIn[4 * j + 3 * blockRowLen] = (i + 3) * blockNumber + j;
        }
        ret = CRYPT_EAL_CipherUpdate(RandCtx, (uint8_t *)aRowIn, 4 * para->n * sizeof(uint16_t), (uint8_t *)aRowOut,
                                     &outLen);
        if (ret != PQCP_SUCCESS) {
            goto EXIT;
        }
        for (int k = 0; k < para->nbar; k++) {
            uint16_t sum[4] = {0};
            for (int j = 0; j < para->n; j++) {
                const uint16_t sp = S[k * para->n + j];
                sum[0] += aRowOut[0 * para->n + j] * sp;
                sum[1] += aRowOut[1 * para->n + j] * sp;
                sum[2] += aRowOut[2 * para->n + j] * sp;
                sum[3] += aRowOut[3 * para->n + j] * sp;
            }
            B[(i + 0) * para->nbar + k] += sum[0];
            B[(i + 1) * para->nbar + k] += sum[1];
            B[(i + 2) * para->nbar + k] += sum[2];
            B[(i + 3) * para->nbar + k] += sum[3];
        }
    }

EXIT:
    CRYPT_EAL_CipherFreeCtx(RandCtx);
    return ret;
}

int32_t SCLOUDPLUS_SA_E(const uint8_t *seedA, const uint16_t *S, uint16_t *E, const SCLOUDPLUS_Para *para, uint16_t *C)
{
    int32_t ret = 0;
    uint32_t outLen = 8 * para->n * sizeof(uint16_t);
    const int blockRowLen = para->h1 * 2;
    const int blockNumber = para->h1 >> 1;
    uint32_t aRowIn[8 * blockRowLen];
    uint16_t aRowOut[8 * para->n];
    memset_s(aRowIn, 8 * blockRowLen * sizeof(uint32_t), 0, 8 * blockRowLen * sizeof(uint32_t));

    CRYPT_EAL_CipherCtx *RandCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_ECB);
    if (RandCtx == NULL) {
        return PQCP_MALLOC_FAIL;
    }
    ret = CRYPT_EAL_CipherInit(RandCtx, seedA, 16, NULL, 0, true);
    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }
    ret = CRYPT_EAL_CipherSetPadding(RandCtx, CRYPT_PADDING_NONE);
    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }

    for (int i = 0; i < para->m; i += 8) {
        for (int q = 0; q < 8; q++) {
            for (int p = 0; p < blockNumber; p += 1) {
                aRowIn[q * blockRowLen + 4 * p] = (i + q) * blockNumber + p;
            }
        }
        ret = CRYPT_EAL_CipherUpdate(RandCtx, (uint8_t *)aRowIn, 8 * para->n * sizeof(uint16_t), (uint8_t *)aRowOut,
                                     &outLen);
        if (ret != PQCP_SUCCESS) {
            goto EXIT;
        }

        for (int j = 0; j < para->mbar; j++) {
            uint16_t sum = 0;
            uint16_t sp[8];
            for (int p = 0; p < 8; p++) {
                sp[p] = S[j * para->m + i + p];
            }
            for (int q = 0; q < para->n; q++) {
                sum = E[j * para->n + q];
                for (int p = 0; p < 8; p++) {
                    sum += sp[p] * aRowOut[p * para->n + q];
                }
                E[j * para->n + q] = sum;
            }
        }
    }
    (void)memcpy_s((unsigned char *)C, 2 * para->mbar * para->n, (unsigned char *)E, 2 * para->mbar * para->n);

EXIT:
    CRYPT_EAL_CipherFreeCtx(RandCtx);
    return ret;
}

static inline void CBD1(const uint8_t in, uint16_t *out)
{
    uint8_t b = 0, b0 = 0, b1 = 0;
    b = in;
    for (size_t j = 0; j < 4; j++) {
        b0 = b & 1;
        b1 = (b >> 1) & 1;
        *(out + j) = (uint16_t)(b0 - b1);
        b = b >> 2;
    }
}

static inline void CBD2(const uint8_t in, uint16_t *out)
{
    uint8_t b = 0;
    b += in & 0x55;
    b += (in >> 1) & 0x55;
    *out = (uint16_t)((b & 0x03) - ((b >> 2) & 0x03));
    *(out + 1) = (uint16_t)(((b >> 4) & 0x03) - ((b >> 6) & 0x03));
}

static inline void cbd3(const uint32_t in, uint16_t *out)
{
    uint32_t b = 0;
    b += in & 0x00249249;
    b += (in >> 1) & 0x00249249;
    b += (in >> 2) & 0x00249249;
    for (int i = 0; i < 4; i++) {
        out[i] = ((b >> (6 * i)) & 0x07) - ((b >> (6 * i + 3)) & 0x07);
    }
}

static inline void CBD7(const uint64_t in, uint16_t *out)
{
    uint64_t b0 = 0;
    b0 += in & 0x2040810204081;
    b0 += (in >> 1) & 0x2040810204081;
    b0 += (in >> 2) & 0x2040810204081;
    b0 += (in >> 3) & 0x2040810204081;
    b0 += (in >> 4) & 0x2040810204081;
    b0 += (in >> 5) & 0x2040810204081;
    b0 += (in >> 6) & 0x2040810204081;
    for (int i = 0; i < 4; i++) {
        out[i] = ((b0 >> (14 * i)) & 0x7F) - ((b0 >> (14 * i + 7)) & 0x7F);
    }
}

int32_t SCLOUDPLUS_SampleEta1(const uint8_t *seed, const SCLOUDPLUS_Para *para, uint16_t *matrixE)
{
    memset_s(matrixE, para->m * para->nbar * sizeof(uint16_t), 0, para->m * para->nbar * sizeof(uint16_t));
    int32_t ret = PQCP_SUCCESS;
    uint32_t hashLen = (para->m * para->nbar * 2 * para->eta1) >> 3;
    uint8_t *tmp = BSL_SAL_Malloc(hashLen);
    if (tmp == NULL) {
        return PQCP_MALLOC_FAIL;
    }
    uint8_t *ptrTmp = tmp;
    uint16_t *ptrMatrix = matrixE;
    ret = SCLOUDPLUS_MdFunc(CRYPT_MD_SHAKE256, seed, SCLOUDPLUS_SEED_R2_LEN, NULL, 0, tmp, &hashLen);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    if (para->eta1 == 2) {
        for (size_t i = 0; i < para->m * para->nbar; i = i + 2) {
            CBD2(*ptrTmp, ptrMatrix);
            ptrTmp = ptrTmp + 1;
            ptrMatrix = ptrMatrix + 2;
        }
    } else if (para->eta1 == 3) {
        for (size_t i = 0; i < para->m * para->nbar; i = i + 4) {
            cbd3(U8ToU24(ptrTmp) & 0xFFFFFF, ptrMatrix);
            ptrTmp = ptrTmp + 3;
            ptrMatrix = ptrMatrix + 4;
        }
    } else if (para->eta1 == 7) {
        for (size_t i = 0; i < para->m * para->nbar; i = i + 4) {
            CBD7(U8ToU56(ptrTmp) & 0xFFFFFFFFFFFFFF, ptrMatrix);
            ptrTmp = ptrTmp + 7;
            ptrMatrix = ptrMatrix + 4;
        }
    } else {
        ret = PQCP_SCLOUDPLUS_INVALID_ARG;
    }
EXIT:
    BSL_SAL_FREE(tmp);
    return ret;
}

int32_t SCLOUDPLUS_SampleEta2(const uint8_t *seed, const SCLOUDPLUS_Para *para, uint16_t *matrixE1, uint16_t *matrixE2)
{
    memset_s(matrixE1, para->mbar * para->n * 2, 0, para->mbar * para->n * 2);
    memset_s(matrixE2, para->mbar * para->nbar * 2, 0, para->mbar * para->nbar * 2);
    int32_t ret = 0;
    const uint32_t hash1Len = ((para->mbar * para->n) * (2 * para->eta2)) >> 3;
    const uint32_t hash2Len = ((para->mbar * para->nbar) * (2 * para->eta2) + 7) >> 3;
    uint32_t hashLen = hash1Len + hash2Len;
    uint8_t *tmp = BSL_SAL_Malloc(hash1Len + hash2Len);
    if (tmp == NULL) {
        return PQCP_MALLOC_FAIL;
    }
    uint8_t *ptrTmp1 = tmp;
    uint8_t *ptrTmp2 = tmp + hash1Len;
    uint16_t *ptrMatrix1 = matrixE1;
    uint16_t *ptrMatrix2 = matrixE2;
    ret = SCLOUDPLUS_MdFunc(CRYPT_MD_SHAKE256, seed, SCLOUDPLUS_SEED_R2_LEN, NULL, 0, tmp, &hashLen);
    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }
    if (para->eta2 == 1) {
        for (size_t i = 0; i < para->mbar * para->n; i = i + 4) {
            CBD1(*ptrTmp1, ptrMatrix1);
            ptrTmp1 = ptrTmp1 + 1;
            ptrMatrix1 = ptrMatrix1 + 4;
        }
        for (size_t i = 0; i < para->mbar * para->nbar; i = i + 4) {
            CBD1(*ptrTmp2, ptrMatrix2);
            ptrTmp2 = ptrTmp2 + 1;
            ptrMatrix2 = ptrMatrix2 + 4;
        }
    } else if (para->eta2 == 2) {
        for (size_t i = 0; i < para->mbar * para->n; i = i + 2) {
            CBD2(*ptrTmp1, ptrMatrix1);
            ptrTmp1 = ptrTmp1 + 1;
            ptrMatrix1 = ptrMatrix1 + 2;
        }
        for (size_t i = 0; i < para->mbar * para->nbar; i = i + 2) {
            CBD2(*ptrTmp2, ptrMatrix2);
            ptrTmp2 = ptrTmp2 + 1;
            ptrMatrix2 = ptrMatrix2 + 2;
        }
    } else if (para->eta2 == 7) {
        for (size_t i = 0; i < para->mbar * para->n; i = i + 4) {
            CBD7(U8ToU56(ptrTmp1) & 0xFFFFFFFFFFFFFF, ptrMatrix1);
            ptrTmp1 = ptrTmp1 + 7;
            ptrMatrix1 = ptrMatrix1 + 4;
        }
        for (size_t i = 0; i < para->mbar * para->nbar; i = i + 4) {
            CBD7(U8ToU56(ptrTmp2) & 0xFFFFFFFFFFFFFF, ptrMatrix2);
            ptrTmp2 = ptrTmp2 + 7;
            ptrMatrix2 = ptrMatrix2 + 4;
        }
    } else {
        ret = PQCP_SCLOUDPLUS_INVALID_ARG;
    }
EXIT:
    BSL_SAL_FREE(tmp);
    return ret;
}

int32_t SCLOUDPLUS_SamplePsi(const uint8_t *seed, const SCLOUDPLUS_Para *para, uint16_t *matrixS)
{
    int32_t ret;
    (void)memset_s(matrixS, para->n * para->nbar * sizeof(uint16_t), 0, para->n * para->nbar * sizeof(uint16_t));
    uint8_t hash[680] = {0}; // 5*136 shake256_rate
    uint16_t tmp[para->mnout];
    int outLen, k = 0;
    const int inLen = sizeof(hash);
    CRYPT_EAL_MdCTX *psiCtx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHAKE256);
    if (psiCtx == NULL) {
        ret = PQCP_MALLOC_FAIL;
    }
    ret = CRYPT_EAL_MdInit(psiCtx);
    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }
    ret = CRYPT_EAL_MdUpdate(psiCtx, seed, SCLOUDPLUS_SEED_R1_LEN);
    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }
    ret = CRYPT_EAL_MdSqueeze(psiCtx, hash, inLen);
    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }
    U8ToN(hash, para->mnin, para, tmp, &outLen);
    for (int i = 0; i < para->nbar; i++) {
        int j = 0;
        while (j < para->h1 * 2) { // h1 1 and h1 -1
            if (k == outLen) {
                ret = CRYPT_EAL_MdSqueeze(psiCtx, hash, inLen);
                if (ret != PQCP_SUCCESS) {
                    goto EXIT;
                }
                U8ToN(hash, para->mnin, para, tmp, &outLen);
                k = 0;
            }
            const uint16_t location = tmp[k];
            const int32_t condition = (matrixS[i * para->n + location] == 0);
            const uint16_t mask = -condition;
            matrixS[i * para->n + location] = (matrixS[i * para->n + location] & ~mask) |
                ((1 - 2 * (j & 1)) & mask);
            j += condition;
            k++;
        }
    }
EXIT:
    CRYPT_EAL_MdFreeCtx(psiCtx);
    return ret;
}

int32_t SCLOUDPLUS_SamplePhi(const uint8_t *seed, const SCLOUDPLUS_Para *para, uint16_t *matrixs)
{
    int32_t ret = 0;
    memset_s(matrixs, para->m * para->mbar * 2, 0, para->m * para->mbar * 2);
    uint8_t hash[680] = {0}; // 5*136 shake256_rate
    uint16_t tmp[para->mnout];
    int outLen, k = 0;
    const int inLen = sizeof(hash);
    CRYPT_EAL_MdCTX *phiCtx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHAKE256);
    if (phiCtx == NULL) {
        return PQCP_MALLOC_FAIL;
    }
    ret = CRYPT_EAL_MdInit(phiCtx);
    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }
    ret = CRYPT_EAL_MdUpdate(phiCtx, seed, 32);
    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }
    ret = CRYPT_EAL_MdSqueeze(phiCtx, hash, inLen);
    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }
    U8ToM(hash, para->mnin, para, tmp, &outLen);
    for (int i = 0; i < para->mbar; i++) {
        int j = 0;
        while (j < para->h2 * 2) {
            if (k == outLen) {
                CRYPT_EAL_MdSqueeze(phiCtx, hash, inLen);
                U8ToM(hash, para->mnin, para, tmp, &outLen);
                k = 0;
            }
            const uint16_t location = tmp[k];
            const int32_t condition = (matrixs[i * para->m + location] == 0);
            const uint16_t mask = -condition;
            matrixs[i * para->m + location] =
                (matrixs[i * para->m + location] & ~mask) |
                ((1 - 2 * (j & 1)) & mask);
            j += condition;
            k++;
        }
    }
EXIT:
    CRYPT_EAL_MdFreeCtx(phiCtx);
    return ret;
}

int32_t SCLOUDPLUS_MdFunc(const CRYPT_MD_AlgId id, const uint8_t *input1, const uint32_t inLen1, const uint8_t *input2,
    const uint32_t inLen2, uint8_t *output, uint32_t *outLen)
{
    CRYPT_EAL_MdCTX *MdCtx = CRYPT_EAL_MdNewCtx(id);
    if (MdCtx == NULL) {
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = CRYPT_EAL_MdInit(MdCtx);
    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }
    ret = CRYPT_EAL_MdUpdate(MdCtx, input1, inLen1);
    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }
    if (input2 != NULL) {
        ret = CRYPT_EAL_MdUpdate(MdCtx, input2, inLen2);
        if (ret != PQCP_SUCCESS) {
            goto EXIT;
        }
    }
    ret = CRYPT_EAL_MdFinal(MdCtx, output, outLen);
EXIT:
    CRYPT_EAL_MdFreeCtx(MdCtx);
    return ret;
}

