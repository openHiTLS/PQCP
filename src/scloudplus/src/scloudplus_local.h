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


#ifndef SCLOUDPLUS_LOCAL_H
#define SCLOUDPLUS_LOCAL_H
#include <stdint.h>
#include "scloudplus.h"
#include "crypt_algid.h"
#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#define SCLOUDPLUS_ALPHA_LEN 32
#define SCLOUDPLUS_SEED_A_LEN 16
#define SCLOUDPLUS_SEED_R1_LEN 32
#define SCLOUDPLUS_SEED_R2_LEN 32
#define SCLOUDPLUS_SEED_K_LEN 32
#define SCLOUDPLUS_RAND_R_LEN 32
#define SCLOUDPLUS_RAND_Z_LEN 32
#define SCLOUDPLUS_HPK_LEN 32
#define SCLOUDPLUS_SECBITS1 128
#define SCLOUDPLUS_SECBITS2 192
#define SCLOUDPLUS_SECBITS3 256
#define SCLOUDPLUS_BW_COMPLEX_LEN 16
#define SCLOUDPLUS_MOD_Q 0xFFF
typedef struct {
    int32_t real;
    int32_t imag;
} Complex;

typedef enum SCLOUDPLUS_PARA_SET {
    SCLOUDPLUS_PARA_SET1,
    SCLOUDPLUS_PARA_SET2,
    SCLOUDPLUS_PARA_SET3,
    SCLOUDPLUS_PARA_MAX
} SCLOUDPLUS_PARA_SET;

struct SCLOUDPLUSPara {
    uint8_t ss; //secure_level
    uint8_t mbar;
    uint8_t nbar;
    uint16_t m;
    uint16_t n;
    uint8_t logq;
    uint8_t logq1;
    uint8_t logq2;
    uint16_t h1;
    uint16_t h2;
    uint8_t eta1;
    uint8_t eta2;
    uint8_t mu;
    uint8_t muConut;
    uint8_t tau;
    uint16_t mnin;
    uint16_t mnout;
    uint16_t c1Size;
    uint16_t c2Size;
    uint16_t ctxSize;
    uint16_t pkSize;
    uint16_t pkeSkSize;
    uint16_t kemSkSize;
};

int32_t SCLOUDPLUS_SamplePsi(const uint8_t* seed, const SCLOUDPLUS_Para* para, uint16_t* matrixS);
int32_t SCLOUDPLUS_SamplePhi(const uint8_t* seed, const SCLOUDPLUS_Para* para, uint16_t* matrixs);
int32_t SCLOUDPLUS_SampleEta1(const uint8_t* seed, const SCLOUDPLUS_Para* para, uint16_t* matrixE);
int32_t SCLOUDPLUS_SampleEta2(const uint8_t* seed, const SCLOUDPLUS_Para* para, uint16_t* matrixE1, uint16_t* matrixE2);
int32_t SCLOUDPLUS_AS_E(const uint8_t* seedA, const uint16_t* S,
                        const uint16_t* E, const SCLOUDPLUS_Para* para, uint16_t* B);
int32_t SCLOUDPLUS_SA_E(const uint8_t* seedA, const uint16_t* S,
                        uint16_t* E, const SCLOUDPLUS_Para* para, uint16_t* C);
void SCLOUDPLUS_SB_E(const uint16_t* S, const uint16_t* B,
                     const uint16_t* E, const SCLOUDPLUS_Para* para, uint16_t* out);
void SCLOUDPLUS_CS(const uint16_t* C, const uint16_t* S, const SCLOUDPLUS_Para* para, uint16_t* out);
void SCLOUDPLUS_Add(const uint16_t* in0, const uint16_t* in1, const int len, uint16_t* out);
void SCLOUDPLUS_Sub(const uint16_t* in0, const uint16_t* in1, const int len, uint16_t* out);
void SCLOUDPLUS_PackPK(const uint16_t* B, const SCLOUDPLUS_Para* para, uint8_t* pk);
void SCLOUDPLUS_UnPackPK(const uint8_t* pk, const SCLOUDPLUS_Para* para, uint16_t* B);
void SCLOUDPLUS_PackSK(const uint16_t* S, const SCLOUDPLUS_Para* para, uint8_t* sk);
void SCLOUDPLUS_UnPackSK(const uint8_t* sk, const SCLOUDPLUS_Para* para, uint16_t* S);
void SCLOUDPLUS_CompressC1(const uint16_t* C, const SCLOUDPLUS_Para* para, uint16_t* out);
void SCLOUDPLUS_DeCompressC1(const uint16_t* in, const SCLOUDPLUS_Para* para, uint16_t* C);
void SCLOUDPLUS_CompressC2(const uint16_t* C, const SCLOUDPLUS_Para* para, uint16_t* out);
void SCLOUDPLUS_DeCompressC2(const uint16_t* in, const SCLOUDPLUS_Para* para, uint16_t* C);
void SCLOUDPLUS_PackC1(const uint16_t* C, const SCLOUDPLUS_Para* para, uint8_t* out);
void SCLOUDPLUS_UnPackC1(const uint8_t* in, const SCLOUDPLUS_Para* para, uint16_t* C);
void SCLOUDPLUS_PackC2(const uint16_t* C, const SCLOUDPLUS_Para* para, uint8_t* out);
void SCLOUDPLUS_UnPackC2(const uint8_t* in, const SCLOUDPLUS_Para* para, uint16_t* C);

void SCLOUDPLUS_MsgEncode(const uint8_t* msg, const SCLOUDPLUS_Para* para, uint16_t* matrixM);
void SCLOUDPLUS_MsgDecode(const uint16_t* matrixM, const SCLOUDPLUS_Para* para, uint8_t* msg);

int8_t SCLOUDPLUS_Verify(const uint8_t* a, const uint8_t* b, const int Len);
void SCLOUDPLUS_CMov(uint8_t* r, const uint8_t* a, const uint8_t* b, const int Len, const int8_t bl);
int32_t SCLOUDPLUS_MdFunc(const CRYPT_MD_AlgId id, const uint8_t* input1, const uint32_t inLen1, const uint8_t* input2,
                          const uint32_t inLen2,
                          uint8_t* output, uint32_t* outLen);
#ifdef __cplusplus
}
#endif

#endif //SCLOUDPLUS_LOCAL_H
