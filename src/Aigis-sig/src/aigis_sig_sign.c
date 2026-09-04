/* Copyright (c) 2025 LiuRuikang
 * School Of Cyber Engineering, Xidian University
 *
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
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "bsl_sal.h"
#include "pqcp_err.h"
#include "aigis_sig_local.h"
#include "crypt_eal_rand.h"
#ifdef PQCP_AIGIS_SIG_PORTABLE_BACKEND
#endif

#define AIGIS_SIG_WORKSPACE_ALIGNMENT 32U

static void *AllocWorkspace(size_t workspaceSize, size_t bufferSize, void **allocation, uint8_t **buffer)
{
    uintptr_t address;
    size_t allocationSize;

    if (workspaceSize > SIZE_MAX - (AIGIS_SIG_WORKSPACE_ALIGNMENT - 1U) ||
        bufferSize > SIZE_MAX - workspaceSize - (AIGIS_SIG_WORKSPACE_ALIGNMENT - 1U)) {
        return NULL;
    }
    allocationSize = workspaceSize + (AIGIS_SIG_WORKSPACE_ALIGNMENT - 1U) + bufferSize;
    if (allocationSize > UINT32_MAX) {
        return NULL;
    }
    *allocation = BSL_SAL_Malloc((uint32_t)allocationSize);
    if (*allocation == NULL) {
        return NULL;
    }
    address = (uintptr_t)*allocation;
    address = (address + AIGIS_SIG_WORKSPACE_ALIGNMENT - 1U) & ~(uintptr_t)(AIGIS_SIG_WORKSPACE_ALIGNMENT - 1U);
    if (buffer != NULL) {
        *buffer = (uint8_t *)address + workspaceSize;
    }
    return (void *)address;
}

/*************************************************
 * generate a pair of public key pubKey and secret key prvKey,
 * where pubKey = rho|t1
 *       prvKey = rho|key|hash(pubKey)|s1|s2|t0
 **************************************************/
int32_t PQCP_AIGIS_SIG_KeyGenInternal(const PQCP_AIGIS_SIG_CoreCtx *opCtx, uint8_t *pubKey, uint8_t *prvKey)
{
    typedef struct {
        uint8_t buf[3U * AIGIS_SIG_MAX_SEED_BYTES + AIGIS_SIG_MAX_CRH_BYTES];
        AigisSigPolyVecL s1;
        AigisSigPolyVecL s1hat;
        AigisSigPolyVecK s2;
        AigisSigPolyVecK t;
        AigisSigPolyVecK t0;
    } KeyGenSecretWorkspace;
    typedef struct {
        KeyGenSecretWorkspace secret;
#ifdef PQCP_AIGIS_SIG_PORTABLE_BACKEND
        union {
            AigisSigPolyVecL matRow;
            AigisSigPolyVecK t1;
        };
#else
        AigisSigPolyVecL mat[AIGIS_SIG_MAX_K];
        AigisSigPolyVecK t1;
#endif
    } KeyGenWorkspace;
    int32_t i;
    int32_t ret = PQCP_AIGIS_SIG_OPERATION_FAIL;
    void *allocation = NULL;
    KeyGenWorkspace *workspace = NULL;
    KeyGenSecretWorkspace *secret = NULL;
    uint8_t *buf; // buf = r|rho|key|hash(pubKey)
    uint8_t *rnd, *rho, *key, *hashpk;
    uint8_t nonce = 0;
    AigisSigPolyVecL *s1;
    AigisSigPolyVecL *s1hat;
    AigisSigPolyVecK *s2;
    AigisSigPolyVecK *t;
    AigisSigPolyVecK *t0;
    if (opCtx == NULL || opCtx->params == NULL || pubKey == NULL || prvKey == NULL) {
        return PQCP_NULL_INPUT;
    }
    const AigisSigParams *params = opCtx->params;
    const uint32_t k = params->k;
    const uint32_t l = params->l;
    workspace = AllocWorkspace(sizeof(*workspace), 0U, &allocation, NULL);
    if (workspace == NULL) {
        return PQCP_MEM_ALLOC_FAIL;
    }
    secret = &workspace->secret;
    buf = secret->buf;
    rnd = buf;
    rho = &buf[params->seedBytes];
    key = &buf[2U * params->seedBytes];
    hashpk = &buf[3U * params->seedBytes];
    s1 = &secret->s1;
    s1hat = &secret->s1hat;
    s2 = &secret->s2;
    t = &secret->t;
    t0 = &secret->t0;
    if (CRYPT_EAL_Randbytes(buf, params->seedBytes) != 0) {
        goto cleanup;
    }

    ret = KDF(opCtx, buf, 3U * params->seedBytes, buf, params->seedBytes);
    if (ret != PQCP_SUCCESS) {
        goto cleanup;
    }

#ifndef PQCP_AIGIS_SIG_PORTABLE_BACKEND
    ret = PQCP_AIGIS_SIG_ExpandMatrix(opCtx, workspace->mat, rho);
    if (ret != PQCP_SUCCESS) {
        goto cleanup;
    }
#endif
    ret = PQCP_AIGIS_SIG_PolyVecLUniformEta1(opCtx, s1, rnd, nonce);
    if (ret != PQCP_SUCCESS) {
        goto cleanup;
    }

    nonce += l;
    ret = PQCP_AIGIS_SIG_PolyVecKUniformEta2(opCtx, s2, rnd, nonce);
    if (ret != PQCP_SUCCESS) {
        goto cleanup;
    }
    PQCP_AIGIS_SIG_PolyVecLNttCopy(opCtx, s1hat, s1);

    for (i = 0; i < (int32_t)k; ++i) {
#ifdef PQCP_AIGIS_SIG_PORTABLE_BACKEND
        ret = PQCP_AIGIS_SIG_ExpandMatrixRow(opCtx, &workspace->matRow, rho, (uint32_t)i);
        if (ret != PQCP_SUCCESS) {
            goto cleanup;
        }
        PQCP_AIGIS_SIG_PolyVecLPointwiseAcc(opCtx, &t->vec[i], &workspace->matRow, s1hat);
#else
        PQCP_AIGIS_SIG_PolyVecLPointwiseAcc(opCtx, &t->vec[i], workspace->mat + i,
                                            s1hat); // output coefficient < L * Q in absolute value
        PQCP_AIGIS_SIG_InvNtt(t->vec[i].coeffs); // output coefficient < 0.6 * Q in absolute value
#endif
    }
#ifdef PQCP_AIGIS_SIG_PORTABLE_BACKEND
    PQCP_AIGIS_SIG_PolyVecKInvNttPair(opCtx, t);
    PQCP_AIGIS_SIG_PolyVecKAddPower2Round(opCtx, &workspace->t1, t0, t, s2);
#else
    if (opCtx->paramId == 3) {
        PQCP_AIGIS_SIG_PolyVecKAddPower2RoundD13Armv8(&workspace->t1, t0, t, s2, k);
    } else {
        PQCP_AIGIS_SIG_PolyVecKAddPower2RoundArmv8(&workspace->t1, t0, t, s2, k);
    }
#endif

    PQCP_AIGIS_SIG_PackPublicKey(opCtx, pubKey, rho, &workspace->t1);

    ret = KDF(opCtx, hashpk, params->crhBytes, pubKey, params->publicKeyBytes);
    if (ret != PQCP_SUCCESS) {
        goto cleanup;
    }

    PQCP_AIGIS_SIG_PackPrivateKey(opCtx, prvKey, rho, key, hashpk, s1, s2, t0);

    ret = PQCP_SUCCESS;
cleanup:
    BSL_SAL_CleanseData(secret, sizeof(*secret));
    BSL_SAL_FREE(allocation);
    return ret;
}

#ifndef PQCP_AIGIS_SIG_PORTABLE_BACKEND
static void ChallengeMultiply(AigisSigPoly *result, const AigisSigPoly *challengeNtt, const AigisSigPoly *operandNtt)
{
    PQCP_AIGIS_SIG_PolyPointwise(result, challengeNtt, operandNtt);
    PQCP_AIGIS_SIG_InvNtt(result->coeffs);
    PQCP_AIGIS_SIG_PolyCModQ(result);
}
#endif

/*************************************************
 * create a signature sig on message msg, where
 * sig = z|h|c
 **************************************************/
int32_t PQCP_AIGIS_SIG_SignInternal(const PQCP_AIGIS_SIG_CoreCtx *opCtx, const uint8_t *prvKey, const uint8_t *msg,
                                    uint32_t msgLen, uint8_t *sig, uint32_t *sigLen)
{
    typedef struct {
        union {
            AigisSigPolyVecL y;
            uint8_t mu[AIGIS_SIG_MAX_CRH_BYTES];
        };
        AigisSigPolyVecL yhatOrZ;
        AigisSigPolyVecL s1Ntt;
        AigisSigPolyVecK s2Ntt;
        AigisSigPolyVecK t0Ntt;
        AigisSigPolyVecK wOrH;
        AigisSigPolyVecK tmp;
    } SignSecretWorkspace;
    typedef struct {
        SignSecretWorkspace secret;
        AigisSigPoly c;
        AigisSigPolyVecL mat[AIGIS_SIG_MAX_K];
        AigisSigPolyVecK w1;
    } SignWorkspace;
    int i;
    int32_t n;
    int32_t ret = PQCP_AIGIS_SIG_OPERATION_FAIL;
    uint8_t rho[AIGIS_SIG_MAX_SEED_BYTES], challengeSeed[AIGIS_SIG_MAX_SEED_BYTES];
    uint8_t *buf = NULL, *key, *hashpk;
    uint32_t nonce = 0;
    void *allocation = NULL;
    SignWorkspace *workspace = NULL;
    SignSecretWorkspace *secret = NULL;

    if (opCtx == NULL || opCtx->params == NULL || prvKey == NULL || sig == NULL || sigLen == NULL ||
        (msgLen != 0U && msg == NULL)) {
        return PQCP_NULL_INPUT;
    }
    const AigisSigParams *params = opCtx->params;
    if (msgLen > UINT32_MAX - params->seedBytes - params->crhBytes) {
        return PQCP_INVALID_ARG;
    }
    const uint32_t k = params->k;
    const uint32_t l = params->l;
    const uint32_t zBound = params->gamma1 - params->beta1;
    const uint32_t s2Bound = params->gamma2 - params->beta2 - ETA1;
    const uint32_t gamma3 = params->gamma3;
    const uint32_t omega = params->omega;
    *sigLen = 0;
    workspace = AllocWorkspace(sizeof(*workspace), params->seedBytes + params->crhBytes, &allocation, &buf);
    if (workspace == NULL) {
        return PQCP_MEM_ALLOC_FAIL;
    }
    secret = &workspace->secret;
    key = buf;
    hashpk = &buf[params->seedBytes];
    PQCP_AIGIS_SIG_UnpackPrivateKey(opCtx, rho, key, hashpk, &secret->s1Ntt, &secret->s2Ntt, &secret->t0Ntt, prvKey);
    PQCP_AIGIS_SIG_PolyVecLNtt(opCtx, &secret->s1Ntt);
    PQCP_AIGIS_SIG_PolyVecKNtt(opCtx, &secret->s2Ntt);
    PQCP_AIGIS_SIG_PolyVecKNtt(opCtx, &secret->t0Ntt);

    ret = PQCP_AIGIS_SIG_KdfTwoSegment(opCtx, secret->mu, params->crhBytes, hashpk, params->crhBytes, msg, msgLen);
    if (ret != PQCP_SUCCESS) {
        goto cleanup;
    }
    (void)memcpy(hashpk, secret->mu, params->crhBytes);

    ret = PQCP_AIGIS_SIG_ExpandMatrix(opCtx, workspace->mat, rho);
    if (ret != PQCP_SUCCESS) {
        goto cleanup;
    }

    for (;;) {
        /* ExpandMask encodes nonce as two bytes.  Do not wrap and reuse a mask
         * after the 16-bit nonce domain has been exhausted. */
        if (nonce > UINT16_MAX - (l - 1U)) {
            ret = PQCP_AIGIS_SIG_OPERATION_FAIL;
            goto cleanup;
        }
        ret = PQCP_AIGIS_SIG_PolyVecLUniformGamma1(opCtx, &secret->y, key, nonce);
        if (ret != PQCP_SUCCESS) {
            goto cleanup;
        }
        nonce += l;
        PQCP_AIGIS_SIG_PolyVecLNttCopy(opCtx, &secret->yhatOrZ, &secret->y);

        for (i = 0; i < (int)k; ++i) {
            PQCP_AIGIS_SIG_PolyVecLPointwiseAcc(opCtx, secret->wOrH.vec + i, workspace->mat + i,
                                                &secret->yhatOrZ); // output coefficient < L * Q in absolute value
        }
#ifdef PQCP_AIGIS_SIG_PORTABLE_BACKEND
        PQCP_AIGIS_SIG_PolyVecKInvNttPair(opCtx, &secret->wOrH);
        PQCP_AIGIS_SIG_PolyVecKAModQDecompose(opCtx, &workspace->w1, &secret->tmp, &secret->wOrH);
#else
        PQCP_AIGIS_SIG_PolyVecKInvNtt(opCtx, &secret->wOrH);
        PQCP_AIGIS_SIG_PolyVecKAModQ(opCtx, &secret->wOrH);
        PQCP_AIGIS_SIG_PolyVecKDecompose(opCtx, &workspace->w1, &secret->tmp, &secret->wOrH);
#endif
        ret = PQCP_AIGIS_SIG_Challenge(opCtx, challengeSeed, hashpk, &workspace->w1);
        if (ret != PQCP_SUCCESS) {
            goto cleanup;
        }
        ret = PQCP_AIGIS_SIG_SampleInBall(opCtx, &workspace->c, challengeSeed);
        if (ret != PQCP_SUCCESS) {
            goto cleanup;
        }
        PQCP_AIGIS_SIG_Ntt(workspace->c.coeffs);

#ifdef PQCP_AIGIS_SIG_PORTABLE_BACKEND
        uint32_t outOfRange = PQCP_AIGIS_SIG_ChallengeMultiplyAddCheckNormVec(
            secret->wOrH.vec, secret->yhatOrZ.vec, secret->y.vec, &workspace->c, secret->s1Ntt.vec, l, zBound);
        if (outOfRange != 0U) {
            continue;
        }
#else
        for (i = 0; i < (int)l; i++) {
            ChallengeMultiply(&secret->wOrH.vec[i], &workspace->c, &secret->s1Ntt.vec[i]);
            PQCP_AIGIS_SIG_PolyAdd(&secret->yhatOrZ.vec[i], &secret->y.vec[i], &secret->wOrH.vec[i]);
        }
        if (PQCP_AIGIS_SIG_PolyVecLCheckNorm(opCtx, &secret->yhatOrZ, zBound)) {
            continue;
        }
#endif

#ifdef PQCP_AIGIS_SIG_PORTABLE_BACKEND
        outOfRange = PQCP_AIGIS_SIG_ChallengeMultiplySubCheckNormVec(secret->wOrH.vec, secret->tmp.vec, secret->tmp.vec,
                                                                     &workspace->c, secret->s2Ntt.vec, k, s2Bound);
        if (outOfRange != 0U) {
            continue;
        }
#else
        for (i = 0; i < (int)k; i++) {
            ChallengeMultiply(&secret->wOrH.vec[i], &workspace->c, &secret->s2Ntt.vec[i]);
            PQCP_AIGIS_SIG_PolySub(&secret->tmp.vec[i], &secret->tmp.vec[i], &secret->wOrH.vec[i]);
        }
        if (PQCP_AIGIS_SIG_PolyVecKCheckNorm(opCtx, &secret->tmp, s2Bound)) {
            continue;
        }
#endif

#ifdef PQCP_AIGIS_SIG_PORTABLE_BACKEND
        outOfRange = PQCP_AIGIS_SIG_ChallengeMultiplyAddCheckNormVec(secret->wOrH.vec, secret->tmp.vec, secret->tmp.vec,
                                                                     &workspace->c, secret->t0Ntt.vec, k, gamma3);
        if (outOfRange != 0U) {
            continue;
        }
#else
        for (i = 0; i < (int)k; i++) {
            ChallengeMultiply(&secret->wOrH.vec[i], &workspace->c, &secret->t0Ntt.vec[i]);
            PQCP_AIGIS_SIG_PolyAdd(&secret->tmp.vec[i], &secret->tmp.vec[i], &secret->wOrH.vec[i]);
        }
        if (PQCP_AIGIS_SIG_PolyVecKCheckNorm(opCtx, &secret->tmp, gamma3)) {
            continue;
        }
#endif

        PQCP_AIGIS_SIG_PolyVecKAModQ(opCtx, &secret->tmp);
        n = PQCP_AIGIS_SIG_PolyVecKMakeHint(opCtx, &secret->wOrH, &secret->tmp, &workspace->w1);

        if (n > (int32_t)omega || n < 0) {
            continue;
        }

        *sigLen = PQCP_AIGIS_SIG_PackSignature(opCtx, sig, &secret->yhatOrZ, challengeSeed, &secret->wOrH);
        ret = PQCP_SUCCESS;
        break;
    }
cleanup:
    BSL_SAL_CleanseData(secret, sizeof(*secret));
    BSL_SAL_CleanseData(buf, params->seedBytes + params->crhBytes);
    BSL_SAL_FREE(allocation);
    return ret;
}

int32_t PQCP_AIGIS_SIG_VerifyInternal(const PQCP_AIGIS_SIG_CoreCtx *opCtx, const uint8_t *pubKey, const uint8_t *sig,
                                      uint32_t sigLen, const uint8_t *msg, uint32_t msgLen)
{
    typedef struct {
        AigisSigPoly c;
#ifdef PQCP_AIGIS_SIG_PORTABLE_BACKEND
        union {
            AigisSigPolyVecL matRow;
            AigisSigEmulateCt1Scratch emulateCt1Scratch;
        };
#else
        union {
            AigisSigPolyVecL mat[AIGIS_SIG_MAX_K];
            AigisSigEmulateCt1PairScratch emulateCt1PairScratch[2];
        };
#endif
        AigisSigPolyVecL z;
        AigisSigPolyVecK t1;
        AigisSigPolyVecK w1;
        AigisSigPolyVecK hOrTmp2;
        AigisSigPolyVecK tmp1;
    } VerifyWorkspace;
    int i;
    int32_t ret = PQCP_AIGIS_SIG_VERIFY_FAIL;
    uint8_t challengeDiff = 0;
    uint8_t rho[AIGIS_SIG_MAX_SEED_BYTES], challengeSeed[AIGIS_SIG_MAX_SEED_BYTES];
    uint8_t tcseed[AIGIS_SIG_MAX_SEED_BYTES];
    uint8_t hashpk[AIGIS_SIG_MAX_CRH_BYTES], mu[AIGIS_SIG_MAX_CRH_BYTES];
    void *allocation = NULL;
    VerifyWorkspace *workspace = NULL;
    if (opCtx == NULL || opCtx->params == NULL || pubKey == NULL || sig == NULL || (msgLen != 0U && msg == NULL)) {
        return PQCP_INVALID_ARG;
    }
    const AigisSigParams *params = opCtx->params;
    if (sigLen != params->signatureBytes) {
        return PQCP_INVALID_ARG;
    }
    if (msgLen > UINT32_MAX - params->crhBytes) {
        return PQCP_INVALID_ARG;
    }
    const uint32_t k = params->k;
    const uint32_t zBound = params->gamma1 - params->beta1;
    const uint32_t gamma3 = params->gamma3;
    workspace = AllocWorkspace(sizeof(*workspace), 0U, &allocation, NULL);
    if (workspace == NULL) {
        return PQCP_MEM_ALLOC_FAIL;
    }

#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
    if (PQCP_AIGIS_SIG_UnpackSignatureCheckZ(opCtx, &workspace->z, &workspace->hOrTmp2, challengeSeed, sig, sigLen,
                                             zBound) != 0) {
#else
    if (PQCP_AIGIS_SIG_UnpackSignature(opCtx, &workspace->z, &workspace->hOrTmp2, challengeSeed, sig, sigLen) != 0 ||
        PQCP_AIGIS_SIG_PolyVecLCheckNorm(opCtx, &workspace->z, zBound)) {
#endif
        goto cleanup;
    }

#ifdef PQCP_AIGIS_SIG_ARMV8_BACKEND
    if (opCtx->paramId == 3) {
        PQCP_AIGIS_SIG_UnpackPublicKey(opCtx, rho, &workspace->t1, pubKey);
        PQCP_AIGIS_SIG_PolyVecKShiftLeft(opCtx, &workspace->t1, params->d);
        PQCP_AIGIS_SIG_PolyVecKNtt(opCtx, &workspace->t1);
    } else {
        (void)memcpy(rho, pubKey, params->seedBytes);
    }
#else
    PQCP_AIGIS_SIG_UnpackPublicKey(opCtx, rho, &workspace->t1, pubKey);
#endif
#ifdef PQCP_AIGIS_SIG_PORTABLE_BACKEND
    if (k != 2U) {
        /* Parameter II t1 is in [0, 127], so shifting by D=15 remains below q.
         * Transform the scaled operand once and fuse its product with Az. */
        PQCP_AIGIS_SIG_PolyVecKShiftLeft(opCtx, &workspace->t1, params->d);
        PQCP_AIGIS_SIG_PolyVecKNtt(opCtx, &workspace->t1);
    }
#endif

    ret = KDF(opCtx, hashpk, params->crhBytes, pubKey, params->publicKeyBytes);
    if (ret != PQCP_SUCCESS) {
        goto cleanup;
    }
    ret = PQCP_AIGIS_SIG_KdfTwoSegment(opCtx, mu, params->crhBytes, hashpk, params->crhBytes, msg, msgLen);
    if (ret != PQCP_SUCCESS) {
        goto cleanup;
    }
    ret = PQCP_AIGIS_SIG_VERIFY_FAIL;

#ifndef PQCP_AIGIS_SIG_PORTABLE_BACKEND
    ret = PQCP_AIGIS_SIG_ExpandMatrix(opCtx, workspace->mat, rho);
    if (ret != PQCP_SUCCESS) {
        goto cleanup;
    }
#endif
    PQCP_AIGIS_SIG_PolyVecLNtt(opCtx, &workspace->z);
    for (i = 0; i < (int)k; ++i) {
#ifdef PQCP_AIGIS_SIG_PORTABLE_BACKEND
        ret = PQCP_AIGIS_SIG_ExpandMatrixRow(opCtx, &workspace->matRow, rho, (uint32_t)i);
        if (ret != PQCP_SUCCESS) {
            goto cleanup;
        }
        PQCP_AIGIS_SIG_PolyVecLPointwiseAcc(opCtx, workspace->tmp1.vec + i, &workspace->matRow, &workspace->z);
#else
        PQCP_AIGIS_SIG_PolyVecLPointwiseAcc(opCtx, workspace->tmp1.vec + i, workspace->mat + i,
                                            &workspace->z); // output coefficient <= L*Q in absolute value
#endif
    }
    ret = PQCP_AIGIS_SIG_SampleInBall(opCtx, &workspace->c, challengeSeed);
    if (ret != PQCP_SUCCESS) {
        goto cleanup;
    }
#ifdef PQCP_AIGIS_SIG_PORTABLE_BACKEND
    if (k == 2U) {
        PQCP_AIGIS_SIG_PolyVecKInvNttPair(opCtx, &workspace->tmp1);
        for (i = 0; i < 2; ++i) {
            PQCP_AIGIS_SIG_EmulateCt1ShiftSubGReduce(&workspace->emulateCt1Scratch, &workspace->tmp1.vec[i],
                                                     &workspace->c, &workspace->t1.vec[i], params->d);
        }
    } else {
        PQCP_AIGIS_SIG_Ntt(workspace->c.coeffs);
        for (i = 0; i < (int)k; ++i) {
            PQCP_AIGIS_SIG_ChallengePointwiseSubNtt(&workspace->tmp1.vec[i], &workspace->c, &workspace->t1.vec[i]);
        }
        PQCP_AIGIS_SIG_PolyVecKInvNttPair(opCtx, &workspace->tmp1);
        PQCP_AIGIS_SIG_PolyVecKGReduce(opCtx, &workspace->tmp1);
    }
#else
    if (opCtx->paramId == 3) {
        PQCP_AIGIS_SIG_Ntt(workspace->c.coeffs);
        for (i = 0; i < (int)k; ++i) {
            AigisSigPoly ct1;
            PQCP_AIGIS_SIG_PolyPointwise(&ct1, &workspace->c, &workspace->t1.vec[i]);
            PQCP_AIGIS_SIG_PolySub(&workspace->tmp1.vec[i], &workspace->tmp1.vec[i], &ct1);
            PQCP_AIGIS_SIG_InvNtt(workspace->tmp1.vec[i].coeffs);
            PQCP_AIGIS_SIG_PolyGReduce(&workspace->tmp1.vec[i]);
        }
    } else {
    PQCP_AIGIS_SIG_PolyVecKInvNtt(opCtx, &workspace->tmp1);
    /* Matrix rows are dead after the pointwise accumulators, so their
     * workspace can now hold the public T1 stable tables. */
    PQCP_AIGIS_SIG_UnpackT1StablePairArmv8(&workspace->emulateCt1PairScratch[0], pubKey + params->seedBytes);
    PQCP_AIGIS_SIG_EmulateCt1PairShiftSubGReduceArmv8(&workspace->emulateCt1PairScratch[0], workspace->tmp1.vec,
                                                      &workspace->c, params->challengeWeight);
    if (k == 4U) {
        PQCP_AIGIS_SIG_UnpackT1StablePairArmv8(&workspace->emulateCt1PairScratch[1],
                                               pubKey + params->seedBytes + 2U * params->polyT1PackedBytes);
        (void)memcpy(workspace->emulateCt1PairScratch[1].offsets,
                     workspace->emulateCt1PairScratch[0].offsets,
                     params->challengeWeight * sizeof(workspace->emulateCt1PairScratch[0].offsets[0]));
        PQCP_AIGIS_SIG_EmulateCt1PairShiftSubGReduceArmv8(&workspace->emulateCt1PairScratch[1],
                                                          workspace->tmp1.vec + 2, &workspace->c,
                                                          params->challengeWeight | AIGIS_SIG_PSPM_REUSE_OFFSETS);
    }
    }
#endif
    PQCP_AIGIS_SIG_PolyVecKUseHint(opCtx, &workspace->w1, &workspace->tmp1, &workspace->hOrTmp2);
    ret = PQCP_AIGIS_SIG_Challenge(opCtx, tcseed, mu, &workspace->w1);
    if (ret != PQCP_SUCCESS) {
        goto cleanup;
    }

    for (i = 0; i < (int)params->seedBytes; ++i) {
        challengeDiff |= challengeSeed[i] ^ tcseed[i];
    }
    if (challengeDiff != 0) {
        ret = PQCP_AIGIS_SIG_VERIFY_FAIL;
        goto cleanup;
    }

#ifdef PQCP_AIGIS_SIG_PORTABLE_BACKEND
    if (PQCP_AIGIS_SIG_PolyVecKSubWCModQCheckNorm(opCtx, &workspace->hOrTmp2, &workspace->tmp1, &workspace->w1,
                                                  gamma3)) {
#else
    PQCP_AIGIS_SIG_PolyVecKSubW(opCtx, &workspace->hOrTmp2, &workspace->tmp1, &workspace->w1);
    PQCP_AIGIS_SIG_PolyVecKCModQ(opCtx, &workspace->hOrTmp2);
    if (PQCP_AIGIS_SIG_PolyVecKCheckNorm(opCtx, &workspace->hOrTmp2, gamma3)) {
#endif
        ret = PQCP_AIGIS_SIG_VERIFY_FAIL;
        goto cleanup;
    }

    ret = PQCP_SUCCESS;
cleanup:
    BSL_SAL_CleanseData(hashpk, sizeof(hashpk));
    BSL_SAL_CleanseData(mu, sizeof(mu));
    BSL_SAL_FREE(allocation);
    return ret;
}
