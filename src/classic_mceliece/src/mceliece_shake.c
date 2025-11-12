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

#include "mceliece_shake.h"

CRYPT_ERROR McElieceShake256(uint8_t *output, const size_t outlen, const uint8_t *input, size_t inlen)
{
    uint32_t len = (uint32_t)outlen;
    return McElieceMdFunc(CRYPT_MD_SHAKE256, input, inlen, NULL, 0, output, &len);
}

CRYPT_ERROR McElieceMdFunc(const CRYPT_MD_AlgId id, const uint8_t *input1, const uint32_t inLen1, const uint8_t *input2,
                           const uint32_t inLen2, uint8_t *output, uint32_t *outLen)
{
    CRYPT_EAL_MdCTX *MdCtx = CRYPT_EAL_MdNewCtx(id);
    if (MdCtx == NULL)
    {
        return BSL_MALLOC_FAIL;
    }
    CRYPT_ERROR ret = CRYPT_EAL_MdInit(MdCtx);
    if (ret != PQCP_SUCCESS)
    {
        goto EXIT;
    }
    ret = CRYPT_EAL_MdUpdate(MdCtx, input1, inLen1);
    if (ret != PQCP_SUCCESS)
    {
        goto EXIT;
    }
    if (input2 != NULL)
    {
        ret = CRYPT_EAL_MdUpdate(MdCtx, input2, inLen2);
        if (ret != PQCP_SUCCESS)
        {
            goto EXIT;
        }
    }
    ret = CRYPT_EAL_MdFinal(MdCtx, output, outLen);
EXIT:
    CRYPT_EAL_MdFreeCtx(MdCtx);
    return ret;
}

// McEliece PRG using SHAKE256
void McEliecePrg(const uint8_t *seed, uint8_t *output, const size_t outputLen)
{
    uint8_t tempSeed[33]; // length mush be 33
    tempSeed[0] = 64;     // the value of first element of tempSeed must be 64
    memcpy_s(tempSeed + 1, MCELIECE_L_BYTES, seed, MCELIECE_L_BYTES);
    McElieceShake256(output, outputLen, tempSeed, 33);
}
