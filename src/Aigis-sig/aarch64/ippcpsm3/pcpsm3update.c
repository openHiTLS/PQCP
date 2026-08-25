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

/*
//
//  Purpose:
//     Cryptography Primitive.
//     Digesting message according to SM3
//
//  Contents:
//        ippsSM3Update()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcphash.h"
//#include "pcphash_rmf.h"
#include "pcptool.h"
#include "pcpsm3stuff.h"

/*F*
//    Name: ippsSM3Update
//
// Purpose: Updates intermediate digest based on input stream.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSrc == NULL
//                            pState == NULL
//    ippStsContextMatchErr   pState->idCtx != idCtxSM3
//    ippStsLengthErr         len <0
//    ippStsNoErr             no errors
//
// Parameters:
//    pSrc        pointer to the input stream
//    len         input stream length
//    pState      pointer to the SM3 state
//
*F*/
IPPFUN(IppStatus, ippsSM3Update, (const Ipp8u* pSrc, int len, IppsSM3State* pState))
{
	/* test state pointer and ID */
	IPP_BAD_PTR1_RET(pState);
	pState = (IppsSM3State*)(IPP_ALIGNED_PTR(pState, SM3_ALIGNMENT));
	IPP_BADARG_RET(idCtxSM3 != HASH_CTX_ID(pState), ippStsContextMatchErr);

	/* test input length */
	IPP_BADARG_RET((len < 0), ippStsLengthErr);
	/* test source pointer */
	IPP_BADARG_RET((len && !pSrc), ippStsNullPtrErr);

	/*
	// handle non empty message
	*/
	if (len) {
		int procLen;

		int idx = HAHS_BUFFIDX(pState);
		Ipp8u* pBuffer = HASH_BUFF(pState);
		Ipp64u lenLo = HASH_LENLO(pState) + len;

		/* if non empty internal buffer filling */
		if (idx) {
			/* copy from input stream to the internal buffer as match as possible */
			procLen = IPP_MIN(len, (MBS_SM3 - idx));
			CopyBlock(pSrc, pBuffer + idx, procLen);

			/* update message pointer and length */
			idx += procLen;
			pSrc += procLen;
			len -= procLen;

			/* update digest if buffer full */
			if (MBS_SM3 == idx) {
				UpdateSM3(HASH_VALUE(pState), pBuffer, MBS_SM3, sm3_cnt);
				idx = 0;
			}
		}

		/* main message part processing */
		procLen = len & ~(MBS_SM3 - 1);
		if (procLen) {
			UpdateSM3(HASH_VALUE(pState), pSrc, procLen, sm3_cnt);
			pSrc += procLen;
			len -= procLen;
		}

		/* store rest of message into the internal buffer */
		if (len) {
			CopyBlock(pSrc, pBuffer, len);
			idx += len;
		}

		/* update length of processed message */
		HASH_LENLO(pState) = lenLo;
		HAHS_BUFFIDX(pState) = idx;
	}

	return ippStsNoErr;
}
