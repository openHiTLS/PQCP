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
//        ippsSM3MessageDigest()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcphash.h"
//#include "pcphash_rmf.h"
#include "pcptool.h"
#include "pcpsm3stuff.h"

/*F*
//    Name: ippsSM3MessageDigest
//
// Purpose: Digest of the whole message.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pMsg == NULL
//                            pMD == NULL
//    ippStsLengthErr         len <0
//    ippStsNoErr             no errors
//
// Parameters:
//    pMsg        pointer to the input message
//    len         input message length
//    pMD         address of the output digest
//
*F*/
IPPFUN(IppStatus, ippsSM3MessageDigest, (const Ipp8u* pMsg, int len, Ipp8u* pMD))
{
	/* test digest pointer */
	IPP_BAD_PTR1_RET(pMD);
	/* test message length */
	IPP_BADARG_RET((len < 0), ippStsLengthErr);
	/* test message pointer */
	IPP_BADARG_RET((len && !pMsg), ippStsNullPtrErr);

	{
		/* message length in the multiple MBS and the rest */
		int msgLenBlks = len & (-MBS_SM3);
		int msgLenRest = len - msgLenBlks;

		/* init hash */
		((Ipp32u*)(pMD))[0] = sm3_iv[0];
		((Ipp32u*)(pMD))[1] = sm3_iv[1];
		((Ipp32u*)(pMD))[2] = sm3_iv[2];
		((Ipp32u*)(pMD))[3] = sm3_iv[3];
		((Ipp32u*)(pMD))[4] = sm3_iv[4];
		((Ipp32u*)(pMD))[5] = sm3_iv[5];
		((Ipp32u*)(pMD))[6] = sm3_iv[6];
		((Ipp32u*)(pMD))[7] = sm3_iv[7];

		/* process main part of the message */
		if (msgLenBlks) {
			UpdateSM3((Ipp32u*)pMD, pMsg, msgLenBlks, sm3_cnt);
			pMsg += msgLenBlks;
		}

		cpFinalizeSM3((Ipp32u*)pMD, pMsg, msgLenRest, len);
		((Ipp32u*)pMD)[0] = ENDIANNESS32(((Ipp32u*)pMD)[0]);
		((Ipp32u*)pMD)[1] = ENDIANNESS32(((Ipp32u*)pMD)[1]);
		((Ipp32u*)pMD)[2] = ENDIANNESS32(((Ipp32u*)pMD)[2]);
		((Ipp32u*)pMD)[3] = ENDIANNESS32(((Ipp32u*)pMD)[3]);
		((Ipp32u*)pMD)[4] = ENDIANNESS32(((Ipp32u*)pMD)[4]);
		((Ipp32u*)pMD)[5] = ENDIANNESS32(((Ipp32u*)pMD)[5]);
		((Ipp32u*)pMD)[6] = ENDIANNESS32(((Ipp32u*)pMD)[6]);
		((Ipp32u*)pMD)[7] = ENDIANNESS32(((Ipp32u*)pMD)[7]);

		return ippStsNoErr;
	}
}
