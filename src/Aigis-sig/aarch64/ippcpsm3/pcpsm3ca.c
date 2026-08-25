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
//     cpFinalizeSM3()
//
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcphash.h"
//#include "pcphash_rmf.h"
#include "pcptool.h"
#include "pcpsm3stuff.h"

void cpFinalizeSM3(DigestSHA1 pHash, const Ipp8u* inpBuffer, int inpLen, Ipp64u processedMsgLen)
{
	/* local buffer and it length */
	Ipp8u buffer[MBS_SM3 * 2];
	int bufferLen = inpLen < (MBS_SM3 - (int)MLR_SM3) ? MBS_SM3 : MBS_SM3 * 2;

	/* copy rest of message into internal buffer */
	CopyBlock(inpBuffer, buffer, inpLen);

	/* padd message */
	buffer[inpLen++] = 0x80;
	PaddBlock(0, buffer + inpLen, bufferLen - inpLen - MLR_SM3);

	/* put processed message length in bits */
	processedMsgLen = ENDIANNESS64(processedMsgLen << 3);
	((Ipp64u*)(buffer + bufferLen))[-1] = processedMsgLen;

	/* copmplete hash computation */
	UpdateSM3(pHash, buffer, bufferLen, sm3_cnt);
}
