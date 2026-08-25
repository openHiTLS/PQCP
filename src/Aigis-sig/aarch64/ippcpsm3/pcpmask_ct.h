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
//     Constant time Mask operations
//
//
*/

#if !defined(_PCP_MASK_CT_H)
#define _PCP_MASK_CT_H

#include "owncp.h"
#include "pcpbnuimpl.h"

/*
// The following functions test particular conditions
// and returns either 0 or 0xffffffff.
//
// The result is suitable for boolean and masked operations.
//
// Inspite of operation below are using BNU_CHUNK_T operand(s) it can be applied to Ipp32u, Ipp32s, Ipp16u, Ipp16s, Ipp8u and Ipp8s too.
// For example, if
//    Ipp32u uns_int;
//    Ipp32s sgn_int;
//    Ipp8u  uns_char;
//    Ipp8s  sgn_char;
// then
//    cpIs_msb_ct((Ipp32s)uns_int)     tests 31 bit of uns_int
//    cpIs_msb_ct(        sgn_int)     tests 31 bit of sgn_int
//    cpIs_msb_ct((Ipp8u)uns_char)     tests  7 bit of uns_char
//    cpIs_msb_ct(       sgn_char)     tests  7 bit of sgn_char
*/

/* tests if MSB(a)==1 */
__INLINE BNU_CHUNK_T cpIsMsb_ct(BNU_CHUNK_T a)
{
	return (BNU_CHUNK_T)0 - (a >> (sizeof(a) * 8 - 1));
}

/* tests if LSB(a)==1 */
__INLINE BNU_CHUNK_T cpIsLsb_ct(BNU_CHUNK_T a)
{
	return (BNU_CHUNK_T)0 - (a & 1);
}

/* tests if a is odd */
__INLINE BNU_CHUNK_T cpIsOdd_ct(BNU_CHUNK_T a)
{
	return cpIsLsb_ct(a);
}

/* tests if a is even */
__INLINE BNU_CHUNK_T cpIsEven_ct(BNU_CHUNK_T a)
{
	return ~cpIsLsb_ct(a);
}

/* tests if a==0 */
__INLINE BNU_CHUNK_T cpIsZero_ct(BNU_CHUNK_T a)
{
	return cpIsMsb_ct(~a & (a - 1));
}

/* tests if a==b */
__INLINE BNU_CHUNK_T cpIsEqu_ct(BNU_CHUNK_T a, BNU_CHUNK_T b)
{
	return cpIsZero_ct(a ^ b);
}

/* replace under mask: dst[] = replaceFlag? src[] : dst[] */
__INLINE void cpMaskedReplace_ct(BNU_CHUNK_T* dst, const BNU_CHUNK_T* src, int len, BNU_CHUNK_T replaceMask)
{
	BNU_CHUNK_T dstMask = ~replaceMask;
	int n;
	for (n = 0; n < len; n++)
		dst[n] = (src[n] & replaceMask) ^ (dst[n] & dstMask);
}

/* copy under mask: dst[] = src1[] & mask) ^ src2[] & ~mask  */
__INLINE void cpMaskedCopyBNU_ct(BNU_CHUNK_T* dst, BNU_CHUNK_T mask, const BNU_CHUNK_T* src1, const BNU_CHUNK_T* src2, int len)
{
	int i;
	for (i = 0; i < (len); i++)
		dst[i] = (src1[i] & mask) ^ (src2[i] & ~mask);
}

/* test if GF elmement is equal to x chunk */
__INLINE BNU_CHUNK_T cpIsGFpElemEquChunk_ct(const BNU_CHUNK_T* pE, int nsE, BNU_CHUNK_T x)
{
	int i;
	BNU_CHUNK_T accum = pE[0] ^ x;
	for (i = 1; i < nsE; i++) {
		accum |= pE[i];
	}
	return cpIsZero_ct(accum);
}

#define GFPE_IS_ZERO_CT(a,size)  cpIsGFpElemEquChunk_ct((a),(size), 0)

#endif /* _PCP_MASK_CT_H */
