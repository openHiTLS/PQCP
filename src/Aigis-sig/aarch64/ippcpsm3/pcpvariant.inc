; Copyright (c) 2025 LiuRuikang
; School Of Cyber Engineering, Xidian University
;
; This file is part of the openHiTLS project.
;
; openHiTLS is licensed under the Mulan PSL v2.
; You can use this software according to the terms and conditions of the Mulan PSL v2.
; You may obtain a copy of Mulan PSL v2 at:
;
; http://license.coscl.org.cn/MulanPSL2
;
; THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
; EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
; MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
; See the Mulan PSL v2 for more details.

_FEATURE_OFF_      =0   ;; feature is OFF
_FEATURE_ON_       =1   ;; feature is ON
_FEATURE_TICKTOCK_ =2   ;; dectect is feature OFF/ON

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;_XMM7560_ = 1
IFDEF _XMM7560_
include pcpvariant_xmm7560.inc
endif

;;_TXT_ACM_ = 1
IFDEF _TXT_ACM_
include pcpvariant_txt_acm.inc
endif
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;
;; it possible to force use of C-version of some implementtaions
;; instead of ASM one
;;
IFNDEF _USE_C_cpAdd_BNU_
_USE_C_cpAdd_BNU_ = _FEATURE_OFF_
ENDIF

IFNDEF _USE_C_cpSub_BNU_
_USE_C_cpSub_BNU_ = _FEATURE_OFF_
ENDIF

IFNDEF _USE_C_cpInc_BNU_
_USE_C_cpInc_BNU_ = _FEATURE_OFF_
ENDIF

IFNDEF _USE_C_cpAddMulDgt_BNU_
_USE_C_cpAddMulDgt_BNU_ = _FEATURE_OFF_
ENDIF

IFNDEF _USE_C_cpMulAdc_BNU_school_
_USE_C_cpMulAdc_BNU_school_ = _FEATURE_OFF_
ENDIF

IFNDEF _USE_C_cpSqrAdc_BNU_school_
_USE_C_cpMulSqr_BNU_school_ = _FEATURE_OFF_
ENDIF

IFNDEF _USE_C_cpMontRedAdc_BNU_
_USE_C_cpMontRedAdc_BNU_ = _FEATURE_OFF_
ENDIF


;;
;; set _AES_NI_ENABLING_
;;
IFDEF _IPP_AES_NI_
   IF (_IPP_AES_NI_ EQ 0)
      _AES_NI_ENABLING_ = _FEATURE_OFF_
   ELSEIF (_IPP_AES_NI_ EQ 1)
      _AES_NI_ENABLING_ = _FEATURE_ON_
   ELSE
      .ERR  <Define _IPP_AES_NI_=0 or 1 or omit _IPP_AES_NI_ at all>
   ENDIF
ELSE
   IF (_IPP32E GE _IPP32E_Y8)
      _AES_NI_ENABLING_ = _FEATURE_TICKTOCK_
   ELSE
      _AES_NI_ENABLING_ = _FEATURE_OFF_
   ENDIF
ENDIF

;;
;; if there is no outside assignment
;; set _SHA_NI_ENABLING_  based on CPU specification
;;
IFNDEF _SHA_NI_ENABLING_
   IF (_IPP32E GE _IPP32E_Y8 )
      _SHA_NI_ENABLING_ = _FEATURE_TICKTOCK_
   ELSE
      _SHA_NI_ENABLING_ = _FEATURE_OFF_
   ENDIF
ENDIF

;;
;; set _ADCOX_NI_ENABLING_
;;
IFDEF _IPP_ADCX_NI_
   IF (_IPP_ADCX_NI_ EQ 0)
      _ADCOX_NI_ENABLING_ = _FEATURE_OFF_
   ELSEIF (_IPP_ADCX_NI_ EQ 1)
      _ADCOX_NI_ENABLING_ = _FEATURE_ON_
   ELSE
      .ERR  <Define _IPP_ADCX_NI_=0 or 1 or omit _IPP_ADCX_NI_ at all>
   ENDIF
ELSE
   IF (_IPP32E GE _IPP32E_L9)
      _ADCOX_NI_ENABLING_ = _FEATURE_TICKTOCK_
   ELSE
      _ADCOX_NI_ENABLING_ = _FEATURE_OFF_
   ENDIF
ENDIF


;;
;; select Hash algorithm
;;
IFNDEF _DISABLE_ALG_SHA1_
   _ENABLE_ALG_SHA1_   = _FEATURE_ON_  ;; SHA1 on
ELSE
   _ENABLE_ALG_SHA1_   = _FEATURE_OFF_ ;; SHA1 on
ENDIF

IFNDEF _DISABLE_ALG_SHA256_
   _ENABLE_ALG_SHA256_ = _FEATURE_ON_  ;; SHA256 on
ELSE
   _ENABLE_ALG_SHA256_ = _FEATURE_OFF_ ;; SHA256 off
ENDIF

IFNDEF _DISABLE_ALG_SHA521_
   _ENABLE_ALG_SHA512_ = _FEATURE_ON_  ;; SHA512 on
ELSE
   _ENABLE_ALG_SHA512_ = _FEATURE_OFF_ ;; SHA512 off
ENDIF

IFNDEF _DISABLE_ALG_MD5_
   _ENABLE_ALG_MD5_    = _FEATURE_ON_  ;; MD5 on
ELSE
   _ENABLE_ALG_MD5_    = _FEATURE_OFF_ ;; MD5 off
ENDIF

IFNDEF _DISABLE_ALG_SM3_
   _ENABLE_ALG_SM3_    = _FEATURE_ON_  ;; SM3 on
ELSE
   _ENABLE_ALG_SM3_    = _FEATURE_OFF_ ;; SM3 off
ENDIF

;;
;; BN arithmetic
;;
_ENABLE_KARATSUBA_ = _FEATURE_OFF_  ;; not use Karatsuba method for multiplication

;;
;; EC specific
;;
_ECP_IMPL_NONE_       = 0
_ECP_IMPL_ARBIRTRARY_ = 1
_ECP_IMPL_SPECIFIC_   = 2
_ECP_IMPL_MFM_        = 3

IFNDEF _ECP_128_
_ECP_128_ =  _ECP_IMPL_SPECIFIC_
ENDIF

IFNDEF _ECP_192_
_ECP_192_ =  _ECP_IMPL_MFM_
ENDIF

IFNDEF _ECP_224_
_ECP_224_ =  _ECP_IMPL_MFM_
ENDIF

IFNDEF _ECP_256_
_ECP_256_ =  _ECP_IMPL_MFM_
ENDIF

IFNDEF _ECP_384_
_ECP_384_ =  _ECP_IMPL_MFM_
ENDIF

IFNDEF _ECP_521_
_ECP_521_ =  _ECP_IMPL_MFM_
ENDIF

IFNDEF _ECP_SM2_
_ECP_SM2_ =  _ECP_IMPL_MFM_
ENDIF
