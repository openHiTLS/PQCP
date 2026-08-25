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

IFNDEF __ASMDEFS_INC__
  __ASMDEFS_INC__=1

_IPP_PX=0    ; pure C-code ia32
_IPP_M5=1    ; Intel(R) Quark(TM) processor - ia32
_IPP_W7=8    ; Intel(R) Streaming SIMD Extensions 2 - ia32
_IPP_T7=16   ; Intel(R) Streaming SIMD Extensions 3 - ia32
_IPP_V8=32   ; Supplemental Streaming SIMD Extensions 3 (SSSE3)
_IPP_S8=33   ; SSSE3 + MOVBE instruction - ia32
_IPP_P8=64   ; Intel(R) Streaming SIMD Extensions 4.2 - ia32
_IPP_G9=128  ; Intel(R) Advanced Vector Extensions - ia32
_IPP_H9=256  ; Intel(R) Advanced Vector Extensions 2 - ia32
_IPP_I0=512  ; Intel(R) Advanced Vector Extensions 512 - Intel(R) Xeon Phi(TM) processor (formerly Knight Landing) - ia32
_IPP_S0=1024 ; Intel(R) Advanced Vector Extensions 512 - Intel(R) Xeon(R) processor (formerly Skylake) - ia32

_IPP32E_PX=_IPP_PX ; pure C-code x64
_IPP32E_M7=32   ; Intel(R) Streaming SIMD Extensions 3 - intel64
_IPP32E_U8=64   ; Supplemental Streaming SIMD Extensions 3 (SSSE3) - intel64
_IPP32E_N8=65   ; SSSE3 + MOVBE instruction - intel64
_IPP32E_Y8=128  ; Intel(R) Streaming SIMD Extensions 4.2 - intel64
_IPP32E_E9=256  ; Intel(R) Advanced Vector Extensions - intel64
_IPP32E_L9=512  ; Intel(R) Advanced Vector Extensions 2 - intel64
_IPP32E_N0=1024 ; Intel(R) Advanced Vector Extensions 512 - Intel(R) Xeon Phi(TM) processor (formerly Knight Landing) - intel64
_IPP32E_K0=2048 ; Intel(R) Advanced Vector Extensions 512 - Intel(R) Xeon(R) processor (formerly Skylake) - intel64

_IPP=_IPP_PX
_IPP32E=_IPP32E_PX


IFDEF _M5 ; Intel(R) Quark(TM) processor - ia32
    _IPP=_IPP_M5
ELSEIFDEF _W7 ; Intel(R) Streaming SIMD Extensions 2 - ia32
    _IPP=_IPP_W7
ELSEIFDEF _T7 ; Intel(R) Streaming SIMD Extensions 3 - ia32
    _IPP=_IPP_T7
ELSEIFDEF _V8 ; Supplemental Streaming SIMD Extensions 3 (SSSE3)
    _IPP=_IPP_V8
ELSEIFDEF _S8 ; SSSE3 + MOVBE instruction - ia32
    _IPP=_IPP_S8
ELSEIFDEF _P8 ; Intel(R) Streaming SIMD Extensions 4.2 - ia32
    _IPP=_IPP_P8
ELSEIFDEF _G9 ; Intel(R) Advanced Vector Extensions - ia32
     IPP_ALIGN_FACTOR EQU 32
    _IPP=_IPP_G9
ELSEIFDEF _H9 ; Intel(R) Advanced Vector Extensions 2 - ia32
     IPP_ALIGN_FACTOR EQU 32
    _IPP=_IPP_H9
ELSEIFDEF _S0 ; Intel(R) Advanced Vector Extensions 512 - Intel(R) Xeon(R) processor (formerly Skylake) - ia32
     IPP_ALIGN_FACTOR EQU 64
    _IPP=_IPP_S0
ELSEIFDEF _M7 ; Intel(R) Streaming SIMD Extensions 3 - intel64
    _IPP=_IPP_PX
    _IPP32E=_IPP32E_M7
ELSEIFDEF _U8 ; Supplemental Streaming SIMD Extensions 3 (SSSE3) - intel64
    _IPP=_IPP_PX
    _IPP32E=_IPP32E_U8
ELSEIFDEF _N8 ; SSSE3 + MOVBE instruction - intel64
    _IPP=_IPP_PX
    _IPP32E=_IPP32E_N8
ELSEIFDEF _Y8 ; Intel(R) Streaming SIMD Extensions 4.2 - intel64
    _IPP=_IPP_PX
    _IPP32E=_IPP32E_Y8
ELSEIFDEF _E9 ; Intel(R) Advanced Vector Extensions - intel64
     IPP_ALIGN_FACTOR EQU 32
    _IPP=_IPP_PX
    _IPP32E=_IPP32E_E9
ELSEIFDEF _L9 ; Intel(R) Advanced Vector Extensions 2 - intel64
     IPP_ALIGN_FACTOR EQU 32
    _IPP=_IPP_PX
    _IPP32E=_IPP32E_L9
ELSEIFDEF _N0 ; Intel(R) Advanced Vector Extensions 512 (formerly Knights Landing) - intel64
     IPP_ALIGN_FACTOR EQU 64
    _IPP=_IPP_PX
    _IPP32E=_IPP32E_N0
ELSEIFDEF _K0 ; Intel(R) Advanced Vector Extensions 512 - Intel(R) Xeon(R) processor (formerly Skylake) - intel64
     IPP_ALIGN_FACTOR EQU 64
    _IPP=_IPP_PX
    _IPP32E=_IPP32E_K0
ELSE
    _IPP=_IPP_PX ; pure C-code
ENDIF

IF (_IPP GT _IPP_H9)OR(_IPP32E GT _IPP32E_L9)
     IPP_ALIGN_FACTOR EQU 64
ELSEIF (_IPP GT _IPP_P8)OR(_IPP32E GT _IPP32E_Y8)
     IPP_ALIGN_FACTOR EQU 32
ELSE
     IPP_ALIGN_FACTOR EQU 16
ENDIF

IFDEF LINUX32
  IFNDEF OSX32
%ECHO .section .note.GNU-stack,"",%progbits
  ENDIF
ENDIF 

IFDEF LINUX32E
  IFNDEF OSXEM64T
    IFNDEF _ARCH_KNC
%ECHO .section .note.GNU-stack,"",%progbits
    ENDIF
  ENDIF
ENDIF 

; define _OWN_MERGED_BLD if _MERGED_BLD defined
IFDEF _MERGED_BLD
_OWN_MERGED_BLD = 1
ENDIF ; _MERGED_BLD

;; compile data only for _MERGED_BLD and (g9 or e9) CPU
IFNDEF _MERGED_BLD
_IPP_DATA = 1
ELSE
IF (_IPP EQ _IPP_G9) OR (_IPP32E EQ _IPP32E_E9)
_IPP_DATA = 1
ENDIF
ENDIF ; _MERGED_BLD

ENDIF ; IFNDEF __ASMDEFS_INC__

;;;;;;;;;;;;;;;;;;;;;;;;;; End of file "asmdefs.inc" ;;;;;;;;;;;;;;;;;;;;;;;;;;
