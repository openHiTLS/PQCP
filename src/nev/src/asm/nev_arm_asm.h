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

#ifndef PQCP_NEV_ARM_ASM_H
#define PQCP_NEV_ARM_ASM_H

#if defined(__ASSEMBLER__) && defined(__aarch64__)

/* Older openHiTLS crypt_arm.h revisions do not expose an SVE2 architecture
 * directive. Keep the optional PQCP backend self-contained. */
#ifndef CRYPT_AARCH64_ARCH_SVE2
#define CRYPT_AARCH64_ARCH_SVE2 .arch armv8-a+sve2
#endif

/* Keep the NEV kernels independent of the OpenHiTLS crypt_arm.h version.
 * Newer versions provide equivalent VLDQ/VSTQ helpers, while older macOS
 * builds only provide the Mach-O symbol compatibility layer. */
#define VLDQ_8H NEV_VLDQ_8H
#define VSTQ_8H NEV_VSTQ_8H

#ifdef HITLS_BIG_ENDIAN
.macro NEV_VLDQ_8H vd, base, offset=#0
    ldr     q\vd, [\base, \offset]
    rev64   v\vd\().8h, v\vd\().8h
    ext     v\vd\().16b, v\vd\().16b, v\vd\().16b, #8
.endm

.macro NEV_VSTQ_8H vd, base, offset=#0
    ext     v\vd\().16b, v\vd\().16b, v\vd\().16b, #8
    rev64   v\vd\().8h, v\vd\().8h
    str     q\vd, [\base, \offset]
.endm
#else
.macro NEV_VLDQ_8H vd, base, offset=#0
    ldr     q\vd, [\base, \offset]
.endm

.macro NEV_VSTQ_8H vd, base, offset=#0
    str     q\vd, [\base, \offset]
.endm
#endif

#endif /* __ASSEMBLER__ && __aarch64__ */

#endif
