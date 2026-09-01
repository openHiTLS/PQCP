# White-box unit test for the NEV ARMv8 rejection-sampling compaction buffer
# (PR #57 review comment #4).  Builds the production compaction driver
# (asm_nev_sample.c) and the ARMv8 kernel (nev_sample_armv8.S) unhidden,
# together with a driver that exercises NEV_Ternary3Ext() over boundary and
# overflow-triggering (n, rate) combinations.
#
# Requires: PQCP_ENABLE_NEV=ON, PQCP_NEV_ENABLE_NEON=ON (the bug only exists
# on the ARMv8 asm compaction path), an AArch64 build host.

add_executable(nev_asm_compact_test
    nev_asm_compact_test.c
    ${NEV_SRC_ROOT}/asm/asm_nev_sample.c
    ${NEV_ASM_ROOT}/nev_sample_armv8.S
)

target_include_directories(nev_asm_compact_test PRIVATE
    ${NEV_SRC_ROOT}
    ${NEV_ASM_ROOT}
    ${HITLS_ROOT_PATH}/config/macro_config
    ${HITLS_ROOT_PATH}/crypto/include
)

target_compile_definitions(nev_asm_compact_test PRIVATE
    HITLS_CRYPTO_NEV
)

# The namespace header (-include) renames NEV_* symbols identically in the C
# driver and the assembly kernel, mirroring how pqcp_nev_neon_asm is built.
# -fstack-protector-all turns the cbuf overflow into a deterministic abort.
target_compile_options(nev_asm_compact_test PRIVATE
    -include ${NEV_ASM_NAMESPACE_HEADER}
    -march=armv8-a+simd
    -fstack-protector-all
)

add_test(NAME nev_asm_compact_overflow COMMAND nev_asm_compact_test)
