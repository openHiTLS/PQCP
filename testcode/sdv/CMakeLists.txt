set(TEST_SOURCE
    ${PQCP_ROOT}/testcode/framework/gen_test/helper.c
    ${PQCP_ROOT}/testcode/framework/gen_test/test.c
    ${PQCP_ROOT}/testcode/framework/crypto/alg_check.c
    ${PQCP_ROOT}/testcode/framework/crypto/crypto_test_util.c
)

add_library(TESTCASE_PRE ${TEST_SOURCE})

target_include_directories(TESTCASE_PRE PRIVATE
    ${PQCP_ROOT}/testcode/framework/include
    ${PQCP_ROOT}/testcode/framework/crypto
    ${HITLS_ROOT_DIR}/config/macro_config
    ${HITLS_ROOT_DIR}/crypto/include
    ${HITLS_ROOT_DIR}/include/crypto
    ${HITLS_ROOT_DIR}/include/bsl
    ${HITLS_ROOT_DIR}/bsl/err/include
    ${HITLS_ROOT_DIR}/crypto/eal/src
)
add_library(SHARED_COMPILE_DEFS INTERFACE)

target_compile_definitions(SHARED_COMPILE_DEFS INTERFACE
    HITLS_CRYPTO_EAL
    HITLS_CRYPTO_PKEY
    HITLS_CRYPTO_MD
    HITLS_CRYPTO_DRBG
    HITLS_CRYPTO_DRBG_HASH
    HITLS_CRYPTO_SHA256
    HITLS_NO_CONFIG_CHECK
)

if(MACROS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${MACROS}")
else()
    message(STATUS "No additional macros provided")
    target_link_libraries(TESTCASE_PRE PRIVATE SHARED_COMPILE_DEFS)
endif()

if(GEN_TEST_FILES)
    # test1 test2 ...
    string(REPLACE " " ";" GEN_TEST_FILES ${GEN_TEST_FILES})
    foreach(gen_test_suite ${GEN_TEST_FILES})
        get_filename_component(suite ${gen_test_suite} NAME)
        execute_process(COMMAND touch ${PQCP_ROOT}/testcode/output/${suite}.c
            WORKING_DIRECTORY ${PQCP_ROOT}/testcode/output
        )
        message(STATUS "WORKING_DIRECTORY: ${PQCP_ROOT}/testcode/output")
        add_custom_target(${suite}_phony
                          COMMAND ./gen_testcase ${gen_test_suite}
                          DEPENDS gen_testcase
                          WORKING_DIRECTORY ${PQCP_ROOT}/testcode/output)
        message(STATUS "${suite}: ${gen_test_suite}")
        set(TEST_FILES "${TEST_FILES};${gen_test_suite}")
    endforeach()
else()
    message(STATUS "No file needs to be generated")
endif()

# Create test cases with shared library linking for STUB framework compatibility
foreach(test_suite ${TEST_FILES})
    get_filename_component(sdv_exe ${test_suite} NAME_WE)
    add_executable(${sdv_exe} ${PQCP_ROOT}/testcode/output/${sdv_exe}.c)
    # Apply GNU ld-specific link options only on Linux
    if(NOT APPLE)
        target_link_options(${sdv_exe} PRIVATE "LINKER:-z,noexecstack")
    endif()
    add_dependencies(${sdv_exe} ${sdv_exe}_phony)
    set_target_properties(${sdv_exe} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${PQCP_ROOT}/testcode/output"
    )

    target_include_directories(${sdv_exe} PRIVATE
        ${PQCP_ROOT}/testcode/framework/include
        ${PQCP_ROOT}/testcode/framework/crypto
        ${HITLS_ROOT_DIR}/include/crypto
        ${HITLS_ROOT_DIR}/include/bsl
        ${HITLS_ROOT_DIR}/config/macro_config
    )
    target_link_libraries(${sdv_exe} PRIVATE TESTCASE_PRE 
                            ${HITLS_CRYPTO_LIB} ${HITLS_BSL_LIB} ${SECUREC_LIB})
    if(NOT MACROS)
        target_link_libraries(${sdv_exe} PRIVATE SHARED_COMPILE_DEFS)
    endif()
endforeach()
