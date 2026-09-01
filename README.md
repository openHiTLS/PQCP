# pqcp

PQCP means Pioneer Quotable Crypto Provider

This project provides a provider of non-standardized algorithms for OpenHTLS to support the new generation of advanced cryptographic algorithms.

## Features
- Post-quantum algorithms
    - Post-quantum KEM (Key Encapsulation Mechanism) algorithms
    - Post-quantum digital signature algorithms
    - Key management for post-quantum algorithms
- A new generation of hash algorithms
- A new generation of symmetry algorithms
- Post-Quantum Certificate
- Post-quantum protocols

## Building

### Prerequisites

- CMake 3.10 or higher
- C compiler with C11 support
- OpenHiTLS development files

### Build Instructions

```bash
mkdir build
cd build
cmake ..
make
```

### Algorithm Selection

`build_pqcp.sh` supports algorithm selection at build time.

- Build all algorithms:

```bash
bash ./build_pqcp.sh
```

- Enable only specific algorithms:

```bash
bash ./build_pqcp.sh --enable scloudplus polarlac
```

- Disable specific algorithms:

```bash
bash ./build_pqcp.sh --disable hiae
```

Supported command-line algorithm names are normalized to lowercase with `-` represented as `_`, for example:

- `aigis_sig` (`src/Aigis-sig`)
- `scloudplus`
- `polarlac`
- `composite_sign`
- `hiae`
- `nev`

### NEV Implementations

NEV follows the same source layout as HiAE: public headers are under
`src/nev/include`, while implementation files are under `src/nev/src`. The
runtime-parameterized implementation is built by default on every
supported target, using its portable C path where ARMv8 assembly is not
available. Its Hash/KDF backend is configurable, and defaults to the openHiTLS
SHA3/Keccak core:

```bash
bash ./build_pqcp.sh                         # SHA3 (default)
bash ./build_pqcp.sh --nev-hash-backend sm3 # ICCS SM3 Hash/KDF
```

The existing ICCS known-answer vectors apply only to the `SM3` configuration.
The default `SHA3` configuration is intended for integration and performance
testing and is not checked against those ICCS vectors.

To validate the SM3 configuration against all 12 ICCS parameter-set KATs:

```bash
bash ./build_pqcp.sh --nev-hash-backend sm3
cd testcode/script
bash ./build_pqcp_sdv.sh run-tests=test_suite_sdv_pqcp_nev no-demo
bash ./execute_sdv.sh test_suite_sdv_pqcp_nev
```

The SDV build rejects an explicitly requested NEV ICCS KAT unless the selected
provider build records the `SM3` backend; an all-suite run skips that KAT for
other backends.

On AArch64, enable the ARMv8 assembly path in the NEON implementation with:

```bash
bash ./build_pqcp.sh --nev-neon
```

The resulting provider uses runtime Advanced SIMD detection and falls back to
the portable C path from the same NEON implementation when ASIMD is
unavailable. With CMake directly, use `-DPQCP_NEV_ENABLE_NEON=ON`.

For CPUs that implement ARMv8.2 FEAT_SHA3, build the linked openHiTLS dependency
with its accelerated Keccak backend before configuring PQCP:

```bash
cd ../openhitls_ngcc/testcode/script
bash build_hitls.sh shared \
    add-options=-DHITLS_ASM_ARMV8 \
    add-options=-DHITLS_CRYPTO_SHA3_ARMV8_EXT
cd ../../../pqcp
bash ./build_pqcp.sh --hitls_dir ../openhitls_ngcc --nev-neon
```

`HITLS_CRYPTO_SHA3_ARMV8_EXT` is a compile-time selection and must only be used
when the deployment CPU supports FEAT_SHA3. The SHA3 backend uses its
two-lane Keccak path for non-compressed NEV encapsulation and decapsulation.

On AArch64 systems with SVE2, the optional SVE2 build selects the SVE2 NEV
polynomial, NTT, sampling and codec kernels and the local multi-stream
SHA3/SHAKE permutation at compile time. It performs no SVE2 HWCAP or vector
length probe: enabling this option is an explicit promise that every target
CPU supports SVE2.

```bash
bash ./build_pqcp.sh \
    --hitls_dir ../openhitls_ngcc \
    --nev-sve2
```

The equivalent PQCP CMake option is `-DPQCP_NEV_ENABLE_SVE2=ON`; it requires
`PQCP_NEV_ENABLE_NEON=ON` and the SHA3 backend. The SVE2 implementation is
compiled from PQCP's assembly sources and does not require a SHA3-SVE2 macro
or header from openHiTLS. Leave `PQCP_NEV_ENABLE_SVE2` off for an NEON-only
binary or leave both acceleration switches off for the portable C build.

The NTT and primary polynomial kernels are specialized for a 256-bit vector
length. Enabling SVE2 is therefore also a compile-time promise that the target
runs with SVE VL=256. If the target additionally supports FEAT_SVE_SHA3, enable
the hybrid SHA3 backend with:

```bash
bash ./build_pqcp.sh \
    --hitls_dir ../openhitls_ngcc \
    --nev-sve2-sha3
```

The equivalent additional CMake option is
`-DPQCP_NEV_ENABLE_SVE2_SHA3=ON`. It uses compact FEAT_SHA3 NEON permutations
for one or two streams and the `RAX1` SVE2 permutation for the four-stream
key-generation ladder. It performs no runtime feature detection and must only
be enabled when every deployment CPU supports FEAT_SVE_SHA3. The base
`--nev-sve2` path remains available for 256-bit SVE2 CPUs without that optional
extension.

With CMake, select an integrated backend using
`-DPQCP_NEV_HASH_BACKEND=SHA3` or `-DPQCP_NEV_HASH_BACKEND=SM3`. To integrate a
different implementation, select `CUSTOM` and provide one or more source files:

```bash
cmake -S . -B build \
    -DHITLS_ROOT_PATH=../openhitls7 \
    -DPQCP_NEV_HASH_BACKEND=CUSTOM \
    -DPQCP_NEV_CUSTOM_HASH_SOURCES=/path/to/nev_hash_backend.c \
    -DPQCP_NEV_CUSTOM_HASH_INCLUDE_DIRS=/path/to/include
```

The required custom interface is declared in
`src/nev/src/nev_symmetric_backend.h`. A custom backend supplies
`NEV_KdfRate`, `NEV_Hash`, `NEV_Hash2`, `NEV_Kdf`, `NEV_KdfAbsorb`, and
`NEV_KdfSqueezeBlocks`; the returned KDF rate must not exceed 168 bytes.

### NEV Benchmark

Build the NEV provider benchmark together with the provider:

```bash
cmake -S . -B build \
    -DHITLS_ROOT_PATH=../openhitls7 \
    -DPQCP_BUILD_NEV_BENCHMARK=ON
cmake --build build --target pqcp_nev_benchmark
```

The command-line options follow the openHiTLS benchmark convention. For
example, benchmark all three KEM operations of one parameter set, or only
encapsulation for every parameter set:

```bash
./build/testcode/benchmark/pqcp_nev_benchmark -p nev-512-769-c -t 1000
./build/testcode/benchmark/pqcp_nev_benchmark -a nev-Encaps -s 1
```

Use `-m /path/to/provider/directory` when the provider is not in the CMake
build directory. Run with `-h` to list all options.

### Aigis-Sig+ KAT

The Aigis-Sig+ KAT vectors and test source are included in this repository and are discovered by
the standard PQCP SDV flow. From a clean clone, build the provider and run its 61-case suite:

```bash
bash ./build_pqcp.sh --enable aigis_sig
bash ./testcode/script/build_pqcp_sdv.sh no-demo \
    run-tests=test_suite_sdv_pqcp_aigis_sig
cd testcode/script
bash ./execute_sdv.sh test_suite_sdv_pqcp_aigis_sig
```

The suite covers SHA3-I, SHA3-II, SHA3-III, SM3-I, SM3-II, and SM3-III key generation,
byte-exact signatures, verification, imported-key interoperability, and public provider API lifecycle checks. The normal
`build_pqcp.sh` dependency flow prepares the required openHiTLS build; no parent repository files or
pre-generated local test output are required.

## Usage

To use this provider with OpenHiTLS:

1. Set the provider path:
```c
CRYPT_EAL_ProviderSetLoadPath(libCtx, "/path/to/providers");
```

2. Load the provider:
```c
CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_SO, "pqcp", NULL, NULL);
```

## Supported Algorithms

- KEM: Scloud+, PolarLAC, NEV
- Digital Signatures: 
- Symmetric Cipher (AEAD): HiAE
- MAC: HiAE-MAC

## License

This project is licensed under the same terms as OpenHiTLS. 
