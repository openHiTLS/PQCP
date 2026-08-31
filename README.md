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

- KEM: Scloud+
- Digital Signatures: 
- Symmetric Cipher (AEAD): HiAE
- MAC: HiAE-MAC

## License

This project is licensed under the same terms as OpenHiTLS. 
