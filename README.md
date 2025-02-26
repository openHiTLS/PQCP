# pqcp

PQCP means Post-quantum cryptography Provider

This project implements a Post-Quantum Cryptography Provider (PQCP) for OpenHiTLS, supporting various post-quantum cryptographic algorithms.

## Features

- Post-quantum KEM (Key Encapsulation Mechanism) algorithms
- Post-quantum digital signature algorithms
- Key management for post-quantum algorithms

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

- KEM: Kyber
- Digital Signatures: Dilithium

## License

This project is licensed under the same terms as OpenHiTLS. 