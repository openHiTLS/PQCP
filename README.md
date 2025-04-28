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

## License

This project is licensed under the same terms as OpenHiTLS. 