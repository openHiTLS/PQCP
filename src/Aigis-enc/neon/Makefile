# Copyright (c) 2025 LiuRuikang
# School Of Cyber Engineering, Xidian University
#
# This file is part of the openHiTLS project.
#
# openHiTLS is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
# http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

CC=/usr/bin/gcc
LDFLAGS= -march=armv8-a+simd -O3 -fomit-frame-pointer -std=c99


SOURCES= cbd.c fips202.c fips202x4.c poly.c  cpucycles.c precomp.c ntt.c polyvec.c owcpa.c  kem.c verify.c keccak4x/KeccakP-1600-times4-SIMD256.o hashkdf.c genmatrix.c speed_print.c \
auxfunc.c KEM_AlgorithmInstance.c drng.c pack.c

HEADERS= cbd.h fips202.h fips202x4.h params.h poly.h ntt.h polyvec.h owcpa.h verify.h api.h cpucycles.h hashkdf.h genmatrix.h speed_print.h \
 keccak4x/align.h keccak4x/brg_endian.h keccak4x/KeccakP-1600-times4-SnP.h keccak4x/KeccakP-1600-unrolling.macros keccak4x/SIMD256-config.h KEM_AlgorithmInstance.h auxfunc.h drng.h randombytes.h 

RANDOM = randombytes.c

DRANDOM = rng.c

SPEED_TARGETS = speed128_sha3 speed256_sha3 speed512_sha3
KAT_TARGETS = PQCgenKAT_kem128_iccs PQCgenKAT_kem256_iccs PQCgenKAT_kem512_iccs
all: $(SPEED_TARGETS) $(KAT_TARGETS)


keccak4x/KeccakP-1600-times4-SIMD256.o: keccak4x/KeccakP-1600-times4-SIMD256.c \
										keccak4x/align.h \
										keccak4x/brg_endian.h \
										keccak4x/KeccakP-1600-times4-SIMD256.c \
										keccak4x/KeccakP-1600-times4-SnP.h \
										keccak4x/KeccakP-1600-unrolling.macros \
										keccak4x/SIMD256-config.h
																				
	$(CC) $(LDFLAGS) -c keccak4x/KeccakP-1600-times4-SIMD256.c -o $@


speed128_sha3: $(HEADERS) $(SOURCES) $(RANDOM) test_speed.c
	$(CC) -o $@ $(SOURCES) $(RANDOM) -DPARAMS=1 -DUSE_SHA3 -DKDF_AVX $(LDFLAGS) test_speed.c

speed256_sha3: $(HEADERS) $(SOURCES) test_speed.c $(RANDOM)
	$(CC) -o $@ $(SOURCES) $(RANDOM) -DPARAMS=2 -DUSE_SHA3 -DKDF_AVX $(LDFLAGS) test_speed.c
	
speed512_sha3: $(HEADERS) $(SOURCES) $(RANDOM) test_speed.c
	$(CC) -o $@ $(SOURCES) $(RANDOM) -DPARAMS=3 -DUSE_SHA3 -DKDF_AVX $(LDFLAGS) test_speed.c
	
PQCgenKAT_kem128_iccs: KAT_KEM.c $(SOURCES) $(DRANDOM) $(HEADERS)
	$(CC) -DPARAMS=1 -DUSE_NICCS_API $(SOURCES) $(DRANDOM) KAT_KEM.c -o $@ $(LDFLAGS)

PQCgenKAT_kem256_iccs: KAT_KEM.c $(SOURCES) $(DRANDOM) $(HEADERS)
	$(CC) -DPARAMS=2 -DUSE_NICCS_API $(SOURCES) $(DRANDOM) KAT_KEM.c -o $@ $(LDFLAGS)

PQCgenKAT_kem512_iccs: KAT_KEM.c $(SOURCES) $(HEADERS) $(DRANDOM)
	$(CC) -DPARAMS=3 -DUSE_NICCS_API $(SOURCES) $(DRANDOM) KAT_KEM.c -o $@ $(LDFLAGS)

SPEED: $(SPEED_TARGETS)
	@echo "test speed..."
	./$(SPEED_TARGETS)

KAT: $(KAT_TARGETS)
	@echo "generate kat files..."
	./$(KAT_TARGETS)

.PHONY: clean SPEED KAT all


clean:
	-rm $(SPEED_TARGETS)
	-rm $(KAT_TARGETS)
	-rm -rf output

