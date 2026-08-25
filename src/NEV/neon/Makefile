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
CFLAGS += -Wno-incompatible-pointer-types -march=armv8-a -mtune=native -O3 -fomit-frame-pointer -std=c99

SPEED_TARGETS = speed-nev-512-769-c-sha3 speed-nev-1024-769-c-sha3 speed-nev-2048-769-c-sha3 speed-nev-512-1409-sha3 speed-nev-1024-1409-sha3 speed-nev-2048-1409-sha3 speed-nev-512-3329-sha3 speed-nev-1024-3329-sha3 speed-nev-2048-3329-sha3 speed-nev-512-769-sha3 speed-nev-1024-769-sha3 speed-nev-2048-769-sha3
KAT_TARGETS = PQCgenKAT_kem-nev-512-769-c-iccs PQCgenKAT_kem-nev-1024-769-c-iccs PQCgenKAT_kem-nev-2048-769-c-iccs PQCgenKAT_kem-nev-512-1409-iccs PQCgenKAT_kem-nev-1024-1409-iccs PQCgenKAT_kem-nev-2048-1409-iccs PQCgenKAT_kem-nev-512-3329-iccs PQCgenKAT_kem-nev-1024-3329-iccs PQCgenKAT_kem-nev-2048-3329-iccs PQCgenKAT_kem-nev-512-769-iccs PQCgenKAT_kem-nev-1024-769-iccs PQCgenKAT_kem-nev-2048-769-iccs

all: $(SPEED_TARGETS) $(KAT_TARGETS)

SOURCES = poly.c  ntt.c owpke.c  verify.c sample.c pack.c

KEM = cca.c cpa.c

HEADERS = params.h poly.h ntt.h owpke.h verify.h api.h randombytes.h kat_test/KEM_AlgorithmInstance.h align.h sample.h

TEST_SPEED = speed_test/test_speed.c speed_test/cpucycles.c speed_test/speed_print.c

SYMMETRICS = symmetrics/hashkdf.c symmetrics/fips202.c symmetrics/auxfunc.c \

RANDOM = randombytes.c

DRANDOM = kat_test/rng.c kat_test/drng.c

KAT_FILES = kat_test/KAT_KEM.c kat_test/KEM_AlgorithmInstance.c

all_targets: $(SPEED_TARGETS) $(KAT_TARGETS)

speed-nev-512-769-c-sha3: $(HEADERS) $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM) 
	$(CC) $(CFLAGS) -DPARAMS=1 -DUSE_SHA3 -o $@ $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM)
speed-nev-1024-769-c-sha3: $(HEADERS) $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM) 
	$(CC) $(CFLAGS) -DPARAMS=2 -DUSE_SHA3 -o $@ $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM)
speed-nev-2048-769-c-sha3: $(HEADERS) $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM) 
	$(CC) $(CFLAGS) -DPARAMS=3 -DUSE_SHA3 -o $@ $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM)
speed-nev-512-1409-sha3: $(HEADERS) $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM) 
	$(CC) $(CFLAGS) -DPARAMS=4 -DUSE_SHA3 -o $@ $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM)
speed-nev-1024-1409-sha3: $(HEADERS) $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM) 
	$(CC) $(CFLAGS) -DPARAMS=5 -DUSE_SHA3 -o $@ $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM)
speed-nev-2048-1409-sha3: $(HEADERS) $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM) 
	$(CC) $(CFLAGS) -DPARAMS=6 -DUSE_SHA3 -o $@ $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM)
speed-nev-512-3329-sha3: $(HEADERS) $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM) 
	$(CC) $(CFLAGS) -DPARAMS=7 -DUSE_SHA3 -o $@ $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM)
speed-nev-1024-3329-sha3: $(HEADERS) $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM) 
	$(CC) $(CFLAGS) -DPARAMS=8 -DUSE_SHA3 -o $@ $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM)
speed-nev-2048-3329-sha3: $(HEADERS) $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM) 
	$(CC) $(CFLAGS) -DPARAMS=9 -DUSE_SHA3 -o $@ $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM)
speed-nev-512-769-sha3: $(HEADERS) $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM) 
	$(CC) $(CFLAGS) -DPARAMS=10 -DUSE_SHA3 -o $@ $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM)
speed-nev-1024-769-sha3: $(HEADERS) $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM) 
	$(CC) $(CFLAGS) -DPARAMS=11 -DUSE_SHA3 -o $@ $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM)
speed-nev-2048-769-sha3: $(HEADERS) $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM) 
	$(CC) $(CFLAGS) -DPARAMS=12 -DUSE_SHA3 -o $@ $(SOURCES) $(KEM) $(SYMMETRICS) $(TEST_SPEED) $(RANDOM)


PQCgenKAT_kem-nev-512-769-c-iccs: $(KAT_FILES) $(SOURCES) $(KEM) $(SYMMETRICS) $(HEADERS) $(DRANDOM)
	$(CC) $(CFLAGS) -DPARAMS=1 -DUSE_ICCS $(SOURCES) $(KEM) $(SYMMETRICS) $(DRANDOM) $(KAT_FILES) -o $@

PQCgenKAT_kem-nev-1024-769-c-iccs: $(KAT_FILES) $(SOURCES) $(KEM) $(SYMMETRICS) $(HEADERS) $(DRANDOM)
	$(CC) $(CFLAGS) -DPARAMS=2 -DUSE_ICCS $(SOURCES) $(KEM) $(SYMMETRICS) $(DRANDOM) $(KAT_FILES) -o $@

PQCgenKAT_kem-nev-2048-769-c-iccs: $(KAT_FILES) $(SOURCES) $(KEM) $(SYMMETRICS) $(HEADERS) $(DRANDOM)
	$(CC) $(CFLAGS) -DPARAMS=3 -DUSE_ICCS $(SOURCES) $(KEM) $(SYMMETRICS) $(DRANDOM) $(KAT_FILES) -o $@

PQCgenKAT_kem-nev-512-1409-iccs: $(KAT_FILES) $(SOURCES) $(KEM) $(SYMMETRICS) $(HEADERS) $(DRANDOM)
	$(CC) $(CFLAGS) -DPARAMS=4 -DUSE_ICCS $(SOURCES) $(KEM) $(SYMMETRICS) $(DRANDOM) $(KAT_FILES) -o $@

PQCgenKAT_kem-nev-1024-1409-iccs: $(KAT_FILES) $(SOURCES) $(KEM) $(SYMMETRICS) $(HEADERS) $(DRANDOM)
	$(CC) $(CFLAGS) -DPARAMS=5 -DUSE_ICCS $(SOURCES) $(KEM) $(SYMMETRICS) $(DRANDOM) $(KAT_FILES) -o $@

PQCgenKAT_kem-nev-2048-1409-iccs: $(KAT_FILES) $(SOURCES) $(KEM) $(SYMMETRICS) $(HEADERS) $(DRANDOM)
	$(CC) $(CFLAGS) -DPARAMS=6 -DUSE_ICCS $(SOURCES) $(KEM) $(SYMMETRICS) $(DRANDOM) $(KAT_FILES) -o $@

PQCgenKAT_kem-nev-512-3329-iccs: $(KAT_FILES) $(SOURCES) $(KEM) $(SYMMETRICS) $(HEADERS) $(DRANDOM)
	$(CC) $(CFLAGS) -DPARAMS=7 -DUSE_ICCS $(SOURCES) $(KEM) $(SYMMETRICS) $(DRANDOM) $(KAT_FILES) -o $@

PQCgenKAT_kem-nev-1024-3329-iccs: $(KAT_FILES) $(SOURCES) $(KEM) $(SYMMETRICS) $(HEADERS) $(DRANDOM)
	$(CC) $(CFLAGS) -DPARAMS=8 -DUSE_ICCS $(SOURCES) $(KEM) $(SYMMETRICS) $(DRANDOM) $(KAT_FILES) -o $@

PQCgenKAT_kem-nev-2048-3329-iccs: $(KAT_FILES) $(SOURCES) $(KEM) $(SYMMETRICS) $(HEADERS) $(DRANDOM)
	$(CC) $(CFLAGS) -DPARAMS=9 -DUSE_ICCS $(SOURCES) $(KEM) $(SYMMETRICS) $(DRANDOM) $(KAT_FILES) -o $@

PQCgenKAT_kem-nev-512-769-iccs: $(KAT_FILES) $(SOURCES) $(KEM) $(SYMMETRICS) $(HEADERS) $(DRANDOM)
	$(CC) $(CFLAGS) -DPARAMS=10 -DUSE_ICCS $(SOURCES) $(KEM) $(SYMMETRICS) $(DRANDOM) $(KAT_FILES) -o $@

PQCgenKAT_kem-nev-1024-769-iccs: $(KAT_FILES) $(SOURCES) $(KEM) $(SYMMETRICS) $(HEADERS) $(DRANDOM)
	$(CC) $(CFLAGS) -DPARAMS=11 -DUSE_ICCS $(SOURCES) $(KEM) $(SYMMETRICS) $(DRANDOM) $(KAT_FILES) -o $@

PQCgenKAT_kem-nev-2048-769-iccs: $(KAT_FILES) $(SOURCES) $(KEM) $(SYMMETRICS) $(HEADERS) $(DRANDOM)
	$(CC) $(CFLAGS) -DPARAMS=12 -DUSE_ICCS $(SOURCES) $(KEM) $(SYMMETRICS) $(DRANDOM) $(KAT_FILES) -o $@

SPEED: $(SPEED_TARGETS)
	@echo "test speed..."
	./$(SPEED_TARGETS)

KAT: $(KAT_TARGETS)
	@echo "generate kat files..."
	./$(KAT_TARGETS)

.PHONY: all SPEED KAT all_targets clean all

clean:
	-rm $(SPEED_TARGETS)
	-rm $(KAT_TARGETS)
	-rm -rf output

