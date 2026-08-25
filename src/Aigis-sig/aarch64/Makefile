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

CC = /usr/bin/cc
CFLAGS = -Wall -Wextra -march=native -mtune=native -fomit-frame-pointer -O3
SOURCES = sign.c polyvec.c packing.c poly.c reduce.c ntt.c rounding.c fips202.c hashkdf.c \
	auxfunc.c SIG_AlgorithmInstance.c drng.c pspm.c
HEADERS = api.h params.h polyvec.h packing.h poly.h reduce.h ntt.h pspm.h\
  rounding.h fips202.h hashkdf.h auxfunc.h SIG_AlgorithmInstance.h drng.h randombytes.h 

RANDOM = randombytes.c

DRANDOM = rng.c

SPEED_TARGETS = speed128_sha3 speed256_sha3 speed512_sha3
KAT_TARGETS = PQCgenKAT_sign128_iccs PQCgenKAT_sign256_iccs PQCgenKAT_sign512_iccs

all: $(SPEED_TARGETS) $(KAT_TARGETS)

speed128_sha3: $(SOURCES) $(RANDOM) aigis_sig.c \
  speed.c cpucycles.c $(HEADERS) speed.h \
  cpucycles.h
	$(CC) $(CFLAGS) -DPARAMS=1 -DUSE_SHA3 $(SOURCES) $(RANDOM)  aigis_sig.c \
	  speed.c cpucycles.c -o $@

speed256_sha3: $(SOURCES) $(RANDOM) aigis_sig.c \
  speed.c cpucycles.c $(HEADERS) speed.h \
  cpucycles.h
	$(CC) $(CFLAGS) -DPARAMS=2 -DUSE_SHA3 $(SOURCES) $(RANDOM)  aigis_sig.c \
	  speed.c cpucycles.c -o $@
	  
speed512_sha3: $(SOURCES) $(RANDOM) aigis_sig.c \
  speed.c cpucycles.c $(HEADERS) speed.h \
  cpucycles.h
	$(CC) $(CFLAGS) -DPARAMS=3 -DUSE_SHA3 $(SOURCES) $(RANDOM)  aigis_sig.c \
	  speed.c cpucycles.c -o $@

PQCgenKAT_sign128_iccs: KAT_SIG.c $(SOURCES) $(HEADERS) $(DRANDOM)  
	$(CC) $(CFLAGS) -DPARAMS=1 -DUSE_ICCS $(SOURCES) $(DRANDOM) KAT_SIG.c -o $@

PQCgenKAT_sign256_iccs: KAT_SIG.c $(SOURCES) $(HEADERS) $(DRANDOM) 
	$(CC) $(CFLAGS) -DPARAMS=2 -DUSE_ICCS $(SOURCES) $(DRANDOM) KAT_SIG.c -o $@ 

PQCgenKAT_sign512_iccs: KAT_SIG.c $(SOURCES) $(HEADERS) $(DRANDOM) 
	$(CC) $(CFLAGS) -DPARAMS=3 -DUSE_ICCS $(SOURCES) $(DRANDOM) KAT_SIG.c -o $@ 

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
