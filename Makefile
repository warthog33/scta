CC=gcc
CXX = g++
OBJS =  main.o 
OBJS += Simple/DES.o SimpleSoftware.o 
OBJS += mbedtls/des.o MbedTLS.o mbedtls/aes.o 
OBJS += TexasInstruments/TI_aes_128.o TexasInstruments/DES.o TexasInstruments.o
OBJS += openssl/aes_core.o openssl/des_enc.o openssl/ecb_enc.o openssl/ecb3_enc.o openssl/set_key.o openssl/aes_ecb.o OpenSSL.o 
OBJS += smartcard-aes-fw-master/inv_aes.o SmartCardAES.o
CFLAGS = -I.  -std=c99
CXXFLAGS = -I. -std=c99

OBJS +=  TexasInstruments/TI_aes_128.o TexasInstruments/DES.o TexasInstruments.o


INCLUDE_LIBGCRYPT = 0
ifeq ($(INCLUDE_LIBGCRYPT), 1 )
  OBJS = $(OBJS) libgcrypt/src/rijndael.o libgcrypt/src/des.o libgcrypt/src/cipher-ocb.o libgcrypt/src/fips.o libgcrypt/src/misc.
  CFLAGS = $(CFLAGS) -Ilibgcrypt -Ilibgcrypt/src
endif

INCLUDE_WOLFSSL = 1
#'ifeq (1, 1 )
OBJS += wolfssl/wolfcrypt/aes.o wolfssl/wolfcrypt/des3.o WolfCrypt.o
CFLAGS += -Iwolfssl/wolfcrypt -Iwolfssl -DHAVE_CONFIG_H
#'endif

OBJS += libtomcrypt/des.o libtomcrypt/aes.o libtomcrypt/crypt_argchk.o libtomcrypt/zeromem.o TomCrypt.o
CFLAGS += -Ilibtomcrypt
CXXFLAGS += -Ilibtomcrypt


OBJS += KernelCrypto.o

scta: $(OBJS)
	g++ -o scta $^ -lstdc++


.o:.c

mbedtls/%.o: mbedtls/%.c

TexasInstruments/%.o: TexasInstruments/%.c

openssl/%.o: openssl/%.c

*.o: *.h


clean:
	rm *.o mbedtls/*.o scta TexasInstruments/*.o
