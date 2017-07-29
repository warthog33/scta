
scta:

*.o: Makefile
CC=gcc
CXX = g++
CXXFLAGS = -g

UNAME = $(shell /bin/uname -m)
ifeq ($(UNAME),armv7l)
	CFLAGS += -std=c11 
endif
ifeq ($(UNAME), x86_64)
	CXXFLAGS += -DTRIGGER=PRINT
endif



OBJS =  main.o Trigger.o
OBJS += Simple/DES.o SimpleSoftware.o 
OBJS += TexasInstruments/TI_aes_128.o TexasInstruments/DES.o TexasInstruments.o
OBJS += smartcard-aes-fw-master/inv_aes.o SmartCardAES.o
OBJS += KernelCrypto.o

OPENSSL_OBJS = OpenSSL.o
OPENSSL_LIB = openssl/lib/libcrypto.a

$(OPENSSL_LIB):
	cd openssl; tar -xzf openssl-1.1.0e.tar.gz
	cd openssl/openssl-1.1.0e; ./config --prefix=`pwd`/.. --openssldir=`pwd`/.. no-shared
	cd openssl/openssl-1.1.0e; make build_libs
	cd openssl/openssl-1.1.0e; make install_sw	

$(OPENSSL_OBJS): $(OPENSSL_LIB)
$(OPENSSL_OBJS): CXXFLAGS += -Iopenssl/include 

OBJS += $(OPENSSL_OBJS) $(OPENSSL_LIB)



MBED_OBJS = MbedTLS.o
MBED_LIB = mbedtls/lib/libmbedcrypto.a

$(MBED_LIB): mbedtls/mbedtls-2.4.2-apache.tgz
	cd mbedtls; tar -xzf mbedtls-2.4.2-apache.tgz
	cd mbedtls/mbedtls-2.4.2; make
	cd mbedtls/mbedtls-2.4.2; make install DESTDIR=`pwd`/..

$(MBED_OBJS): $(MBED_LIB)
$(MBED_OBJS): CXXFLAGS += -Imbedtls/include

OBJS += $(MBED_OBJS) $(MBED_LIB) $(MBED_OBJS)



INCLUDE_LIBGCRYPT = 0
ifdef INCLUDE_LIBGCRYPT
GCRYPT_OBJS = LibGCrypt.o 
GCRYPT_LIBS = libgcrypt/lib/libgcrypt.a libgcrypt/lib/libgpg-error.a
$(GCRYPT_OBJS): CXXFLAGS += -Ilibgcrypt/include 
$(GCRYPT_OBJS): $(GCRYPT_LIBS)
$(GCRYPT_LIBS):
	cd libgcrypt; gunzip --keep --force libgpg-error-1.27.tar.gz
	cd libgcrypt; tar -xf libgpg-error-1.27.tar
	cd libgcrypt/libgpg-error-1.27; ./configure --prefix=`pwd`/.. --enable-static	
	cd libgcrypt/libgpg-error-1.27; make
	cd libgcrypt/libgpg-error-1.27; make install
	cd libgcrypt; bunzip2 --keep --force libgcrypt-1.7.6.tar.bz2
	cd libgcrypt; tar -xf libgcrypt-1.7.6.tar 
	cd libgcrypt/libgcrypt-1.7.6; ./configure --enable-static --prefix=`pwd`/.. --with-libgpg-error-prefix=`pwd`/..
	cd libgcrypt/libgcrypt-1.7.6; make
	cd libgcrypt/libgcrypt-1.7.6; make install

OBJS += $(GCRYPT_OBJS) $(GCRYPT_LIBS) 
endif


INCLUDE_WOLFSSL = 1
ifdef INCLUDE_WOLFSSL

WOLFOBJS = WolfCrypt.o
WOLFLIBS =  wolfssl/lib/libwolfssl.a 

$(WOLFOBJS): CXXFLAGS += -I. -Iwolfssl/include/wolfssl -Iwolfssl/include -DHAVE_CONFIG_H -I.  -DBUILDING_WOLFSSL -fvisibility=hidden -fvisibility=hidden -DBUILDING_WOLFSSL -D_POSIX_THREADS -g -DDEBUG -DDEBUG_WOLFSSL  -DHAVE_THREAD_LS -pthread -DTFM_TIMING_RESISTANT -DECC_TIMING_RESISTANT -DWC_RSA_BLINDING -DHAVE_AESGCM -DWOLFSSL_AES_COUNTER -DWOLFSSL_AES_DIRECT -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DNO_DSA -DHAVE_ECC -DTFM_ECC256 -DECC_SHAMIR -DWOLFSSL_BASE64_ENCODE -DNO_RC4 -DNO_HC128 -DNO_RABBIT -DWOLFSSL_SHA224 -DHAVE_POLY1305 -DHAVE_ONE_TIME_AUTH -DHAVE_CHACHA -DHAVE_HASHDRBG -DHAVE_TLS_EXTENSIONS -DHAVE_SUPPORTED_CURVES -DHAVE_EXTENDED_MASTER -DNO_PSK -DNO_MD4 -DNO_PWDBASED -DWOLFCRYPT_ONLY -DWOLFSSL_X86_64_BUILD -DWC_NO_ASYNC_THREADING -Wall -Wno-unused -DHAVE___UINT128_T -DWOLFSSL_DES_ECB -DHAVE_AES_ECB  -g -ggdb -O0 -Wno-pragmas -Wall -Wno-strict-aliasing -Wextra -Wunknown-pragmas --param=ssp-buffer-size=1  -fwrapv -DWOLFSSL_KEY_GEN

main.o: CXXFLAGS += -DINCLUDE_WOLFSSL
$(WOLFOBJS): $(WOLFLIBS)

$(WOLFLIBS):
	cd wolfssl; rm -rf wolfssl-3.11.0/*
	cd wolfssl; unzip -o wolfssl-3.11.0.zip 
	cd wolfssl/wolfssl-3.11.0; ./configure --prefix=`pwd`/..  --enable-static --enable-cryptonly --enable-des3 "CFLAGS=-DWOLFSSL_DES_ECB -DHAVE_AES_ECB" --enable-aesctr --enable-debugCFLAGS="-Dmp_init=wolf_mp_init" --disable-fastmath --enable-keygen --enable-debug
	cd wolfssl/wolfssl-3.11.0; make
	cd wolfssl/wolfssl-3.11.0; make install

OBJS += $(WOLFOBJS) $(WOLFLIBS)
endif


INCLUDE_TOMCRYPT = 1
ifdef INCLUDE_TOMCRYPT
main.o: CXXFLAGS += -DINCLUDE_TOMCRYPT

TOMLIBS = libtomcrypt/lib/libtomcrypt.a libtomcrypt/lib/libtfm.a
TOMOBJS = TomCrypt.o

$(TOMLIBS):
	cd libtomcrypt; unzip -o tomsfastmath-develop.zip
	cd libtomcrypt/tomsfastmath-develop; make LIBPATH=`pwd`/../lib INCPATH=`pwd`/../include DATAPATH=`pwd`/../docs install
	cd libtomcrypt; unzip -o libtomcrypt-develop.zip
	cd libtomcrypt/libtomcrypt-develop; CFLAGS="-g -DTFM_DESC -DUSE_TFM -DLTC_NO_RSA_BLINDING -I../include" NODOCS=1 make LIBPATH=`pwd`/../lib INCPATH=`pwd`/../include DATAPATH=`pwd`/../docs install

$(TOMOBJS): $(TOMLIBS)
$(TOMOBJS): CXXFLAGS += -Ilibtomcrypt/include/ -DUSE_TFM -DTFM_DESC -DLTC_NO_RSA_BLINDING

OBJS += $(TOMOBJS) $(TOMLIBS)
endif

scta: $(OBJS)
	g++ -g -o scta $^ -lmcheck -Bsymbolic -Xlinker -Map=output.map
	
clean:
	rm *.o mbedtls/*.o scta TexasInstruments/*.o
