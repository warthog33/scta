
scta:

*.o: Makefile
CC=gcc
CXX = g++
CFLAGS = -I. -g
CXXFLAGS = -I. -g

UNAME = $(shell /bin/uname -m)
ifeq ($(UNAME), x86_64)
	CXXFLAGS += -DTRIGGER=PRINT
endif



OBJS =  main.o Trigger.o
OBJS += Simple/DES.o SimpleSoftware.o 
#OBJS += mbedtls/des.o MbedTLS.o mbedtls/aes.o mbedtls/rsa.o mbedtls/pk.o mbedtls/bignum.o mbedtls/md.o mbedtls/pk_wrap.o mbedtls/pkparse.o mbedtls/asn1parse.o mbedtls/oid.o mbedtls/pem.o mbedtls/base64.o
#OBJS += MbedTLS.o mbedtls/mbedtls-2.4.2/library/libmbedcrypto.a
OBJS += TexasInstruments/TI_aes_128.o TexasInstruments/DES.o TexasInstruments.o
#OBJS += openssl/aes_core.o openssl/des_enc.o openssl/ecb_enc.o openssl/ecb3_enc.o openssl/set_key.o openssl/aes_ecb.o OpenSSL.o 
OBJS += smartcard-aes-fw-master/inv_aes.o SmartCardAES.o

OBJS += KernelCrypto.o

OPENSSL_OBJS = OpenSSL.o
OPENSSL_LIB = openssl/lib/libcrypto.a

$(OPENSSL_LIB):
	cd openssl; tar -xzf openssl-1.1.0e.tar.gz
	cd openssl/openssl-1.1.0e; ./config --prefix=`pwd`/.. --openssldir=`pwd`/.. no-shared
	cd openssl/openssl-1.1.0e; make
	cd openssl/openssl-1.1.0e; make install_sw	

$(OPENSSL_OBJS): CXXFLAGS += -Iopenssl/include 

OBJS += $(OPENSSL_OBJS) $(OPENSSL_LIB)


#MBED_LIB = mbedtls/mbedtls-2.4.2/library/libmbedcrypto.a
MBED_OBJS = MbedTLS.o
MBED_LIB = mbedtls/lib/libmbedcrypto.a
#$(MBED_OBJS): $(MBED_LIB)
$(MBED_OBJS): CXXFLAGS += -Imbedtls/mbedtls-2.4.2/include
$(MBED_LIB): mbedtls/mbedtls-2.4.2-apache.tgz
	cd mbedtls
	tar -xzf mbedtls-2.4.2-apache.tgz
	cd mbedtls-2.4.2-apache
	make
	make install DEST_DIR=`pwd`/..
OBJS += $(MBED_OBJS) $(MBED_LIB) $(MBED_OBJS)

INCLUDE_LIBGCRYPT = 0
ifdef INCLUDE_LIBGCRYPT
GCRYPT_OBJS = LibGCrypt.o 
GCRYPT_LIBS = libgcrypt/lib/libgcrypt.a libgcrypt/lib/libgpg-error.a
$(GCRYPT_OBJS): CXXFLAGS += -Ilibgcrypt/include 
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
#CFLAGS += -Ilibgcrypt -Ilibgcrypt/src
endif

INCLUDE_WOLFSSL = 1
ifdef INCLUDE_WOLFSSL
# WOLFOBJS = wolfssl/wolfcrypt/aes.o wolfssl/wolfcrypt/des3.o wolfssl/wolfcrypt/rsa.o WolfCrypt.o wolfssl/wolfcrypt/integer.o wolfssl/wolfcrypt/memory.o wolfssl/wolfcrypt/hash.o wolfssl/wolfcrypt/md5.o wolfssl/wolfcrypt/sha.o wolfssl/wolfcrypt/sha256.o wolfssl/wolfcrypt/random.o wolfssl/wolfcrypt/integer.o
WOLFOBJS = WolfCrypt.o
WOLFLIBS =  wolfssl/lib/libwolfssl.a 
$(WOLFOBJS): CXXFLAGS += -I. -Iwolfssl/include/wolfssl -Iwolfssl/include -DHAVE_CONFIG_H -I.  -DBUILDING_WOLFSSL -fvisibility=hidden -fvisibility=hidden -DBUILDING_WOLFSSL -D_POSIX_THREADS -g -DDEBUG -DDEBUG_WOLFSSL  -DHAVE_THREAD_LS -pthread -DTFM_TIMING_RESISTANT -DECC_TIMING_RESISTANT -DWC_RSA_BLINDING -DHAVE_AESGCM -DWOLFSSL_AES_COUNTER -DWOLFSSL_AES_DIRECT -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DNO_DSA -DHAVE_ECC -DTFM_ECC256 -DECC_SHAMIR -DWOLFSSL_BASE64_ENCODE -DNO_RC4 -DNO_HC128 -DNO_RABBIT -DWOLFSSL_SHA224 -DHAVE_POLY1305 -DHAVE_ONE_TIME_AUTH -DHAVE_CHACHA -DHAVE_HASHDRBG -DHAVE_TLS_EXTENSIONS -DHAVE_SUPPORTED_CURVES -DHAVE_EXTENDED_MASTER -DNO_PSK -DNO_MD4 -DNO_PWDBASED -DWOLFCRYPT_ONLY -DWOLFSSL_X86_64_BUILD -DWC_NO_ASYNC_THREADING -Wall -Wno-unused -DHAVE___UINT128_T -DWOLFSSL_DES_ECB -DHAVE_AES_ECB  -g -ggdb -O0 -Wno-pragmas -Wall -Wno-strict-aliasing -Wextra -Wunknown-pragmas --param=ssp-buffer-size=1  -fwrapv -DWOLFSSL_KEY_GEN
#$(WOLFOBJS): CXXFLAGS += -I. -Iwolfssl/include/wolfssl -Iwolfssl/include -DHAVE_AESGCM -DWOLFSSL_AES_COUNTER -DWOLFSSL_AES_DIRECT -DWOLFSSL_DES_ECB -DHAVE_AES_ECB -DWC_RSA_BLINDING
OBJS += $(WOLFOBJS) $(WOLFLIBS)
 main.o: CXXFLAGS += -DINCLUDE_WOLFSSL

 $(WOLFLIBS):
	cd wolfssl; rm -rf wolfssl-3.11.0/*
	cd wolfssl; unzip -o wolfssl-3.11.0.zip 
	cd wolfssl/wolfssl-3.11.0; ./configure --prefix=`pwd`/..  --enable-static --enable-cryptonly --enable-des3 "CFLAGS=-DWOLFSSL_DES_ECB -DHAVE_AES_ECB" --enable-aesctr --enable-debugCFLAGS="-Dmp_init=wolf_mp_init" --disable-fastmath --enable-keygen --enable-debug
	cd wolfssl/wolfssl-3.11.0; make
	cd wolfssl/wolfssl-3.11.0; make install
endif


INCLUDE_TOMCRYPT = 1
ifdef INCLUDE_TOMCRYPT
 #TOMOBJS = libtomcrypt/des.o libtomcrypt/aes.o libtomcrypt/crypt_argchk.o libtomcrypt/zeromem.o TomCrypt.o libtomcrypt/pk/rsa/rsa_import.o libtomcrypt/pk/rsa/multi.o libtomcrypt/pk/rsa/crypt_ltc_mp_descriptor.o libtomcrypt/pk/rsa/der_decode_subject_public_key_info.o libtomcrypt/pk/rsa/der_decode_sequence_multi.o libtomcrypt/pk/rsa/der_decode_sequence_ex.o libtomcrypt/pk/rsa/der_decode_boolean.o libtomcrypt/pk/rsa/der_decode_integer.o libtomcrypt/pk/rsa/der_decode_utf8_string.o libtomcrypt/pk/rsa/der_length_sequence.o libtomcrypt/pk/rsa/der_length_octet_string.o libtomcrypt/pk/rsa/der_length_boolean.o libtomcrypt/pk/rsa/der_length_integer.o libtomcrypt/pk/rsa/der_length_short_integer.o libtomcrypt/pk/rsa/der_decode_utctime.o libtomcrypt/pk/rsa/der_decode_short_integer.o libtomcrypt/pk/rsa/der_length_bit_string.o libtomcrypt/pk/rsa/der_decode_ia5_string.o libtomcrypt/pk/rsa/der_encode_ia5_string.o libtomcrypt/pk/rsa/der_length_ia5_string.o libtomcrypt/pk/rsa/der_encode_object_identifier.o libtomcrypt/pk/rsa/der_length_printable_string.o libtomcrypt/pk/rsa/der_decode_teletex_string.o libtomcrypt/pk/rsa/der_length_teletex_string.o libtomcrypt/pk/rsa/der_length_object_identifier.o libtomcrypt/pk/rsa/der_length_utctime.o libtomcrypt/pk/rsa/der_length_utf8_string.o libtomcrypt/pk/rsa/der_encode_generalizedtime.o libtomcrypt/pk/rsa/der_length_generalizedtime.o libtomcrypt/pk/rsa/der_decode_choice.o libtomcrypt/pk/rsa/der_decode_bit_string.o libtomcrypt/pk/rsa/der_decode_raw_bit_string.o libtomcrypt/pk/rsa/der_decode_octet_string.o libtomcrypt/pk/rsa/der_decode_object_identifier.o libtomcrypt/pk/rsa/der_decode_printable_string.o libtomcrypt/pk/rsa/der_decode_generalizedtime.o libtomcrypt/pk/rsa/pk_get_oid.o
# $(TOMOBJS): CFLAGS += -Ilibtomcrypt -D LTC_SOURCE -DUSE_TFM -TFM_DESC


main.o: CXXFLAGS += -DINCLUDE_TOMCRYPT


#TOMLIBS = libtomcrypt/lib/libtomcrypt.a libtomcrypt/lib/libtommath.a
TOMLIBS = libtomcrypt/lib/libtomcrypt.a libtomcrypt/lib/libtfm.a

$(TOMLIBS):
	#cd libtomcrypt; unzip -o libtommath-develop.zip
	#cd libtomcrypt/libtommath-develop; make LIBPATH=`pwd`/../lib INCPATH=`pwd`/../include DATAPATH=`pwd`/../docs install
	cd libtomcrypt; unzip -o tomsfastmath-develop.zip
	cd libtomcrypt/tomsfastmath-develop; make LIBPATH=`pwd`/../lib INCPATH=`pwd`/../include DATAPATH=`pwd`/../docs install
	cd libtomcrypt; unzip -o libtomcrypt-develop.zip
	#cd libtomcrypt/libtomcrypt-develop; CFLAGS="-g -DLTM_DESC -DUSE_LTM -I../include" NODOCS=1 make LIBPATH=`pwd`/../lib INCPATH=`pwd`/../include DATAPATH=`pwd`/../docs install
	cd libtomcrypt/libtomcrypt-develop; CFLAGS="-g -DTFM_DESC -DUSE_TFM -DLTC_NO_RSA_BLINDING -I../include" NODOCS=1 make LIBPATH=`pwd`/../lib INCPATH=`pwd`/../include DATAPATH=`pwd`/../docs install

TOMOBJS = TomCrypt.o
#TOMAR = TomCrypt.a

#$(TOMAR): $(TOMLIBS) $(TOMOBJS) $(TOMLIBS)
#	ar -rcsT $(TOMAR) $(TOMOBJS) $(TOMLIBS)
 
#$(TOMOBJS): CXXFLAGS += -Ilibtomcrypt/include -DUSE_LTM -DLTM_DESC
$(TOMOBJS): CXXFLAGS += -Ilibtomcrypt/include/ -DUSE_TFM -DTFM_DESC -DLTC_NO_RSA_BLINDING
OBJS += $(TOMOBJS) $(TOMLIBS)
#OBJS += $(TOMAR)
endif

scta: $(OBJS)
	g++ -g -o scta $^ -lmcheck -Bsymbolic -Xlinker -Map=output.map
	
#g++ -g -o scta $^ -lstdc++ -lmcheck -Bsymbolic -Xlinker -Map=output.map -Wl,--warn-common -Wl,--fatal-warnings -Wl,--whole-archive


clean:
	rm *.o mbedtls/*.o scta TexasInstruments/*.o
