CC=gcc
CXX = g++
CFLAGS = -I. -g
CXXFLAGS = -I. -g

UNAME = $(shell /bin/uname -m)
ifeq ($(UNAME), x86_64)
	CXXFLAGS += -DTRIGGER=PRINT
endif


OBJS =  main.o 
OBJS += Simple/DES.o SimpleSoftware.o 
#OBJS += mbedtls/des.o MbedTLS.o mbedtls/aes.o mbedtls/rsa.o mbedtls/pk.o mbedtls/bignum.o mbedtls/md.o mbedtls/pk_wrap.o mbedtls/pkparse.o mbedtls/asn1parse.o mbedtls/oid.o mbedtls/pem.o mbedtls/base64.o
OBJS += MbedTLS.o mbedtls/mbedtls-2.4.2/library/libmbedcrypto.a
OBJS += TexasInstruments/TI_aes_128.o TexasInstruments/DES.o TexasInstruments.o
OBJS += openssl/aes_core.o openssl/des_enc.o openssl/ecb_enc.o openssl/ecb3_enc.o openssl/set_key.o openssl/aes_ecb.o OpenSSL.o 
OBJS += smartcard-aes-fw-master/inv_aes.o SmartCardAES.o

OBJS += KernelCrypto.o

INCLUDE_LIBGCRYPT = 0
ifdef INCLUDE_LIBGCRYPT
  GCRYPT_OBJS += LibGCrypt.o libgcrypt/lib/libgcrypt.so
$(GCRYPT_OBJS): CXXFLAGS += -Ilibgcrypt/libgcrypt-1.7.6/src/ 
  OBJS += $(GCRYPT_OBJS) 
  CFLAGS = $(CFLAGS) -Ilibgcrypt -Ilibgcrypt/src
endif

INCLUDE_WOLFSSL = 1
ifdef INCLUDE_WOLFSSL
 WOLFOBJS = wolfssl/wolfcrypt/aes.o wolfssl/wolfcrypt/des3.o wolfssl/wolfcrypt/rsa.o WolfCrypt.o wolfssl/wolfcrypt/integer.o wolfssl/wolfcrypt/memory.o wolfssl/wolfcrypt/hash.o wolfssl/wolfcrypt/md5.o wolfssl/wolfcrypt/sha.o wolfssl/wolfcrypt/sha256.o wolfssl/wolfcrypt/random.o wolfssl/wolfcrypt/integer.o
 $(WOLFOBJS): CFLAGS += -I. -Iwolfssl/wolfcrypt -Iwolfssl -DHAVE_CONFIG_H
 $(WOLFOBJS): CXXFLAGS += -I. -Iwolfssl/wolfcrypt -Iwolfssl -DHAVE_CONFIG_H
 OBJS += $(WOLFOBJS)
 main.o: CXXFLAGS += -DINCLUDE_WOLFSSL
endif


###' Rules specific for building TomCrypt
INCLUDE_TOMCRYPT = 1
ifdef INCLUDE_TOMCRYPT
 TOMOBJS = libtomcrypt/des.o libtomcrypt/aes.o libtomcrypt/crypt_argchk.o libtomcrypt/zeromem.o TomCrypt.o libtomcrypt/pk/rsa/rsa_import.o libtomcrypt/pk/rsa/multi.o libtomcrypt/pk/rsa/crypt_ltc_mp_descriptor.o libtomcrypt/pk/rsa/der_decode_subject_public_key_info.o libtomcrypt/pk/rsa/der_decode_sequence_multi.o libtomcrypt/pk/rsa/der_decode_sequence_ex.o libtomcrypt/pk/rsa/der_decode_boolean.o libtomcrypt/pk/rsa/der_decode_integer.o libtomcrypt/pk/rsa/der_decode_utf8_string.o libtomcrypt/pk/rsa/der_length_sequence.o libtomcrypt/pk/rsa/der_length_octet_string.o libtomcrypt/pk/rsa/der_length_boolean.o libtomcrypt/pk/rsa/der_length_integer.o libtomcrypt/pk/rsa/der_length_short_integer.o libtomcrypt/pk/rsa/der_decode_utctime.o libtomcrypt/pk/rsa/der_decode_short_integer.o libtomcrypt/pk/rsa/der_length_bit_string.o libtomcrypt/pk/rsa/der_decode_ia5_string.o libtomcrypt/pk/rsa/der_encode_ia5_string.o libtomcrypt/pk/rsa/der_length_ia5_string.o libtomcrypt/pk/rsa/der_encode_object_identifier.o libtomcrypt/pk/rsa/der_length_printable_string.o libtomcrypt/pk/rsa/der_decode_teletex_string.o libtomcrypt/pk/rsa/der_length_teletex_string.o libtomcrypt/pk/rsa/der_length_object_identifier.o libtomcrypt/pk/rsa/der_length_utctime.o libtomcrypt/pk/rsa/der_length_utf8_string.o libtomcrypt/pk/rsa/der_encode_generalizedtime.o libtomcrypt/pk/rsa/der_length_generalizedtime.o libtomcrypt/pk/rsa/der_decode_choice.o libtomcrypt/pk/rsa/der_decode_bit_string.o libtomcrypt/pk/rsa/der_decode_raw_bit_string.o libtomcrypt/pk/rsa/der_decode_octet_string.o libtomcrypt/pk/rsa/der_decode_object_identifier.o libtomcrypt/pk/rsa/der_decode_printable_string.o libtomcrypt/pk/rsa/der_decode_generalizedtime.o libtomcrypt/pk/rsa/pk_get_oid.o
 $(TOMOBJS): CFLAGS += -Ilibtomcrypt -D LTC_SOURCE
 $(TOMOBJS): CXXFLAGS += -Ilibtomcrypt
 OBJS += $(TOMOBJS)
 main.o: CXXFLAGS += -DINCLUDE_TOMCRYPT
endif

scta: $(OBJS)
	g++ -g -o scta $^ -lstdc++

clean:
	rm *.o mbedtls/*.o scta TexasInstruments/*.o
