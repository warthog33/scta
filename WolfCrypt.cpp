#include <error.h>
#include <endian.h>
#include "scta.h"
#include "Trigger.h"
#include <stdio.h>
#include "wolfssl/wolfcrypt/des3.h"
#define HAVE_AES_ECB
#include "wolfssl/wolfcrypt/aes.h"

std::vector<uint_8> WolfCrypt::DoDES ( std::vector<uint_8> const& input, std::vector<uint_8> const& key, FLAGS flags )
{
    // Sanity checks
    if (( input.size() % 8 ) != 0 )
	error_at_line ( 1, 0, __FILE__, __LINE__, "Invalid datalen(%i) in WolfCrypt::DoDES", (int)input.size() );
	
    if ( key.size() != 8 && key.size() != 16 && key.size() != 24)
	error_at_line ( 1, 0, __FILE__, __LINE__, "Invalid keylen(%i) in WolfCrypt::DoDES", (int)key.size() );

	std::vector<uint_8> output ( input.size());
    	if ( key.size() == 8 )
	{
		Des ks;
		if ( wc_Des_SetKey ( &ks, key.data(), NULL, DES_ENCRYPTION ) != 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "wc_Des_SetKey returned error" );
		trigger.Raise();
		if ( wc_Des_EcbEncrypt ( &ks, output.data(), input.data(), input.size() ) !=  0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "wc_Des_EcbEncrypt returned error" );
		trigger.Lower();
	}

    	if ( key.size() == 16  )
	{
		Des3 ks;
		uint_8 keycopy [24];
		memcpy (keycopy, key.data(), 16);
		memcpy (keycopy+16, key.data(), 8 );
		if ( wc_Des3_SetKey ( &ks, keycopy, NULL, DES_ENCRYPTION ) != 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "wc_Des_SetKey returned error" );
		trigger.Raise();
		if ( wc_Des3_EcbEncrypt ( &ks, output.data(), input.data(), input.size() ) !=  0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "wc_Des_EcbEncrypt returned error" );
		trigger.Lower();
	}
    	if ( key.size() == 24 )
	{
		Des3 ks;
		if ( wc_Des3_SetKey ( &ks, key.data(), NULL, DES_ENCRYPTION ) != 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "wc_Des_SetKey returned error" );
		trigger.Raise();
		if ( wc_Des3_EcbEncrypt ( &ks, output.data(), input.data(), input.size() ) !=  0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "wc_Des_EcbEncrypt returned error" );
		trigger.Lower();
	}
	return output;
}


std::vector<uint_8> WolfCrypt::DoAES ( std::vector<uint_8>const& input, std::vector<uint_8> const& key, FLAGS flags )
{
	if ( key.size() != 16 && key.size() != 24 && key.size() != 32)
                error_at_line ( 1, 0, __FILE__, __LINE__,  "Invalid key len");
        if (( input.size() % 16 ) != 0 )
                error (1, 0, "Data len not a multiple of 8" );

	Aes ctx;	
        if ( wc_AesSetKey(&ctx, key.data(), key.size(), NULL, AES_ENCRYPTION ) != 0 )
                error_at_line ( 1, 0, __FILE__, __LINE__, "wc_AesSetKey returned error" );

	std::vector<uint_8> output(input.size());
	trigger.Raise();
        if ( wc_AesEcbEncrypt ( &ctx, output.data(), input.data(), input.size() ) != 0 )
                error_at_line ( 1, 0, __FILE__, __LINE__, "mbedtls_aes_crypt_ecb returned error" );
	trigger.Lower();
	return output;
}
