#include <error.h>
#include <endian.h>
#include "scta.h"
//#include "DES.h"
#include <stdio.h>
#include "Trigger.h"

#include "mbedtls/des.h"
#include "mbedtls/aes.h"

std::vector<uint_8> MbedTLSImplementation::DoDES ( std::vector<uint_8> const& input, std::vector<uint_8> const& key, FLAGS flags )
{
	if ( key.size() != 8 && key.size() != 16 && key.size() != 24 )
		error_at_line ( 1, 0, __FILE__, __LINE__,  "Invalid key len");
	if (( input.size() % 8 ) != 0 )
		error (1, 0, "Data len not a multiple of 8" );

	std::vector<uint_8> output ( input.size());
	if ( key.size() == 8 )
	{
		mbedtls_des_context ctx;
		mbedtls_des_init ( &ctx );
	
		if ( mbedtls_des_setkey_enc ( &ctx, key.data() ) != 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "mbedtls_des_setkey_enc returned error " );
	
		for ( int offset = 0; offset < input.size(); offset+=8 )	
		{
			trigger.Raise();
			if ( mbedtls_des_crypt_ecb ( &ctx, input.data()+offset, output.data()+offset ) != 0 )
				error_at_line ( 1, 0, __FILE__, __LINE__, "mbedtls_des_crypt_ecb returned error" );	
			trigger.Lower();
		}
	}	
	else if ( key.size() == 16 || key.size() == 24 )
	{	
		mbedtls_des3_context ctx;
		mbedtls_des3_init ( &ctx );
	
		if ( (key.size() == 16 ? mbedtls_des3_set2key_enc : mbedtls_des3_set3key_enc)(&ctx, key.data() ) != 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "mbedtls_des3_set2/3key_enc returned error" );
			
		for ( int offset = 0; offset < input.size();  offset+=8 )	
		{
			trigger.Raise();
			if ( mbedtls_des3_crypt_ecb ( &ctx, input.data()+offset, output.data()+offset ) != 0 )
				error_at_line ( 1, 0, __FILE__, __LINE__, "mbedtls_des3_crypt_ecb returned error" );	
			trigger.Lower();
		}
	}
	return output;
}


std::vector<uint_8> MbedTLSImplementation::DoAES ( std::vector<uint_8>const& input, std::vector<uint_8>const& key, FLAGS flags )
{
	if ( key.size() != 16 && key.size() != 24 && key.size() != 32)
		error_at_line ( 1, 0, __FILE__, __LINE__,  "Invalid key len");
	if (( input.size() % 16 ) != 0 )
		error (1, 0, "Data len not a multiple of 8" );

	std::vector<uint_8> output(input.size());

	mbedtls_aes_context ctx;
	mbedtls_aes_init ( &ctx );
	
	if ( mbedtls_aes_setkey_enc(&ctx, key.data(), key.size() * 8 ) != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "mbedtls_aes_setkey_enc returned error" );
			
	for ( int offset = 0; offset < input.size(); offset+=16 )	
	{
		trigger.Raise();
		if ( mbedtls_aes_crypt_ecb ( &ctx, MBEDTLS_AES_ENCRYPT, input.data()+offset, output.data()+offset ) != 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "mbedtls_aes_crypt_ecb returned error" );	
		trigger.Lower();
	}
	return output;
}
