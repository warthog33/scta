#include <error.h>
#include <endian.h>
#include "scta.h"
#include <stdio.h>
#include "openssl/des.h"
#include "openssl/aes.h"
#include "Trigger.h"
std::vector<uint_8> OpenSSL::DoDES ( std::vector<uint_8> const& input, std::vector<uint_8> const& key, FLAGS& flags )
{
	if (( input.size() % 8 ) != 0 )
		error (1, 0, "Data len not a multiple of 8" );
	if (( flags & ( ENCRYPT | DECRYPT )) == 0 )
		flags = (FLAGS)( flags | ENCRYPT );

	std::vector<uint_8> output(input.size());
	if ( key.size() == 8 )
	{
		DES_key_schedule ks;
		DES_set_key_unchecked ( (const_DES_cblock*)key.data(), &ks );
			
		for ( int offset = 0; offset < input.size(); offset+=8 )	
		{
			trigger->Raise();
			DES_ecb_encrypt( (const_DES_cblock*)(input.data()+offset), (DES_cblock*)(output.data()+offset), &ks, DES_ENCRYPT );
			trigger->Lower();
		}
	}	
	else if ( key.size() == 16 || key.size() == 24 )
	{	
		DES_key_schedule ks1, ks2, ks3;
		
		DES_set_key_unchecked ( (const_DES_cblock*)key.data(), &ks1 );
		DES_set_key_unchecked ( (const_DES_cblock*)(key.data()+8), &ks2 );
		DES_set_key_unchecked ( (const_DES_cblock*)(key.data()+(key.size()==16?0:16)), &ks3 );
			
		for ( int offset = 0; offset < input.size(); offset+=8 )	
		{
			trigger->Raise();
			DES_ecb3_encrypt ( (const_DES_cblock*)(input.data() + offset), (DES_cblock*)(output.data() + offset), &ks1, &ks2, &ks3, DES_ENCRYPT );
			trigger->Lower();
		}
	}
	else
	{
		error_at_line ( 1, 0, __FILE__, __LINE__,  "Invalid key len");
	}
	return output;
}


std::vector<uint_8> OpenSSL::DoAES ( std::vector<uint_8> const& input, std::vector<uint_8> const& key, FLAGS& flags )
{
	if (( input.size() % 16 ) != 0 )
		error (1, 0, "Data len not a multiple of 8" );

	if (( flags & ( ENCRYPT | DECRYPT )) == 0 )
		flags = (FLAGS)( flags | ENCRYPT );

	std::vector<uint_8> output(input.size());
	AES_KEY ks;	
	if ( AES_set_encrypt_key(key.data(), key.size()*8, &ks ) != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "AES_set_encrypt_key returned error" );
			
	for ( int offset = 0; offset < input.size(); offset+=16 )	
	{
		trigger->Raise();
		AES_ecb_encrypt ( input.data()+offset, output.data()+offset, &ks, AES_ENCRYPT );
		trigger->Lower();
	}
	return output;
}

extern "C" {
int BIO_snprintf(char* buf, size_t n, const char* format, va_list args )
{
	error_at_line ( 1, 0, __FILE__, __LINE__,  "BIO_snprintf called");
}
}
	
