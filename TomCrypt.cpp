#include <error.h>
#include <endian.h>
#include "scta.h"
#include <stdio.h>
#include "libtomcrypt/tomcrypt.h"
#include "Trigger.h"

std::vector<uint_8> TomCrypt::DoDES ( std::vector<uint_8>const&  input, std::vector<uint_8> const& key, FLAGS flags )
{
    // Sanity checks
    if (( input.size() % 8 ) != 0 )
	error_at_line ( 1, 0, __FILE__, __LINE__, "Invalid datalen(%i) in SimpleSoftwareImplementation::DoDES", (int)input.size() );
	
    if ( key.size() != 8 && key.size() != 16 && key.size() != 24)
	error_at_line ( 1, 0, __FILE__, __LINE__, "Invalid keylen(%i) in TomCrypt::DoDES", (int)key.size() );

	std::vector<uint_8> output(input.size());
    	if ( key.size() == 8 )
	{
		symmetric_key ks;
		if ( des_setup ( key.data(), key.size(), 16, &ks ) != 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "wc_Des_SetKey returned error" );
		for ( int offset=0; offset < input.size(); offset += 8 ) 
		{
			trigger.Raise();
			if ( des_ecb_encrypt ( input.data()+offset, output.data()+offset, &ks ) !=  0 )
				error_at_line ( 1, 0, __FILE__, __LINE__, "wc_Des_EcbEncrypt returned error" );
			trigger.Lower();
		}
	}

    	if ( key.size() == 16  || key.size() == 24 )
	{
		symmetric_key ks;
		if ( des3_setup ( key.data(), key.size(), 0, &ks ) != 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "wc_Des_SetKey returned error" );
		for ( int offset =0; offset < input.size(); offset += 8 ) 
		{
			trigger.Raise();
			if ( des3_ecb_encrypt ( input.data()+offset, output.data()+offset, &ks ) !=  0 )
				error_at_line ( 1, 0, __FILE__, __LINE__, "wc_Des_EcbEncrypt returned error" );
			trigger.Lower();
		}
	}
	return output;
}


std::vector<uint_8> TomCrypt::DoAES ( std::vector<uint_8> const& input, std::vector<uint_8> const& key, FLAGS flags )
{
	if ( key.size() != 16 && key.size() != 24 && key.size() != 32)
                error_at_line ( 1, 0, __FILE__, __LINE__,  "Invalid key len");
        if (( input.size() % 16 ) != 0 )
                error (1, 0, "Data len not a multiple of 8" );

	symmetric_key ctx;
        if ( aes_setup( key.data(), key.size(), 10, &ctx ) != 0 )
                error_at_line ( 1, 0, __FILE__, __LINE__, "aes_setup returned error" );

	std::vector<uint_8> output (input.size());
	for ( int offset = 0; offset < input.size(); offset+=16 )
	{
		trigger.Raise();
        	if ( aes_ecb_encrypt ( input.data()+offset, output.data()+offset, &ctx ) != 0 )
               		error_at_line ( 1, 0, __FILE__, __LINE__, "bedtls_aes_crypt_ecb returned error" );
		trigger.Lower();
	}
	return output;

}
