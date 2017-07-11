#include <error.h>
#include <endian.h>
#include "scta.h"
//#include "DES.h"
#include <stdio.h>
#include <memory.h>
#include "Trigger.h"

extern "C" {
#include "smartcard-aes-fw-master/inv_aes.h"
}

std::vector<uint_8> SmartCardAES::DoDES ( std::vector<uint_8> const& input, std::vector<uint_8>const& key, FLAGS& flags )
{
	error_at_line ( 1, 0, __FILE__, __LINE__, "Not implemented" );
}


std::vector<uint_8> SmartCardAES::DoAES ( std::vector<uint_8>const& input, std::vector<uint_8>const& key, FLAGS& flags )
{
	if ( key.size() != 16 )
		error_at_line ( 1, 0, __FILE__, __LINE__,  "Invalid key len");
	if (( input.size() % 16 ) != 0 )
		error (1, 0, "Data len not a multiple of 16" );
	if ( flags & ENCRYPT )
		error_at_line ( 1, 0, __FILE__, __LINE__, "SmartCardAES doesn't support encryption, only decryption" );
	
	flags = (FLAGS)(flags | DECRYPT );

	std::vector<uint_8> output = input;
	
	for ( int offset = 0; offset < input.size(); offset+=16 )	
	{
		trigger->Raise();
		inv_aes128 ( output.data() + offset );
		trigger->Lower();
	}
	return output;
}
