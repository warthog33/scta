#include <error.h>
#include <endian.h>
#include "scta.h"
//#include "DES.h"
#include <stdio.h>
#include <memory.h>
#include "Trigger.h"
#include <errno.h>

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

	unsigned int seed;

	FILE* f = fopen("/dev/random", "rb" );
	if ( f == NULL )
		error_at_line(1,0,__FILE__,__LINE__, "unable to open /dev/random errno=%i", errno );
	if ( fread ( &seed, sizeof(seed), 1, f) != 1)
		error_at_line(1,0,__FILE__,__LINE__, "unable to read from /dev/random" );	
	fclose (f);

	srand (seed);
	std::vector<uint_8> output = input;

	if ( flags & RUN_TWICE )
	{
		unsigned char zeros[16] = { 0 };
		inv_aes128 ( zeros ); 
	}

	
	for ( int offset = 0; offset < input.size(); offset+=16 )	
	{
		trigger->Raise();
		inv_aes128 ( output.data() + offset );
		trigger->Lower();
	}
	return output;
}
