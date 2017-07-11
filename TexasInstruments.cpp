#include <error.h>
#include <endian.h>
#include "scta.h"
//#include "DES.h"
#include <stdio.h>
#include <memory.h>
#include "Trigger.h"

extern "C" {
#include "TexasInstruments/TI_aes_128.h"
#include "TexasInstruments/DES.h"
}

std::vector<uint_8> TexasInstrumentsImplementation::DoDES ( std::vector<uint_8>const& input, std::vector<uint_8>const& key2, FLAGS& flags )
{
	std::vector<uint_8> key = key2;
	if ( key.size() != 8 && key.size() != 16 && key.size() != 24 )
		error_at_line ( 1, 0, __FILE__, __LINE__,  "Invalid key len");
	if (( input.size() % 8 ) != 0 )
		error (1, 0, "Data len not a multiple of 8" );

	std::vector<uint_8> output = input;
	des_ctx ctx;
	if ( key.size() == 8 )
	{
		Des_Key ( &ctx, key.data(), EN0 );
		trigger->Raise();
		Des_Enc ( &ctx, output.data(), output.size()/8 );
		trigger->Lower();
	}	
	else if ( key.size() == 16 || key.size() == 24 )
	{
		trigger->Raise();	
		TripleDES_ENC ( &ctx, output.data(), output.size()/8, key.data(), key.data()+8, key.data() + (key.size()==24?16:0) );
		trigger->Lower();
	}
	return output;
}


#define DIR_ENCRYPT 0
#define DIR_DECRYPT 1
std::vector<uint_8> TexasInstrumentsImplementation::DoAES ( std::vector<uint_8> const& input, std::vector<uint_8> const& key, FLAGS& flags )
{
	if ( key.size() != 16 )
		error_at_line ( 1, 0, __FILE__, __LINE__,  "Invalid key len");
	if (( input.size() % 16 ) != 0 )
		error (1, 0, "Data len not a multiple of 16" );
	
	uint_8 keycopy[16];
	std::vector<uint_8> output = input;
	memcpy ( keycopy, key.data(), sizeof(keycopy));

	for ( int offset = 0; offset < output.size(); offset+=16 )	
	{
		trigger->Raise();
		aes_enc_dec ( output.data()+offset, keycopy, DIR_ENCRYPT );
		trigger->Lower();
	}
	return output;
}
