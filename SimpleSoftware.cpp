#include <error.h>
#include <endian.h>
#include "scta.h"
extern "C" {
#include "Simple/des.h"
#include "Simple/aes.h"
}
#include "Trigger.h"
#include <stdio.h>


static void RaiseTrigger()
{
	trigger->Raise();	
}
static void LowerTrigger()
{
	trigger->Lower();
}
std::vector<uint_8> SimpleSoftwareImplementation::DoDES ( std::vector<uint_8> const& input2, std::vector<uint_8>const& key, FLAGS& flags )
{

    if (( flags & (ENCRYPT|DECRYPT)) == 0 )
	flags = (FLAGS)(flags | ENCRYPT );

    // Sanity checks
    if (( input2.size() % 8 ) != 0 )
	error ( 1, 0, "Invalid datalen(%i) in SimpleSoftwareImplementation::DoDES", (int)input2.size() );
	

   std::vector<uint_8> output ( input2.size() );
   if ( key.size() == 8 ) 
   {
   	BYTE schedule[16][6];
   	des_key_setup(key.data(), schedule, DES_ENCRYPT);
  
	if ( flags & TRIGGER_PER_ROUND )
	{
   		for ( int i = 0; i < output.size(); i+= 8 )
   			des_crypt_with_round_triggers(input2.data()+i, output.data()+i, schedule, RaiseTrigger, LowerTrigger);
	}
	else
	{
		trigger->Raise(); 
   		for ( int i = 0; i < output.size(); i+= 8 )
   			des_crypt(input2.data()+i, output.data()+i, schedule);
		trigger->Lower();
	}
   }
   else if ( key.size() == 24 )
   {
        BYTE three_schedule[3][16][6];
	three_des_key_setup ( key.data(), three_schedule, DES_ENCRYPT );

	if ( flags & TRIGGER_PER_ROUND )
	{	
   		for ( int i = 0; i < output.size(); i+= 8 )
   			three_des_crypt_with_round_triggers(input2.data()+i, output.data()+i, three_schedule, RaiseTrigger, LowerTrigger);
	}
	else
	{
		trigger->Raise(); 
   		for ( int i = 0; i < output.size(); i+= 8 )
   			three_des_crypt(input2.data()+i, output.data()+i, three_schedule);
		trigger->Lower(); 
	}
   }
   else
 	error_at_line ( 1, 0, __FILE__, __LINE__, "Unsupported key size %i", (int)key.size() );

   return output;
}

std::vector<uint_8> SimpleSoftwareImplementation::DoAES ( std::vector<uint_8>const& input, std::vector<uint_8> const& key, FLAGS& flags )
{
	std::vector<uint_8> output(input.size());
	trigger->Raise();
	if ( flags & TRIGGER_PER_ROUND )
		AES_ECB_encrypt_with_round_triggers ( input.data(), key.data(), output.data(), output.size(), RaiseTrigger, LowerTrigger );
	else
		AES_ECB_encrypt ( input.data(), key.data(), output.data(), output.size() );
	trigger->Lower();
	return output;
}
