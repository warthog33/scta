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
/*
    // Sanity checks
    if (( input2.size() % 8 ) != 0 )
	error ( 1, 0, "Invalid datalen(%i) in SimpleSoftwareImplementation::DoDES", (int)input2.size() );
	
    if ( key.size() != 8 )
	error ( 1, 0, "Invalid keylen(%i) in SimpleSoftwareImplementation::DoDES", (int)key.size() );

    //
    // Get the 16 subkeys
    //

    uint64_t a_key[16];
    a_key[0] = be64toh(*(uint64_t*)key.data());
    uint64_t next_key;

    for(int ii = 0; ii < 16; ii++)
    {
        key_schedule(&a_key[ii], &next_key, ii);
        if(ii != 15)
            a_key[ii + 1] = next_key;
    }

    std::vector<uint_8> output2 ( input2.size() );

   int datalen = input2.size();
   uint_8 const * input = input2.data();
   uint_8* output = output2.data();
    //
    // 16 Rounds of enc/decryption
    //

    for( ; datalen > 0 ; datalen -=8, input +=8, output+=8  )
    {
    	uint64_t data = be64toh(*(uint64_t*)input);
    printf ( "Input=%016lx\n", data );

	trigger->Raise();

        // Initial permutation
        Permutation(&data, true);

        // Encrypt rounds
        if( flags & ENCRYPT )
        {
            for(int ii = 0; ii < 16; ii++)
	    {
                rounds(&data, a_key[ii]);
    	        printf ( "Encrypt Round %2i Output=%016lx Key=%016lx\n", ii+1, data, a_key[ii] );
            }
        }
        // Decrypt rounds
        else
        {
            // Switching blocks
            data = (data << 32) + (data >> 32);

            for(int ii = 15; ii >= 0; ii--)
	    {
                rounds(&data, a_key[ii]);
    	        printf ( "Decrypt Round %2i Output=%016lx\n", ii+1, data );
	    }
            
            // Switching blocks back
            data = (data << 32) + (data >> 32);
        }

        // Final permutation
        Permutation(&data, false);
	
	trigger->Lower();

        // Write output
    	*(uint64_t*)output = htobe64(data);
    }
*/


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
