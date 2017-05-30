#include <error.h>
#include <endian.h>
#include "scta.h"
#include "Simple/DES.h"
#include "Trigger.h"
#include <stdio.h>

std::vector<uint_8> SimpleSoftwareImplementation::DoDES ( std::vector<uint_8> const& input2, std::vector<uint_8>const& key, FLAGS flags )
{
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

	trigger.Raise();

        // Initial permutation
        Permutation(&data, true);

        // Encrypt rounds
        if( flags & ENCRYPT )
        {
            for(int ii = 0; ii < 16; ii++)
                rounds(&data, a_key[ii]);
        }
        // Decrypt rounds
        else
        {
            // Switching blocks
            data = (data << 32) + (data >> 32);

            for(int ii = 15; ii >= 0; ii--)
                rounds(&data, a_key[ii]);
            
            // Switching blocks back
            data = (data << 32) + (data >> 32);
        }

        // Final permutation
        Permutation(&data, false);
	
	trigger.Lower();

        // Write output
    	*(uint64_t*)output = htobe64(data);
    }
   return output2;

}


std::vector<uint_8> SimpleSoftwareImplementation::DoAES ( std::vector<uint_8>const& input, std::vector<uint_8> const& key, FLAGS flags )
{
}
