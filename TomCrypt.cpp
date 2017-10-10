#include <error.h>
#include <endian.h>
#include "scta.h"
#include <stdio.h>
#define LTC_SOURCE
#include "tomcrypt.h"
//#include "tommath.h"
#include "Trigger.h"

std::vector<uint_8> TomCrypt::DoDES ( std::vector<uint_8>const&  input, std::vector<uint_8> const& key, FLAGS& flags )
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
		if ( flags & RUN_TWICE )
			des_ecb_encrypt ( output.data(), output.data(), &ks );

		for ( int offset=0; offset < input.size(); offset += 8 ) 
		{
			trigger->Raise();
			if ( des_ecb_encrypt ( input.data()+offset, output.data()+offset, &ks ) !=  0 )
				error_at_line ( 1, 0, __FILE__, __LINE__, "wc_Des_EcbEncrypt returned error" );
			trigger->Lower();
		}
	}

    	if ( key.size() == 16  || key.size() == 24 )
	{
		symmetric_key ks;
		if ( des3_setup ( key.data(), key.size(), 0, &ks ) != 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "wc_Des_SetKey returned error" );
		if ( flags & RUN_TWICE )
			des3_ecb_encrypt ( output.data(), output.data(), &ks );

		for ( int offset =0; offset < input.size(); offset += 8 ) 
		{
			trigger->Raise();
			if ( des3_ecb_encrypt ( input.data()+offset, output.data()+offset, &ks ) !=  0 )
				error_at_line ( 1, 0, __FILE__, __LINE__, "wc_Des_EcbEncrypt returned error" );
			trigger->Lower();
		}
	}
	return output;
}


std::vector<uint_8> TomCrypt::DoAES ( std::vector<uint_8> const& input, std::vector<uint_8> const& key, FLAGS& flags )
{
	if ( key.size() != 16 && key.size() != 24 && key.size() != 32)
                error_at_line ( 1, 0, __FILE__, __LINE__,  "Invalid key len");
        if (( input.size() % 16 ) != 0 )
                error (1, 0, "Data len not a multiple of 8" );

	symmetric_key ctx;
        if ( aes_setup( key.data(), key.size(), 10, &ctx ) != 0 )
                error_at_line ( 1, 0, __FILE__, __LINE__, "aes_setup returned error" );

	std::vector<uint_8> output (input.size());
	if ( flags & RUN_TWICE )
        	aes_ecb_encrypt ( input.data(), output.data(), &ctx );
	for ( int offset = 0; offset < input.size(); offset+=16 )
	{
		trigger->Raise();
        	if ( aes_ecb_encrypt ( input.data()+offset, output.data()+offset, &ctx ) != 0 )
               		error_at_line ( 1, 0, __FILE__, __LINE__, "bedtls_aes_crypt_ecb returned error" );
		trigger->Lower();
	}
	return output;

}

std::vector<uint_8> TomCrypt::DoRSA_ned ( std::vector<uint_8> const& input, std::vector<uint_8> & n, std::vector<uint_8> & e, std::vector<uint_8> & d, FLAGS& flags )
{
	std::string str_n = ToString ( n );
	std::string str_e = ToString ( e );
	std::string str_d = ToString ( d );
	rsa_key key;
	int rc;

	//ltc_mp = ltm_desc;
	ltc_mp = tfm_desc;
	
	if ( flags & (ENCRYPT | DECRYPT ) == 0 )
		flags = (FLAGS)(flags | DECRYPT );

//	mp_init ( (mp_int*)&key.N );
//	mp_init ( (mp_int*)&key.e );
//	mp_init ( (mp_int*)&key.d );

	//printf ( "before rsa_import_RADIX %s\n", str_n.c_str() ); 
	if ( flags & ENCRYPT )
		rc = rsa_import_radix ( 16, (char*)str_n.c_str(), (char*)str_e.c_str(), NULL, NULL, NULL, NULL, NULL, NULL, &key ); 
	else // hack private key decryption...
		rc = rsa_import_radix ( 16, (char*)str_n.c_str(), (char*)str_d.c_str(), NULL, NULL, NULL, NULL, NULL, NULL, &key ); 
	//printf ( "after rsa_import_RADIX\n" ); 
	if ( rc != CRYPT_OK )
		error_at_line (1, 0, __FILE__, __LINE__, "rsa_import_radix returned error %i", rc );
	
	std::vector<uint_8> output  (input.size());
	unsigned long outputlen = output.size();
	rc = rsa_exptmod ( input.data(), input.size(), output.data(), &outputlen, PK_PUBLIC, &key );
	if ( rc != CRYPT_OK )
		error_at_line (1,0,__FILE__,__LINE__, "rsa_exptmod returned error %i", rc );
	
	return output;
}
std::vector<uint_8> TomCrypt::DoRSA_epq ( std::vector<uint_8> const& input, std::vector<uint_8> & e, std::vector<uint_8> & p, std::vector<uint_8> & q, FLAGS& flags )
{
	rsa_key key;
	int rc;
	void* p_1, *q_1, *lcm;

	flags = (FLAGS)(flags | CRT );
	//ltc_mp = ltm_desc;
	ltc_mp = tfm_desc;

	rc = ltc_init_multi(&key.e, &key.d, &key.N, &key.dP, &key.dQ, &key.qP, &key.p, &key.q, &p_1, &q_1, &lcm, NULL );	
	if ( rc != CRYPT_OK )
		error_at_line(1,0,__FILE__,__LINE__, "mp_init_multi returned error %i", rc );

	if (( rc = mp_read_unsigned_bin(key.e, e.data(), e.size())) != CRYPT_OK ) { error_at_line(1,0,__FILE__,__LINE__, "mp_read_radix returned error %i", rc ); } 
	if (( rc = mp_read_unsigned_bin(key.p, p.data(), p.size())) != CRYPT_OK ) { error_at_line(1,0,__FILE__,__LINE__, "mp_read_radix returned error %i", rc ); }
	if (( rc = mp_read_unsigned_bin(key.q, q.data(), q.size())) != CRYPT_OK ) { error_at_line(1,0,__FILE__,__LINE__, "mp_read_radix returned error %i", rc ); }

	if (( rc = mp_mul(   key.p, key.q, key.N  )) != CRYPT_OK ) { error_at_line(1,0,__FILE__,__LINE__, "mp_mul returned error %i", rc ); }
	if (( rc = mp_sub_d (key.p, 1,     p_1    )) != CRYPT_OK ) { error_at_line(1,0,__FILE__,__LINE__, "mp_mul returned error %i", rc ); }
	if (( rc = mp_sub_d (key.q, 1,     q_1    )) != CRYPT_OK ) { error_at_line(1,0,__FILE__,__LINE__, "mp_mul returned error %i", rc ); }
	if (( rc = mp_lcm (  p_1,   q_1,   lcm    )) != CRYPT_OK ) { error_at_line(1,0,__FILE__,__LINE__, "mp_mul returned error %i", rc ); }
	if (( rc = mp_invmod(key.e, lcm,   key.d  )) != CRYPT_OK ) { error_at_line(1,0,__FILE__,__LINE__, "mp_invmod returned error" );}
	if (( rc = mp_mod (  key.d, p_1,   key.dP )) != CRYPT_OK ) { error_at_line(1,0,__FILE__,__LINE__, "mp_mod returned error" ); }
	if (( rc = mp_mod (  key.d, q_1,   key.dQ )) != CRYPT_OK ) { error_at_line(1,0,__FILE__,__LINE__, "mp_mod returned error" ); }
	if (( rc = mp_invmod(key.q, key.p, key.qP )) != CRYPT_OK ) { error_at_line(1,0,__FILE__,__LINE__, "mp_invmod returned error" ); }

	key.type = PK_PRIVATE;	

	std::vector<uint_8> output (input.size());
	unsigned long outputlen = output.size();

	if ( flags & RUN_TWICE )
	{
		output[0] = 0xFF;
		rsa_exptmod ( output.data(), output.size(), output.data(), &outputlen, PK_PRIVATE, &key );
	}

	trigger->Raise();
	rc = rsa_exptmod ( input.data(), input.size(), output.data(), &outputlen, PK_PRIVATE, &key );
	trigger->Lower();
	
	if ( rc != CRYPT_OK )
		error_at_line(1,0,__FILE__,__LINE__, "rsa_exptmod returned error %i", rc );

	//rc = mp_to_unsigned_bin ((mp_int*)key.dP, output.data() );
	//if ( rc != CRYPT_OK )
	//	error_at_line(1,0,__FILE__,__LINE__, "mp_to_unsigned_bin returned error %i", rc );
	
	mp_clear_multi(key.q, key.p, key.dP, key.dQ, key.N, key.d, key.e, q_1, p_1, lcm, NULL );
	return output;
}
