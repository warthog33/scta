#include <error.h> 
#include <endian.h>
#include "scta.h"
#include "Trigger.h"
#include <stdio.h>
//#define HAVE_AES_ECB
//#define HAVE_AES_GCM
//#define WOLFSSL_AES_DIRECT
//#define WOLFSSL_AES_COUNTER
#include "wolfcrypt/aes.h"
#include "wolfcrypt/des3.h"
#include "wolfcrypt/rsa.h"

std::vector<uint_8> WolfCrypt::DoDES ( std::vector<uint_8> const& input, std::vector<uint_8> const& key, FLAGS& flags )
{
    // Sanity checks
    if (( input.size() % 8 ) != 0 )
	error_at_line ( 1, 0, __FILE__, __LINE__, "Invalid datalen(%i) in WolfCrypt::DoDES", (int)input.size() );
	
    if ( key.size() != 8 && key.size() != 16 && key.size() != 24)
	error_at_line ( 1, 0, __FILE__, __LINE__, "Invalid keylen(%i) in WolfCrypt::DoDES", (int)key.size() );

	std::vector<uint_8> output ( input.size());
    	if ( key.size() == 8 )
	{
		Des ks;
		if ( wc_Des_SetKey ( &ks, key.data(), NULL, DES_ENCRYPTION ) != 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "wc_Des_SetKey returned error" );
		trigger->Raise();
		if ( wc_Des_EcbEncrypt ( &ks, output.data(), input.data(), input.size() ) !=  0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "wc_Des_EcbEncrypt returned error" );
		trigger->Lower();
	}

    	if ( key.size() == 16  )
	{
		Des3 ks;
		uint_8 keycopy [24];
		memcpy (keycopy, key.data(), 16);
		memcpy (keycopy+16, key.data(), 8 );
		if ( wc_Des3_SetKey ( &ks, keycopy, NULL, DES_ENCRYPTION ) != 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "wc_Des_SetKey returned error" );
		trigger->Raise();
		if ( wc_Des3_EcbEncrypt ( &ks, output.data(), input.data(), input.size() ) !=  0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "wc_Des_EcbEncrypt returned error" );
		trigger->Lower();
	}
    	if ( key.size() == 24 )
	{
		Des3 ks;
		if ( wc_Des3_SetKey ( &ks, key.data(), NULL, DES_ENCRYPTION ) != 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "wc_Des_SetKey returned error" );
		trigger->Raise();
		if ( wc_Des3_EcbEncrypt ( &ks, output.data(), input.data(), input.size() ) !=  0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "wc_Des_EcbEncrypt returned error" );
		trigger->Lower();
	}
	return output;
}

std::vector<uint_8> WolfCrypt::DoAES ( std::vector<uint_8>const& input, std::vector<uint_8> const& key, FLAGS& flags )
{
	if ( key.size() != 16 && key.size() != 24 && key.size() != 32)
                error_at_line ( 1, 0, __FILE__, __LINE__,  "Invalid key len");
        if (( input.size() % 16 ) != 0 )
                error (1, 0, "Data len not a multiple of 8" );

	Aes ctx;	

	//printf ( "sizeof(Aes)=%i\r\n", (int)sizeof(ctx));
        if ( wc_AesSetKey(&ctx, key.data(), key.size(), key.data(), AES_ENCRYPTION ) != 0 )
                error_at_line ( 1, 0, __FILE__, __LINE__, "wc_AesSetKey returned error" );

	std::vector<uint_8> output(input.size());
	trigger->Raise();
        if ( wc_AesEcbEncrypt ( &ctx, output.data(), input.data(), input.size() ) != 0 )
                error_at_line ( 1, 0, __FILE__, __LINE__, "mbedtls_aes_crypt_ecb returned error" );
	trigger->Lower();
	return output;
}
static std::vector<uint_8> WolfCryptDoRSA ( std::vector<uint_8> const& input, RsaKey& key, FLAGS flags )
{
	RNG rng;
	std::vector<uint_8> output (wc_RsaEncryptSize(&key));
	int rc;

	rc =  wc_InitRng (&rng );
	if ( rc != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "wc_InitRng error" );

	//rc = wc_RsaPublicEncrypt(input.data(), input.size()/2, output.data(), output.size(), &rsakey, &rng);
	word32 outlen = output.size();

	if ( flags & RUN_TWICE )
		wc_RsaFunction ( input.data(), input.size(), output.data(), &outlen, flags & ENCRYPT ? RSA_PUBLIC_ENCRYPT : RSA_PRIVATE_DECRYPT, &key, &rng); 

	trigger->Raise();
	rc = wc_RsaFunction ( input.data(), input.size(), output.data(), &outlen, flags & ENCRYPT ? RSA_PUBLIC_ENCRYPT : RSA_PRIVATE_DECRYPT, &key, &rng); 
	trigger->Lower();
	if ( rc < 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "wc_RsaFunction returned error %i", rc );
	
	return output;
}

std::vector<uint_8> WolfCrypt::DoRSA_ned ( std::vector<uint_8> const& input, std::vector<uint_8>& n, std::vector<uint_8>& e, std::vector<uint_8>& d, FLAGS& flags )
{
	RsaKey rsakey;
	int rc;

	rc = wc_InitRsaKey ( &rsakey, NULL );
	if ( rc != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "wc_InitRsaKey returned error" );

	rc = wc_RsaPublicKeyDecodeRaw(n.data(), n.size(), (flags & ENCRYPT) ? e.data() : d.data(), (flags & ENCRYPT) ? e.size() : d.size(), &rsakey);
	if ( rc != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "wc_RsaPublicKeyDecodeRaw returned error %i", rc );
	
	// Add in private components of RSA key ....
	//if ( mp_read_unsigned_bin(&rsakey.d, d.data(), d.size()) != 0 )
	//	error_at_line ( 1, 0, __FILE__, __LINE__, "unable to import d" );

	return WolfCryptDoRSA ( input, rsakey, flags );
}


std::vector<uint_8> WolfCrypt::DoRSA_epq ( std::vector<uint_8> const& input, std::vector<uint_8>& e, std::vector<uint_8>& p, std::vector<uint_8>& q, FLAGS& flags )
{
	RsaKey key;
	mp_int p_1, q_1, lcm;
	int rc;
	RNG rng;

	if (( flags & ( ENCRYPT | DECRYPT )) == 0 )
		flags = (FLAGS)(flags | DECRYPT );	
	if ( flags & DECRYPT )
		flags = (FLAGS)(flags | CRT );

	if (( rc = wc_InitRng (&rng )) != 0 ) { error_at_line ( 1, 0, __FILE__, __LINE__, "wc_InitRng error" ); }
	if (( rc = wc_InitRsaKey ( &key, NULL )) != 0 ) { error_at_line ( 1, 0, __FILE__, __LINE__, "wc_InitRsaKey returned error" ); }

	if (( rc = mp_init_multi( &key.n,  &key.e,  &key.d, &key.p, &key.q, NULL )) != 0 ) { error_at_line (1, 0, __FILE__, __LINE__, "mp_init_multi returned error%i", rc ); }
	if (( rc = mp_init_multi( &key.dP, &key.dQ, &key.u, &p_1,   &q_1,   &lcm )) != 0 ) { error_at_line (1, 0, __FILE__, __LINE__, "mp_init_multi returned error%i", rc ); }

	if (( rc = mp_read_unsigned_bin(&key.e, e.data(), e.size())) != 0 ) { error_at_line(1,0,__FILE__,__LINE__, "mp_read_radix returned error %i", rc ); }
        if (( rc = mp_read_unsigned_bin(&key.p, p.data(), p.size())) != 0 ) { error_at_line(1,0,__FILE__,__LINE__, "mp_read_radix returned error %i", rc ); }
	if (( rc = mp_read_unsigned_bin(&key.q, q.data(), q.size())) != 0 ) { error_at_line(1,0,__FILE__,__LINE__, "mp_read_radix returned error %i", rc ); }

        if (( rc = mp_sub_d (&key.p, 1,     &p_1    )) != 0 ) { error_at_line(1,0,__FILE__,__LINE__, "mp_mul returned error %i", rc ); }
        if (( rc = mp_sub_d (&key.q, 1,     &q_1    )) != 0 ) { error_at_line(1,0,__FILE__,__LINE__, "mp_mul returned error %i", rc ); }
        if (( rc = mp_lcm (  &q_1,   &p_1,  &lcm    )) != 0 ) { error_at_line(1,0,__FILE__,__LINE__, "mp_mul returned error %i", rc ); }
        if (( rc = mp_invmod(&key.e, &lcm,  &key.d  )) != 0 ) { error_at_line(1,0,__FILE__,__LINE__, "mp_invmod returned error" );}
        if (( rc = mp_mul (  &key.p, &key.q, &key.n )) != 0 ) { error_at_line(1,0,__FILE__,__LINE__, "mp_mul returned error %i", rc ); }
        if (( rc = mp_mod (  &key.d, &p_1,   &key.dP )) != 0 ) { error_at_line(1,0,__FILE__,__LINE__, "mp_mod returned error" ); }
        if (( rc = mp_mod (  &key.d, &q_1,   &key.dQ )) != 0 ) { error_at_line(1,0,__FILE__,__LINE__, "mp_mod returned error" ); }
        if (( rc = mp_invmod(&key.q, &key.p, &key.u  )) != 0 ) { error_at_line(1,0,__FILE__,__LINE__, "mp_invmod returned error" ); }
	
	key.type = RSA_PRIVATE;
	return WolfCryptDoRSA ( input, key, flags);
}

