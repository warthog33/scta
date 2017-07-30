#include <error.h>
#include <endian.h>
#include <stdlib.h>
#include "scta.h"
//#include "DES.h"
#include <stdio.h>
#include "Trigger.h"

#include "gcrypt.h"
//#include "mpi.h"

std::vector<uint_8> LibGCrypt::DoSymmetric ( const char* name, std::vector<uint_8> const& input, std::vector<uint_8> const& key_in, FLAGS& flags )
{
	int cipher = 0;
	std::vector<uint_8> key = key_in;
	if ( strcasecmp ( name, "DES" ) == 0 )
	{
		if ( key.size() == 8 )
			cipher = GCRY_CIPHER_DES;
		else if ( key.size() == 16 )
		{
			key.insert ( key.end(), key.data(), key.data()+8 );
			cipher = GCRY_CIPHER_3DES;
		}
		else if ( key.size() == 24 )
			cipher = GCRY_CIPHER_3DES;
		else
			error_at_line ( 1, 0, __FILE__, __LINE__,  "Invalid key len");
	}
	else if ( strcasecmp ( name, "AES" ) == 0 )
	{
		cipher = GCRY_CIPHER_AES;
	}
	else
		error_at_line ( 1, 0, __FILE__, __LINE__, "Unknown algorithm type %s\n", name );

	gcry_error_t rc;
	gcry_cipher_hd_t hdt;
	rc = gcry_cipher_open ( &hdt, cipher, GCRY_CIPHER_MODE_ECB, 0 );
	if (rc != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "gcry_cipher_open returned %i", rc );
	
	rc = gcry_cipher_setkey ( hdt, key.data(), key.size() );
	if (rc != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "gcry_cipher_setkey returned %x", rc );

	std::vector<uint_8> output ( input.size());
	if (( flags & ( ENCRYPT | DECRYPT )) == 0  ) 
		flags = (FLAGS)(flags | ENCRYPT);

	if ( flags & RUN_TWICE )	
		rc = (flags & ENCRYPT ? gcry_cipher_encrypt : gcry_cipher_decrypt ) ( hdt, output.data(), output.size(), output.data(), output.size() );	

	trigger->Raise();
	rc = (flags & ENCRYPT ? gcry_cipher_encrypt : gcry_cipher_decrypt ) ( hdt, output.data(), output.size(), input.data(), input.size() );	
	trigger->Lower();

	
	if (rc != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "gcry_cipher_encrypt returned %i", rc );

	gcry_cipher_close ( hdt );
	return output;
}


static std::vector<uint_8> DoRSA2 ( std::vector<uint_8>const& input, gcry_sexp_t rsa_key, FLAGS& flags )
{
	unsigned char* buffer = NULL;
	size_t buflen = 0;
	size_t scanned = 0;
	gcry_mpi_t mpi_i;
	gcry_error_t rc;

	rc = gcry_mpi_scan ( &mpi_i, GCRYMPI_FMT_USG, input.data(), input.size(), &scanned );
	if ( rc ) {
        	error_at_line( 1, 0, __FILE__, __LINE__, "failed to create a mpi from the message");
	}

	gcry_sexp_t input_parms;
	rc = gcry_sexp_build(&input_parms, NULL, flags & ENCRYPT ? "(data (flags raw) (value %m))" : "(enc-val(rsa(a %m)))", mpi_i);
	if ( rc != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "gcry_sexp_build returned error" );
	gcry_sexp_t output_parms;

	if ( flags & RUN_TWICE )	
		(flags & ENCRYPT ? gcry_pk_encrypt : gcry_pk_decrypt) ( &output_parms, input_parms, rsa_key ); 

	trigger->Raise();
	rc = (flags & ENCRYPT ? gcry_pk_encrypt : gcry_pk_decrypt) ( &output_parms, input_parms, rsa_key ); 
	trigger->Lower();

	if ( rc != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "gcry_pk_encrypt/gry_pk_decrypt returned error %x", rc );

	gcry_mpi_t mpi_a;
	if ( flags & ENCRYPT ) {
		if ( gcry_sexp_extract_param ( output_parms, NULL, "a", &mpi_a, NULL ) != 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "gcry_sexp_extract_param" );
	} else {
		mpi_a = gcry_sexp_nth_mpi ( output_parms, 0, GCRYMPI_FMT_USG );
		if ( mpi_a == NULL )
			error_at_line (1, 0, __FILE__, __LINE__, "gcry_sexp_nth_mpi error" ); 
	}	

	if ( gcry_mpi_aprint ( GCRYMPI_FMT_USG, &buffer, &buflen, mpi_a ) != 0 ) {error_at_line ( 1, 0, __FILE__, __LINE__, "gcry_mpi_aprint" ); }

	std::vector<uint_8> output(buffer, buffer+buflen);
	return output;
}

std::vector<uint_8> LibGCrypt::DoRSA_KeyGen ( std::vector<uint_8>const& input, int numbits, FLAGS& flags )
{
	gcry_sexp_t rsa_parms;
	gcry_sexp_t rsa_key;	

	printf ( "numbits=%i\n", numbits );
	gcry_error_t rc = gcry_sexp_build(&rsa_parms, NULL, "(genkey (rsa (nbits %d)))", numbits);	
	if ( rc != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "gcry_sexpt_t returned error" );

	printf ( "GenKey...\n" );
	rc = gcry_pk_genkey ( &rsa_key, rsa_parms ); 
	if ( rc != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "gcry_pk_genkey returned error" );
	printf ( "End GenKey...\n" );
	
	gcry_mpi_t mpi_n, mpi_e, mpi_d, mpi_p, mpi_q, mpi_u;
	if ( gcry_sexp_extract_param ( rsa_key, NULL, "nedpqu", &mpi_n, &mpi_e, &mpi_d, &mpi_p, &mpi_q, &mpi_u, NULL ) != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "gcry_sexp_extract_param" );

	gcry_mpi_dump(mpi_n);
	printf( " :n\n" );
	gcry_mpi_dump(mpi_e);
	printf( " :e\n" );
	gcry_mpi_dump(mpi_d);
	printf( " :d\n" );
	gcry_mpi_dump(mpi_p);
	printf( " :p\n" );
	gcry_mpi_dump(mpi_q);
	printf( " :q\n" );
	gcry_mpi_dump(mpi_u);
	printf( " :u\n" );
/*
	n.resize(numbits/8+1);
	if (  gcry_mpi_print ( GCRYMPI_FMT_USG, n.data(), n.size(), &buflen, mpi_n ) != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "gcry_mpi_print" );
	n.resize(buflen);
	
	e.resize(numbits/8+1);	
	if (  gcry_mpi_print ( GCRYMPI_FMT_USG, e.data(), e.size(), &buflen, mpi_e ) != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "gcry_mpi_print" );
	e.resize(buflen);

	d.resize(numbits/8+1);	
	if (  gcry_mpi_print ( GCRYMPI_FMT_USG, d.data(), d.size(), &buflen, mpi_d ) != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "gcry_mpi_print" );
	d.resize(buflen);
*/
	return DoRSA2 ( input, rsa_key, flags ); 
}

std::vector<uint_8> LibGCrypt::DoRSA_ned ( std::vector<uint_8>const& input, std::vector<uint_8> & n, std::vector<uint_8>& e, std::vector<uint_8>& d, FLAGS& flags )
{
	gcry_error_t rc;
	gcry_sexp_t rsa_key;	
	size_t buflen = 0;

	if ( flags & ( ENCRYPT | DECRYPT ) == 0 )
		flags = (FLAGS)(flags | ENCRYPT );
	
   	gcry_mpi_t mpi_n, mpi_e, mpi_d;
	if ((rc = gcry_mpi_scan ( &mpi_n, GCRYMPI_FMT_USG, n.data(), n.size(), NULL ))!=0) { error_at_line( 1, 0, __FILE__, __LINE__, "failed to create a mpi from the message"); }
	if ((rc = gcry_mpi_scan ( &mpi_e, GCRYMPI_FMT_USG, e.data(), e.size(), NULL ))!=0) { error_at_line( 1, 0, __FILE__, __LINE__, "failed to create a mpi from the message"); }
	if ((rc = gcry_mpi_scan ( &mpi_d, GCRYMPI_FMT_USG, d.data(), d.size(), NULL ))!=0) { error_at_line( 1, 0, __FILE__, __LINE__, "failed to create a mpi from the message"); }
	if ((rc = gcry_sexp_build(&rsa_key, NULL, "(private-key (rsa (n %m) (e %m) (d %m)))", mpi_n, mpi_e, mpi_d)) != 0 ) 
		error_at_line ( 1, 0, __FILE__, __LINE__, "gcry_sexp_build returned error" );

	mpi_release ( mpi_n);
	mpi_release ( mpi_e );
	mpi_release ( mpi_d );

	return DoRSA2 ( input, rsa_key, flags );
}

std::vector<uint_8> LibGCrypt::DoRSA_epq ( std::vector<uint_8>const& input, std::vector<uint_8>& e, std::vector<uint_8>& p, std::vector<uint_8>& q, FLAGS& flags )
{
	gcry_error_t rc;
	gcry_mpi_t mpi_n, mpi_e, mpi_d, mpi_p, mpi_q, mpi_phi, mpi_g, mpi_f, mpi_u, mpi_t1, mpi_t2;

	if ( flags & DECRYPT )
		flags = (FLAGS)(flags | CRT );

	if ((rc = gcry_mpi_scan ( &mpi_e, GCRYMPI_FMT_USG, e.data(), e.size(), NULL )) != 0 )  { error_at_line( 1, 0, __FILE__, __LINE__, "failed to create a mpi from the message"); }
	if ((rc = gcry_mpi_scan ( &mpi_p, GCRYMPI_FMT_USG, p.data(), p.size(), NULL )) != 0 )  { error_at_line( 1, 0, __FILE__, __LINE__, "failed to create a mpi from the message"); }
	if ((rc = gcry_mpi_scan ( &mpi_q, GCRYMPI_FMT_USG, q.data(), q.size(), NULL )) != 0 )  { error_at_line( 1, 0, __FILE__, __LINE__, "failed to create a mpi from the message"); }
	
	int nbits = mpi_get_nbits(mpi_p) + mpi_get_nbits(mpi_q);
	mpi_t1 = mpi_new ( mpi_get_nbits(mpi_p));
	mpi_t2 = mpi_new ( mpi_get_nbits(mpi_q));
	mpi_phi = mpi_new ( nbits );
	mpi_g  = mpi_new ( nbits );
	mpi_f  = mpi_new ( nbits );
	mpi_n = mpi_new (nbits);

	mpi_mul ( mpi_n, mpi_p, mpi_q );
	mpi_sub_ui ( mpi_t1, mpi_p, 1 );
	mpi_sub_ui ( mpi_t2, mpi_q, 1 );

	mpi_mul ( mpi_phi, mpi_t1, mpi_t2 );
	mpi_gcd ( mpi_g, mpi_t1, mpi_t2 );
	mpi_fdiv(mpi_f/*quotient*/, mpi_t1/*remainder*/, mpi_phi/*dividend*/, mpi_g/*divisor*/ );

	mpi_d = mpi_new ( nbits );
	mpi_invm ( mpi_d, mpi_e, mpi_f );
	mpi_u = mpi_new ( nbits);
	mpi_invm ( mpi_u, mpi_p, mpi_q );

	gcry_sexp_t key;
	rc = gcry_sexp_build ( &key, NULL, "(key-data(public-key(rsa(n%m)(e%m)))(private-key (rsa(n%M)(e%M)(d%M)(p%M)(q%M)(u%M))))", 
		mpi_n, mpi_e, mpi_n, mpi_e, mpi_d, mpi_p, mpi_q, mpi_u );
	if ( rc != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "unable to build key" );

		
	mpi_release ( mpi_n );
	mpi_release ( mpi_e );
	mpi_release ( mpi_d );
	mpi_release ( mpi_p );
	mpi_release ( mpi_q );
	mpi_release ( mpi_phi );
	mpi_release ( mpi_g );
	mpi_release ( mpi_f );
	mpi_release ( mpi_u );
	mpi_release ( mpi_t1 );
	mpi_release ( mpi_t2 );

	return DoRSA2 ( input, key, flags );
}
