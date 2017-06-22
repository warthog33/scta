#include <error.h>
#include <endian.h>
#include <stdlib.h>
#include "scta.h"
//#include "DES.h"
#include <stdio.h>
#include "Trigger.h"

#include "gcrypt.h"

std::vector<uint_8> LibGCrypt::DoDES ( std::vector<uint_8> const& input, std::vector<uint_8> const& key, FLAGS flags )
{
	if ( key.size() != 8 && key.size() != 16 && key.size() != 24 )
		error_at_line ( 1, 0, __FILE__, __LINE__,  "Invalid key len");
	if (( input.size() % 8 ) != 0 )
		error (1, 0, "Data len not a multiple of 8" );

	//if (!gcry_check_version(GCRYPT_VERSION ))
	//{
		//error_at_line ( 1, 0, __FILE__, __LINE__, "libgcrypt version mismatch" );
	//}	
	gcry_error_t rc;
	gcry_cipher_hd_t hdt;
	rc = gcry_cipher_open ( &hdt, key.size() == 8 ? GCRY_CIPHER_DES : GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_ECB, 0 );
	if (rc != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "gcry_cipher_open returned %i", rc );
	
	if ( key.size() == 16 )
	{
		std::vector<uint_8> extendedkey = key;
		extendedkey.insert ( extendedkey.begin(), key.data(), key.data()+8 );
		rc = gcry_cipher_setkey ( hdt, extendedkey.data(), extendedkey.size());
	}
	else
	{	
		rc = gcry_cipher_setkey ( hdt, key.data(), key.size() );
	}
	if (rc != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "gcry_cipher_setkey returned %x", rc );

	std::vector<uint_8> output ( input.size());
	rc = gcry_cipher_encrypt ( hdt, output.data(), output.size(), input.data(), input.size() );	
	if (rc != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "gcry_cipher_encrypt returned %i", rc );

	gcry_cipher_close ( hdt );
	return output;
}



std::vector<uint_8> LibGCrypt::DoAES ( std::vector<uint_8>const& input, std::vector<uint_8>const& key, FLAGS flags )
{
	if ( key.size() != 16 && key.size() != 24 && key.size() != 32)
		error_at_line ( 1, 0, __FILE__, __LINE__,  "Invalid key len");
	if (( input.size() % 16 ) != 0 )
		error (1, 0, "Data len not a multiple of 8" );

	gcry_error_t rc;
	gcry_cipher_hd_t hdt;
	rc = gcry_cipher_open ( &hdt, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_ECB, 0 );
	if (rc != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "gcry_cipher_open returned %i", rc );
	
	rc = gcry_cipher_setkey ( hdt, key.data(), key.size() );
	if (rc != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "gcry_cipher_setkey returned %x", rc );

	std::vector<uint_8> output ( input.size());
	trigger.Raise();
	rc = gcry_cipher_encrypt ( hdt, output.data(), output.size(), input.data(), input.size() );	
	trigger.Lower();
	if (rc != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "gcry_cipher_encrypt returned %i", rc );

	gcry_cipher_close ( hdt );
	return output;
}



std::vector<uint_8> LibGCrypt::DoRSA ( std::vector<uint_8>const& input, const char* privateKey, FLAGS flags )
{
	//mbedtls_pk_context pk;
	
	//mbedtls_pk_init ( &pk );
	int rc;
	//mbedtls_rsa_context ctx;

	if ( privateKey == NULL || privateKey[0] == '\0' )	
	{
		//mbedtls_rsa_init ( &ctx, MBEDTLS_RSA_PKCS_V15, MBEDTLS_RSA_PKCS_V21 );
		srand(0);
		//rc = mbedtls_rsa_gen_key ( &ctx, GetRandomNumbers, 0, input.size()*8/*bits*/, 65537 );
		if ( rc != 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "mbedtls_rsa_gen_key returned error" );
	}
	else
	{
		//mbedtls_pk_context pkctx;
		//mbedtls_pk_init (&pkctx );
		//rc = mbedtls_pk_parse_keyfile ( &pkctx, privateKey, NULL );
		if ( rc != 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "mbedtls_pk_parse_keyfile returned error %x, file=%s", -rc, privateKey );

		//mbedtls_rsa_context* newctx = mbedtls_pk_rsa ( pkctx );	
		//if ( newctx == NULL )
			error_at_line ( 1, 0, __FILE__, __LINE__, "mbedtls_pk_rsa returned NULL" );

		//ctx = *newctx;
			
	}


	char N[2000], E[2000], D[2000], P[2000], Q[2000], DP[2000], DQ[2000], QP[2000] ;
	size_t olen;
	//mbedtls_mpi_write_string ( &ctx.N, 16, N, sizeof(N), &olen);
	//mbedtls_mpi_write_string ( &ctx.E, 16, E, sizeof(E), &olen);
	//mbedtls_mpi_write_string ( &ctx.D, 16, D, sizeof(D), &olen);
	//mbedtls_mpi_write_string ( &ctx.P, 16, P, sizeof(P), &olen);
	//mbedtls_mpi_write_string ( &ctx.Q, 16, Q, sizeof(Q), &olen);
	//mbedtls_mpi_write_string ( &ctx.DP, 16, DP, sizeof(DP), &olen);
	//mbedtls_mpi_write_string ( &ctx.DQ, 16, DQ, sizeof(DQ), &olen);
	//mbedtls_mpi_write_string ( &ctx.QP, 16, QP, sizeof(QP), &olen);

	//printf ( "N=(%lubits) %s\n", mbedtls_mpi_bitlen(&ctx.N), N );
	//printf ( "E=(%lubits) %s\n", mbedtls_mpi_bitlen(&ctx.E), E );
	//printf ( "D=(%lubits) %s\n", mbedtls_mpi_bitlen(&ctx.D), D );
	//printf ( "P=(%lubits) %s\n", mbedtls_mpi_bitlen(&ctx.P), P );
	//printf ( "Q=(%lubits) %s\n", mbedtls_mpi_bitlen(&ctx.Q), Q );
	//printf ( "DP=(%lubits) %s\n", mbedtls_mpi_bitlen(&ctx.DP), DP );
	//printf ( "DQ=(%lubits) %s\n", mbedtls_mpi_bitlen(&ctx.DQ), DQ );
	//printf ( "QP=(%lubits) %s\n", mbedtls_mpi_bitlen(&ctx.QP), QP );

	
	//if ( input.size() * 8 != mbedtls_mpi_bitlen(&ctx.N) )
		//error_at_line ( 1, 0, __FILE__, __LINE__, "Plaintext not correct size %lu != %lu", input.size()*8, mbedtls_mpi_bitlen(&ctx.N));	

	std::vector<uint_8> output(input.size());
	trigger.Raise();
	//rc = mbedtls_rsa_private ( &ctx, GetRandomNumbers, 0, input.data(), output.data() );
	trigger.Lower();

	if ( rc != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "mbedtls_rsa_private returned error %x", -rc );
	return output;
}
