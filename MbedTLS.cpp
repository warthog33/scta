#include <error.h>
#include <endian.h>
#include <stdlib.h>
#include "scta.h"
//#include "DES.h"
#include <stdio.h>
#include "Trigger.h"

#include "mbedtls/des.h"
#include "mbedtls/aes.h"
#include "mbedtls/pk.h"

std::vector<uint_8> MbedTLSImplementation::DoDES ( std::vector<uint_8> const& input, std::vector<uint_8> const& key, FLAGS flags )
{
	if ( key.size() != 8 && key.size() != 16 && key.size() != 24 )
		error_at_line ( 1, 0, __FILE__, __LINE__,  "Invalid key len");
	if (( input.size() % 8 ) != 0 )
		error (1, 0, "Data len not a multiple of 8" );

	std::vector<uint_8> output ( input.size());
	if ( key.size() == 8 )
	{
		mbedtls_des_context ctx;
		mbedtls_des_init ( &ctx );
	
		if ( mbedtls_des_setkey_enc ( &ctx, key.data() ) != 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "mbedtls_des_setkey_enc returned error " );
	
		for ( int offset = 0; offset < input.size(); offset+=8 )	
		{
			trigger.Raise();
			if ( mbedtls_des_crypt_ecb ( &ctx, input.data()+offset, output.data()+offset ) != 0 )
				error_at_line ( 1, 0, __FILE__, __LINE__, "mbedtls_des_crypt_ecb returned error" );	
			trigger.Lower();
		}
	}	
	else if ( key.size() == 16 || key.size() == 24 )
	{	
		mbedtls_des3_context ctx;
		mbedtls_des3_init ( &ctx );
	
		if ( (key.size() == 16 ? mbedtls_des3_set2key_enc : mbedtls_des3_set3key_enc)(&ctx, key.data() ) != 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "mbedtls_des3_set2/3key_enc returned error" );
			
		for ( int offset = 0; offset < input.size();  offset+=8 )	
		{
			trigger.Raise();
			if ( mbedtls_des3_crypt_ecb ( &ctx, input.data()+offset, output.data()+offset ) != 0 )
				error_at_line ( 1, 0, __FILE__, __LINE__, "mbedtls_des3_crypt_ecb returned error" );	
			trigger.Lower();
		}
	}
	return output;
}



std::vector<uint_8> MbedTLSImplementation::DoAES ( std::vector<uint_8>const& input, std::vector<uint_8>const& key, FLAGS flags )
{
	if ( key.size() != 16 && key.size() != 24 && key.size() != 32)
		error_at_line ( 1, 0, __FILE__, __LINE__,  "Invalid key len");
	if (( input.size() % 16 ) != 0 )
		error (1, 0, "Data len not a multiple of 8" );

	std::vector<uint_8> output(input.size());

	mbedtls_aes_context ctx;
	mbedtls_aes_init ( &ctx );
	
	if ( mbedtls_aes_setkey_enc(&ctx, key.data(), key.size() * 8 ) != 0 )
		error_at_line ( 1, 0, __FILE__, __LINE__, "mbedtls_aes_setkey_enc returned error" );
			
	for ( int offset = 0; offset < input.size(); offset+=16 )	
	{
		trigger.Raise();
		if ( mbedtls_aes_crypt_ecb ( &ctx, MBEDTLS_AES_ENCRYPT, input.data()+offset, output.data()+offset ) != 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "mbedtls_aes_crypt_ecb returned error" );	
		trigger.Lower();
	}
	return output;
}

int GetRandomNumbers ( void* parameter, unsigned char* output, size_t numbytes )
{
	for ( int i = 0; i < numbytes; i++ )
		output[i] = (unsigned char)rand();
	return 0;
}


std::vector<uint_8> MbedTLSImplementation::DoRSA ( std::vector<uint_8>const& input, const char* privateKey, FLAGS flags )
{
	//mbedtls_pk_context pk;
	
	//mbedtls_pk_init ( &pk );
	int rc;
	mbedtls_rsa_context ctx;
	mbedtls_rsa_init ( &ctx, MBEDTLS_RSA_PKCS_V15, MBEDTLS_RSA_PKCS_V21 );

	if ( privateKey == NULL )	
	{
		srand(0);
		rc = mbedtls_rsa_gen_key ( &ctx, GetRandomNumbers, 0, input.size()*8/*bits*/, 65537 );
		if ( rc != 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "mbedtls_rsa_gen_key returned error" );
	}
	else
	{
		mbedtls_pk_context pkctx;
		mbedtls_pk_init (&pkctx );
		rc = mbedtls_pk_parse_keyfile ( &pkctx, privateKey, "" );
		if ( rc != 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__, "mbedtls_pk_parse_keyfile returned error %x", -rc );
	}

	std::vector<uint_8> output(input.size());

	rc = mbedtls_rsa_private ( &ctx, GetRandomNumbers, 0, input.data(), output.data() );

	char N[2000], E[2000], D[2000], P[2000], Q[2000], DP[2000], DQ[2000], QP[2000] ;
	size_t olen;
	mbedtls_mpi_write_string ( &ctx.N, 16, N, sizeof(N), &olen);
	mbedtls_mpi_write_string ( &ctx.E, 16, E, sizeof(E), &olen);
	mbedtls_mpi_write_string ( &ctx.D, 16, D, sizeof(D), &olen);
	mbedtls_mpi_write_string ( &ctx.P, 16, P, sizeof(P), &olen);
	mbedtls_mpi_write_string ( &ctx.Q, 16, Q, sizeof(Q), &olen);
	mbedtls_mpi_write_string ( &ctx.DP, 16, DP, sizeof(DP), &olen);
	mbedtls_mpi_write_string ( &ctx.DQ, 16, DQ, sizeof(DQ), &olen);
	mbedtls_mpi_write_string ( &ctx.QP, 16, QP, sizeof(QP), &olen);

	printf ( "N=(%lu) %s\n", olen, N );
	printf ( "E=(%lu) %s\n", olen, E );
	printf ( "D=(%lu) %s\n", olen, D );
	printf ( "P=(%lu) %s\n", olen, P );
	printf ( "Q=(%lu) %s\n", olen, Q );
	printf ( "DP=(%lu) %s\n", olen, DP );
	printf ( "DQ=(%lu) %s\n", olen, DQ );
	printf ( "QP=(%lu) %s\n", olen, QP );
	return output;
}
