#include <stdio.h>
#include <stdint.h>
#include <endian.h>
#include <memory.h>
#include <error.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <vector>
#include "scta.h"
#include "Trigger.h"

Trigger trigger;

void CryptoImplementation::Log (const char* alg, std::vector<uint_8> const & input, std::vector<uint_8> const & output, std::vector<uint_8> const & key, FLAGS flags )
{
	printf ( "%s", alg );
	printf ( " input=" );	
	for ( int i = 0; i < input.size(); i++ ) 
		printf ( "%02x", input[i] );
	printf ( " output=" );	
	for ( int i = 0; i < output.size(); i++ ) 
		printf ( "%02x", output[i] );
	printf ( " key=" );	
	for ( int i = 0; i < key.size(); i++ ) 
		printf ( "%02x", key[i] );
	printf ( " %s\n", GetName()) ;
}

std::vector<uint_8>  StringToByteArray ( char* string )
{
	unsigned int v;
	int stringlen = strlen(string);
	std::vector<uint_8> result;
	for ( int i = 0; i < stringlen; i+=2, string+=2 )
	{
		if ( sscanf ( string, "%02x", &v ) == 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__,  "Unable to parse string %s", string );
		result.push_back ( (uint_8)v );
	}
	return result;
}

void RunSelfTests();
int main (int argc, char** argv)
{
	std::vector<uint_8> key = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0 } ;
	std::vector<uint_8> input = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }; 
	const char* algorithm = "DES";
	CryptoImplementation* implementation = new MbedTLSImplementation();
	
	int c;
	while ((c = getopt (argc, argv, "k:i:a:m:t")) != -1)
    		switch (c)
      		{
     	 	case 'k':
       		 key = StringToByteArray(optarg);
       		 break;
     	 	case 'i':
       		 input = StringToByteArray(optarg);
       		 break;
      		case 'a':
        	 algorithm = optarg;
        	 break;
      		case 'm':
		  if ( strcasecmp ( optarg, "mbedtls" ) == 0 )
			implementation = new MbedTLSImplementation();
		  else if ( strcasecmp ( optarg, "openssl" ) == 0 )
			implementation = new OpenSSL();
		  else if ( strcasecmp ( optarg, "SimpleSoftware" ) == 0 )
			implementation = new SimpleSoftwareImplementation();
		  else if ( strcasecmp ( optarg, "WolfCrypt" ) == 0 ) 
			implementation = new WolfCrypt();
		  else if ( strcasecmp ( optarg, "TexasInstruments" ) == 0 )
			implementation = new TexasInstrumentsImplementation();
		  else if ( strcasecmp ( optarg, "TomCrypt" ) == 0 )
			implementation = new TomCrypt();
		  else if ( strcasecmp ( optarg, "SmartCardAES" ) == 0 )
			implementation = new SmartCardAES();
		  else if ( strcasecmp ( optarg, "KernelCrypto" ) == 0 )
			implementation = new KernelCrypto();
        	 break;
		case 't':
		 RunSelfTests();
		 return 0;
		 break;

	}	

	
	std::vector<uint_8> output;
	if ( strcasecmp ( algorithm, "DES" ) == 0 ) 
		output = implementation->DoDESWithLogging ( input, key );
	else if ( strcasecmp ( algorithm, "AES" ) == 0 ) 
		output = implementation->DoAESWithLogging ( input, key );
}


void RunSelfTests ()
{

	//std::vector<uint_8> input = { 0, 1, 2, 3, 4, 5 ,6 ,7 ,8 ,9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
	std::vector<uint_8> input = { 0, 0, 0, 0, 0,0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	std::vector<uint_8> input2 = { 0xec, 0x3a, 0x75, 0x0f, 0x6a, 0xe8, 0xd5, 0x92, 0x82, 0x1e, 0x33, 0xab, 0xf1, 0xf7, 0x30, 0x74};
	//uint_8 output[16];
	std::vector<uint_8> key = { 0, 1, 2, 3, 4,5 ,6, 7 };
	//uint_8 key2[16] = { 0, 1, 2, 3, 4,5 ,6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
	std::vector<uint_8> key2 = {0x55,0xc1,0x79,0x04,0xc3,0xdc,0x04,0x52,0x2a,0x0c,0x76,0xef,0xe8,0xca,0x48,0xb5};
	std::vector<uint_8> key3 = { 0, 1, 2, 3, 4,5 ,6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8 };
	std::vector<uint_8> key4 = {0x55,0xc1,0x79,0x04,0xc3,0xdc,0x04,0x52,0x2a,0x0c,0x76,0xef,0xe8,0xca,0x48,0xb5};

	//CryptoImplementation* cryptoImplementation = new SimpleSoftwareImplementation();
	CryptoImplementation* mbedTLS = new MbedTLSImplementation();
	CryptoImplementation* simpleSoftware = new SimpleSoftwareImplementation();
	CryptoImplementation* texasInstruments = new TexasInstrumentsImplementation();
	CryptoImplementation* openSSL = new OpenSSL();
	CryptoImplementation* wolfCrypt = new WolfCrypt();
	CryptoImplementation* tomCrypt = new TomCrypt();
	CryptoImplementation* smartCard = new SmartCardAES();
	CryptoImplementation* kernelCrypto = new KernelCrypto();
	
	simpleSoftware->DoDESWithLogging ( input, key);
	mbedTLS->DoDESWithLogging ( input, key);
	texasInstruments->DoDESWithLogging ( input, key);
	openSSL->DoDESWithLogging ( input, key);
	wolfCrypt->DoDESWithLogging ( input, key);
	tomCrypt->DoDESWithLogging ( input, key);
	kernelCrypto->DoDESWithLogging ( input, key);

	mbedTLS->DoDESWithLogging ( input, key2);
	texasInstruments->DoDESWithLogging ( input, key2);
	openSSL->DoDESWithLogging ( input, key2);
	wolfCrypt->DoDESWithLogging ( input, key2);
	tomCrypt->DoDESWithLogging ( input, key2);
	kernelCrypto->DoDESWithLogging ( input, key2);

	mbedTLS->DoDESWithLogging ( input, key3);
	texasInstruments->DoDESWithLogging ( input, key3);
	openSSL->DoDESWithLogging ( input, key3);
	wolfCrypt->DoDESWithLogging ( input, key3);
	tomCrypt->DoDESWithLogging ( input, key3);
	kernelCrypto->DoDESWithLogging ( input, key3);

	mbedTLS->DoAESWithLogging ( input, key4);
	texasInstruments->DoAESWithLogging ( input, key4);
	openSSL->DoAESWithLogging ( input, key4);
	wolfCrypt->DoAESWithLogging ( input, key4);
	tomCrypt->DoAESWithLogging ( input, key4);
	smartCard->DoAESWithLogging ( input2, key4);
	kernelCrypto->DoAESWithLogging ( input, key4);

	//mbedTLS->DoAESWithLogging ( input, output, sizeof(input), key3, sizeof(key3));
	//texasInstruments->DoAESWithLogging ( input, output, sizeof(input), key3, sizeof(key3));
	//openSSL->DoAESWithLogging ( input, output, sizeof(input), key3, sizeof(key3));
	//wolfCrypt->DoAESWithLogging ( input, output, sizeof(input), key3, sizeof(key3));
	//tomCrypt->DoAESWithLogging ( input, output, sizeof(input), key3, sizeof(key3));
	//smartCard->DoAESWithLogging ( input2, output, sizeof(input2), key3, sizeof(key3));
	//kernelCrypto->DoAESWithLogging ( input, output, sizeof(input), key3, sizeof(key3));
}