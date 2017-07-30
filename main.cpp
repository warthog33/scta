#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <endian.h>
#include <memory.h>
#include <error.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <vector>
#include "scta.h"
#include "Trigger.h"

Trigger* trigger = new Trigger();
std::ostream& operator<< ( std::ostream& os, std::vector<uint_8>const& v )
{
	char buf[3];
	for ( std::vector<uint_8>::const_iterator vi = v.begin(); vi != v.end(); vi++ )
	{
		sprintf ( buf, "%02x", *vi );
		os << buf;
	}
	return os;
}
std::string ToString ( std::vector<uint_8>const& v )
{
	std::string s;
	char buf[3];
	for ( std::vector<uint_8>::const_iterator vi = v.begin(); vi != v.end(); vi++ )
	{
		sprintf ( buf, "%02x", *vi );
		s += buf;
	}
	return s;
}

std::ostream& operator << ( std::ostream& os, FLAGS flags )
{
	if ( flags & ENCRYPT )
		os << " Encrypt";	
	if ( flags & DECRYPT )
		os << " Decrypt";	
	if ( flags & CRT )
		os << " CRT";	
	if ( flags & RUN_TWICE )
		os << " RunTwice";	
	return os;
}
std::vector<uint_8>  StringToByteArray ( char* string )
{
	unsigned int v;
	if ( sscanf ( string, "Ones%u", &v ) == 1 )
	{
		return std::vector<uint_8> ( v/8, 0x11 );
	}
	if ( sscanf ( string, "Zeros%u", &v ) == 1 )
	{
		return std::vector<uint_8> ( v/8, 0 );
	}
	if ( sscanf ( string, "Zeroes%u", &v ) == 1 )
	{
		return std::vector<uint_8> ( v/8, 0 );
	}
	if ( sscanf ( string, "FFs%u", &v ) == 1 )
	{
		return std::vector<uint_8> ( v/8, 0xFF );
	}

	std::vector<uint_8> result;
	int stringlen = strlen(string);
	for ( int i = 0; i < stringlen; i+=2, string+=2 )
	{
		if ( sscanf ( string, "%02x", &v ) == 0 )
			error_at_line ( 1, 0, __FILE__, __LINE__,  "Unable to parse string %s", string );
		result.push_back ( (uint_8)v );
	}
	return result;
}
void PrintUsage()
{
	printf ( "Side Channel Test Artefact\n" );
	printf ( "Usage: scta -k<key> -i<input> -a<algorithm> -m<implementation> \n" );
	printf ( "    -k<key> is a string of hexadecimal characters, length between 16 and 64 depending upon the algorithm\n" );
	printf ( "    -n<modulus> is string of hexadecimal characters for use with RSA\n" );
	printf ( "    -d<exponent> is string of hexadecimal characters for use with RSA\n" );
	printf ( "    -e<exponent> is string of hexadecimal characters for use with RSA\n" );
	printf ( "    -p<prime1> is string of hexadecimal characters for use with RSA\n" );
	printf ( "    -q<prime2> is string of hexadecimal characters for use with RSA\n" );
	printf ( "    -b<number> is decimal string representing key size for use with RSA_gen\n" );
	printf ( "    -i<input> is string of hexadecimal characters, length must be multiple of block size of cipher\n" );
	printf ( "           can be one of the following formats: Zeros<numbits>, Ones<numbits> or FFs<numbits>\n" );
	printf ( "    -a<algorithm> currently supported include DES, AES, RSA_ned, RSA_epq\n" );
	printf ( "         for Kernel crypto this is the driver/template name from /proc/crypto, eg ecb(aes) or ecb-aes-omap\n" );
	printf ( "    -m<implementation> currently supported: mbedtls, openssl, SimpleSoftware, WolfCrypt  \n" );
	printf ( "       TexasInstruments, TomCrypt, SmartCardAES (masked decryption only), KernelCrypto \n" );
	printf ( "    -t<trigger> currently supported options include StdOut, BeagleBone (pin5 on BeagleBoneBlack) or SysGpio(/sys/class/gpio/gpio60) \n" );
	printf ( "    -f<encrypt|decrypt|printintermediatevalues|RunTwice> flags, see below\n" );
	printf ( "       runtwice: run the crypto twice, only triggering on the second operation to help with cache hits\n" );
	printf ( "    -s Run Self tests \n" );
	printf ( "Note:\n" );
	printf ( "  RSA for TomCrypt does not do blinding, but does do CRT\n" );
	printf ( "\n" );
}
const uint_8 defaultKey[] = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0 } ;
const uint_8 defaultInput[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }; 
const uint_8 default_i[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
const uint_8 default_n[] = { 0xf1,0xff,0x61,0x94,0x66,0x5f,0x12,0xcf,0x9b,0x39,0x1f,0x15,0xc3,0x56,0xce,0x6a,0x85,0xf1,0x47,0x19,0x2f,0x00,0x6b,0x93,0x71,0x34,0x2f,0xfd,0x00,0xc5,0xe4,0x37,0xb6,0xe0,0xd1,0xdf,0x11,0xcd,0x2b,0x86,0xd4,0x0e,0xde,0xa3,0xb1,0xe2,0xb9,0xe4,0x8d,0x60,0x95,0x76,0xe7,0x4d,0x17,0xd2,0x7f,0x0a,0xf2,0x70,0x0b,0x55,0xa2,0xc8,0x6e,0x03,0xfb,0xa8,0x56,0xda,0x83,0xfc,0x12,0x83,0x62,0x11,0xfb,0x52,0x23,0x98,0x2f,0xc9,0x04,0x93,0x46,0xa1,0x6c,0xdd,0xb3,0x82,0xc0,0x75,0x4c,0x81,0x5d,0x3a,0x8e,0x10,0xe3,0x9a,0x8a,0x94,0x48,0x28,0x6f,0xa9,0xdf,0x28,0xd3,0xc8,0x3d,0xc2,0xc6,0xa0,0xf5,0x3b,0xb8,0x21,0x2a,0x70,0x21,0xa8,0xde,0x45,0xbb,0x65,0x42,0x81};
const uint_8 default_e[] = { 0x01, 0x00, 0x01 };
const uint_8 default_d[] = { 0x28,0xfd,0x69,0xad,0x1e,0x08,0xf1,0x11,0xfe,0xb8,0x16,0x72,0x94,0x7f,0x85,0xdf,0xa7,0xb7,0xe6,0x63,0xd6,0xe1,0x02,0x97,0xbb,0x17,0x4c,0xa0,0x95,0x6a,0xaf,0x9d,0x1b,0x4a,0x29,0xea,0x57,0xa4,0xd1,0xc0,0x58,0xf7,0x7a,0xd1,0x2d,0xde,0x9a,0x3f,0xa3,0x0d,0xce,0xcb,0x50,0xe2,0xef,0x4b,0xcd,0x8e,0x90,0x61,0x97,0x9d,0xe6,0x00,0x2a,0x42,0x9e,0x70,0xed,0xaa,0x9f,0x0d,0xd6,0x90,0xa9,0x6d,0xc2,0xe1,0x66,0x20,0x3a,0x90,0x80,0x00,0x3f,0x0f,0xcd,0x2a,0x44,0x6e,0x25,0xc6,0xa2,0x8d,0x02,0xd9,0xaa,0x53,0x3d,0xe6,0x12,0x81,0x90,0x8f,0x20,0x9f,0xe2,0xeb,0x84,0x38,0x35,0xe1,0x5b,0xb4,0x9c,0x3d,0x35,0x4e,0xc9,0x17,0xf1,0xd9,0x7f,0xc1,0x6e,0x8e,0x9c,0xc5};
const uint_8 default_p[] = {0xf4,0x2d,0xbd,0x91,0x5b,0x9c,0x35,0x5c,0xb4,0x7f,0xad,0x9f,0x65,0x55,0x9e,0x1b,0xd0,0x49,0x21,0xd2,0xea,0x26,0x26,0x52,0xe6,0x02,0xf6,0xde,0x79,0x47,0x7d,0xf6,0x10,0xb1,0x11,0xe7,0x1c,0xaa,0x4d,0xe6,0x73,0xd3,0x72,0xee,0x3a,0xb9,0xbb,0x98,0xb8,0x35,0xf7,0x3e,0xac,0x08,0x5d,0x69,0x1f,0x34,0x84,0xd8,0xa4,0x86,0xb7,0x7d};
const uint_8 default_q[] = {0xfd,0xb6,0x9b,0xea,0x16,0xf7,0xca,0x9e,0x91,0xa1,0xc3,0x47,0x25,0xee,0xc0,0xe9,0x92,0x15,0xe0,0x53,0x03,0x80,0xde,0x56,0x52,0xf6,0xbd,0x5d,0xa5,0xe9,0xa0,0x4b,0x45,0x84,0x05,0x42,0x59,0x76,0x05,0xd7,0x7b,0x42,0x02,0x69,0xd6,0x0e,0x0c,0xf9,0xc4,0xf1,0xd8,0x77,0x3f,0xc4,0x2d,0xd1,0x25,0x1e,0x02,0xa8,0xa7,0xdf,0x8e,0x55};
const uint_8 default_u[] = {0xd2,0xb5,0xaf,0xba,0x4e,0x68,0x27,0xfe,0xbc,0xe4,0x65,0xed,0xee,0xd2,0x41,0x2e,0xd4,0x96,0x43,0xe5,0xe7,0x9f,0x58,0x30,0x2c,0x8c,0x28,0xb1,0xd7,0x5b,0xc4,0xf9,0x61,0x4d,0x37,0xb0,0x8f,0x9e,0xc7,0x91,0xb7,0x74,0xae,0x86,0xd9,0xca,0x1b,0xa9,0x45,0xfc,0x44,0xf6,0xf9,0xf1,0x3a,0x12,0xf8,0x6d,0x7c,0xc8,0xef,0x06,0xa1,0xa8};

void RunSelfTests();
int main (int argc, char** argv)
{
	std::vector<uint_8> key (defaultKey, defaultKey+sizeof(defaultKey));
	std::vector<uint_8> input (defaultInput, defaultInput + sizeof(defaultInput)); 
	std::vector<uint_8> n (default_n, default_n+sizeof(default_n));
	std::vector<uint_8> d (default_d, default_d+sizeof(default_d));
	std::vector<uint_8> e (default_e, default_e+sizeof(default_e));
	std::vector<uint_8> p (default_p, default_p+sizeof(default_p));
	std::vector<uint_8> q (default_q, default_q+sizeof(default_q));
	const char* algorithm = "DES";
	const char* keyFile = "";
	CryptoImplementation* implementation = new MbedTLSImplementation();
	FLAGS flags = NONE;
	int numbits = 0;

	int c;
	while ((c = getopt (argc, argv, "k:n:d:e:f:i:a:m:t:shp:q:b:")) != -1)
    		switch (c)
      		{
		case 'b':
		  numbits = atoi ( optarg);
		  break;
		case 'h':
		  PrintUsage();
		  return 1;
     	 	case 'k':
       		 key = StringToByteArray(optarg);
       		 break;
     	 	case 'n':
       		 n = StringToByteArray(optarg);
       		 break;
     	 	case 'd':
       		 d = StringToByteArray(optarg);
       		 break;
     	 	case 'e':
       		 e = StringToByteArray(optarg);
       		 break;
     	 	case 'i':
       		 input = StringToByteArray(optarg);
       		 break;
      		case 'a':
        	 algorithm = optarg;
        	 break;
		case 'p':
		 p = StringToByteArray(optarg);
		 break;
		case 'q':
		 q = StringToByteArray(optarg);
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
		  else if ( strcasecmp ( optarg, "gcrypt" ) == 0 )
			implementation = new LibGCrypt();
		  else
			error_at_line ( 1, 0, __FILE__, __LINE__, "Unknown implementation %s", optarg );
        	 break;
		case 'f':
		 if ( strcasecmp ( optarg, "encrypt" ) == 0 )
			flags = (FLAGS)(flags | ENCRYPT);
		 else if ( strcasecmp ( optarg, "decrypt" ) == 0 )
			flags = (FLAGS)(flags | DECRYPT);
		 else if ( strcasecmp ( optarg, "printintermediatevalues" ) == 0 )
			flags = (FLAGS)(flags | PRINT_INTERMEDIATE_VALUES);
		 else if ( strcasecmp ( optarg, "runtwice" ) == 0 )
			flags = (FLAGS)(flags | RUN_TWICE);
		 else
			error_at_line (1, 0, __FILE__, __LINE__, "Unknown flag %s", optarg );
		 break;	
		case 't':
		 if ( strcasecmp ( optarg, "stdout" ) == 0 )
			trigger = new StdOutTrigger();
		 else if ( strcasecmp ( optarg, "beaglebone" ) == 0 )
			trigger = new BeagleBoneTrigger();
		 else if ( strcasecmp ( optarg, "sysgpio" ) == 0 )
			trigger = new SysGpioTrigger();
		 else
			error_at_line ( 1, 0, __FILE__, __LINE__, "Unknown trigger type %s", optarg );	
		 break;
		case 's':
		 RunSelfTests();
		 return 0;
		 break;

	}	

	trigger->Init();	
	std::vector<uint_8> output;
	if ( strcasecmp ( algorithm, "DES" ) == 0 ) 
		output = implementation->DoDESWithLogging ( input, key, flags );
	else if ( strcasecmp ( algorithm, "AES" ) == 0 ) 
		output = implementation->DoAESWithLogging ( input, key, flags );
	else if ( strcasecmp ( algorithm, "RSA_ned" ) == 0 ) 
		output = implementation->DoRSA_ned_WithLogging ( input, n, e, d, flags );
	else if ( strcasecmp ( algorithm, "RSA_epq" ) == 0 ) 
		output = implementation->DoRSA_epq_WithLogging ( input, e, p, q, flags );
	else if ( strcasecmp ( algorithm, "RSA_Gen" ) == 0 ) 
		output = implementation->DoRSA_KeyGen_WithLogging ( input, numbits, flags );
	else if ( strcasecmp ( algorithm, "RSA_KeyFile" ) == 0 ) 
		output = implementation->DoRSA_KeyFile_WithLogging ( input, keyFile, flags );
	else 
		output = implementation->DoSymmetricWithLogging ( algorithm, input, key, flags );
}


void RunSelfTests ()
{
	const uint_8 defaultInput1[] = { 0, 0, 0, 0, 0,0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	std::vector<uint_8> input (defaultInput1, defaultInput1+sizeof(defaultInput1));
	const uint_8 defaultInput2[] = { 0xec, 0x3a, 0x75, 0x0f, 0x6a, 0xe8, 0xd5, 0x92, 0x82, 0x1e, 0x33, 0xab, 0xf1, 0xf7, 0x30, 0x74};
	std::vector<uint_8> input2 (defaultInput2, defaultInput2+sizeof(defaultInput2));
	const uint_8 defaultKey1[] = { 0, 1, 2, 3, 4,5 ,6, 7 };
	std::vector<uint_8> key (defaultKey1, defaultKey1+sizeof(defaultKey1));
	const uint_8 defaultKey2[] = {0x55,0xc1,0x79,0x04,0xc3,0xdc,0x04,0x52,0x2a,0x0c,0x76,0xef,0xe8,0xca,0x48,0xb5};
	std::vector<uint_8> key2 (defaultKey2, defaultKey2 + sizeof(defaultKey2)); 
	const uint_8 defaultKey3[] = { 0, 1, 2, 3, 4,5 ,6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8 };
	std::vector<uint_8> key3 ( defaultKey3, defaultKey3+sizeof(defaultKey3));
	const uint_8 defaultKey4[] = {0x55,0xc1,0x79,0x04,0xc3,0xdc,0x04,0x52,0x2a,0x0c,0x76,0xef,0xe8,0xca,0x48,0xb5};
	std::vector<uint_8> key4 (defaultKey4, defaultKey4+sizeof(defaultKey4));
	std::vector<uint_8> n (default_n, default_n+sizeof(default_n));
	std::vector<uint_8> e (default_e, default_e+sizeof(default_e));
	std::vector<uint_8> d (default_d, default_d+sizeof(default_d));
	std::vector<uint_8> p (default_p, default_p+sizeof(default_p));
	std::vector<uint_8> q (default_q, default_q+sizeof(default_q));
	std::vector<uint_8> u (default_u, default_u+sizeof(default_u));
	std::vector<uint_8> i (default_i, default_i+sizeof(default_i));
	std::vector<uint_8> result; 


	//CryptoImplementation* cryptoImplementation = new SimpleSoftwareImplementation();
	CryptoImplementation* mbedTLS = new MbedTLSImplementation();
	CryptoImplementation* simpleSoftware = new SimpleSoftwareImplementation();
	CryptoImplementation* texasInstruments = new TexasInstrumentsImplementation();
	CryptoImplementation* openSSL = new OpenSSL();
	CryptoImplementation* wolfCrypt = new WolfCrypt();
	CryptoImplementation* tomCrypt = new TomCrypt();
	CryptoImplementation* smartCard = new SmartCardAES();
	CryptoImplementation* kernelCrypto = new KernelCrypto();
	CryptoImplementation* libGCrypt = new LibGCrypt();

	FLAGS flags = NONE;		
	simpleSoftware->DoDESWithLogging ( input, key, flags);
	mbedTLS->DoDESWithLogging ( input, key, flags);
	texasInstruments->DoDESWithLogging ( input, key, flags);
	openSSL->DoDESWithLogging ( input, key, flags);
	//wolfCrypt->DoDESWithLogging ( input, key, flags);
	tomCrypt->DoDESWithLogging ( input, key, flags);
	kernelCrypto->DoDESWithLogging ( input, key, flags);
	libGCrypt->DoDESWithLogging ( input, key, flags);

	mbedTLS->DoDESWithLogging ( input, key2, flags);
	texasInstruments->DoDESWithLogging ( input, key2, flags);
	openSSL->DoDESWithLogging ( input, key2, flags);
	//wolfCrypt->DoDESWithLogging ( input, key2, flags);
	tomCrypt->DoDESWithLogging ( input, key2, flags);
	kernelCrypto->DoDESWithLogging ( input, key2, flags);
	libGCrypt->DoDESWithLogging ( input, key2, flags);

	mbedTLS->DoDESWithLogging ( input, key3, flags);
	texasInstruments->DoDESWithLogging ( input, key3, flags);
	openSSL->DoDESWithLogging ( input, key3, flags);
	//wolfCrypt->DoDESWithLogging ( input, key3, flags);
	tomCrypt->DoDESWithLogging ( input, key3, flags);
	kernelCrypto->DoDESWithLogging ( input, key3, flags);
	libGCrypt->DoDESWithLogging ( input, key3, flags);

	mbedTLS->DoAESWithLogging ( input, key4, flags);
	texasInstruments->DoAESWithLogging ( input, key4, flags);
	openSSL->DoAESWithLogging ( input, key4, flags);
	//wolfCrypt->DoAESWithLogging ( input, key4, flags);
	tomCrypt->DoAESWithLogging ( input, key4, flags);
	smartCard->DoAESWithLogging ( input2, key4, flags);
	kernelCrypto->DoAESWithLogging ( input, key4, flags);
	libGCrypt->DoAESWithLogging ( input, key4, flags);

	result = libGCrypt->DoRSA_ned_WithLogging ( i, n, e, d, ENCRYPT ); 
	result = wolfCrypt->DoRSA_ned_WithLogging ( i, n, e, d, ENCRYPT ); 
	result = tomCrypt->DoRSA_ned_WithLogging ( i, n, e, d, ENCRYPT );
	libGCrypt->DoRSA_ned_WithLogging ( result, n, e, d, DECRYPT );
	wolfCrypt->DoRSA_ned_WithLogging ( result, n, e, d, DECRYPT );
	tomCrypt->DoRSA_epq_WithLogging ( result, e, p, q, DECRYPT );
	wolfCrypt->DoRSA_epq_WithLogging ( result, e, p, q, DECRYPT );
	libGCrypt->DoRSA_epq_WithLogging ( result, e, p, q, DECRYPT );
	//mbedTLS->DoAESWithLogging ( input, output, sizeof(input), key3, sizeof(key3));
	//texasInstruments->DoAESWithLogging ( input, output, sizeof(input), key3, sizeof(key3));
	//openSSL->DoAESWithLogging ( input, output, sizeof(input), key3, sizeof(key3));
	//wolfCrypt->DoAESWithLogging ( input, output, sizeof(input), key3, sizeof(key3));
	//tomCrypt->DoAESWithLogging ( input, output, sizeof(input), key3, sizeof(key3));
	//smartCard->DoAESWithLogging ( input2, output, sizeof(input2), key3, sizeof(key3));
	//kernelCrypto->DoAESWithLogging ( input, output, sizeof(input), key3, sizeof(key3));
}
