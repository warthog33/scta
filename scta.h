#include <vector>
#include <stdio.h>
#include <string>
#include <iostream>

typedef unsigned char uint_8;
typedef enum 
{
	NONE,
	DEFAULT,
	ENCRYPT = 1,
	DECRYPT = 2,
	CRT     = 4,
	PRINT_INTERMEDIATE_VALUES = 0x8,
	RUN_TWICE = 0x10,
	TRIGGER_PER_ROUND = 0x20
} FLAGS;

//std::string Log ( std::vector<uint_8>const & v );
std::ostream& operator<< ( std::ostream& os, std::vector<uint_8>const& v );
std::ostream& operator<< ( std::ostream& os, FLAGS f );
std::string ToString (std::vector<uint_8>const& v );

typedef std::vector<uint_8> bytevector;

class CryptoImplementation
{
	public:
	virtual const char* GetName () = 0;
	std::vector<uint_8> DoAESWithLogging ( std::vector<uint_8> const& input, std::vector<uint_8> const& key, FLAGS flags = NONE)
	{ 
		std::vector<uint_8> output = DoAES ( input, key, flags );
		std::cout << "AES i=" << input << " o=" << output << " k=" << key << " " << GetName() << flags << std::endl;
		return output;
	}
	std::vector<uint_8> DoDESWithLogging ( std::vector<uint_8>const & input, std::vector<uint_8>const& key, FLAGS flags = NONE)
	{
		std::vector<uint_8> output  = DoDES ( input, key, flags ); 
		std::cout << "DES i=" << input << " o=" << output << " k=" << key << " " << GetName() << flags << std::endl; 
		return output;
	}
	std::vector<uint_8> DoSymmetricWithLogging ( const char* name, std::vector<uint_8>const & input, std::vector<uint_8>const& key, FLAGS flags = NONE)
	{
		std::vector<uint_8> output  = DoSymmetric ( name, input, key, flags ); 
		std::cout << name << " i=" << input << " o=" << output << " k=" << key << " " << GetName() << flags << std::endl; 
		return output;
	}
	std::vector<uint_8> DoRSA_ned_WithLogging ( std::vector<uint_8>const & input, std::vector<uint_8>& n, std::vector<uint_8>& e, std::vector<uint_8>& d, FLAGS flags = NONE )
	{
		std::vector<uint_8> output  = DoRSA_ned ( input, n, e, d, flags ); 
		std::cout << "RSA i=" << input << " o=" << output << " n=" << n << " d=" << d << " " << GetName() << flags << std::endl; 
		return output;
	}

	std::vector<uint_8> DoRSA_epq_WithLogging ( std::vector<uint_8>const & input, std::vector<uint_8>& e, std::vector<uint_8>& p, std::vector<uint_8>& q, FLAGS flags = NONE )
	{
		std::vector<uint_8> output  = DoRSA_epq ( input, e, p, q, flags ); 
		std::cout << "RSA i=" << input << " o=" << output << " e=" << e << " p=" << p << " q=" << q << " " << GetName() << flags << std::endl; 
		return output;
	}
	std::vector<uint_8> DoRSA_KeyGen_WithLogging ( std::vector<uint_8>const & input, int numbits, FLAGS flags = NONE )
	{
		std::vector<uint_8> output  = DoRSA_KeyGen ( input, numbits, flags ); 
		std::cout << "RSA i=" << input << " o=" << output << " n=" << numbits << " " << GetName() << flags << std::endl; 
		return output;
	}
	std::vector<uint_8> DoRSA_KeyFile_WithLogging ( std::vector<uint_8>const & input, const char* keyfile, FLAGS flags = NONE )
	{
		std::vector<uint_8> output  = DoRSA_KeyFile ( input, keyfile, flags ); 
		std::cout << "RSA i=" << input << " o=" << output << " keyfile=" << keyfile << " " << GetName() << flags << std::endl; 
		return output;
	}	
	virtual std::vector<uint_8> DoAES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags )
	{ return DoSymmetric ( "AES", input, key, flags ); } 
	virtual std::vector<uint_8> DoDES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags )
	{ return DoSymmetric ( "DES", input, key, flags ); }
	virtual std::vector<uint_8> DoSymmetric ( const char* name, std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ) 
	{ error ( 1, 0, "Not Implemented" ); return std::vector<uint_8>(); }
	virtual std::vector<uint_8> DoRSA_KeyGen ( std::vector<uint_8> const & input, int numbits, FLAGS& flags )
	{ error ( 1, 0, "Not Implemented" ); return std::vector<uint_8>(); }
	virtual std::vector<uint_8> DoRSA_KeyFile ( std::vector<uint_8> const & input, const char* keyfilename, FLAGS& flags )
	{ error ( 1, 0, "Not Implemented" ); return std::vector<uint_8>(); }
	virtual std::vector<uint_8> DoRSA_ned ( std::vector<uint_8> const & input, std::vector<uint_8>& n, std::vector<uint_8>& e, std::vector<uint_8>& d, FLAGS& flags )
	{ error ( 1, 0, "Not Implemented" ); return std::vector<uint_8>(); }
	virtual std::vector<uint_8> DoRSA_epq ( std::vector<uint_8> const & input, std::vector<uint_8>& e, std::vector<uint_8>& p, std::vector<uint_8>& q, FLAGS& flags )
	{ error ( 1, 0, "Not Implemented" ); return std::vector<uint_8>(); }
};

class SimpleSoftwareImplementation : public CryptoImplementation
{
	public:
	virtual const char* GetName () { return "SimpleSoftware"; }
	virtual std::vector<uint_8> DoAES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
	virtual std::vector<uint_8> DoDES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
	//virtual std::vector<uint_8> DoSymmetric ( const char* name, std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
};
class MbedTLSImplementation : public CryptoImplementation
{
	public:
	virtual const char* GetName () { return "MbedTLS"; }
	virtual std::vector<uint_8> DoAES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
	virtual std::vector<uint_8> DoDES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
	virtual std::vector<uint_8> DoRSA_KeyFile ( std::vector<uint_8> const & input, const char* keyInPemFormat, FLAGS& flags ); 
	virtual std::vector<uint_8> DoRSA_KeyGen ( std::vector<uint_8> const & input, int numbits, FLAGS& flags ); 
	virtual std::vector<uint_8> DoRSA_ned ( std::vector<uint_8> const & input, std::vector<uint_8>& n, std::vector<uint_8>& e, std::vector<uint_8>& d, FLAGS& flags );
	virtual std::vector<uint_8> DoRSA_epq ( std::vector<uint_8> const & input, std::vector<uint_8>& e, std::vector<uint_8>& p, std::vector<uint_8>& q, FLAGS& flags );
};
class LibGCrypt : public CryptoImplementation
{
	public:
	virtual const char* GetName () { return "LibGCrypt"; }
	//virtual std::vector<uint_8> DoAES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
	//virtual std::vector<uint_8> DoDES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
	virtual std::vector<uint_8> DoSymmetric ( const char* name, std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
	virtual std::vector<uint_8> DoRSA_KeyGen ( std::vector<uint_8> const & input, int numbits, FLAGS& flags ); 
	virtual std::vector<uint_8> DoRSA_ned ( std::vector<uint_8> const & input, std::vector<uint_8>& n, std::vector<uint_8>& e, std::vector<uint_8>& d, FLAGS& flags );
	virtual std::vector<uint_8> DoRSA_epq ( std::vector<uint_8> const & input, std::vector<uint_8>& e, std::vector<uint_8>& p, std::vector<uint_8>& q, FLAGS& flags );
};
class TexasInstrumentsImplementation : public CryptoImplementation
{
	public:
	virtual const char* GetName () { return "TexasInstruments"; }
	virtual std::vector<uint_8> DoAES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
	virtual std::vector<uint_8> DoDES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
	//virtual std::vector<uint_8> DoSymmetric ( const char* name,  std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
};
class OpenSSL : public CryptoImplementation
{
	public:
	virtual const char* GetName () { return "OpenSSL"; }
	virtual std::vector<uint_8> DoAES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
	virtual std::vector<uint_8> DoDES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
	//virtual std::vector<uint_8> DoSymmetric ( const char* name, std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
};
class SmartCardAES : public CryptoImplementation
{
	public:
	virtual const char* GetName () { return "SmartCardAES"; }
	virtual std::vector<uint_8> DoAES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
	virtual std::vector<uint_8> DoDES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
	//virtual std::vector<uint_8> DoSymmetric ( const char* name, std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
};
class WolfCrypt : public CryptoImplementation
{
	public:
	virtual const char* GetName () { return "WolfCrypt"; }
	virtual std::vector<uint_8> DoAES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
	virtual std::vector<uint_8> DoDES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
	//virtual std::vector<uint_8> DoSymmetric ( const char* name, std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
	virtual std::vector<uint_8> DoRSA_ned ( std::vector<uint_8> const & input, std::vector<uint_8>& n, std::vector<uint_8>& e, std::vector<uint_8>& d, FLAGS& flags );
	virtual std::vector<uint_8> DoRSA_epq ( std::vector<uint_8> const & input, std::vector<uint_8>& e, std::vector<uint_8>& p, std::vector<uint_8>& q, FLAGS& flags );
};
class TomCrypt : public CryptoImplementation
{
	public:
	virtual const char* GetName () { return "TomCrypt"; }
	virtual std::vector<uint_8> DoAES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
	virtual std::vector<uint_8> DoDES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
	//virtual std::vector<uint_8> DoSymmetic ( const char* name, std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
	virtual std::vector<uint_8> DoRSA_ned ( std::vector<uint_8> const & input, std::vector<uint_8>& n, std::vector<uint_8>& e, std::vector<uint_8>& d, FLAGS& flags );
	virtual std::vector<uint_8> DoRSA_epq ( std::vector<uint_8> const & input, std::vector<uint_8>& e, std::vector<uint_8>& p, std::vector<uint_8>& q, FLAGS& flags );
};
class KernelCrypto : public CryptoImplementation
{
	public:
	virtual const char* GetName () { return "KernelCrypto"; }
	virtual std::vector<uint_8> DoAES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
	virtual std::vector<uint_8> DoDES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
	virtual std::vector<uint_8> DoSymmetric ( const char* name, std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS& flags ); 
};
