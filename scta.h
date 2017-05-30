#include <vector>
#include <stdio.h>

typedef unsigned char uint_8;
typedef enum 
{
	NONE,
	ENCRYPT = 1,
	PRINT_INTERMEDIATE_VALUES = 2,
} FLAGS;

class CryptoImplementation
{
	public:
	virtual const char* GetName () = 0;
	void Log ( const char* alg, std::vector<uint_8> const& input, std::vector<uint_8> const& output, std::vector<uint_8>const & key, FLAGS flags );
	std::vector<uint_8> DoAESWithLogging ( std::vector<uint_8> const& input, std::vector<uint_8> const& key, FLAGS flags = NONE )
	{ 	
		std::vector<uint_8> output = DoAES ( input, key, flags );
		Log ( "AES", input, output, key, flags );
		return output;
	}
	std::vector<uint_8> DoDESWithLogging ( std::vector<uint_8>const & input, std::vector<uint_8>const& key, FLAGS flags = NONE )
	{
		std::vector<uint_8> output  = DoDES ( input, key, flags ); 
		Log ( "DES", input, output, key, flags );
		return output;
	}
	virtual std::vector<uint_8> DoAES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS flags ) = 0 ; 
	virtual std::vector<uint_8> DoDES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS flags ) = 0 ; 
};

class SimpleSoftwareImplementation : public CryptoImplementation
{
	public:
	virtual const char* GetName () { return "SimpleSoftware"; }
	virtual std::vector<uint_8> DoAES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS flags ); 
	virtual std::vector<uint_8> DoDES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS flags ); 
};
class MbedTLSImplementation : public CryptoImplementation
{
	public:
	virtual const char* GetName () { return "MbedTLS"; }
	virtual std::vector<uint_8> DoAES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS flags ); 
	virtual std::vector<uint_8> DoDES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS flags ); 
};
class TexasInstrumentsImplementation : public CryptoImplementation
{
	public:
	virtual const char* GetName () { return "TexasInstruments"; }
	virtual std::vector<uint_8> DoAES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS flags ); 
	virtual std::vector<uint_8> DoDES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS flags ); 
};
class OpenSSL : public CryptoImplementation
{
	public:
	virtual const char* GetName () { return "OpenSSL"; }
	virtual std::vector<uint_8> DoAES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS flags ); 
	virtual std::vector<uint_8> DoDES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS flags ); 
};
class SmartCardAES : public CryptoImplementation
{
	public:
	virtual const char* GetName () { return "SmartCardAES"; }
	virtual std::vector<uint_8> DoAES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS flags ); 
	virtual std::vector<uint_8> DoDES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS flags ); 
};
class WolfCrypt : public CryptoImplementation
{
	public:
	virtual const char* GetName () { return "WolfCrypt"; }
	virtual std::vector<uint_8> DoAES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS flags ); 
	virtual std::vector<uint_8> DoDES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS flags ); 
};
class TomCrypt : public CryptoImplementation
{
	public:
	virtual const char* GetName () { return "TomCrypt"; }
	virtual std::vector<uint_8> DoAES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS flags ); 
	virtual std::vector<uint_8> DoDES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS flags ); 
};
class KernelCrypto : public CryptoImplementation
{
	public:
	virtual const char* GetName () { return "KernelCrypto"; }
	virtual std::vector<uint_8> DoAES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS flags ); 
	virtual std::vector<uint_8> DoDES ( std::vector<uint_8> const & input, std::vector<uint_8> const& key, FLAGS flags ); 
};
