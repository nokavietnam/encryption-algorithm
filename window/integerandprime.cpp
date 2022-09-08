//  Defines the entry point for the console application
/*ECC parameters p,a,b, P (or G), n, h where p=h.n*/

// C++ library
#include <ctime>
#include <iostream>
#include <string>
using namespace std;
// integer convert to string
#include <sstream>
using std::ostringstream;

// cryptopp library
/* Randomly generator*/
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

/* string Source, Sink */
#include "cryptopp/filters.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::PK_DecryptorFilter; // Public key decryption
using CryptoPP::PK_EncryptorFilter; // Public key encryption
using CryptoPP::StringSink;
using CryptoPP::StringSource;

// Genererate keys
#include "cryptopp/cryptlib.h"
using CryptoPP::DecodingResult;
using CryptoPP::Exception;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;

/*Reading key input from file*/
#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

/* Integer arithmatics*/
#include <cryptopp/integer.h>
using CryptoPP::Integer;

#include <cryptopp/nbtheory.h>
using CryptoPP::ModularSquareRoot;
using CryptoPP::PrimeAndGenerator;
#include <cryptopp/modarith.h> // compute in Z_p
using CryptoPP::ModularArithmetic;
// public key
#include <cryptopp/pubkey.h>
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
// hex convert
#include <cryptopp/hex.h>
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

// File operation
#include <cryptopp/files.h>

/* Set _setmode()*/
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

// Set location
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

/* RSA cipher*/
#include "cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_PKCS1v15_Decryptor;
using CryptoPP::RSAES_PKCS1v15_Encryptor;

// functions
wstring s2ws(const std::string &str);
string ws2s(const std::wstring &str);
wstring in2ws(const CryptoPP::Integer &t);
string in2s(const CryptoPP::Integer &t);

int main(int argc, char *argv[])
{

  // key generator
  AutoSeededRandomPool prng;
  RSA::PrivateKey rsaprivateKey;
  rsaprivateKey.GenerateRandomWithKeySize(prng, 3072);
  RSA::PublicKey rsapublicKey(rsaprivateKey);
  /* Pretty print system parameters */
  Integer modul = rsaprivateKey.GetModulus(); // modul n
  Integer prime1 = rsaprivateKey.GetPrime1(); // prime p
  Integer prime2 = rsaprivateKey.GetPrime2(); // prime p
  wcout << "modul n=p.q: " << in2ws(modul) << endl;
  wcout << "prime number p: " << in2ws(prime1) << endl;
  wcout << "prime number q: " << in2ws(prime2) << endl;
  /* Secret exponent d; public exponent e */
  Integer SK = rsaprivateKey.GetPrivateExponent(); // secret exponent d;
  Integer PK = rsapublicKey.GetPublicExponent();   // public exponent e;
  wcout << "secret key d: " << in2ws(SK) << endl;
  wcout << "public key e: " << in2ws(PK) << endl;
  /* Check the keys */
  ModularArithmetic ma(modul); // mod n
  Integer ncheck = ma.Multiply(prime1, prime2);
  wcout << "p.q=n?: " << in2ws(ncheck) << endl;
}

/* convert string to wstring */
wstring s2ws(const std::string &str)
{
  wstring_convert<codecvt_utf8<wchar_t>> towstring;
  return towstring.from_bytes(str);
}

/* convert wstring to string */
string ws2s(const std::wstring &str)
{
  wstring_convert<codecvt_utf8<wchar_t>> tostring;

  return tostring.to_bytes(str);
}
wstring in2ws(const CryptoPP::Integer &t)
{
  std::ostringstream oss;
  oss.str("");
  oss.clear();
  oss << t;
  std::string encoded(oss.str());
  std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
  return towstring.from_bytes(encoded);
}

string in2s(const CryptoPP::Integer &t)
{
  std::ostringstream oss;
  oss.str("");
  oss.clear();
  oss << t;
  std::string encoded(oss.str());
  return encoded;
}