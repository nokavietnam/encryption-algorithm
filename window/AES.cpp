// herders from cpp
#include <iostream>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;
using std::wcin;
using std::wcout;

#include <string>
using std::string;
using std::wstring;

/* Convert string*/
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

/* Set mode */
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

// external header library
/* cryptp library */
#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;

/* string  Transformation*/
#include "cryptopp/filters.h"
using CryptoPP::Redirector;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

/* file input, output*/
#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

/* hex converted */
#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;
/* base64 converted */
#include "cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

/* import lib des */
#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/ccm.h"
using CryptoPP::CBC_Mode;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "assert.h"

// prototype function
/* convert string to wstring */
wstring s2ws(const std::string &str);

/* convert wstring to string */
string ws2s(const std::wstring &str);

int main(int argc, char *argv[])
{
#ifdef __linux__
  setlocale(LC_ALL, "");
#elif _WIN32
  _setmode(_fileno(stdin), _O_U16TEXT);
  _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif

  AutoSeededRandomPool prng;
  CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
  prng.GenerateBlock(key, sizeof(key));

  CryptoPP::byte iv[AES::BLOCKSIZE];
  prng.GenerateBlock(iv, sizeof(iv));

  string plainText = "CBC Mode Test";
  string cipherText, encoded, recovered;

  encoded.clear();

  // StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
  cout << "iv: " << iv << endl;
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
