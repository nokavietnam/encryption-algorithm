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

#include "cryptopp/modes.h"
//#include "cryptopp/ccm.h"
using CryptoPP::CBC_CTS_Mode;
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;

#include "cryptopp/xts.h"
using CryptoPP::XTS;

#include "cryptopp/gcm.h"
using CryptoPP::GCM;

#include "cryptopp/ccm.h"
using CryptoPP::GCM;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "assert.h"

using namespace CryptoPP;

// prototype function
/* convert string to wstring */
wstring s2ws(const std::string &str);

/* convert wstring to string */
string ws2s(const std::wstring &str);

enum eMode
{
  UNKNOW,
  _ECB,
  _CBC,
  _OFB,
  _CFB,
  _CTR,
  _XTS,
  _CCM,
  _GCM
};

/* Encryp Function */
string encrypt(eMode mode, byte *key, size_t keyLengh, byte *iv, string plaintext);

/* Descryp Function */
string decrypt(eMode mode, byte *key, size_t keyLengh, byte *iv, string cipher);

eMode s2e(string mode);

int main(int argc, char *argv[])
{
#ifdef __linux__
  setlocale(LC_ALL, "");
#elif __APPLE__
#if TARGET_OS_MAC
  setlocale(LC_ALL, "");
#else
#endif
#elif _WIN32
  _setmode(_fileno(stdin), _O_U16TEXT);
  _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif

  wstring wsplain;
  wcout << "Enter your plain text: ";
  //  wcin.ignore();
  getline(wcin, wsplain);
  string plaintext = ws2s(wsplain);
  wcout << "Your plain text: " << s2ws(plaintext) << endl;

  string modeSelect, keySelect, ivSelect;
  wstring wsmode, wskey, wsiv;

  /* select mode */
  wcout << "Enter your mode(ECB, CBC, OFB, CFB, CTR, XTS, CCM, GCM):" << endl;
  wcin.ignore();
  getline(wcin, wsmode);
  modeSelect = ws2s(wsmode);

  AutoSeededRandomPool prng;

  /* select key */
  wcout << "Select option input key (1: random, 2: enter, 3:file):";
  wcin.ignore();
  getline(wcin, wskey);
  keySelect = ws2s(wskey);

  byte key[AES::DEFAULT_KEYLENGTH];
  prng.GenerateBlock(key, sizeof(key));

  /* select iv */
  wcout << "Select option input iv (1: random, 2: enter, 3:file): ";
  wcin.ignore();
  getline(wcin, wsiv);
  ivSelect = ws2s(wsiv);

  byte iv[AES::BLOCKSIZE];
  prng.GenerateBlock(iv, sizeof(iv));

  string cipher, encoded, recovered;
  eMode mode = s2e(modeSelect);
  encoded.clear();
  StringSource(key, sizeof(key), true,
               new HexEncoder(
                   new StringSink(encoded)));
  wcout << "key: " << s2ws(encoded) << endl;

  encoded.clear();
  StringSource(iv, sizeof(iv), true,
               new HexEncoder(
                   new StringSink(encoded)));
  wcout << "iv: " << s2ws(encoded) << endl;

  /* encrypt */
  cipher = encrypt(mode, key, sizeof(key), iv, plaintext);
  encoded.clear();
  StringSource(cipher, true,
               new HexEncoder(
                   new StringSink(encoded)));
  wcout << "cipher text: " << s2ws(encoded) << endl;
  /* descrypt */
  recovered = decrypt(mode, key, sizeof(key), iv, cipher);
  wcout << "plain text: " << s2ws(recovered) << endl;
  return 0;
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

string encrypt(eMode mode, byte *key, size_t keyLengh, byte *iv, string plaintext)
{
  string ciphertext, encoded;

  switch (mode)
  {
  case _CBC:
    try
    {
      CBC_Mode<AES>::Encryption e;
      e.SetKeyWithIV(key, keyLengh, iv);
      StringSource s(plaintext, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(ciphertext)));
    }
    catch (const Exception &e)
    {
      return NULL;
    }
    break;
  case _ECB:
    try
    {
      ECB_Mode<AES>::Encryption e;
      e.SetKeyWithIV(key, keyLengh, iv);
      StringSource s(plaintext, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(ciphertext)));
    }
    catch (const Exception &e)
    {
      return NULL;
    }
  default:
    break;
  }

  return ciphertext;
}

string decrypt(eMode mode, byte *key, size_t keyLengh, byte *iv, string cipher)
{
  string plaintext;
  switch (mode)
  {
  case _CBC:
    try
    {
      CBC_Mode<AES>::Decryption d;
      d.SetKeyWithIV(key, keyLengh, iv);
      StringSource s(cipher, true,
                     new StreamTransformationFilter(d,
                                                    new StringSink(plaintext)) // StreamTransformationFilter
      );                                                                       // StringSource
    }
    catch (const Exception &e)
    {
      return NULL;
    }
    break;
  case _ECB:
    try
    {
      ECB_Mode<AES>::Decryption d;
      d.SetKeyWithIV(key, keyLengh, iv);
      StringSource s(cipher, true,
                     new StreamTransformationFilter(d,
                                                    new StringSink(plaintext)) // StreamTransformationFilter
      );                                                                       // StringSource
    }
    catch (const Exception &e)
    {
      return NULL;
    }
    break;
  default:
    return "mode not supported!!";
  }

  return plaintext;
}

eMode s2e(string mode)
{
  if (mode == "ECB")
    return eMode::_ECB;
  if (mode == "CBC")
    return eMode::_CBC;
  if (mode == "OFB")
    return eMode::_OFB;
  if (mode == "CFB")
    return eMode::_CFB;
  if (mode == "CTR")
    return eMode::_CTR;
  if (mode == "XTS")
    return eMode::_XTS;
  if (mode == "CCM")
    return eMode::_CCM;
  if (mode == "GCB")
    return eMode::_GCM;
  return eMode::UNKNOW;
}