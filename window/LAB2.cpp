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
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;

#include "cryptopp/xts.h"
using CryptoPP::XTS_Mode;

// #include "cryptopp/ccm.h"
// using CryptoPP::CCM_Mode;

// #include "cryptopp/gcm.h"
// using CryptoPP::GCM_Mode;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include "assert.h"


// lib caculator time run
#include <chrono>
using std::chrono::high_resolution_clock;
 

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

  /*
   * Select Mode
   */
  wstring wsmode;
  wcout << "Enter your mode:" << endl;
  wcout << "ECB --> Enter 1" << endl;
  wcout << "CBC --> Enter 2" << endl;
  wcout << "CFB --> Enter 3" << endl;
  wcin.ignore();
  getline(wcin, wsmode);
  string mode = ws2s(wsmode);
  try
  {
    switch (std::stoi(mode))
    {
    case 1:
      wcout << "Mode ECB";
      break;
    case 2:
      wcout << "Mode CBC";
      break;
    case 3:
      wcout << "Mode CFB";
      break;
    default:
      wcout << "Mode Unknow";
      break;
    }
  }
  catch (const CryptoPP::Exception &e)
  {
    cerr << e.what() << endl;
    exit(1);
  }

  /*
   *
   */

  AutoSeededRandomPool prng;
  byte key[32];
  // byte fkey[32];

  // prng.GenerateBlock(fkey, sizeof(fkey));
  // StringSource ss(fkey, sizeof(fkey), true, new FileSink("AES_key.key"));

  // FileSource fs("AES_key.key", false);

  // CryptoPP::ArraySink copykey(key, sizeof(key));
  // fs.Detach(new Redirector(copykey));
  // fs.Pump(sizeof(key));

  byte iv[AES::BLOCKSIZE];
  prng.GenerateBlock(iv, sizeof(iv));

  string cipher, encoded, recovered;
  encoded.clear();
  StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
  wcout << "Key: " << s2ws(encoded) << endl;

  wstring wsplain;
  wcout << "Enter your plain text: ";
  //  wcin.ignore();
  getline(wcin, wsplain);
  string plaintext = ws2s(wsplain);

  wcout << "Your plain text: " << s2ws(plaintext);

  // wstring wsmode;
  // wcout << "Enter your mode:" << endl;
  // wcout << "ECB --> Enter 1" << endl;
  // wcout << "CBC --> Enter 2" << endl;
  // wcout << "CFB --> Enter 3" << endl;
  // wcin.ignore();
  // getline(wcin, wsmode);
  // string mode = ws2s(wsmode);
  // try
  // {
  //   switch (std::stoi(mode))
  //   {
  //   case 1:
  //     wcout << "Mode ECB";
  //     break;
  //   case 2:
  //     wcout << "Mode CBC";
  //     break;
  //   case 3:
  //     wcout << "Mode CFB";
  //     break;
  //   default:
  //     wcout << "Mode Unknow";
  //     break;
  //   }
  // }
  // catch (const CryptoPP::Exception &e)
  // {
  //   cerr << e.what() << endl;
  //   exit(1);
  // }

  encoded.clear();
  StringSource(key, sizeof(key), true,
               new HexEncoder(
                   new StringSink(encoded)));

  wcout << "key: " << s2ws(encoded) << endl;

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

byte readfile(const char *filename, const int size)
{
  byte data[size];
  FileSource fs(filename, false);
  CryptoPP::ArraySink copykey(data, sizeof(data));
  fs.Detach(new Redirector(copykey));
  fs.Pump(size);
}