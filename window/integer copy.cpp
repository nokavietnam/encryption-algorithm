//  Defines the entry point for the console application
/*ECC parameters p,a,b, P (or G), n, h where p=h.n*/

/* Source, Sink */
#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include <ctime>
#include <iostream>
#include <string>
using namespace std;

/* Randomly generator*/
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

/* Integer arithmatics*/
#include <cryptopp/integer.h>
using CryptoPP::Integer;

#include <cryptopp/nbtheory.h>
using CryptoPP::ModularSquareRoot;

#include <cryptopp/modarith.h> // Z_p
using CryptoPP::ModularArithmetic;

#include <cryptopp/pubkey.h>
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
// hex convert
#include <cryptopp/hex.h>
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool; // random number generator

// File operation
#include <cryptopp/files.h>
#include <sstream>
using std::ostringstream;

// Set location
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

/* Print large interger number */
string integer_to_string(const CryptoPP::Integer &t);
wstring integer_to_wstring(const CryptoPP::Integer &t);

int main(int argc, char *argv[])
{
  // Construct an Integer from a base 10 string
  Integer a("012345678");
  Integer b("012345678.");

  // Construct an Integer from a base 16 string
  Integer c("0x01234567");
  Integer d("01234567h");

  // Construct an Integer from a base 8 string
  Integer e("01234567o");

  // large numbers
  Integer x("81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822H");
  Integer y("7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892H");

  // prime number
  Integer p("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3H");

  cout << "number a=" << a << endl;
  cout << "number b=" << b << endl;
  cout << "number c=" << c << endl;
  cout << "number d=" << d << endl;
  cout << "number e=" << e << endl;
  cout << "number x=" << x << endl;
  cout << "number y=" << y << endl;
  cout << "prime number p=" << p << endl;
  // compute mod p in Z_p
  ModularArithmetic ma(p); // mod p
  cout << "x+y mod p: " << ma.Add(x, y) << endl;
  cout << "x-y mod p: " << ma.Subtract(x, y) << endl;
  cout << "x*y mod p: " << ma.Multiply(x, y) << endl;
  cout << "x/y mod p: " << ma.Divide(x, y) << endl;
  cout << "x%y mod p: " << ma.Reduce(x, y) << endl;
  cout << "x^y mod p: " << ma.Exponentiate(x, y) << endl;
  cout << "x1=x^-1 mod p: " << ma.Divide(1, x) << endl;
  Integer x1("1958569211444031162104289660421262539500678100766128832735.");
  cout << "x*x1 mod p: " << ma.Multiply(x, x1) << endl;

  // Message to string
  string ss;
  cout << "input message:";
  getline(cin, ss);
  string hexss;
  StringSource(ss, true, new HexEncoder(new StringSink(hexss)));
  hexss = hexss + "H";
  cout << "string to hex:" << hexss << endl;
  Integer h(hexss.data()); // yes
  cout << "number from string  h=" << h << endl;
  wcout << "wstring  h:" << integer_to_wstring(h) << endl;

  string destination;
  HexDecoder decoder(new StringSink(destination));
  // cout << hexss.data() << endl;
  // cout << hexss.size() - 1 << endl;

  string messageout = integer_to_string(h);

  HexDecoder decoder(new StringSink(messageout));
  decoder.Put(messageout.data(), messageout.size() - 1);
  decoder.MessageEnd();

  cout << messageout << endl;

  // decoder.Put((byte *)hexss.data(), hexss.size());
  // decoder.MessageEnd();
}

wstring integer_to_wstring(const CryptoPP::Integer &t)
{
  std::ostringstream oss;
  oss.str("");
  oss.clear();
  oss << t;
  std::string encoded(oss.str());
  std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
  return towstring.from_bytes(encoded);
}

string integer_to_string(const CryptoPP::Integer &t)
{
  std::ostringstream oss;
  oss.str("");
  oss.clear();
  oss << t;
  std::string encoded(oss.str());
  return encoded;
}