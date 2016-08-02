#ifndef ROSSEC
#define ROSSEC

#include <iostream>
#include <string>
using std::string;

#include "cryptopp/hex.h"
#include "cryptopp/osrng.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
#include "cryptopp/gcm.h"
#include "cryptopp/ccm.h"

namespace rossec
{

class AESGCM
{
public:
    AESGCM(byte new_key[]);
    ~AESGCM(void);
    string encryptString(string msg);
    string decryptString(string msg);
    bool setKey (byte new_key[], int new_size=CryptoPP::AES::DEFAULT_KEYLENGTH);
    string getKeyHexString();
    string getIVHexString();
    string getHexString(string msg);

    const static int DEFAULT_KEYLENGTH = CryptoPP::AES::DEFAULT_KEYLENGTH;

private:
    int key_size_;
    int iv_size_;
    byte *iv_;
    CryptoPP::AutoSeededRandomPool *prng_;
    byte *key_;
    const static int TAG_SIZE = 12;

    CryptoPP::GCM<CryptoPP::AES>::Encryption e_;
    CryptoPP::GCM<CryptoPP::AES>::Decryption d_;

};

class AESCBC
{
public:
    AESCBC(byte new_key[]);
    ~AESCBC(void);
    string encryptString(string msg);
    string decryptString(string msg);
    bool setKey (byte new_key[], int new_size=CryptoPP::AES::DEFAULT_KEYLENGTH);
    string getKeyHexString();
    string getIVHexString();
    string getHexString(string msg);

    const static int DEFAULT_KEYLENGTH = CryptoPP::AES::DEFAULT_KEYLENGTH;

private:
    int key_size_;
    int iv_size_;
    byte *iv_;
    CryptoPP::AutoSeededRandomPool *prng_;
    byte *key_;

    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e_;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d_;

};

}

#endif // ROSSEC


