#ifndef ROSSEC
#define ROSSEC

#include "ros/ros.h"
#include "std_msgs/String.h"

#include <sstream>
#include <iostream>

#include <string>

#include "cryptopp/hex.h"
#include "cryptopp/osrng.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
#include "cryptopp/gcm.h"
#include "cryptopp/ccm.h"
#include "assert.h"

using std::string;


namespace rossec
{

class AESGCM {
public:
    AESGCM(byte newkey[]);
    ~AESGCM(void);
    string encryptString(string msg);
    string decryptString(string msg);
    bool setKey (byte newkey[], int newsize=CryptoPP::AES::DEFAULT_KEYLENGTH);
    string getKeyHexString();
    string getIvHexString();
    string getHexString(string msg);

    const static int DEFAULT_KEYLENGTH = CryptoPP::AES::DEFAULT_KEYLENGTH;

private:
    int key_size;
    int iv_size;
    byte *iv;
    CryptoPP::AutoSeededRandomPool *prng;
    byte *key;
    const static int TAG_SIZE = 12;

    CryptoPP::GCM< CryptoPP::AES >::Encryption e;
    CryptoPP::GCM< CryptoPP::AES >::Decryption d;

};

class AESCBC {
public:
    AESCBC(byte newkey[]);
    ~AESCBC(void);
    string encryptString(string msg);
    string decryptString(string msg);
    bool setKey (byte newkey[], int newsize=CryptoPP::AES::DEFAULT_KEYLENGTH);
    string getKeyHexString();
    string getIvHexString();
    string getHexString(string msg);

    const static int DEFAULT_KEYLENGTH = CryptoPP::AES::DEFAULT_KEYLENGTH;

private:
    int key_size;
    int iv_size;
    byte *iv;
    CryptoPP::AutoSeededRandomPool *prng;
    byte *key;

    CryptoPP::CBC_Mode< CryptoPP::AES >::Encryption e;
    CryptoPP::CBC_Mode< CryptoPP::AES >::Decryption d;

};

}

#endif // ROSSEC


