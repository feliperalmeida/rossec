#include "rossec/rossec.h"

using std::cout;
using std::endl;
using std::cerr;

using CryptoPP::StringSource;
using CryptoPP::StringSink;

rossec::AESCBC::AESCBC(byte *newkey) {
    // Constructor
    this->key_size = CryptoPP::AES::DEFAULT_KEYLENGTH;
    this->iv_size = CryptoPP::AES::BLOCKSIZE;
    this->prng = new CryptoPP::AutoSeededRandomPool();

    iv = (byte*) malloc(iv_size * sizeof(byte));
    prng->GenerateBlock(iv, iv_size );

    key = (byte*) malloc(key_size * sizeof(byte));
    this->setKey(newkey);
}

rossec::AESCBC::~AESCBC(void) {
    memset(key, '0', key_size);
    free(prng);
    // Destructor
}

bool rossec::AESCBC::setKey (byte newkey[], int newsize) {
    if (key_size != newsize) {
        if ((key = (byte*) malloc(newsize * sizeof(byte)) ) == NULL)
            return false;
        key_size = newsize;
    }
    memcpy(key, newkey, key_size);
    e.SetKeyWithIV( key, key_size, iv, iv_size );
    return true;
}

string rossec::AESCBC::getKeyHexString() {
    string encoded;
    StringSource( key, key_size, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink( encoded )
        ) // HexEncoder
    ); // StringSource
    return encoded;
}

string rossec::AESCBC::getIvHexString() {
    string encoded;
    StringSource( iv, iv_size, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink( encoded )
        ) // HexEncoder
    ); // StringSource
    return encoded;
}

string rossec::AESCBC::getHexString(string msg) {
    string encoded;
    StringSource( msg, true,
        new CryptoPP::HexEncoder(
            new StringSink( encoded )
        ) // HexEncoder
    ); // StringSource
    return encoded;
}

string rossec::AESCBC::encryptString(string msg) {
    string cipher;
    string final;

    try
    {
        //CBC_Mode< AES >::Encryption e;

        e.SetKeyWithIV(key, key_size, iv, iv_size);

        //The StreamTransformationFilter removes padding as required.
        StringSource s(msg, true,
            new CryptoPP::StreamTransformationFilter(e,
                new StringSink(cipher)
            ) // StreamTransformationFilter
        ); // StringSource

        std::string s_iv(reinterpret_cast<char const*>(iv), iv_size);

        final = s_iv + cipher;

        e.GetNextIV(*prng, iv);
        e.Resynchronize(iv);

        return final;
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    return "Error.";
}

string rossec::AESCBC::decryptString(string msg) {

    int ciphertextLength = msg.size() - iv_size;

    string cipher, s_iv;
    string rpdata;
    //string encoded;

    s_iv.resize(iv_size);
    cipher.resize(ciphertextLength);

    for(int i = 0; i < iv_size; i++)
        s_iv[i] = msg[i];

    for(int i = 0; i < ciphertextLength; i++)
        cipher[i] = msg[i + iv_size];

    try
    {
        //CBC_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, key_size, (const byte*) s_iv.c_str(), iv_size);

        // The StreamTransformationFilter removes padding as required.
        StringSource s(cipher, true,
            new CryptoPP::StreamTransformationFilter(d,
                new StringSink(rpdata)
            ) // StreamTransformationFilter
        ); // StringSource

        return rpdata;
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    return "Error.";
}
