#include "rossec/rossec.h"

using std::endl;
using std::cerr;

using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::HexEncoder;

rossec::AESCBC::AESCBC(byte *new_key)
{
    // Constructor
    key_size_ = CryptoPP::AES::DEFAULT_KEYLENGTH;
    iv_size_ = CryptoPP::AES::BLOCKSIZE;
    prng_ = new CryptoPP::AutoSeededRandomPool();

    iv_ = (byte*) malloc(iv_size_ * sizeof(byte));
    prng_->GenerateBlock(iv_, iv_size_);

    key_ = (byte*) malloc(key_size_ * sizeof(byte));
    this->setKey(new_key);
}

rossec::AESCBC::~AESCBC(void)
{
    memset(key_, '0', key_size_);
    free(prng_);
    // Destructor
}

bool rossec::AESCBC::setKey(byte new_key[], int new_size)
{
    if (key_size_ != new_size)
    {
        if ((key_ = (byte*) malloc(new_size * sizeof(byte))) == NULL)
            return false;
        key_size_ = new_size;
    }
    memcpy(key_, new_key, key_size_);
    e_.SetKeyWithIV(key_, key_size_, iv_, iv_size_);
    return true;
}

string rossec::AESCBC::getKeyHexString()
{
    string encoded;
    StringSource(key_, key_size_, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    return encoded;
}

string rossec::AESCBC::getIVHexString()
{
    string encoded;
    StringSource(iv_, iv_size_, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    return encoded;
}

string rossec::AESCBC::getHexString(string msg)
{
    string encoded;
    StringSource(msg, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    return encoded;
}

string rossec::AESCBC::encryptString(string msg)
{
    string cipher;
    string final;

    try
    {
        e_.SetKeyWithIV(key_, key_size_, iv_, iv_size_);

        //The StreamTransformationFilter removes padding as required.
        StringSource s(msg, true,
            new CryptoPP::StreamTransformationFilter(e_,
                new StringSink(cipher)
            ) // StreamTransformationFilter
        ); // StringSource

        std::string s_iv(reinterpret_cast<char const*>(iv_), iv_size_);

        final = s_iv + cipher;

        e_.GetNextIV(*prng_, iv_);
        e_.Resynchronize(iv_);

        return final;
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    return "Error.";
}

string rossec::AESCBC::decryptString(string msg)
{
    int ciphertext_length = msg.size() - iv_size_;

    string cipher, s_iv;
    string recovered_plaintext;

    s_iv.resize(iv_size_);
    cipher.resize(ciphertext_length);

    for(int i = 0; i < iv_size_; i++)
        s_iv[i] = msg[i];

    for(int i = 0; i < ciphertext_length; i++)
        cipher[i] = msg[i + iv_size_];

    try
    {
        d_.SetKeyWithIV(key_, key_size_, (const byte*) s_iv.c_str(), iv_size_);

        // The StreamTransformationFilter removes padding as required.
        StringSource s(cipher, true,
            new CryptoPP::StreamTransformationFilter(d_,
                new StringSink(recovered_plaintext)
            ) // StreamTransformationFilter
        ); // StringSource

        return recovered_plaintext;
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    return "Error.";
}
