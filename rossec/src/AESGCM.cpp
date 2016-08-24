#include "rossec/rossec.h"

using std::endl;
using std::cerr;

using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::HexEncoder;

rossec::AESGCM::AESGCM(byte *new_key)
{
    key_size_ = CryptoPP::AES::DEFAULT_KEYLENGTH;
    iv_size_ = CryptoPP::AES::BLOCKSIZE;
    prng_ = new CryptoPP::AutoSeededRandomPool();

    iv_ = (byte*) malloc(iv_size_ * sizeof(byte));
    prng_->GenerateBlock(iv_, iv_size_);

    key_ = (byte*) malloc(key_size_ * sizeof(byte));
    this->setKey(new_key);
}

rossec::AESGCM::~AESGCM(void)
{
    memset(key_, '0', key_size_);
    memset(iv_, '0', iv_size_);
    free(key_);
    free(iv_);
    free(prng_);
}

bool rossec::AESGCM::setKey(byte new_key[], int new_size)
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

string rossec::AESGCM::getKeyHexString()
{
    string encoded;
    StringSource(key_, key_size_, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    return encoded;
}

string rossec::AESGCM::getIVHexString()
{
    string encoded;
    StringSource(iv_, iv_size_, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    return encoded;
}

string rossec::AESGCM::getHexString(string msg)
{
    string encoded;
    StringSource(msg, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    return encoded;
}

string rossec::AESGCM::encryptString(string msg)
{
    string cipher;
    string final;

    try
    {
        e_.SetKeyWithIV(key_, key_size_, iv_, iv_size_);

        StringSource(msg, true,
            new CryptoPP::AuthenticatedEncryptionFilter(e_,
                new StringSink(cipher), false, TAG_SIZE
            ) // AuthenticatedEncryptionFilter
        ); // StringSource

    std::string s_iv(reinterpret_cast<char const*>(iv_), iv_size_);
    final = s_iv + cipher;

    e_.GetNextIV(*prng_, iv_);
    e_.Resynchronize(iv_);

    return final;

    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    return "Error.";
}

string rossec::AESGCM::decryptString(string msg)
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

        CryptoPP::AuthenticatedDecryptionFilter df(d_,
            new StringSink(recovered_plaintext),
                CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS, TAG_SIZE
        ); // AuthenticatedDecryptionFilter

        // The StringSource dtor will be called immediately
        //  after construction below. This will cause the
        //  destruction of objects it owns. To stop the
        //  behavior so we can get the decoding result from
        //  the DecryptionFilter, we must use a redirector
        //  or manually Put(...) into the filter without
        //  using a StringSource.
        StringSource(cipher, true,
            new CryptoPP::Redirector(df)
        ); // StringSource

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        bool b = df.GetLastResult();
        assert( true == b );

       return recovered_plaintext;

    }
    catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e )
    {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    return "Error.";
}
