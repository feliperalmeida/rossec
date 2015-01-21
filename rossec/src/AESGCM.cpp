#include "rossec/rossec.h"

using std::cout;
using std::endl;
using std::cerr;

using CryptoPP::StringSource;
using CryptoPP::StringSink;

rossec::AESGCM::AESGCM(byte *newkey) {
    // Constructor
    this->key_size = CryptoPP::AES::DEFAULT_KEYLENGTH;
    this->iv_size = CryptoPP::AES::BLOCKSIZE;
    this->prng = new CryptoPP::AutoSeededRandomPool();

    iv = (byte*) malloc(iv_size * sizeof(byte));
    prng->GenerateBlock(iv, iv_size );

    key = (byte*) malloc(key_size * sizeof(byte));
    this->setKey(newkey);
}

rossec::AESGCM::~AESGCM(void) {
    memset(key, '0', key_size);
    free(prng);
    // Destructor
}

bool rossec::AESGCM::setKey (byte newkey[], int newsize) {
    if (key_size != newsize) {
        if ((key = (byte*) malloc(newsize * sizeof(byte)) ) == NULL)
            return false;
        key_size = newsize;
    }
    memcpy(key, newkey, key_size);
    e.SetKeyWithIV( key, key_size, iv, iv_size );
    return true;
}

string rossec::AESGCM::getKeyHexString() {
    string encoded;
    StringSource( key, key_size, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink( encoded )
        ) // HexEncoder
    ); // StringSource
    return encoded;
}

string rossec::AESGCM::getIvHexString() {
    string encoded;
    StringSource( iv, iv_size, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink( encoded )
        ) // HexEncoder
    ); // StringSource
    return encoded;
}

string rossec::AESGCM::getHexString(string msg) {
    string encoded;
    StringSource( msg, true,
        new CryptoPP::HexEncoder(
            new StringSink( encoded )
        ) // HexEncoder
    ); // StringSource
    return encoded;
}

string rossec::AESGCM::encryptString(string msg) {
    string cipher;
    string final;

    try
    {
//        CryptoPP::GCM< CryptoPP::AES >::Encryption e;
        e.SetKeyWithIV( key, key_size, iv, iv_size );
        // e.SpecifyDataLengths( 0, pdata.size(), 0 );

        StringSource( msg, true,
            new CryptoPP::AuthenticatedEncryptionFilter( e,
                new StringSink( cipher ), false, TAG_SIZE
            ) // AuthenticatedEncryptionFilter
        ); // StringSource

    std::string s_iv(reinterpret_cast<char const*>(iv), iv_size);
    final = s_iv + cipher;

    e.GetNextIV(*prng, iv);
    e.Resynchronize(iv);

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

string rossec::AESGCM::decryptString(string msg) {

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
        //GCM< AES >::Decryption d;
        d.SetKeyWithIV( key, key_size, (const byte*) s_iv.c_str(), iv_size);
        // d.SpecifyDataLengths( 0, cipher.size()-TAG_SIZE, 0 );

        CryptoPP::AuthenticatedDecryptionFilter df( d,
            new StringSink( rpdata ),
                CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
                    TAG_SIZE
        ); // AuthenticatedDecryptionFilter

        // The StringSource dtor will be called immediately
        //  after construction below. This will cause the
        //  destruction of objects it owns. To stop the
        //  behavior so we can get the decoding result from
        //  the DecryptionFilter, we must use a redirector
        //  or manually Put(...) into the filter without
        //  using a StringSource.
        StringSource( cipher, true,
            new CryptoPP::Redirector( df )
        ); // StringSource

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        bool b = df.GetLastResult();
        assert( true == b );

       return rpdata;

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
