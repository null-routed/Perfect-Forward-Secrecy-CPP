#include <cstring>
#include <stdexcept>
#include <iostream>

#include "Crypto.h"
#include "Constants.h"
#include "Utils.h"

using namespace std;

std::string Crypto::read_owner_from_cert(X509 *cert)
{
    X509_NAME *owner_name = X509_get_subject_name(cert);
    char buffer[256];
    X509_NAME_oneline(owner_name, buffer, sizeof(buffer));
    return std::string(buffer);
}

bool Crypto::verify_certificate(X509_STORE *store, X509 *cert)
{
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();

    if (X509_STORE_CTX_init(ctx, store, cert, NULL) != 1)
    {
        X509_STORE_CTX_free(ctx);
        throw runtime_error("Failed to initialize X509_STORE_CTX");
    }

    int verify_result = X509_verify_cert(ctx);

    X509_STORE_CTX_free(ctx);

    return verify_result;
}

vector<unsigned char> Crypto::read_public_key_from_cert(X509 *cert)
{
    if (cert == nullptr)
    {
        throw runtime_error("Invalid X509 certificate pointer.");
    }

    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey == nullptr)
    {
        throw runtime_error("Could not extract public key from certificate.");
    }

    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa)
    {
        throw runtime_error("Could not get RSA from EVP_PKEY.");
    }

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
        throw runtime_error("Could not create BIO for public key.");
    }

    if (!PEM_write_bio_RSA_PUBKEY(bio, rsa))
    {
        BIO_free(bio);
        throw runtime_error("Could not write RSA public key to BIO.");
    }

    char *pem_data;
    long length = BIO_get_mem_data(bio, &pem_data);

    vector<unsigned char> pem_key(pem_data, pem_data + length);

    EVP_PKEY_free(pkey);
    RSA_free(rsa);
    BIO_free(bio);

    return pem_key;
}

int Crypto::rsa_encrypt(const vector<unsigned char> &pub_key, string &message, vector<unsigned char> &encrypted)
{
    RSA *rsa = RSA_new();
    BIO *bio = BIO_new_mem_buf(pub_key.data(), (int)pub_key.size());

    if (!PEM_read_bio_RSAPublicKey(bio, &rsa, NULL, NULL))
    {
        RSA_free(rsa);
        BIO_free(bio);
        return -1;
    }

    encrypted.resize(RSA_size(rsa));

    unsigned char iv[EVP_MAX_IV_LENGTH];
    if (RAND_poll() == 0 || RAND_bytes(iv, sizeof(iv)) != 1)
    {
        RSA_free(rsa);
        BIO_free(bio);
        return -1;
    }

    int encrypted_length = RSA_public_encrypt(message.size(), (const unsigned char *)message.data(), encrypted.data(), rsa, RSA_PKCS1_OAEP_PADDING);

    RSA_free(rsa);
    BIO_free(bio);

    message.clear();

    return encrypted_length;
}

int Crypto::rsa_decrypt(const vector<unsigned char> &priv_key, const vector<unsigned char> &encrypted, string &message)
{
    RSA *rsa = RSA_new();
    BIO *bio = BIO_new_mem_buf(priv_key.data(), (int)priv_key.size());

    if (!PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL))
    {
        RSA_free(rsa);
        BIO_free(bio);
        return -1;
    }

    vector<unsigned char> decrypted(RSA_size(rsa));

    int decrypted_length = RSA_private_decrypt(encrypted.size(), encrypted.data(), decrypted.data(), rsa, RSA_PKCS1_OAEP_PADDING);

    if (decrypted_length != -1)
    {
        message = string(decrypted.begin(), decrypted.begin() + decrypted_length);
    }

    RSA_free(rsa);
    BIO_free(bio);

    return decrypted_length;
}

int Crypto::aes_encrypt(const vector<unsigned char> &key, string &message, vector<unsigned char> &encryptedMessage)
{
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    int iv_length = EVP_CIPHER_iv_length(cipher);

    // Seeding the OpenSSL PRNG
    if (RAND_poll() == -1)
    {
        return -1;
    }

    vector<unsigned char> iv(iv_length);
    if (RAND_bytes(iv.data(), iv_length) != 1)
    {
        return -1;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        return -1;
    }

    if (EVP_EncryptInit(ctx, cipher, key.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Adding IV to the beginning of the encrypted message
    encryptedMessage = iv;

    int outlen;
    vector<unsigned char> block(message.size());
    if (EVP_EncryptUpdate(ctx, block.data(), &outlen, (unsigned char *)message.data(), message.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    encryptedMessage.insert(encryptedMessage.end(), block.begin(), block.begin() + outlen);

    int finallen;
    block.resize(message.size() - outlen);
    if (EVP_EncryptFinal(ctx, block.data(), &finallen) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    encryptedMessage.insert(encryptedMessage.end(), block.begin(), block.begin() + finallen);
    EVP_CIPHER_CTX_free(ctx);
    message.clear();

    return encryptedMessage.size();
}

bool Crypto::generate_key_pair(vector<unsigned char> &priv_key, vector<unsigned char> &pub_key)
{
    int ret = 0;
    RSA *r = RSA_new();
    BIGNUM *bignum = BN_new();

    ret = BN_set_word(bignum, RSA_F4);
    if (ret != 1)
    {
        return false;
    }

    ret = RSA_generate_key_ex(r, 2048, bignum, NULL);
    if (ret != 1)
    {
        RSA_free(r);
        BN_free(bignum);
        return false;
    }

    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, r, NULL, NULL, 0, NULL, NULL);

    char *pem_key;
    long keylen = BIO_get_mem_data(bio, &pem_key);

    priv_key.assign(pem_key, pem_key + keylen);

    BIO_free(bio);

    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, r);

    keylen = BIO_get_mem_data(bio, &pem_key);

    pub_key.assign(pem_key, pem_key + keylen);

    BIO_free(bio);
    RSA_free(r);
    BN_free(bignum);

    return true;
}

bool Crypto::generate_hmac(const vector<unsigned char> &key, const string &message, vector<unsigned char> &hmac)
{
    unsigned int hmac_size = EVP_MD_size(EVP_sha256());
    hmac.resize(hmac_size);

    // Create HMAC
    HMAC(EVP_sha256(), key.data(), key.size(), (const unsigned char *)message.data(), message.size(), hmac.data(), &hmac_size);

    return true;
}

bool Crypto::verify_hmac(const vector<unsigned char> &key, const string &message, const vector<unsigned char> &hmac)
{
    vector<unsigned char> expected_hmac;
    generate_hmac(key, message, expected_hmac);

    bool result = (hmac == expected_hmac);

    return result;
}

int Crypto::aes_decrypt(const vector<unsigned char> &key, const vector<unsigned char> &encryptedMessage, string &decryptedMessage)
{
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    int iv_length = EVP_CIPHER_iv_length(cipher);
    int outlen, totallen;

    vector<unsigned char> iv(encryptedMessage.begin(), encryptedMessage.begin() + iv_length);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        return -1;
    }

    if (EVP_DecryptInit(ctx, cipher, key.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // temp buffer for the plaintext
    vector<unsigned char> plaintext(encryptedMessage.size());

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, encryptedMessage.data() + iv_length, encryptedMessage.size() - iv_length) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    totallen = outlen;

    if (EVP_DecryptFinal(ctx, plaintext.data() + outlen, &outlen) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    totallen += outlen;

    decryptedMessage.assign(plaintext.begin(), plaintext.begin() + totallen);

    // overwriting the plaintext temp buffer with zeroes
    memset(plaintext.data(), 0, plaintext.size());

    EVP_CIPHER_CTX_free(ctx);
    return totallen;
};

vector<unsigned char> Crypto::generate_nonce(int length)
{
    vector<unsigned char> buffer;
    if (RAND_poll() != 1)
    {
        return buffer;
    }

    buffer.resize(length);

    if (RAND_bytes(buffer.data(), length) != 1)
    {
        return buffer;
    }
    return buffer;
}

int Crypto::generate_signature(const vector<unsigned char> &priv_key, const string &message, vector<unsigned char> &signature)
{

    RSA *rsa = RSA_new();
    BIO *bio = BIO_new_mem_buf(priv_key.data(), (int)priv_key.size());

    if (!PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL))
    {
        RSA_free(rsa);
        BIO_free(bio);
        return -1;
    }

    EVP_PKEY *evp_pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_pkey, rsa);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (EVP_SignInit(ctx, EVP_sha256()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(evp_pkey);
        BIO_free(bio);
        return -1;
    }

    if (EVP_SignUpdate(ctx, message.c_str(), message.size()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(evp_pkey);
        BIO_free(bio);
        return -1;
    }

    unsigned int sig_len;
    if (EVP_SignFinal(ctx, NULL, &sig_len, evp_pkey) != 1)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(evp_pkey);
        BIO_free(bio);
        return -1;
    }

    signature.resize(sig_len);

    if (EVP_SignFinal(ctx, signature.data(), &sig_len, evp_pkey) != 1)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(evp_pkey);
        BIO_free(bio);
        return -1;
    }

    signature.resize(sig_len);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(evp_pkey);
    BIO_free(bio);

    return sig_len;
}

bool Crypto::verify_signature(const string &message, const vector<unsigned char> &signature, const vector<unsigned char> &pub_key)
{
    BIO *bio = BIO_new_mem_buf(pub_key.data(), -1);
    if (!bio)
    {
        std::cerr << "Failed to create BIO" << std::endl;
        return false;
    }

    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey)
    {
        std::cerr << "Failed to read public key" << std::endl;
        BIO_free(bio);
        return false;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        std::cerr << "Failed to create EVP_MD_CTX" << std::endl;
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return false;
    }

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1)
    {
        std::cerr << "Failed to initialize EVP_MD_CTX" << std::endl;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return false;
    }

    bool result;
    if (EVP_DigestVerify(ctx, signature.data(), signature.size(), (const unsigned char *)message.data(), message.size()) == 1)
    {
        result = true;
    }
    else
    {
        result = false;
    }

    // cleanup
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return result;
}

bool Crypto::hash_with_salt(const string &plaintext, vector<unsigned char> &saltedHash, vector<unsigned char> salt)
{
    salt = salt.empty() ? Crypto::generate_nonce(Constants::SALT_SIZE) : salt;

    string toHash = bytes_to_hex(salt) + plaintext;
    vector<unsigned char> digest(EVP_MD_size(EVP_sha256()));
    unsigned int digestlen;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (!ctx)
    {
        return false;
    }

    if (EVP_DigestInit(ctx, EVP_sha256()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return false;
    };

    if (EVP_DigestUpdate(ctx, toHash.c_str(), toHash.length()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return false;
    };
    if (EVP_DigestFinal(ctx, digest.data(), &digestlen) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return false;
    };

    saltedHash.insert(saltedHash.end(), salt.begin(), salt.end());
    saltedHash.insert(saltedHash.end(), digest.begin(), digest.end());

    EVP_MD_CTX_free(ctx);
    return true;
}

bool Crypto::verify_hash(const string &plaintext, const vector<unsigned char> &hash)
{

    vector<unsigned char> salt(hash.begin(), hash.begin() + Constants::SALT_SIZE);
    vector<unsigned char> newHash;
    if (!Crypto::hash_with_salt(plaintext, newHash, salt))
        return false;

    return CRYPTO_memcmp(newHash.data(), hash.data(), EVP_MD_size(EVP_sha256())) == 0;
}