#include "../include/SecureBankApplication/Crypto.h"
#include "../include/SecureBankApplication/Constants.h"
#include "Utils.cpp"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <vector>
#include <string>
#include <cstring>

using namespace std;

int rsa_encrypt(const vector<unsigned char>& pub_key, string& message, vector<unsigned char>& encrypted)
{
    RSA* rsa = RSA_new();
    BIO* bio = BIO_new_mem_buf(pub_key.data(), (int)pub_key.size());

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

    int encrypted_length = RSA_public_encrypt(message.size(), (const unsigned char*)message.data(), encrypted.data(), rsa, RSA_PKCS1_OAEP_PADDING);

    RSA_free(rsa);
    BIO_free(bio);

    message.clear();

    return encrypted_length;
}

int RSA_decrypt(const vector<unsigned char>& priv_key, const vector<unsigned char>& encrypted, string& message)
{
    RSA* rsa = RSA_new();
    BIO* bio = BIO_new_mem_buf(priv_key.data(), (int)priv_key.size());

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
    int block_size = EVP_CIPHER_block_size(cipher);
    unsigned char iv[iv_length];

    // Checking for integer overflow
    if (message.size() + 1 > INT_MAX - block_size)
    {
        return -1;
    }

    // Seeding the OpenSSL PRNG
    if (RAND_poll() == -1)
    {
        return -1;
    }

    // Generating random bytes for the IV
    if (RAND_bytes(iv, iv_length) == -1)
    {
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        return -1;
    }

    if (EVP_EncryptInit(ctx, cipher, key.data(), iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    encryptedMessage.resize(EVP_CIPHER_block_size(cipher) + message.length() + 1 + iv_length);
    memcpy(encryptedMessage.data(), iv, iv_length);

    int outlen;
    if (EVP_EncryptUpdate(ctx, encryptedMessage.data() + iv_length, &outlen, (unsigned char *)message.data(), message.length() + 1) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int finallen;
    if (EVP_EncryptFinal(ctx, encryptedMessage.data() + iv_length + outlen, &finallen) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Resizing the output length in case of the enc buffer being oversized
    encryptedMessage.resize(iv_length + outlen + finallen);

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

bool Crypto::generateHMAC(const vector<unsigned char> &key, const string &message, vector<unsigned char> &hmac)
{
    unsigned int hmac_size = EVP_MD_size(EVP_sha256());
    hmac.resize(hmac_size);

    // Create HMAC
    HMAC(EVP_sha256(), key.data(), key.size(), (const unsigned char *)message.data(), message.size(), hmac.data(), &hmac_size);

    return true;
}

bool Crypto::verifyHMAC(const vector<unsigned char> &key, const string &message, const vector<unsigned char> &hmac)
{
    vector<unsigned char> expected_hmac;
    generateHMAC(key, message, expected_hmac);

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
    vector<unsigned char> plaintext(encryptedMessage.size() - iv_length);

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, encryptedMessage.data() + iv_length, plaintext.size()) != 1)
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
#pragma optimize("", off)
    memset(plaintext.data(), 0, plaintext.size());
#pragma optimisze("", on)

    EVP_CIPHER_CTX_free(ctx);
    return totallen;
};

vector<unsigned char> Crypto::generateNonce(int length)
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
    RSA *rsa = RSA_new();
    BIO *bio = BIO_new_mem_buf(pub_key.data(), (int)pub_key.size());

    if (!PEM_read_bio_RSAPublicKey(bio, &rsa, NULL, NULL))
    {
        RSA_free(rsa);
        BIO_free(bio);
        return false;
    }

    EVP_PKEY *evp_pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_pkey, rsa);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_VerifyInit(ctx, EVP_sha256());

    if (EVP_VerifyUpdate(ctx, message.c_str(), message.size()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(evp_pkey);
        BIO_free(bio);
        return false;
    }

    bool result = (EVP_VerifyFinal(ctx, signature.data(), (unsigned int)signature.size(), evp_pkey) == 1);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(evp_pkey);
    BIO_free(bio);

    return result;
}

bool Crypto::hash_with_salt(const string &plaintext, vector<unsigned char> &saltedHash, vector<unsigned char> salt)
{
    salt = salt.empty() ? Crypto::generateNonce(Constants::SALT_SIZE) : salt;

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

bool Crypto::verifyHash(const string &plaintext, const vector<unsigned char> &hash)
{

    vector<unsigned char> salt(hash.begin(), hash.begin() + Constants::SALT_SIZE);
    vector<unsigned char> newHash;
    if (!Crypto::hash_with_salt(plaintext, newHash, salt))
        return false;

    return CRYPTO_memcmp(newHash.data(), hash.data(), EVP_MD_size(EVP_sha256())) == 0;
}