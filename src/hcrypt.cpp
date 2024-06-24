#include "hcrypt.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <cstring>
#include <stdexcept>
#include <cstdlib>

void openssl_init() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

void openssl_cleanup() {
    EVP_cleanup();
    ERR_free_strings();
}

hcrypt::hcrypt(const std::string& serverIP, int port) {
    openssl_init();
}

hcrypt::~hcrypt() {
    openssl_cleanup();
}

void hcrypt::setKey(const std::string& key) {
    this->key = key;
}

void hcrypt::setIV(const std::string& iv) {
    this->iv = iv;
}

std::string hcrypt::crypt(char mode, const std::string& input, bool& success) {
    if (mode == 'e') {
        return encrypt(input, success);
    } else if (mode == 'd') {
        return decrypt(input, success);
    }
    success = false;
    return "";
}

std::string hcrypt::encrypt(const std::string& plaintext, bool& success) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        success = false;
        return "";
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key.c_str(), (unsigned char*)iv.c_str())) {
        EVP_CIPHER_CTX_free(ctx);
        success = false;
        return "";
    }

    std::string ciphertext;
    ciphertext.resize(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

    int len;
    if (1 != EVP_EncryptUpdate(ctx, (unsigned char*)&ciphertext[0], &len, (const unsigned char*)plaintext.c_str(), plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        success = false;
        return "";
    }
    int ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, (unsigned char*)&ciphertext[0] + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        success = false;
        return "";
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    success = true;
    return ciphertext;
}

std::string hcrypt::decrypt(const std::string& ciphertext, bool& success) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        success = false;
        return "";
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key.c_str(), (unsigned char*)iv.c_str())) {
        EVP_CIPHER_CTX_free(ctx);
        success = false;
        return "";
    }

    std::string plaintext;
    plaintext.resize(ciphertext.size());

    int len;
    if (1 != EVP_DecryptUpdate(ctx, (unsigned char*)&plaintext[0], &len, (const unsigned char*)ciphertext.c_str(), ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        success = false;
        return "";
    }
    int plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, (unsigned char*)&plaintext[0] + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        success = false;
        return "";
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(plaintext_len);
    success = true;
    return plaintext;
}

extern "C" {
    hcrypt* hcrypt_new(const char* serverIP, int port) {
        return new hcrypt(serverIP, port);
    }

    void hcrypt_setKey(hcrypt* hc, const char* key) {
        hc->setKey(key);
    }

    void hcrypt_setIV(hcrypt* hc, const char* iv) {
        hc->setIV(iv);
    }

    const char* hcrypt_crypt_alloc(hcrypt* hc, char mode, const char* input) {
        bool success;
        std::string result = hc->crypt(mode, input, success);
        if (!success) {
            return nullptr;
        }
        size_t size = result.size();
        char* result_cstr = (char*)malloc(size + 1);
        if (!result_cstr) {
            return nullptr;
        }
        std::memcpy(result_cstr, result.c_str(), size + 1);
        return result_cstr;
    }

    void hcrypt_free_result(const char* result) {
        free((void*)result);
    }
}
//g++ -shared -o hcrypt.dll hcrypt.cpp -I../include -I"C:/Program Files/OpenSSL-Win64/include" -L"C:/Program Files/OpenSSL-Win64/lib/VC/x64/MTd" "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MTd/libssl.lib" "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MTd/libcrypto.lib"
