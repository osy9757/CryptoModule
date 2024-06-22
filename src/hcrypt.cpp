#include "hcrypt.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <stdexcept>
#include <cstdlib> // for malloc and free

hcrypt::hcrypt(const std::string& serverIP, int port) {
    // 서버IP와 포트를 사용한 초기화 로직이 필요하다면 추가
}

void hcrypt::setKey(const std::string& key) {
    this->key = key;
}

std::string hcrypt::crypt(char mode, const std::string& input) {
    if (mode == 'e') {
        return encrypt(input);
    } else if (mode == 'd') {
        return decrypt(input);
    }
    throw std::invalid_argument("Invalid mode");
}

std::string hcrypt::encrypt(const std::string& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key.c_str(), (unsigned char*)iv.c_str()))
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    std::string ciphertext;
    ciphertext.resize(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

    int len;
    if (1 != EVP_EncryptUpdate(ctx, (unsigned char*)&ciphertext[0], &len, (const unsigned char*)plaintext.c_str(), plaintext.size()))
        throw std::runtime_error("EVP_EncryptUpdate failed");
    int ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, (unsigned char*)&ciphertext[0] + len, &len))
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

std::string hcrypt::decrypt(const std::string& ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key.c_str(), (unsigned char*)iv.c_str()))
        throw std::runtime_error("EVP_DecryptInit_ex failed");

    std::string plaintext;
    plaintext.resize(ciphertext.size());

    int len;
    if (1 != EVP_DecryptUpdate(ctx, (unsigned char*)&plaintext[0], &len, (const unsigned char*)ciphertext.c_str(), ciphertext.size()))
        throw std::runtime_error("EVP_DecryptUpdate failed");
    int plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, (unsigned char*)&plaintext[0] + len, &len))
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(plaintext_len);
    return plaintext;
}

extern "C" {
    hcrypt* hcrypt_new(const char* serverIP, int port) {
        return new hcrypt(serverIP, port);
    }

    void hcrypt_setKey(hcrypt* hc, const char* key) {
        hc->setKey(key);
    }

    const char* hcrypt_crypt_alloc(hcrypt* hc, char mode, const char* input) {
        std::string result = hc->crypt(mode, input);
        char* result_cstr = (char*)malloc(result.size() + 1);
        std::strcpy(result_cstr, result.c_str());
        return result_cstr;
    }

    void hcrypt_free_result(const char* result) {
        free((void*)result);
    }
}


//g++ -shared -o hcrypt.dll hcrypt.cpp -I../include -I"C:/Program Files/OpenSSL-Win64/include" -L"C:/Program Files/OpenSSL-Win64/lib/VC/x64/MTd" "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MTd/libssl.lib" "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MTd/libcrypto.lib"