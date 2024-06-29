#include "hcrypt.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <cstring>
#include <stdexcept>
#include <iostream>

static bool openssl_initialized = false;

void openssl_init() {
    if (!openssl_initialized) {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        openssl_initialized = true;
    }
}

void openssl_cleanup() {
    if (openssl_initialized) {
        EVP_cleanup();
        ERR_free_strings();
        openssl_initialized = false;
    }
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

std::string hcrypt::crypt(char mode, const std::string& input) {
    if (mode == 'e') {
        return encrypt(input);
    } else if (mode == 'd') {
        return decrypt(input);
    }
    throw std::invalid_argument("Invalid mode: use 'e' for encryption and 'd' for decryption");
}

std::string hcrypt::encrypt(const std::string& plaintext) {
    return aes_crypt(plaintext, true);
}

std::string hcrypt::decrypt(const std::string& ciphertext) {
    return aes_crypt(ciphertext, false);
}

std::string hcrypt::aes_crypt(const std::string& input, bool is_encrypt) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

    try {
        const EVP_CIPHER* cipher = EVP_aes_256_cbc();
        if (is_encrypt) {
            if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, (unsigned char*)key.c_str(), (unsigned char*)iv.c_str())) {
                throw std::runtime_error("EncryptInit failed: " + std::string(ERR_reason_error_string(ERR_get_error())));
            }
        } else {
            if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, (unsigned char*)key.c_str(), (unsigned char*)iv.c_str())) {
                throw std::runtime_error("DecryptInit failed: " + std::string(ERR_reason_error_string(ERR_get_error())));
            }
        }

        std::string output;
        output.resize(input.size() + EVP_CIPHER_block_size(cipher));

        int len;
        if (is_encrypt) {
            if (1 != EVP_EncryptUpdate(ctx, (unsigned char*)&output[0], &len, (const unsigned char*)input.c_str(), static_cast<int>(input.size()))) {
                throw std::runtime_error("EncryptUpdate failed: " + std::string(ERR_reason_error_string(ERR_get_error())));
            }
        } else {
            if (1 != EVP_DecryptUpdate(ctx, (unsigned char*)&output[0], &len, (const unsigned char*)input.c_str(), static_cast<int>(input.size()))) {
                throw std::runtime_error("DecryptUpdate failed: " + std::string(ERR_reason_error_string(ERR_get_error())));
            }
        }

        int output_len = len;
        if (is_encrypt) {
            if (1 != EVP_EncryptFinal_ex(ctx, (unsigned char*)&output[0] + len, &len)) {
                throw std::runtime_error("EncryptFinal failed: " + std::string(ERR_reason_error_string(ERR_get_error())));
            }
        } else {
            if (1 != EVP_DecryptFinal_ex(ctx, (unsigned char*)&output[0] + len, &len)) {
                throw std::runtime_error("DecryptFinal failed: " + std::string(ERR_reason_error_string(ERR_get_error())));
            }
        }
        output_len += len;

        output.resize(output_len);
        EVP_CIPHER_CTX_free(ctx);

        // 민감한 데이터 지우기
        std::memset((void*)key.c_str(), 0, key.size());
        std::memset((void*)iv.c_str(), 0, iv.size());

        return output;

    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
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

    char* hcrypt_crypt_alloc(hcrypt* hc, char mode, const char* input) {
        try {
            std::string result = hc->crypt(mode, input);
            size_t size = result.size();
            char* result_cstr = new char[size + 1];
            if (!result_cstr) return nullptr;
            std::memcpy(result_cstr, result.c_str(), size);
            result_cstr[size] = '\0'; // null-terminate the string
            return result_cstr;
        } catch (const std::exception& e) {
            std::cerr << "Exception caught in hcrypt_crypt_alloc: " << e.what() << std::endl;
            return nullptr;
        } catch (...) {
            std::cerr << "Unknown exception caught in hcrypt_crypt_alloc." << std::endl;
            return nullptr;
        }
    }

    void hcrypt_free_result(char* result) {
        delete[] result;
    }

    void hcrypt_delete(hcrypt* hc) {
        delete hc;
    }
}
