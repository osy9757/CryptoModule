#include "aesCrypt.h"
#include <openssl/evp.h>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <cstring>

namespace {
    const int AES_BLOCK_SIZE = 16;

    // 패딩을 적용하여 데이터 크기를 블록사이즈의 배수로 설정
    std::string addPadding(const std::string &data, int blockSize) {
        int padLen = blockSize - data.size() % blockSize;
        std::string padding(padLen, padLen);
        return data + padding;
    }

    // 패딩을 제거하여 원래 데이터를 복원
    std::string removePadding(const std::string &data) {
        int padLen = data[data.size() - 1];
        return data.substr(0, data.size() - padLen);
    }
}

// 전역 변수로 암호화 및 복호화 결과 저장
std::string encrypted_result;
std::string decrypted_result;

// 암호화 함수 정의
std::string AESCrypt::encrypt(const std::string &plaintext, const std::string &key, const std::string &iv, int key_length) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    const EVP_CIPHER *cipher;
    if (key_length == 256) {
        cipher = EVP_aes_256_cbc();
    } else {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Invalid key length");
    }

    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, (unsigned char *)key.data(), (unsigned char *)iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    std::string paddedPlainText = addPadding(plaintext, AES_BLOCK_SIZE);
    std::vector<unsigned char> cipherText(paddedPlainText.size() + AES_BLOCK_SIZE);
    int len;

    if (1 != EVP_EncryptUpdate(ctx, cipherText.data(), &len, (unsigned char *)paddedPlainText.data(), paddedPlainText.size())) {
        EVP_CIPHER_CTX_free(ctx);
        std::cerr << "EVP_EncryptUpdate failed. paddedPlainText size: " << paddedPlainText.size() << std::endl;
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    int cipherTextLen = len;

    if (1 != EVP_EncryptFinal_ex(ctx, cipherText.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        std::cerr << "EVP_EncryptFinal_ex failed. cipherTextLen: " << cipherTextLen << std::endl;
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    cipherTextLen += len;

    EVP_CIPHER_CTX_free(ctx);
    encrypted_result = std::string((char *)cipherText.data(), cipherTextLen);
    return encrypted_result;
}

// 복호화 함수 정의
std::string AESCrypt::decrypt(const std::string &cipherText, const std::string &key, const std::string &iv, int keyLength) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    const EVP_CIPHER *cipher;
    if (keyLength == 256) {
        cipher = EVP_aes_256_cbc();
    } else {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Invalid key length");
    }

    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, (unsigned char *)key.data(), (unsigned char *)iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    std::vector<unsigned char> plainText(cipherText.size());
    int len;

    if (1 != EVP_DecryptUpdate(ctx, plainText.data(), &len, (unsigned char *)cipherText.data(), cipherText.size())) {
        EVP_CIPHER_CTX_free(ctx);
        std::cerr << "EVP_DecryptUpdate failed. cipherText size: " << cipherText.size() << std::endl;
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }

    int plainTextLen = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plainText.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        std::cerr << "EVP_DecryptFinal_ex failed. plainTextLen: " << plainTextLen << std::endl;
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    }
    plainTextLen += len;

    EVP_CIPHER_CTX_free(ctx);
    decrypted_result = removePadding(std::string((char *)plainText.data(), plainTextLen));
    return decrypted_result;
}

// 전역 버퍼에 결과 저장
char encrypted_buffer[1024];
char decrypted_buffer[1024];

extern "C" {
    const char* encrypt(const char* plaintext, const char* key, const char* iv, int key_length) {
        std::string encrypted = AESCrypt::encrypt(plaintext, key, iv, key_length);
        std::strncpy(encrypted_buffer, encrypted.c_str(), sizeof(encrypted_buffer));
        encrypted_buffer[sizeof(encrypted_buffer) - 1] = '\0';  // null-terminate
        return encrypted_buffer;
    }

    const char* decrypt(const char* ciphertext, const char* key, const char* iv, int key_length) {
        std::string decrypted = AESCrypt::decrypt(ciphertext, key, iv, key_length);
        std::strncpy(decrypted_buffer, decrypted.c_str(), sizeof(decrypted_buffer));
        decrypted_buffer[sizeof(decrypted_buffer) - 1] = '\0';  // null-terminate
        return decrypted_buffer;
    }
}
