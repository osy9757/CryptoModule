#include "aes_crypt.h"
#include <openssl/evp.h>
#include <vector>
#include <stdexcept>

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

std::string AESCrypt::encrypt(const std::string &plaintext, const std::string &key, const std::string &iv, int key_length) {

    //EVP_CIPHER_CTX 구조체를 사용하여 암호화 컨텍스트 생성
    //EVP_CIPHER_CTX : OpenSSL 라이브러리에서 암복화화 작업을 수행하는 상태와 설정정보 저장 구조체
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    // 컨텍스트 생성 실패 에러
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    //암호화 방식을 선택
    //TODO : 추후에 512bit 추가
    const EVP_CIPHER *cipher;
    if (key_length == 256) {
        cipher = EVP_aes_256_cbc();
    } else {
        // 잘못된 키 길이 입력으로 리소스 해제및 오류 출력
        EVP_CIPHER_CTX_free(ctx); 
        throw std::runtime_error("Invalid key length");
    }

    //패딩적용
    std::string paddedPlaintext = addPadding(plaintext, AES_BLOCK_SIZE);
    //메모리 할당
    std::vector<unsigned char> cipherText(paddedPlaintext.size() + AES_BLOCK_SIZE);
    int len;

    //데이터 암호화
    //EVP_EncryptUpdate로 암호화 진행후 성공하면 1을 반환
    if (1 != EVP_EncryptUpdate(ctx, cipherText.data(), &len, (unsigned char *)paddedPlaintext.data(), paddedPlaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    int cipherTextLen = len;

    //암호화 완료
    if (1 != EVP_EncryptFinal_ex(ctx, cipherText.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }

    cipherTextLen += len;

    EVP_CIPHER_CTX_free(ctx);
    // 암호화된 문자열 반환
    return std::string((char *)cipherText.data(), cipherTextLen);
}

std::string AESCrypt::decrypt(const std::string &cipherText, const std::string &key, const std::string &iv, int keyLength) {
    // EVP_CIPHER_CTX 구조체를 사용하여 복호화 컨텍스트를 생성
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed"); 

    const EVP_CIPHER *cipher;
    if (keyLength == 256) {
        cipher = EVP_aes_256_cbc();
    } else {
        EVP_CIPHER_CTX_free(ctx); 
        throw std::runtime_error("Invalid key length"); 
    }

    // 복호화 초기화
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, (unsigned char *)key.data(), (unsigned char *)iv.data())) {
        EVP_CIPHER_CTX_free(ctx); 
        throw std::runtime_error("EVP_DecryptInit_ex failed"); 
    }

    std::vector<unsigned char> plainText(cipherText.size());
    int len;

    // 데이터 복호화
    if (1 != EVP_DecryptUpdate(ctx, plainText.data(), &len, (unsigned char *)cipherText.data(), cipherText.size())) {
        EVP_CIPHER_CTX_free(ctx); 
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    int plainTextLen = len;

    // 복호화 완료
    if (1 != EVP_DecryptFinal_ex(ctx, plainText.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx); 
        throw std::runtime_error("EVP_DecryptFinal_ex failed"); 
    }
    plainTextLen += len;

    EVP_CIPHER_CTX_free(ctx); 
    // 패딩 제거
    return removePadding(std::string((char *)plainText.data(), plainTextLen)); 
}