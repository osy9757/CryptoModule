#ifndef AES_CRYPT_H
#define AES_CRYPT_H

#include <string>

class AESCrypt {
public:
    // AES 암호화 함수
    static std::string encrypt(const std::string &plaintext, const std::string &key, 
        const std::string &iv, int key_length);
    static std::string decrypt(const std::string &ciphertext, const std::string &key, 
        const std::string &iv, int key_length);
};

#ifdef __cplusplus
extern "C" {
#endif

const char* encrypt(const char* plaintext, const char* key, const char* iv, int key_length);
const char* decrypt(const char* ciphertext, const char* key, const char* iv, int key_length);

#ifdef __cplusplus
}
#endif

#endif