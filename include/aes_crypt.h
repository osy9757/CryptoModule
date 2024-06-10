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

#endif