#include "aesCrypt.h"
#include <iostream>
#include <string>

int main() {
    std::string key = "12334556&^1230809";
    std::string iv = "0123456789012345";
    std::string plaintext = "Hello, World!";

    try {
        std::string encrypted = AESCrypt::encrypt(plaintext, key, iv, 256);
        std::string decrypted = AESCrypt::decrypt(encrypted, key, iv, 256);

        if (decrypted == plaintext) {
            std::cout << "암호화 및 복호화 테스트 성공: " << decrypted << std::endl;
        } else {
            std::cout << "암호화 및 복호화 테스트 실패" << std::endl;
        }
    } catch (const std::exception &e) {
        std::cerr << "오류 발생: " << e.what() << std::endl;
    }

    return 0;
}
