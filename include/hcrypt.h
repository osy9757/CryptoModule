#ifndef HCRYPT_H
#define HCRYPT_H

#include <string>

class hcrypt {
public:
    hcrypt(const std::string& serverIP, int port);
    void setKey(const std::string& key);
    std::string crypt(char mode, const std::string& input);

private:
    std::string key;
    std::string iv = "thisisaninitvector"; // IV는 고정 값 사용 (필요 시 변경 가능)

    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);
};

extern "C" {
    hcrypt* hcrypt_new(const char* serverIP, int port);
    void hcrypt_setKey(hcrypt* hc, const char* key);
    const char* hcrypt_crypt(hcrypt* hc, char mode, const char* input);
}

#endif
