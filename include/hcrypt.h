#ifndef HCRYPT_H
#define HCRYPT_H

#include <string>

class hcrypt {
public:
    hcrypt(const std::string& serverIP, int port);
    ~hcrypt();
    void setKey(const std::string& key);
    void setIV(const std::string& iv);
    std::string crypt(char mode, const std::string& input, bool& success);

private:
    std::string key;
    std::string iv;

    std::string encrypt(const std::string& plaintext, bool& success);
    std::string decrypt(const std::string& ciphertext, bool& success);
};

extern "C" {
    hcrypt* hcrypt_new(const char* serverIP, int port);
    void hcrypt_setKey(hcrypt* hc, const char* key);
    void hcrypt_setIV(hcrypt* hc, const char* iv);
    const char* hcrypt_crypt_alloc(hcrypt* hc, char mode, const char* input);
    void hcrypt_free_result(const char* result);
}

#endif