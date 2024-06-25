#ifndef HCRYPT_H
#define HCRYPT_H

#ifdef _WIN32
    #ifdef HCRYPT_EXPORTS
        #define HCRYPT_API __declspec(dllexport)
    #else
        #define HCRYPT_API __declspec(dllimport)
    #endif
#else
    #define HCRYPT_API
#endif

#include <string>

class HCRYPT_API hcrypt {
public:
    hcrypt(const std::string& serverIP, int port);
    ~hcrypt();

    void setKey(const std::string& key);
    void setIV(const std::string& iv);
    std::string crypt(char mode, const std::string& input);

private:
    std::string key;
    std::string iv;
    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);
    std::string aes_crypt(const std::string& input, bool is_encrypt);
};

extern "C" {
    HCRYPT_API hcrypt* hcrypt_new(const char* serverIP, int port);
    HCRYPT_API void hcrypt_setKey(hcrypt* hc, const char* key);
    HCRYPT_API void hcrypt_setIV(hcrypt* hc, const char* iv);
    HCRYPT_API const char* hcrypt_crypt_alloc(hcrypt* hc, char mode, const char* input);
    HCRYPT_API void hcrypt_free_result(const char* result);
    HCRYPT_API void hcrypt_delete(hcrypt* hc);
}

#endif // HCRYPT_H
