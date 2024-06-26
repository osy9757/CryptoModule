#ifndef AES256_H
#define AES256_H

#include <string>
#include <vector>
#include <openssl/aes.h>
#include <openssl/rand.h>

class AES256 {
public:
    AES256(const std::string& key);
    ~AES256();
    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);

private:
    AES_KEY enc_key;
    AES_KEY dec_key;
    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;

    void pad(std::vector<uint8_t>& buffer);
    void unpad(std::vector<uint8_t>& buffer);
    void generateIV();
};

#endif // AES256_H
