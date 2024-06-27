#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <cstring>
#include <string>
#include <vector>

class hcrypt {
public:
    hcrypt() {}

    void setKey(const unsigned char *key) {
        std::memcpy(this->key, key, 32); // AES-256 key size is 32 bytes
    }

    std::string encrypt(const std::string &plaintext) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int len;
        int ciphertext_len;
        unsigned char iv[16];
        std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);

        // Generate random IV
        RAND_bytes(iv, sizeof(iv));
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        
        // Encrypt the plaintext
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), static_cast<int>(plaintext.size()));
        ciphertext_len = len;

        // Finalize encryption
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        std::string encrypted(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
        std::string iv_str(reinterpret_cast<char*>(iv), sizeof(iv));
        return iv_str + encrypted;
    }

    std::string decrypt(const std::string &ciphertext) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int len;
        int plaintext_len;
        std::vector<unsigned char> plaintext(ciphertext.size());
        unsigned char iv[16];

        // Extract IV from ciphertext
        std::memcpy(iv, ciphertext.c_str(), sizeof(iv));
        const unsigned char *encrypted = reinterpret_cast<const unsigned char*>(ciphertext.c_str()) + sizeof(iv);

        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, encrypted, static_cast<int>(ciphertext.size()) - sizeof(iv));
        plaintext_len = len;

        // Finalize decryption
        EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
    }

private:
    unsigned char key[32];
};

extern "C" {
    __declspec(dllexport) hcrypt* aes_create() {
        return new hcrypt();
    }

    __declspec(dllexport) void aes_destroy(hcrypt* aes) {
        delete aes;
    }

    __declspec(dllexport) void aes_set_key(hcrypt* aes, const unsigned char* key) {
        aes->setKey(key);
    }

    __declspec(dllexport) char* aes_encrypt(hcrypt* aes, const char* plaintext) {
        std::string ciphertext = aes->encrypt(plaintext);
        char* cstr = new char[ciphertext.size() + 1];
        strcpy_s(cstr, ciphertext.size() + 1, ciphertext.c_str());
        return cstr;
    }

    __declspec(dllexport) char* aes_decrypt(hcrypt* aes, const char* ciphertext) {
        std::string plaintext = aes->decrypt(ciphertext);
        char* cstr = new char[plaintext.size() + 1];
        strcpy_s(cstr, plaintext.size() + 1, plaintext.c_str());
        return cstr;
    }
}
