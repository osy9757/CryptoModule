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

    int encrypt(const char *plaintext, char *ciphertext, int ciphertext_len) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int len;
        int total_len = 0;
        unsigned char iv[16];

        // Generate random IV
        RAND_bytes(iv, sizeof(iv));
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

        // Copy IV to the beginning of the ciphertext buffer
        std::memcpy(ciphertext, iv, sizeof(iv));
        total_len += sizeof(iv);

        // Encrypt the plaintext
        EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(ciphertext + total_len), &len, reinterpret_cast<const unsigned char*>(plaintext), std::strlen(plaintext));
        total_len += len;

        // Finalize encryption
        EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(ciphertext + total_len), &len);
        total_len += len;

        EVP_CIPHER_CTX_free(ctx);
        return total_len;
    }

    int decrypt(const char *ciphertext, int ciphertext_len, char *plaintext, int plaintext_len) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int len;
        int total_len = 0;
        unsigned char iv[16];

        // Extract IV from ciphertext
        std::memcpy(iv, ciphertext, sizeof(iv));
        const unsigned char *encrypted = reinterpret_cast<const unsigned char*>(ciphertext) + sizeof(iv);
        int encrypted_len = ciphertext_len - sizeof(iv);

        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plaintext), &len, encrypted, encrypted_len);
        total_len += len;

        // Finalize decryption
        EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plaintext + total_len), &len);
        total_len += len;

        EVP_CIPHER_CTX_free(ctx);
        return total_len;
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

    __declspec(dllexport) int aes_encrypt(hcrypt* aes, const char* plaintext, char* ciphertext, int ciphertext_len) {
        return aes->encrypt(plaintext, ciphertext, ciphertext_len);
    }

    __declspec(dllexport) int aes_decrypt(hcrypt* aes, const char* ciphertext, int ciphertext_len, char* plaintext, int plaintext_len) {
        return aes->decrypt(ciphertext, ciphertext_len, plaintext, plaintext_len);
    }
}

//g++ -shared -o hcrypt.dll hcrypt.cpp -I../include -I"C:/Program Files/OpenSSL-Win64/include" -L"C:/Program Files/OpenSSL-Win64/lib/VC/x64/MTd" "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MTd/libssl.lib" "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MTd/libcrypto.lib"
