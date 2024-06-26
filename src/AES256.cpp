#include "AES256.h"
#include <stdexcept>
#include <cstring>

AES256::AES256(const std::string& key) {
    if (key.size() != 32) { // 256-bit key size
        throw std::runtime_error("Invalid key size");
    }
    this->key.assign(key.begin(), key.end());
    AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(key.data()), 256, &enc_key);
    AES_set_decrypt_key(reinterpret_cast<const unsigned char*>(key.data()), 256, &dec_key);
    generateIV();
}

AES256::~AES256() {
    // Destructor for any cleanup if needed
}

void AES256::generateIV() {
    iv.resize(AES_BLOCK_SIZE);
    if (!RAND_bytes(iv.data(), AES_BLOCK_SIZE)) {
        throw std::runtime_error("Failed to generate IV");
    }
}

void AES256::pad(std::vector<uint8_t>& buffer) {
    size_t padding = AES_BLOCK_SIZE - (buffer.size() % AES_BLOCK_SIZE);
    buffer.insert(buffer.end(), padding, static_cast<uint8_t>(padding));
}

void AES256::unpad(std::vector<uint8_t>& buffer) {
    if (!buffer.empty()) {
        uint8_t padding = buffer.back();
        buffer.resize(buffer.size() - padding);
    }
}

std::string AES256::encrypt(const std::string& plaintext) {
    std::vector<uint8_t> buffer(plaintext.begin(), plaintext.end());
    pad(buffer);

    std::vector<uint8_t> ciphertext(buffer.size() + AES_BLOCK_SIZE);
    std::memcpy(ciphertext.data(), iv.data(), AES_BLOCK_SIZE); // IV를 첫 블록에 추가
    AES_cbc_encrypt(buffer.data(), ciphertext.data() + AES_BLOCK_SIZE, buffer.size(), &enc_key, iv.data(), AES_ENCRYPT);

    return std::string(ciphertext.begin(), ciphertext.end());
}

std::string AES256::decrypt(const std::string& ciphertext) {
    if (ciphertext.size() < AES_BLOCK_SIZE) {
        throw std::runtime_error("Invalid ciphertext size");
    }

    std::vector<uint8_t> buffer(ciphertext.begin() + AES_BLOCK_SIZE, ciphertext.end()); // IV를 제외한 나머지 블록
    std::vector<uint8_t> iv(ciphertext.begin(), ciphertext.begin() + AES_BLOCK_SIZE); // 첫 블록은 IV

    std::vector<uint8_t> plaintext(buffer.size());
    AES_cbc_encrypt(buffer.data(), plaintext.data(), buffer.size(), &dec_key, iv.data(), AES_DECRYPT);

    unpad(plaintext);
    return std::string(plaintext.begin(), plaintext.end());
}
