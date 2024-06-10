#include "aes_crypt.h"
#include <openssl/evp.h>
#include <vector>
#include <stdexcept>

namespace {
    const int AES_BLOCK_SIZE = 16;

    std:string addPadding(const std::string &data, int blockSize) {
        int padLen = blockSize - data.size() % blockSize;
        std::string padding(padLen, padLen);
        return data + padding;

    std::string removePadding(const std::string &data) {
        int padLen = data[data.size() - 1];
        return data.substr(0, data.size() - padLen);
    }
    }
}