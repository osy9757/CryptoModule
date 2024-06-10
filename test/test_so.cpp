#include <iostream>
#include <dlfcn.h>
#include <string>

typedef std::string (*EncryptFunc)(const std::string&, const std::string&, const std::string&, int);
typedef std::string (*DecryptFunc)(const std::string&, const std::string&, const std::string&, int);

int main() {
    void* handle = dlopen("./libaes_crypt.so", RTLD_LAZY);
    if (!handle) {
        std::cerr << "Cannot open library: " << dlerror() << '\n';
        return 1;
    }

    dlerror(); // Clear any existing error

    EncryptFunc encrypt = (EncryptFunc) dlsym(handle, "_ZN7AESCrypt7encryptERKSsS2_S2_i");
    DecryptFunc decrypt = (DecryptFunc) dlsym(handle, "_ZN7AESCrypt7decryptERKSsS2_S2_i");

    const char *dlsym_error = dlerror();
    if (dlsym_error) {
        std::cerr << "Cannot load symbol 'encrypt' or 'decrypt': " << dlsym_error << '\n';
        dlclose(handle);
        return 1;
    }

    std::string key = "01234567890123456789012345678901";
    std::string iv = "0123456789012345";
    std::string plainText = "Hello, World!";

    std::string cipherText = encrypt(plainText, key, iv, 256);
    std::string decryptedText = decrypt(cipherText, key, iv, 256);

    std::cout << "Plaintext: " << plainText << std::endl;
    std::cout << "Ciphertext: " << cipherText << std::endl;
    std::cout << "Decrypted: " << decryptedText << std::endl;

    dlclose(handle);
    return 0;
}
