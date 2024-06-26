#include <phpcpp.h>
#include "AES256.h"

class Hcrypt : public Php::Base {
private:
    AES256* aes;
    std::string ip;
    int port;
public:
    Hcrypt() = default;
    virtual ~Hcrypt() {
        delete aes;
    }

    void __construct(Php::Parameters &params) {
        ip = params[0].stringValue();
        port = params[1].numericValue();
    }

    void setKey(Php::Parameters &params) {
        std::string key = params[0].stringValue();
        aes = new AES256(key);
    }

    Php::Value crypt(Php::Parameters &params) {
        std::string mode = params[0].stringValue();
        std::string data = params[1].stringValue();
        if (mode == "e") {
            return aes->encrypt(data);
        } else if (mode == "d") {
            return aes->decrypt(data);
        } else {
            throw Php::Exception("Invalid mode");
        }
    }
};

extern "C" {
    PHPCPP_EXPORT void *get_module() {
        static Php::Extension extension("hcrypt", "1.0");
        Php::Class<Hcrypt> hcrypt("Hcrypt");
        hcrypt.method<&Hcrypt::__construct>("__construct", {
            Php::ByVal("ip", Php::Type::String),
            Php::ByVal("port", Php::Type::Numeric)
        });
        hcrypt.method<&Hcrypt::setKey>("setKey", {
            Php::ByVal("key", Php::Type::String)
        });
        hcrypt.method<&Hcrypt::crypt>("crypt", {
            Php::ByVal("mode", Php::Type::String),
            Php::ByVal("data", Php::Type::String)
        });
        extension.add(std::move(hcrypt));
        return extension;
    }
}
