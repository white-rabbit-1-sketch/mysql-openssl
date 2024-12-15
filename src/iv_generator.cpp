#include "iv_generator.h"

std::string generate_iv(const EVP_CIPHER *cipher) {
    int iv_length = EVP_CIPHER_iv_length(cipher);
    if (iv_length <= 0) {
        return "";
    }

    std::string iv(iv_length, '\0');
    if (!RAND_bytes(reinterpret_cast<unsigned char *>(&iv[0]), iv_length)) {
        throw std::runtime_error("Failed to generate IV");
    }

    return iv;
}