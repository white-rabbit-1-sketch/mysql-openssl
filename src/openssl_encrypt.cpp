#include "openssl_encrypt.h"

std::string encrypt(
    const std::string &plaintext,
    const std::string &key,
    const std::string &cipher_name,
    const std::optional<std::string> &iv
) {
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name.c_str());
    if (!cipher) {
        throw std::invalid_argument("Invalid cipher name: " + cipher_name);
    }

    if (key.size() != EVP_CIPHER_key_length(cipher)) {
        int expected_length = EVP_CIPHER_key_length(cipher);
        throw std::invalid_argument(
            "Invalid key length for cipher: " + cipher_name +
            ". Expected key length: " + std::to_string(expected_length) +
            ", provided: " + std::to_string(key.size())
        );
    }

    std::string actual_iv;
    if (iv.has_value()) {
        actual_iv = iv.value();
    } else {
        actual_iv = generate_iv(cipher);
    }

    int expected_iv_length = EVP_CIPHER_iv_length(cipher);
    if (actual_iv.size() != expected_iv_length) {
        throw std::invalid_argument(
            "Invalid IV length for cipher: " + cipher_name +
            ". Expected IV length: " + std::to_string(expected_iv_length) +
            ", provided: " + std::to_string(actual_iv.size())
        );
    }

    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    if (EVP_EncryptInit_ex(
        ctx.get(),
        cipher,
        nullptr,
        reinterpret_cast<const unsigned char *>(key.c_str()),
        reinterpret_cast<const unsigned char *>(actual_iv.c_str())
    ) != 1) {
        throw std::runtime_error("Failed to initialize encryption");
    }

    std::string ciphertext(plaintext.size() + EVP_CIPHER_block_size(cipher), '\0');
    int out_len = 0;
    if (EVP_EncryptUpdate(
        ctx.get(),
        reinterpret_cast<unsigned char *>(&ciphertext[0]),
        &out_len,
        reinterpret_cast<const unsigned char *>(plaintext.c_str()),
        plaintext.size()
    ) != 1) {
        throw std::runtime_error("Failed to encrypt data");
    }

    int final_out_len = 0;
    if (EVP_EncryptFinal_ex(
        ctx.get(),
        reinterpret_cast<unsigned char *>(&ciphertext[out_len]),
        &final_out_len
    ) != 1) {
        throw std::runtime_error("Failed to finalize encryption");
    }

    ciphertext.resize(out_len + final_out_len);

    return actual_iv + ciphertext;
}
