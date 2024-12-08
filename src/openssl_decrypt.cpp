#include "openssl_decrypt.h"

std::string decrypt(const std::string &ciphertext, const std::string &key, const std::string &cipher_name) {
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name.c_str());
    if (!cipher) {
        throw std::invalid_argument("Invalid cipher name: " + cipher_name);
    }

    if (key.size() != EVP_CIPHER_key_length(cipher)) {
        throw std::invalid_argument(
            "Invalid key length for cipher: " + cipher_name +
            ". Expected key length: " + std::to_string(EVP_CIPHER_key_length(cipher)) +
            ", provided: " + std::to_string(key.size())
        );
    }

    int iv_length = EVP_CIPHER_iv_length(cipher);
    if (ciphertext.size() <= iv_length) {
        throw std::invalid_argument("Ciphertext is too short to contain IV");
    }

    std::string iv = ciphertext.substr(0, iv_length);
    std::string encrypted_data = ciphertext.substr(iv_length);

    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    if (EVP_DecryptInit_ex(
        ctx.get(),
        cipher,
        nullptr,
        reinterpret_cast<const unsigned char *>(key.c_str()),
        reinterpret_cast<const unsigned char *>(iv.c_str())
    ) != 1) {
        throw std::runtime_error("Failed to initialize decryption");
    }

    std::string plaintext(encrypted_data.size(), '\0');
    int out_len = 0;
    if (EVP_DecryptUpdate(
        ctx.get(),
        reinterpret_cast<unsigned char *>(&plaintext[0]),
        &out_len,
        reinterpret_cast<const unsigned char *>(encrypted_data.c_str()),
        encrypted_data.size()
    ) != 1) {
        throw std::runtime_error("Failed to decrypt data");
    }

    int final_out_len = 0;
    if (EVP_DecryptFinal_ex(
        ctx.get(),
        reinterpret_cast<unsigned char *>(&plaintext[out_len]),
        &final_out_len
    ) != 1) {
        unsigned long err_code = ERR_get_error();
        std::string err_msg = ERR_reason_error_string(err_code);
        throw std::runtime_error("Decryption failed: " + err_msg);
    }

    plaintext.resize(out_len + final_out_len);

    return plaintext;
}
