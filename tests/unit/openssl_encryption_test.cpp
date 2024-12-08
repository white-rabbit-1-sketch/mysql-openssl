#include <gtest/gtest.h>
#include "openssl_encrypt.h"
#include "openssl_decrypt.h"

TEST(EncryptionTests, EncryptDecrypt) {
    std::string plaintext = "Hello, World!";
    std::string key = "12345678901234567890123456789012";
    std::string cipher = "aes-256-cbc";

    std::string encrypted = encrypt(plaintext, key, cipher);
    ASSERT_FALSE(encrypted.empty());

    std::string decrypted = decrypt(encrypted, key, cipher);
    ASSERT_EQ(decrypted, plaintext);
}

TEST(EncryptionTests, EncryptDecryptWithIv) {
    std::string plaintext = "Hello, World!";
    std::string key = "12345678901234567890123456789012";
    std::string cipher = "aes-256-cbc";
    std::string iv = "IIIIIIIIIIIIIIII";

    std::string encrypted = encrypt(plaintext, key, cipher, std::nullopt);
    ASSERT_FALSE(encrypted.empty());

    std::string decrypted = decrypt(encrypted, key, cipher);
    ASSERT_EQ(decrypted, plaintext);

    encrypted = encrypt(plaintext, key, cipher, iv);
    ASSERT_FALSE(encrypted.empty());

    decrypted = decrypt(encrypted, key, cipher);
    ASSERT_EQ(decrypted, plaintext);
}

TEST(EncryptionTests, InvalidKeyLength) {
    std::string plaintext = "Hello, World!";
    std::string key = "shortkey";
    std::string cipher = "aes-256-cbc";

    ASSERT_THROW(encrypt(plaintext, key, cipher), std::invalid_argument);
}

TEST(EncryptionTests, InvalidCipherName) {
    std::string plaintext = "Hello, World!";
    std::string key = "12345678901234567890123456789012";
    std::string cipher = "invalid-cipher";

    ASSERT_THROW(encrypt(plaintext, key, cipher), std::invalid_argument);
}