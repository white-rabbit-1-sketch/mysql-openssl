#ifndef OPENSSL_ENCRYPT_H
#define OPENSSL_ENCRYPT_H

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string>
#include <memory>
#include <stdexcept>
#include <optional>
#include "cipher_ctx_deleter.h"
#include "iv_generator.h"

std::string encrypt(
    const std::string &plaintext,
    const std::string &key,
    const std::string &cipher_name,
    const std::optional<std::string> &iv = std::nullopt
);

#endif // OPENSSL_ENCRYPT_H
