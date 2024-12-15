#ifndef OPENSSL_DECRYPT_H
#define OPENSSL_DECRYPT_H

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string>
#include <memory>
#include <stdexcept>
#include "cipher_ctx_deleter.h"
#include "iv_generator.h"

std::string decrypt(const std::string &ciphertext, const std::string &key, const std::string &cipher_name);

#endif // OPENSSL_DECRYPT_H
