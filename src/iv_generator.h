#ifndef IV_GENERATOR_H
#define IV_GENERATOR_H

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string>
#include <stdexcept>

std::string generate_iv(const EVP_CIPHER *cipher);

#endif // IV_GENERATOR_H
