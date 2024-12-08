#ifndef CIPHER_CTX_DELETER_H
#define CIPHER_CTX_DELETER_H

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <memory>

struct CipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX *ctx) const {
        if (ctx) EVP_CIPHER_CTX_free(ctx);
    }
};

using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

#endif // CIPHER_CTX_DELETER_H
