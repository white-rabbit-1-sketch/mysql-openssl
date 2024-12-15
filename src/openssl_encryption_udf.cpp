#include <mysql/mysql.h>
#include <cstring>
#include <optional>
#include "openssl_encrypt.h"
#include "openssl_decrypt.h"

thread_local std::string last_error_message = "";

extern "C" bool openssl_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    if (args->arg_count < 3 || args->arg_count > 4) {
        strcpy(message, "Function requires 3 to 4 arguments: cipher_name, key, plaintext, [iv]");
        return 1;
    }

    for (int i = 0; i < args->arg_count; ++i) {
        if (args->arg_type[i] != STRING_RESULT) {
            strcpy(message, "All arguments except padding must be strings");
            return 1;
        }
    }

    initid->maybe_null = 1;
    initid->const_item = 0;

    return 0;
}

extern "C" void openssl_encrypt_deinit(UDF_INIT *initid) {
    if (initid->ptr) {
        free(initid->ptr);
        initid->ptr = nullptr;
    }
}

extern "C" char *openssl_encrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error) {
    try {
        last_error_message = "";
        std::string cipher_name(args->args[0], args->lengths[0]);
        std::string key(args->args[1], args->lengths[1]);
        std::string plaintext(args->args[2], args->lengths[2]);

        std::optional<std::string> iv;
        if (args->arg_count > 3 && args->args[3] && args->lengths[3] > 0) {
            iv = std::string(args->args[3], args->lengths[3]);
        } else {
            iv = std::nullopt;
        }

        std::string ciphertext = encrypt(plaintext, key, cipher_name, iv);

        *length = ciphertext.size();
        initid->ptr = (char *)malloc(*length + 1);
        if (!initid->ptr) {
            throw std::runtime_error("Memory allocation failed");
        }
        memcpy(initid->ptr, ciphertext.data(), *length);
        initid->ptr[*length] = '\0';

        return initid->ptr;
    } catch (const std::exception &e) {
        last_error_message = e.what();
        *error = 1;
        *is_null = 1;

        return nullptr;
    }
}

extern "C" bool openssl_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    if (args->arg_count < 3 || args->arg_count > 3) {
        strcpy(message, "Function requires 3 arguments: cipher_name, key, plaintext");
        return 1;
    }

    for (int i = 0; i < args->arg_count; ++i) {
        if (args->arg_type[i] != STRING_RESULT) {
            strcpy(message, "All arguments except padding must be strings");
            return 1;
        }
    }

    initid->maybe_null = 1;
    initid->const_item = 0;

    return 0;
}

extern "C" void openssl_decrypt_deinit(UDF_INIT *initid) {
    if (initid->ptr) {
        free(initid->ptr);
        initid->ptr = nullptr;
    }
}

extern "C" char *openssl_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error) {
    try {
        last_error_message = "";

        std::string cipher_name(args->args[0], args->lengths[0]);
        std::string key(args->args[1], args->lengths[1]);
        std::string ciphertext(args->args[2], args->lengths[2]);

        std::string plaintext = decrypt(ciphertext, key, cipher_name);

        *length = plaintext.size();
        initid->ptr = (char *)malloc(*length + 1);
        if (!initid->ptr) {
            throw std::runtime_error("Memory allocation failed");
        }
        memcpy(initid->ptr, plaintext.c_str(), *length);
        initid->ptr[*length] = '\0';

        return initid->ptr;
    } catch (const std::exception &e) {
        last_error_message = e.what();
        *error = 1;
        *is_null = 1;

        return nullptr;
    }
}


extern "C" bool openssl_get_last_error_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    if (args->arg_count != 0) {
        strcpy(message, "No arguments allowed");

        return 1;
    }

    initid->maybe_null = 1;
    initid->const_item = 0;

    return 0;
}

extern "C" void openssl_get_last_error_deinit(UDF_INIT *initid) {
    if (initid->ptr) {
        free(initid->ptr);
        initid->ptr = nullptr;
    }
}

extern "C" char *openssl_get_last_error(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error) {
    *length = last_error_message.size();

    if (*length == 0) {
        *is_null = 1;

        return nullptr;
    }

    *length = last_error_message.size();
    initid->ptr = (char *)malloc(*length + 1);
    if (!initid->ptr) {
        throw std::runtime_error("Memory allocation failed");
    }
    memcpy(initid->ptr, last_error_message.c_str(), *length);
    initid->ptr[*length] = '\0';

    return initid->ptr;
}