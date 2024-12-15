import mysql.connector
import pytest
import logging

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger()

MYSQL_CONFIG = {
    "user": "root",
    "password": "root",
    "host": "localhost",
}

UDF_NAME = "openssl_encryption_udf.so"

SUPPORTED_CIPHERS = [
    "aes-128-cbc",
    "aes-128-ecb",
    "aes-192-cbc",
    "aes-192-ecb",
    "aes-256-cbc",
    "aes-256-ecb",
    "camellia-128-cbc",
    "camellia-128-ecb",
    "camellia-192-cbc",
    "camellia-192-ecb",
    "camellia-256-cbc",
    "camellia-256-ecb",
    "des-cbc",
    "des-ecb",
    "des-ede-cbc",
    "des-ede3-cbc",
    "seed-cbc",
    "seed-ecb"
]

KEY_LENGTHS = {
    "aes-128-cbc": 16,
    "aes-128-ecb": 16,
    "aes-192-cbc": 24,
    "aes-192-ecb": 24,
    "aes-256-cbc": 32,
    "aes-256-ecb": 32,
    "aes-128-gcm": 16,
    "aes-256-gcm": 32,
    "camellia-128-cbc": 16,
    "camellia-128-ecb": 16,
    "camellia-192-cbc": 24,
    "camellia-192-ecb": 24,
    "camellia-256-cbc": 32,
    "camellia-256-ecb": 32,
    "des-cbc": 8,
    "des-ecb": 8,
    "des-ede-cbc": 16,
    "des-ede3-cbc": 24,
    "seed-cbc": 16,
    "seed-ecb": 16,
}

IV_LENGTHS = {
    "aes-128-cbc": 16,
    "aes-128-ecb": 0,
    "aes-192-cbc": 16,
    "aes-192-ecb": 0,
    "aes-256-cbc": 16,
    "aes-256-ecb": 0,
    "aes-128-gcm": 12,
    "aes-256-gcm": 12,
    "camellia-128-cbc": 16,
    "camellia-128-ecb": 0,
    "camellia-192-cbc": 16,
    "camellia-192-ecb": 0,
    "camellia-256-cbc": 16,
    "camellia-256-ecb": 0,
    "des-cbc": 8,
    "des-ecb": 0,
    "des-ede-cbc": 8,
    "des-ede3-cbc": 8,
    "seed-cbc": 16,
    "seed-ecb": 0,
    "blowfish-cbc": 8,
    "blowfish-ecb": 0,
}

def register_functions(conn, cursor):
    execute_query(cursor, f"CREATE FUNCTION openssl_encrypt RETURNS STRING SONAME '{UDF_NAME}';")
    execute_query(cursor, f"CREATE FUNCTION openssl_decrypt RETURNS STRING SONAME '{UDF_NAME}';")
    execute_query(cursor, f"CREATE FUNCTION openssl_get_last_error RETURNS STRING SONAME '{UDF_NAME}';")
    conn.commit()

def unregister_functions(conn, cursor):
    execute_query(cursor, f"DROP FUNCTION IF EXISTS openssl_encrypt;")
    execute_query(cursor, f"DROP FUNCTION IF EXISTS openssl_decrypt;")
    execute_query(cursor, f"DROP FUNCTION IF EXISTS openssl_get_last_error;")
    conn.commit()

def execute_query(cursor, query, params=None):
    if params:
        formatted_query = query % tuple(map(lambda x: f"'{x}'" if isinstance(x, str) else x, params))
    else:
        formatted_query = query

    logger.debug(f"Executing SQL: {formatted_query}")
    cursor.execute(query, params)

@pytest.fixture(scope="module")
def db_connection():
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    cursor = conn.cursor()

    unregister_functions(conn, cursor)
    register_functions(conn, cursor)

    yield conn, cursor

    #unregister_functions(conn, cursor)

    cursor.close()
    conn.close()

@pytest.mark.parametrize("cipher", SUPPORTED_CIPHERS)
def test_encrypt_decrypt(db_connection, cipher):
    conn, cursor = db_connection

    plaintext = b"A" * 10
    key = b"A" * KEY_LENGTHS[cipher]

    execute_query(
        cursor,
        "SELECT openssl_encrypt(%s, %s, %s)",
        (cipher, key, plaintext)
    )
    encrypted = cursor.fetchone()[0]
    assert encrypted is not None
    assert encrypted != plaintext

    execute_query(
        cursor,
        "SELECT openssl_decrypt(%s, %s, %s)",
        (cipher, key, encrypted)
    )
    decrypted = cursor.fetchone()[0]
    assert decrypted == plaintext

@pytest.mark.parametrize("cipher", SUPPORTED_CIPHERS)
def test_encrypt_decrypt_with_custom_iv(db_connection, cipher):
    conn, cursor = db_connection

    plaintext = b"A" * 10
    key = b"A" * KEY_LENGTHS[cipher]
    iv = b"I" * IV_LENGTHS[cipher]

    execute_query(
        cursor,
        "SELECT openssl_encrypt(%s, %s, %s, %s)",
        (cipher, key, plaintext, iv)
    )
    encrypted = cursor.fetchone()[0]
    assert encrypted is not None
    assert encrypted != plaintext

    execute_query(
        cursor,
        "SELECT openssl_decrypt(%s, %s, %s)",
        (cipher, key, encrypted)
    )
    decrypted = cursor.fetchone()[0]
    assert decrypted == plaintext

@pytest.mark.parametrize("cipher", SUPPORTED_CIPHERS)
def test_encrypt_decrypt_with_invalid_key_length(db_connection, cipher):
    conn, cursor = db_connection

    plaintext = b"A" * 10
    key = b"A" * (KEY_LENGTHS[cipher] - 1)

    execute_query(
        cursor,
        "SELECT openssl_encrypt(%s, %s, %s)",
        (cipher, key, plaintext)
    )
    encrypted = cursor.fetchone()[0]
    assert encrypted is None

    execute_query(cursor, "SELECT openssl_get_last_error() AS error_message;")
    error_message = cursor.fetchone()[0]
    assert b"Invalid key length for cipher" in error_message

@pytest.mark.parametrize("cipher", SUPPORTED_CIPHERS)
def test_encrypt_decrypt_with_invalid_key(db_connection, cipher):
    conn, cursor = db_connection

    plaintext = b"A" * 10
    key = b"A" * KEY_LENGTHS[cipher]

    execute_query(
        cursor,
        "SELECT openssl_encrypt(%s, %s, %s)",
        (cipher, key, plaintext)
    )
    encrypted = cursor.fetchone()[0]
    assert encrypted is not None
    assert encrypted != plaintext

    key = b"B" * KEY_LENGTHS[cipher]
    execute_query(
        cursor,
        "SELECT openssl_decrypt(%s, %s, %s)",
        (cipher, key, encrypted)
    )
    decrypted = cursor.fetchone()[0]
    assert decrypted is None

    execute_query(cursor, "SELECT openssl_get_last_error() AS error_message;")
    error_message = cursor.fetchone()[0]
    assert b"Decryption failed: bad decrypt" in error_message