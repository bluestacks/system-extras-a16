#ifndef SU_CRYPTO_H
#define SU_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Cryptographic utility functions
bool verify_signature_sha256(const unsigned char* data, size_t datalen,
                            const unsigned char* sig, size_t siglen,
                            void* pubkey);

void* load_pubkey_from_pem(const char* pem);

void free_pubkey(void* pubkey);

// Certificate and signature related
int digest_from_key(const char* key, int key_is_hex, char out_hex[65]);

#ifdef __cplusplus
}
#endif

#endif // SU_CRYPTO_H