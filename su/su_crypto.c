#include "su_crypto.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <string.h>
#include "su_utils.h"

// Load public key from PEM
void* load_pubkey_from_pem(const char* pem) {
    BIO* bio = BIO_new_mem_buf((void*)pem, -1);
    if (!bio) return NULL;
    EVP_PKEY* pk = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return (void*)pk;
}

// Free public key
void free_pubkey(void* pubkey) {
    if (pubkey) {
        EVP_PKEY_free((EVP_PKEY*)pubkey);
    }
}

// SHA256 signature verification
bool verify_signature_sha256(const unsigned char* data, size_t datalen,
                            const unsigned char* sig, size_t siglen,
                            void* pubkey) {
    if (!pubkey) return false;

    bool ok = false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

    EVP_PKEY* pk = (EVP_PKEY*)pubkey;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pk) == 1 &&
        EVP_DigestVerifyUpdate(ctx, data, datalen) == 1) {
        int r = EVP_DigestVerifyFinal(ctx, sig, siglen);
        ok = (r == 1);
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

// Generate digest from key
int digest_from_key(const char* key, int key_is_hex, char out_hex[65]) {
    uint8_t buf[8192]; size_t blen=0;
    if(key_is_hex){
        blen=hex2bin(key, buf, sizeof(buf));
        if(blen==0) return -1;
    }else{
        blen=base64_decode(key, buf, sizeof(buf));
        if(blen==0) return -1;
    }
    uint8_t d[32];
    SHA256(buf, blen, d);
    static const char* hexmap="0123456789ABCDEF";
    for(int i=0;i<32;i++){
        out_hex[i*2]=hexmap[(d[i]>>4)&0xF];
        out_hex[i*2+1]=hexmap[d[i]&0xF];
    }
    out_hex[64]='\0';
    return 0;
}