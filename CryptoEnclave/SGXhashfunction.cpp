#include "SGXhashfunction.h"

std::string SGXHashFunc::sha256(const char* data) {
    size_t data_len = strlen(data);
    sgx_sha256_hash_t sha256_hash;
    sgx_status_t ret = sgx_sha256_msg((uint8_t*)data, data_len, &sha256_hash);
    //printf("%d",SGX_SHA256_HASH_SIZE);
    if (ret == SGX_SUCCESS) {
        std::string sha256_hash_str;
        for (int i = 0; i < SGX_SHA256_HASH_SIZE; i++) {
            sha256_hash_str += (unsigned char)(sha256_hash[i]);
        }
        return sha256_hash_str;
    } else {
        return "";
    }
}