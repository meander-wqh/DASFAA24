#include "hashfunction.h"

// string HashFunc::sha1(const char* key){
// 	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
// 	unsigned char md_value[EVP_MAX_MD_SIZE];
// 	unsigned int md_len;

// 	EVP_DigestInit(mdctx, EVP_sha1());
// 	EVP_DigestUpdate(mdctx, (const void*) key, sizeof(key));
// 	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
// 	EVP_MD_CTX_free(mdctx);

// 	return std::string((char*)md_value, (size_t)md_len);
// }


// string HashFunc::md5(const char* key){
// 	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
// 	unsigned char md_value[EVP_MAX_MD_SIZE];
// 	unsigned int md_len;

// 	EVP_DigestInit(mdctx, EVP_md5());
// 	EVP_DigestUpdate(mdctx, (const void*) key, sizeof(key));
// 	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
// 	EVP_MD_CTX_free(mdctx);

// 	return std::string((char*)md_value, (size_t)md_len);
// }


std::string HashFunc::sha256(const char* data) {
    size_t data_len = strlen(data);
    sgx_sha256_hash_t sha256_hash;

    sgx_status_t ret = sgx_sha256_msg((const uint8_t*)data, data_len, &sha256_hash);
    
    if (ret == SGX_SUCCESS) {
        std::string sha256_hash_str;
        for (int i = 0; i < SGX_SHA256_HASH_SIZE; i++) {
            sha256_hash_str += char(sha256_hash[i]);
        }
        return sha256_hash_str;
    } else {
        std::cerr << "[*] SGX SHA-256 hash error: " << ret << std::endl;
        return "";
    }
}