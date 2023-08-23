#ifndef HASHFUNCTION_H
#define HASHFUNCTION_H

#include<string>
#include "EnclaveUtils.h"
// #include<openssl/evp.h>
#include "sgx_trts.h"
#include "sgx_tcrypto.h"


using namespace std;

class SGXHashFunc{
public:
	SGXHashFunc();
	~SGXHashFunc();
	static std::string sha1(const char* key);
	static std::string sha256(const char* data);
	static std::string md5(const char* key);
};

#endif //HASHFUNCTION_H