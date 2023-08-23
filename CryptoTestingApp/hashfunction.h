#ifndef HASHFUNCTION_H
#define HASHFUNCTION_H

#include <string>
#include <cstring>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <iostream>
#include "Utils.h"

using namespace std;

class HashFunc{
public:
	HashFunc();
	~HashFunc();
	static std::string sha1(const char* key);
	static std::string sha256(const char* key);
	static std::string md5(const char* key);
};

#endif //HASHFUNCTION_H