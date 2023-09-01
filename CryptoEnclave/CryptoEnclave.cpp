#include "CryptoEnclave_t.h"

#include "EnclaveUtils.h"

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "stdlib.h"
#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <unordered_map>
#include <algorithm> // for std::find
#include <iterator> // for std::begin, std::end
#include <vector>
#include <list>
#include "../common/data_type.h"
#include "cuckoofilter.h"
#include "linktree.h"
#include <queue>

using namespace std;

// change to malloc for tokens, run ulimit -s 65536 to set stack size to 
// 65536 KB in linux 


//local variables inside Enclave
unsigned char KW[ENC_KEY_SIZE] = {0}; //关键字密钥
unsigned char KC[ENC_KEY_SIZE] = {0}; //计数器密钥
unsigned char KF[ENC_KEY_SIZE] = {0}; //文件密钥

unsigned char K_T[ENC_KEY_SIZE] = {0}; 
unsigned char K_Z[ENC_KEY_SIZE] = {0}; 
unsigned char K_X[ENC_KEY_SIZE] = {0}; 

std::unordered_map<std::string, int> ST; //关键字与对应文件次数哈希表
std::unordered_map<std::string, std::vector<std::string>> D; //关键字与被删文件ID哈希表
std::unordered_map<std::string, int> UpdateCnt;
std::unordered_map<std::string, CuckooFilter*> CFs;
std::queue<std::string> CFQueue;

LinkTree* cf_tree = nullptr;

int fingerprint_size = 0;
int single_table_length = 0;
int single_capacity = 0;


std::vector<std::string> d; //被删文件ID列表

/*** setup */
// void ecall_init(unsigned char *keyF, size_t len){ 
// 	d.reserve(750000); //初始化d
//     memcpy(KF,keyF,len); //拷贝文件密钥到KF
//     sgx_read_rand(KW, ENC_KEY_SIZE); //产生真随机数KW，用于生成密钥k_w
//     sgx_read_rand(KC, ENC_KEY_SIZE); //产生真随机数KC，用于生成密钥k_c
// }

void ecall_init(unsigned char key_array[3][16]){
    memcpy(K_T,key_array[0],ENC_KEY_SIZE);
    memcpy(K_Z,key_array[1],ENC_KEY_SIZE);
    memcpy(K_X,key_array[2],ENC_KEY_SIZE);
    // print_bytes((uint8_t*)key_array[0],ENC_KEY_SIZE);
    // print_bytes((uint8_t*)key_array[1],ENC_KEY_SIZE);
    // print_bytes((uint8_t*)key_array[2],ENC_KEY_SIZE);
    
    int capacity = ITEM_NUMBER;
	
	single_table_length = upperpower2(capacity/4.0/EXP_BLOCK_NUM);

	single_capacity = single_table_length*0.9375*4;//s=6 1920 s=12 960 s=24 480 s=48 240 s=96 120

	double false_positive = FALSE_POSITIVE;
	double single_false_positive = 1-pow(1.0-false_positive, ((double)single_capacity/capacity));
	double fingerprint_size_double = ceil(log(8.0/single_false_positive)/log(2));
	if(fingerprint_size_double>0 && fingerprint_size_double<=4){
		fingerprint_size = 4;
	}else if(fingerprint_size_double>4 && fingerprint_size_double<=8){
		fingerprint_size = 8;
	}else if(fingerprint_size_double>8 && fingerprint_size_double<=12){
		fingerprint_size = 12;
	}else if(fingerprint_size_double>12 && fingerprint_size_double<=16){
		fingerprint_size = 16;
	}else if(fingerprint_size_double>16 && fingerprint_size_double<=24){
		fingerprint_size = 16;
	}else if(fingerprint_size_double>24 && fingerprint_size_double<=32){
		fingerprint_size = 16;
	}else{
		//cout<<"fingerprint out of range!!!"<<endl;
		fingerprint_size = 16;
	}

    //init cf_tree
    cf_tree = new LinkTree();
}

void ecall_test(char* encrypted_content, size_t length_content){
    size_t plain_doc_len = (size_t)length_content - AESGCM_MAC_SIZE - AESGCM_IV_SIZE;
	unsigned char *plain_doc_content = (unsigned char *) malloc(plain_doc_len* sizeof(unsigned char));
    //decrypt the cipher from the server
    dec_aes_gcm(KF,encrypted_content,length_content,
                plain_doc_content,plain_doc_len);
    std::string doc_i((char*)plain_doc_content,plain_doc_len);
    printf("Plain doc ==> %s\n",doc_i.c_str());
    //free(plain_doc_content);

    //修改密文内容，再次加密发送给server
    //设置明文
    printf("明文后再增加一个yangxu");
    char* temp = "yangxu";
    std::string new_plain_doc_content_temp = string((char*)plain_doc_content) + string(temp); 
    const char *new_plain_doc_content = new_plain_doc_content_temp.c_str();
    size_t new_plain_size = new_plain_doc_content_temp.length();
    //初始化密文
    size_t new_encrypted_size = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + new_plain_size;
    char* new_encrypted_content =  (char *) malloc(new_encrypted_size);
    //加密
    enc_aes_gcm(KF,new_plain_doc_content,new_plain_size,new_encrypted_content,new_encrypted_size);
    ocall_test2(new_encrypted_content,new_encrypted_size);
}

void ecall_hash_test(const char* data, size_t len){
    printf("%s", data);
    std::string res = SGXHashFunc::sha256(data);
    const char* cres = res.c_str();
    ocall_print_string(cres);
}

void ecall_Conjunctive_Exact_Social_Search(char* str){
    std::string sResList = "";
    std::string input(str);
    std::vector<std::string> tokens;//w1...wn
    int LeastWIndex = 0;//UpdateCnt次数最少的w的下标
    int leastUpdateCnt = -1;
    int index = 0;
    //分割
    size_t pos = 0;
    while((pos = input.find('&', pos)) != std::string::npos){
        tokens.push_back(input.substr(0, pos));
        if(index == 0){
            leastUpdateCnt = UpdateCnt[input.substr(0, pos)];
            LeastWIndex = index;
        }else{
            leastUpdateCnt = UpdateCnt[input.substr(0, pos)]<leastUpdateCnt? UpdateCnt[input.substr(0, pos)]:leastUpdateCnt;
            if(UpdateCnt[input.substr(0, pos)]<leastUpdateCnt){
                LeastWIndex = index;
            }
        }
        index++;
        pos++;
        input = input.substr(pos);
        pos = 0;
    }
    // 最后的一节字符串
    if(UpdateCnt[input]<leastUpdateCnt){
        LeastWIndex = index;
    }
    tokens.push_back(input); 

    // for(int i=0;i<tokens.size();i++){
    //     ocall_print_string(tokens[i].c_str());
    // }
    std::vector<unsigned char*> stokenList;

    //ocall_print_string(tokens[LeastWIndex].c_str());
    //查询
    for(int j=1;j<=UpdateCnt[tokens[LeastWIndex]];++j){
        //这里每一个stag地址都一样
        unsigned char stag[ENTRY_HASH_KEY_LEN_128];
        unsigned char* msg = (unsigned char*)(tokens[LeastWIndex] + std::to_string(j)).c_str();
        int msg_len = (tokens[LeastWIndex] + std::to_string(j)).length();
        // printf("msg_len:");
        // ocall_print_int(msg_len);
        hash_SHA128(K_T, msg, msg_len, stag);
        // printf("stag:");
        // print_bytes(stag,ENTRY_HASH_KEY_LEN_128);
        unsigned char* stag_copy = new unsigned char[ENTRY_HASH_KEY_LEN_128];
        memcpy(stag_copy, stag, ENTRY_HASH_KEY_LEN_128);
        stokenList.push_back(stag_copy);
    }

    int length = ENTRY_HASH_KEY_LEN_128*stokenList.size();
    unsigned char StrStokenList[length];
    unsigned char* p = StrStokenList;
    for(int i=0;i<stokenList.size();i++){
        // printf("stokenList[i]:");
        // print_bytes(stokenList[i],ENTRY_HASH_KEY_LEN_128);
        memcpy(p,stokenList[i],ENTRY_HASH_KEY_LEN_128);
        p += ENTRY_HASH_KEY_LEN_128;
    }
    //print_bytes(StrStokenList,length);

    int CidList_max_len = stokenList.size() * ENTRY_HASH_KEY_LEN_128;
    unsigned char CidList[CidList_max_len+1];//凡是要通过ocall，ecall传出传入的字符串，都需要加一位存储终止操作符，不然桥函数不会自动分配终止符导致长度混乱？
    int CidListSize;
    ocall_send_stokenList(StrStokenList,length,stokenList.size(),CidList,CidList_max_len+1,&CidListSize,(size_t)sizeof(int));

    unsigned char* CidListP = CidList;
    // printf("CidList_len:");
    // ocall_print_int(strlen((const char*)CidList));//TODO,长度为22？,有小概率长度为0？为什么:长度为0时说明stag不正确，没有取出值，而长度是因为没设置终止符
    // ocall_print_int(CidListSize);
    // ocall_print_int(CidList_max_len);
    //print_bytes(CidList,CidList_max_len);
    for(int j=0;j<CidListSize;j++){
        int flag = 0;
        unsigned char Cid[ENTRY_HASH_KEY_LEN_128];
        unsigned char tempF_2[ENTRY_HASH_KEY_LEN_128];
        hash_SHA128(K_Z,(unsigned char*)tokens[LeastWIndex].c_str(),tokens[LeastWIndex].length(),tempF_2);
        memcpy(Cid,CidListP,ENTRY_HASH_KEY_LEN_128);
        //print_bytes(Cid,ENTRY_HASH_KEY_LEN_128);
        CidListP+=ENTRY_HASH_KEY_LEN_128;
        unsigned char id[ENTRY_HASH_KEY_LEN_128];
        Hashxor(Cid,tempF_2,ENTRY_HASH_KEY_LEN_128,id);//这里的id是经过填充的
        string sid = DePatch(id);
        // printf(sid.c_str());
        for(int i=0;i<tokens.size();i++){
            if(i != LeastWIndex){
                std::string sxtag = tokens[i] + sid;
                //ocall_print_string(sxtag.c_str());
                const char* xtag = sxtag.c_str();
                // printf("xtag strlen:");
                // ocall_print_int(strlen(xtag));
                size_t index;
                uint32_t fingerprint;
                generateIF(xtag,index,fingerprint,fingerprint_size,single_table_length);
                std::string CFId = cf_tree->getCFId(fingerprint,fingerprint_size);
                if(CFs.find(CFId) == CFs.end()){
                    if(CFs.size() == MostCFs){
                        delete CFs[CFQueue.front()];
                        CFs.erase(CFQueue.front());
                        CFQueue.pop();
                    }
                    CFQueue.push(CFId);
                    uint32_t fingerprints[single_table_length*4];
                    //这里single_table_length*4太大了，会导致段错误
                    ocall_Get_CF((unsigned char*)CFId.c_str(), CFId.length() ,fingerprints, sizeof(uint32_t), single_table_length*4);
                    CFs[CFId] = new CuckooFilter(CFId,single_table_length, fingerprint_size, single_capacity, CFId.length());	
                    int index = 0;
                    int notNull = 0;
                    while(index<single_table_length*4){
                        CFs[CFId]->write(index / 4, index%4 , fingerprints[index]);
                        //这里只能取到1个指纹，但应该是两个
                        // if(fingerprints[index] != 0){
                        //     notNull++;
                        //     ocall_print_int(notNull);
                        //     printf("fingerprint:");
                        //     ocall_print_int(fingerprints[index]);
                        // }
                        index++;
                    }
                }
                CuckooFilter* CF = CFs[CFId];
                //这里面xtag求出的指纹没有问题
                if(CF->queryItem(xtag) == false){
                    //printf("not found");
                    flag = 1; //没找到
                    break;
                }
            }
        }
        if(flag == 0){
            sResList += sid;
            sResList += "&";
        }
    }


    for(int i=0;i<stokenList.size();i++){
        delete stokenList[i];
    }
    printf("Res:");
    printf((char*)sResList.c_str());
    ///ocall_Get_Res((char*)sResList.c_str(),sResList.length());
}

//输入是要模糊查询的子串，然后在SGX里面处理成需要的数据结构
void ecall_Conjunctive_Fuzzy_Social_Search(char* str){
    std::string sResList = "";
    std::string input(str);
    std::vector<std::string> tokens;//w1...wn
    int LeastWIndex = 0;//UpdateCnt次数最少的w的下标
    int leastUpdateCnt = -1;
    int index = 0;
    //分割
    size_t pos = 0;//&的位置
    size_t pospos = 0;//|的位置
    while((pos = input.find('&', pos)) != std::string::npos){   
        tokens.push_back(input.substr(0, pos));
        if(index == 0){
            leastUpdateCnt = UpdateCnt[input.substr(0, pos)];
            LeastWIndex = index;
        }else{
            leastUpdateCnt = UpdateCnt[input.substr(0, pos)]<leastUpdateCnt? UpdateCnt[input.substr(0, pos)]:leastUpdateCnt;
            if(UpdateCnt[input.substr(0, pos)]<leastUpdateCnt){
                LeastWIndex = index;
            }
        }
        index++;
        pos++;
        input = input.substr(pos);
        pos = 0;
    }
    // 最后的一节字符串
    if(UpdateCnt[input]<leastUpdateCnt){
        LeastWIndex = index;
    }
    tokens.push_back(input); 

    // for(int i=0;i<tokens.size();i++){
    //     ocall_print_string(tokens[i].c_str());
    // }
    std::vector<unsigned char*> stokenList;

    //ocall_print_string(tokens[LeastWIndex].c_str());
    //查询
    for(int j=1;j<=UpdateCnt[tokens[LeastWIndex]];++j){
        //这里每一个stag地址都一样
        unsigned char stag[ENTRY_HASH_KEY_LEN_128];
        unsigned char* msg = (unsigned char*)(tokens[LeastWIndex] + std::to_string(j)).c_str();
        int msg_len = (tokens[LeastWIndex] + std::to_string(j)).length();
        // printf("msg_len:");
        // ocall_print_int(msg_len);
        hash_SHA128(K_T, msg, msg_len, stag);
        // printf("stag:");
        // print_bytes(stag,ENTRY_HASH_KEY_LEN_128);
        unsigned char* stag_copy = new unsigned char[ENTRY_HASH_KEY_LEN_128];
        memcpy(stag_copy, stag, ENTRY_HASH_KEY_LEN_128);
        stokenList.push_back(stag_copy);
    }

    int length = ENTRY_HASH_KEY_LEN_128*stokenList.size();
    unsigned char StrStokenList[length];
    unsigned char* p = StrStokenList;
    for(int i=0;i<stokenList.size();i++){
        // printf("stokenList[i]:");
        // print_bytes(stokenList[i],ENTRY_HASH_KEY_LEN_128);
        memcpy(p,stokenList[i],ENTRY_HASH_KEY_LEN_128);
        p += ENTRY_HASH_KEY_LEN_128;
    }
    //print_bytes(StrStokenList,length);

    int CidList_max_len = stokenList.size() * ENTRY_HASH_KEY_LEN_128;
    unsigned char CidList[CidList_max_len+1];//凡是要通过ocall，ecall传出传入的字符串，都需要加一位存储终止操作符，不然桥函数不会自动分配终止符导致长度混乱？
    int CidListSize;
    ocall_send_stokenList(StrStokenList,length,stokenList.size(),CidList,CidList_max_len+1,&CidListSize,(size_t)sizeof(int));

    unsigned char* CidListP = CidList;
    // printf("CidList_len:");
    // ocall_print_int(strlen((const char*)CidList));//TODO,长度为22？,有小概率长度为0？为什么:长度为0时说明stag不正确，没有取出值，而长度是因为没设置终止符
    // ocall_print_int(CidListSize);
    // ocall_print_int(CidList_max_len);
    //print_bytes(CidList,CidList_max_len);
    for(int j=0;j<CidListSize;j++){
        int flag = 0;
        unsigned char Cid[ENTRY_HASH_KEY_LEN_128];
        unsigned char tempF_2[ENTRY_HASH_KEY_LEN_128];
        hash_SHA128(K_Z,(unsigned char*)tokens[LeastWIndex].c_str(),tokens[LeastWIndex].length(),tempF_2);
        memcpy(Cid,CidListP,ENTRY_HASH_KEY_LEN_128);
        //print_bytes(Cid,ENTRY_HASH_KEY_LEN_128);
        CidListP+=ENTRY_HASH_KEY_LEN_128;
        unsigned char id[ENTRY_HASH_KEY_LEN_128];
        Hashxor(Cid,tempF_2,ENTRY_HASH_KEY_LEN_128,id);//这里的id是经过填充的
        string sid = DePatch(id);
        // printf(sid.c_str());
        for(int i=0;i<tokens.size();i++){
            if(i != LeastWIndex){
                std::string sxtag = tokens[i] + sid;
                //ocall_print_string(sxtag.c_str());
                const char* xtag = sxtag.c_str();
                // printf("xtag strlen:");
                // ocall_print_int(strlen(xtag));
                size_t index;
                uint32_t fingerprint;
                generateIF(xtag,index,fingerprint,fingerprint_size,single_table_length);
                std::string CFId = cf_tree->getCFId(fingerprint,fingerprint_size);
                if(CFs.find(CFId) == CFs.end()){
                    if(CFs.size() == MostCFs){
                        delete CFs[CFQueue.front()];
                        CFs.erase(CFQueue.front());
                        CFQueue.pop();
                    }
                    CFQueue.push(CFId);
                    uint32_t fingerprints[single_table_length*4];
                    //这里single_table_length*4太大了，会导致段错误
                    ocall_Get_CF((unsigned char*)CFId.c_str(), CFId.length() ,fingerprints, sizeof(uint32_t), single_table_length*4);
                    CFs[CFId] = new CuckooFilter(CFId,single_table_length, fingerprint_size, single_capacity, CFId.length());	
                    int index = 0;
                    int notNull = 0;
                    while(index<single_table_length*4){
                        CFs[CFId]->write(index / 4, index%4 , fingerprints[index]);
                        //这里只能取到1个指纹，但应该是两个
                        // if(fingerprints[index] != 0){
                        //     notNull++;
                        //     ocall_print_int(notNull);
                        //     printf("fingerprint:");
                        //     ocall_print_int(fingerprints[index]);
                        // }
                        index++;
                    }
                }
                CuckooFilter* CF = CFs[CFId];
                //这里面xtag求出的指纹没有问题
                if(CF->queryItem(xtag) == false){
                    //printf("not found");
                    flag = 1; //没找到
                    break;
                }
            }
        }
        if(flag == 0){
            sResList += sid;
            sResList += "&";
        }
    }


    for(int i=0;i<stokenList.size();i++){
        delete stokenList[i];
    }
    printf("Res:");
    printf((char*)sResList.c_str());
    ///ocall_Get_Res((char*)sResList.c_str(),sResList.length());
}

void ecall_update_data(const char* w, size_t w_len, const char* id, size_t id_len, size_t op){
    std::string xtag;
    std::string sw(w,w_len);
    std::string sid(id,id_len);
    xtag = sw + sid;
    //cal fingerprint

    uint32_t fingerprint = 0;
    size_t index = 0;
    //ocall_print_string(xtag.c_str());
    generateIF(xtag.c_str(), index, fingerprint, fingerprint_size, single_table_length);
    //ocall_print_int((int)fingerprint);
    std::string CFId = cf_tree->getCFId(fingerprint,fingerprint_size);
    if(op == 1){
        //add
        if(UpdateCnt.find(sw) == UpdateCnt.end()){
            UpdateCnt[sw] = 0;
        }
        UpdateCnt[sw]++;
        unsigned char stag[ENTRY_HASH_KEY_LEN_128];
        unsigned char* msg = (unsigned char*)(sw+std::to_string(UpdateCnt[sw])).c_str();
        int msg_len = (sw+std::to_string(UpdateCnt[sw])).length();

        hash_SHA128(K_T, msg, msg_len, stag);
        //print_bytes(stag,ENTRY_HASH_KEY_LEN_128);
        unsigned char C_id[ENTRY_HASH_KEY_LEN_128];
        unsigned char PatchValue[ENTRY_HASH_KEY_LEN_128];
        PatchTo128(sid, PatchValue);

        unsigned char tempF_2[ENTRY_HASH_KEY_LEN_128];
        hash_SHA128(K_Z,sw.c_str(),sw.length(),tempF_2);

        Hashxor(PatchValue, tempF_2, ENTRY_HASH_KEY_LEN_128, C_id);
        unsigned char ind[ENTRY_HASH_KEY_LEN_128];
        hash_SHA128(K_X,(sw+sid).c_str(),(sw+sid).length(),ind);

        PatchTo128((sw+std::to_string(UpdateCnt[sw]).c_str()),PatchValue);
        unsigned char C_stag[ENTRY_HASH_KEY_LEN_128];
        Hashxor(PatchValue,tempF_2,ENTRY_HASH_KEY_LEN_128,C_stag);
        //ocall_print_int(fingerprint);
        //Send to Server
        ocall_add_update(
            stag,ENTRY_HASH_KEY_LEN_128,
            C_id,ENTRY_HASH_KEY_LEN_128,
            ind,ENTRY_HASH_KEY_LEN_128,
            C_stag,ENTRY_HASH_KEY_LEN_128,
            fingerprint,
            index,
            (unsigned char*)CFId.c_str(),CFId.length()
        );
    }else{
        unsigned char stag_inverse[ENTRY_HASH_KEY_LEN_128];
        hash_SHA128(K_T, (sw+std::to_string(UpdateCnt[sw])).c_str() , (sw+std::to_string(UpdateCnt[sw])).length(), stag_inverse);
        UpdateCnt[sw]--;
        unsigned char C_id_inverse[ENTRY_HASH_KEY_LEN_128];
        ocall_Query_TSet(stag_inverse,ENTRY_HASH_KEY_LEN_128, C_id_inverse,ENTRY_HASH_KEY_LEN_128);
        unsigned char tempF_2[ENTRY_HASH_KEY_LEN_128];
        hash_SHA128(K_Z,sw.c_str(),sw.length(),tempF_2);
        unsigned char PatchValue[ENTRY_HASH_KEY_LEN_128];
        Hashxor(C_id_inverse,tempF_2,ENTRY_HASH_KEY_LEN_128,PatchValue);
        std::string sid_inverse = DePatch(PatchValue);
        unsigned char ind_inverse[ENTRY_HASH_KEY_LEN_128];
        unsigned char ind[ENTRY_HASH_KEY_LEN_128];
        hash_SHA128(K_X,(sw+sid_inverse).c_str(),(sw+sid_inverse).length(),ind_inverse);
        hash_SHA128(K_X,(sw+sid).c_str(),(sw+sid).length(),ind);
        unsigned char C_stag[ENTRY_HASH_KEY_LEN_128];
        ocall_Query_iTSet(ind, ENTRY_HASH_KEY_LEN_128,C_stag,ENTRY_HASH_KEY_LEN_128);
        Hashxor(C_stag,tempF_2,ENTRY_HASH_KEY_LEN_128,PatchValue);
        std::string sDePatchValue = DePatch(PatchValue);
        unsigned char stag[ENTRY_HASH_KEY_LEN_128];
        hash_SHA128(K_T,sDePatchValue.c_str(),sDePatchValue.length(),stag);
        //Send to Server
        ocall_del_update(
            stag,ENTRY_HASH_KEY_LEN_128,
            stag_inverse,ENTRY_HASH_KEY_LEN_128,
            ind,ENTRY_HASH_KEY_LEN_128,
            ind_inverse,ENTRY_HASH_KEY_LEN_128,
            fingerprint,
            index,
            (unsigned char*)CFId.c_str(),CFId.length()
        );
    }
}

void ecall_update_data_Fuzzy(const char* w, size_t w_len, const char* id, size_t id_len, size_t pos, size_t op){
    std::string xtag;
    std::string sw(w,w_len);
    std::string sid(id,id_len);
    std::string spos = std::to_string(pos);
    xtag = sw + sid + spos;
    //cal fingerprint

    uint32_t fingerprint = 0;
    size_t index = 0;
    //ocall_print_string(xtag.c_str());
    generateIF(xtag.c_str(), index, fingerprint, fingerprint_size, single_table_length);
    //ocall_print_int((int)fingerprint);
    std::string CFId = cf_tree->getCFId(fingerprint,fingerprint_size);
    if(op == 1){
        //add
        if(UpdateCnt.find(sw) == UpdateCnt.end()){
            UpdateCnt[sw] = 0;
        }
        UpdateCnt[sw]++;
        unsigned char stag[ENTRY_HASH_KEY_LEN_128];
        unsigned char* msg = (unsigned char*)(sw+std::to_string(UpdateCnt[sw])).c_str();
        int msg_len = (sw+std::to_string(UpdateCnt[sw])).length();

        hash_SHA128(K_T, msg, msg_len, stag);
        //print_bytes(stag,ENTRY_HASH_KEY_LEN_128);
        unsigned char C_id[ENTRY_HASH_KEY_LEN_128];
        unsigned char PatchValue[ENTRY_HASH_KEY_LEN_128];

        sid = sid + "|" + spos; //id与pos用|分割
        PatchTo128(sid, PatchValue); 

        unsigned char tempF_2[ENTRY_HASH_KEY_LEN_128];
        hash_SHA128(K_Z,sw.c_str(),sw.length(),tempF_2);

        Hashxor(PatchValue, tempF_2, ENTRY_HASH_KEY_LEN_128, C_id);
        unsigned char ind[ENTRY_HASH_KEY_LEN_128];
        hash_SHA128(K_X,(sw+sid).c_str(),(sw+sid).length(),ind);

        PatchTo128((sw+std::to_string(UpdateCnt[sw]).c_str()),PatchValue);
        unsigned char C_stag[ENTRY_HASH_KEY_LEN_128];
        Hashxor(PatchValue,tempF_2,ENTRY_HASH_KEY_LEN_128,C_stag);
        //ocall_print_int(fingerprint);
        //Send to Server
        ocall_add_update(
            stag,ENTRY_HASH_KEY_LEN_128,
            C_id,ENTRY_HASH_KEY_LEN_128,
            ind,ENTRY_HASH_KEY_LEN_128,
            C_stag,ENTRY_HASH_KEY_LEN_128,
            fingerprint,
            index,
            (unsigned char*)CFId.c_str(),CFId.length()
        );
    }else{
        unsigned char stag_inverse[ENTRY_HASH_KEY_LEN_128];
        hash_SHA128(K_T, (sw+std::to_string(UpdateCnt[sw])).c_str() , (sw+std::to_string(UpdateCnt[sw])).length(), stag_inverse);
        UpdateCnt[sw]--;
        unsigned char C_id_inverse[ENTRY_HASH_KEY_LEN_128];
        ocall_Query_TSet(stag_inverse,ENTRY_HASH_KEY_LEN_128, C_id_inverse,ENTRY_HASH_KEY_LEN_128);
        unsigned char tempF_2[ENTRY_HASH_KEY_LEN_128];
        hash_SHA128(K_Z,sw.c_str(),sw.length(),tempF_2);
        unsigned char PatchValue[ENTRY_HASH_KEY_LEN_128];
        Hashxor(C_id_inverse,tempF_2,ENTRY_HASH_KEY_LEN_128,PatchValue);
        std::string sid_inverse = DePatch(PatchValue);
        unsigned char ind_inverse[ENTRY_HASH_KEY_LEN_128];
        unsigned char ind[ENTRY_HASH_KEY_LEN_128];
        hash_SHA128(K_X,(sw+sid_inverse).c_str(),(sw+sid_inverse).length(),ind_inverse);
        hash_SHA128(K_X,(sw+sid).c_str(),(sw+sid).length(),ind);
        unsigned char C_stag[ENTRY_HASH_KEY_LEN_128];
        ocall_Query_iTSet(ind, ENTRY_HASH_KEY_LEN_128,C_stag,ENTRY_HASH_KEY_LEN_128);
        Hashxor(C_stag,tempF_2,ENTRY_HASH_KEY_LEN_128,PatchValue);
        std::string sDePatchValue = DePatch(PatchValue);
        unsigned char stag[ENTRY_HASH_KEY_LEN_128];
        hash_SHA128(K_T,sDePatchValue.c_str(),sDePatchValue.length(),stag);
        //Send to Server
        ocall_del_update(
            stag,ENTRY_HASH_KEY_LEN_128,
            stag_inverse,ENTRY_HASH_KEY_LEN_128,
            ind,ENTRY_HASH_KEY_LEN_128,
            ind_inverse,ENTRY_HASH_KEY_LEN_128,
            fingerprint,
            index,
            (unsigned char*)CFId.c_str(),CFId.length()
        );
    }
}

/*** update with op=add */
void ecall_addDoc(char *doc_id, size_t id_length,char *content,int content_length){
              
    //parse content to keywords splited by comma
    std::vector<std::string> wordList;
    wordList = wordTokenize(content,content_length); //划分文件为单词列表
    size_t pair_no = wordList.size(); // pair_no:单词个数 


    //rand_t:消息数据结构
    rand_t t1_u_arr[pair_no];
    rand_t t1_v_arr[pair_no]; 
    rand_t t2_u_arr[pair_no];
    rand_t t2_v_arr[pair_no];

    int index=0;
    //对于doc中的每一个word，进行遍历，也就是说，一个doc中如果存多个相同的w，那么对于这个w，对于该doc有很多个c。
    for(std::vector<std::string>::iterator it = wordList.begin(); it != wordList.end(); ++it) {
      
      std::string word = (*it);
 
      entryKey k_w, k_c; //entryKey:密钥结构体？

      k_w.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + word.length(); //k_w密钥长度
	  k_w.content = (char *) malloc(k_w.content_length); //k_w初始化
      //AES对称加密
      //parm1: 密钥 parm2:明文 parm3:明文长度; parm4:密文; parm5:密文长度
      enc_aes_gcm(KW,word.c_str(),word.length(),k_w.content,k_w.content_length);
    

      k_c.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + word.length(); //k_c密钥长度
	  k_c.content = (char *) malloc(k_c.content_length); //k_c初始化
      //AES对称加密
      //parm1: 密钥 parm2:明文 parm3:明文长度; parm4:密文; parm5:密文长度
      enc_aes_gcm(KC,word.c_str(),word.length(),k_c.content,k_c.content_length);
          
      int c=0;//对于每一个文件的计数器，初始化为0

      std::unordered_map<std::string,int>::const_iterator got = ST.find(word); //在关键字与对应文件数量哈希表中寻找关键字word对应键值对
      if ( got == ST.end()) {
          //第一次加入，c == 0
          c = 0;  
      }else{
          //非第一次加入，直接用second，因为操作结束后c++
        c = got->second;
      }
      c++;

      //find k_id
      unsigned char *k_id =  (unsigned char *) malloc(ENTRY_HASH_KEY_LEN_128); //初始化k_id,128bit 
      //将c转为字符
      std::string c_str = std::to_string(c);
      char const *c_char = c_str.c_str(); 
      //Hash-128
      //parm1: 哈希密钥 parm2:消息 parm3:消息长度; parm4:随机数 kid由此产生
      //k_id <- H1(k_w,c) 
      hash_SHA128(k_w.content,c_char,c_str.length(),k_id);

      //len is used for hash_SHA128_key multiple times
      size_t len = ENTRY_HASH_KEY_LEN_128 + k_w.content_length;
      
      //生成键值对(u,v)
      unsigned char *_u = (unsigned char *) malloc(len * sizeof(unsigned char));
      //Hash-128
      //parm1: 哈希密钥 parm2:消息 parm3:消息长度; parm4:msg len;parm5:digist T1u 由此产生
      //u <- H2(k_w,c)
      hash_SHA128_key(k_w.content,k_w.content_length, c_char,c_str.length(),_u);
      memcpy(&t1_u_arr[index].content,_u,len); 
      t1_u_arr[index].content_length = len;


      size_t message_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + id_length;
      char* message = (char *) malloc(message_length);

      //k_id加密id
      enc_aes_gcm(k_id,doc_id,id_length,message,message_length);
      memcpy(&t1_v_arr[index].content,(unsigned char*)message,message_length);
      t1_v_arr[index].content_length = message_length;

      //生成键值对(u',v')
      unsigned char *_u_prime = (unsigned char *) malloc(len * sizeof(unsigned char));
      hash_SHA128_key(k_w.content,k_w.content_length, doc_id,id_length,_u_prime);
      memcpy(&t2_u_arr[index].content,_u_prime,len);
      t2_u_arr[index].content_length = len;

      size_t message_length2 = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + c_str.length();
      char* message2 = (char *) malloc(message_length2);

      enc_aes_gcm(k_c.content,c_char,c_str.length(),message2,message_length2);
      memcpy(&t2_v_arr[index].content,(unsigned char*)message2,message_length2);
      t2_v_arr[index].content_length = message_length2;

      //update ST
      got = ST.find(word); //在关键字与对应文件数量哈希表中寻找关键字word对应键值对
      if( got == ST.end()){ //若不存在则新建
          ST.insert(std::pair<std::string,int>(word,c));
      } else{ //若存在，直接赋值
          ST.at(word) = c;
      }

      index++;

      //free memory
      free(k_id);
      free(_u);
      free(_u_prime);

      //free k_w, k_c
      free(k_w.content);
      free(k_c.content);

      //free value
      free(message);
      free(message2);
    }

    //call Server to update ocall 把T1T2传给server
    ocall_transfer_encrypted_entries(t1_u_arr,
                                     t1_v_arr,
                                     t2_u_arr,
                                     t2_v_arr,
                                     pair_no, sizeof(rand_t));

}

/*** update with op=del */
void ecall_delDoc(char *doc_id, size_t id_length){
    std::string delId(doc_id,id_length);
    d.push_back(delId); //被删文件ID列后添加一个ID
}

void ecall_test_int(size_t test){
    uint32_t* fingerprint = new uint32_t[10];
    ocall_test_int(test, fingerprint, sizeof(uint32_t),10);
    for(int i=0;i<10;i++){
        ocall_print_int((int)fingerprint[i]);
    }
}

/*** search for a keyword */
void ecall_search(const char *keyword, size_t keyword_len){

    //init keys
    std::string keyword_str(keyword,keyword_len); //keyword_str要查找的关键字

    entryKey k_w, k_c; //entryKey:密钥结构体

    //生成关键字密钥k_w
    k_w.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + keyword_len; 
	k_w.content = (char *) malloc(k_w.content_length);
    enc_aes_gcm(KW,keyword,keyword_len,k_w.content,k_w.content_length);
    
    //生成计数器密钥k_c
    k_c.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + keyword_len; 
	k_c.content = (char *) malloc(k_c.content_length);
    enc_aes_gcm(KC,keyword,keyword_len,k_c.content,k_c.content_length);


    unsigned char *encrypted_content = (unsigned char *) malloc(BUFLEN * sizeof(unsigned char));
    int length_content;
    //遍历被删除文件ID
    for(auto&& del_id: d){

    	//retrieve encrypted doc
        /***********this is an ocall**************************************/
        //调用结束后encrypted_content中保存了文件内容的密文
        ocall_retrieve_encrypted_doc(del_id.c_str(),del_id.size(),
                                     encrypted_content,BUFLEN * sizeof(unsigned char),
                                     &length_content,sizeof(int));
        /****************************************************************/
        //decrypt the doc 内容解密
        //设置明文长度
        size_t plain_doc_len = (size_t)length_content - AESGCM_MAC_SIZE - AESGCM_IV_SIZE;
	    //根据长度进行密文的初始化
        unsigned char *plain_doc_content = (unsigned char *) malloc(plain_doc_len* sizeof(unsigned char));
        //decrypt the cipher from the server
        //解密
        dec_aes_gcm(KF,encrypted_content,length_content,
                    plain_doc_content,plain_doc_len);
        
        //check the keyword in the doc
        //std::string plaintext_str((char*)plain_doc_content,plain_doc_len);
        //std::size_t found = plaintext_str.find(keyword_str);
        //if (found!=std::string::npos){

        //update all the states for all keywords
        std::vector<std::string> wordList;
        //分词
        wordList = wordTokenize((char*)plain_doc_content,plain_doc_len);
	    //printf("%s:%d", del_id.c_str(), wordList.size());
        //对于每一个关键词w，都对于d中的被删除id进行操作，即将该id加入到该关键词的D[w]中
        for(std::vector<std::string>::iterator it = wordList.begin(); it != wordList.end(); ++it) {
      
            std::string keyword_str = (*it);
            //std::unordered_map<std::string, std::vector<std::string>> D
            //update D[w] with id
            auto delTrack = D.find(keyword_str);
            if ( delTrack == D.end()) {
                //has no records then create a new key-value
                std::vector<std::string> del_w;
                del_w.push_back(del_id);
                D.insert(std::pair<std::string,std::vector<std::string>>(keyword_str,del_w));
            }else{
                //already had record then push_back
                delTrack->second.push_back(del_id);
            }

            //call Server to delete the entry (delete by batch later same time with I_c)
            //ocall_del_encrypted_doc(del_id.c_str(),del_id.size());     
        }
        
        //reset
        free(plain_doc_content);
        memset(encrypted_content, 0, BUFLEN * sizeof(unsigned char));
        length_content = 0;
        //Question:暂时没有看到delete R[id]操作
    }

    //free memory
    free(encrypted_content);

    //reset the deleted id docs d-> save time for later searchs
    d.clear();

    //retrieve the latest state of the keyword 
    int w_c_max=0;
    std::unordered_map<std::string,int>::const_iterator got = ST.find(keyword_str);
    if ( got == ST.end()) {
        printf("Keyword is not existed for search");
        return;
    }else{
        //get c
        w_c_max = got->second;
    }

    //printf("c max value [1-c] %d", w_c_max);

    //init st_w_c and Q_w
    //st_w_c先是保存了从1到该关键词w的c值的所有值（这个时候还没有删除已经删除的文件id）
    std::vector<int> st_w_c;
    for(int i_c = 1; i_c <= w_c_max;i_c++)
        st_w_c.push_back(i_c);

    std::vector<int> st_w_c_difference;

    //
    size_t _u_prime_size = ENTRY_HASH_KEY_LEN_128 + k_w.content_length;
    unsigned char *_u_prime = (unsigned char *) malloc(_u_prime_size * sizeof(unsigned char));
    unsigned char *_v_prime = (unsigned char *) malloc(ENTRY_VALUE_LEN * sizeof(unsigned char));
    int _v_prime_size;

    //retrieve states of del_id in D[w]
    std::unordered_map<std::string, std::vector<std::string>>::const_iterator delTrack = D.find(keyword_str);
    if(delTrack != D.end()){
        std::vector<std::string> matched_id_del = D[keyword_str];
        for(auto&& id_del: matched_id_del){
         
            //retrieve a pair (u',v')
            //u_prime<-H3(k_w,id)
            hash_SHA128_key(k_w.content,k_w.content_length, (unsigned char*)id_del.c_str(),id_del.size(),_u_prime);
            //retrieve v' from an ocall
            //在M_c中根据刚刚生成的u_prime找到v_prime
            ocall_retrieve_M_c(_u_prime,_u_prime_size * sizeof(unsigned char),
                                     _v_prime,ENTRY_VALUE_LEN * sizeof(unsigned char),
                                     &_v_prime_size,sizeof(int));
            

            size_t c_value_len = (size_t)_v_prime_size - AESGCM_MAC_SIZE - AESGCM_IV_SIZE;
            //use v' to calculate c c_value_content
	        unsigned char *c_value_content = (unsigned char *) malloc(c_value_len* sizeof(unsigned char)); 
            //解密获得c
            dec_aes_gcm(k_c.content,_v_prime,_v_prime_size,
                    c_value_content,c_value_len);
            
            //print_bytes((uint8_t*)c_value_content,(uint32_t)c_value_len);
            std::string c_str1((char*)c_value_content,c_value_len);

            int temp = std::stoi(c_str1);
            //st_w_c_difference includes the cs needed to be take outside
            st_w_c_difference.push_back(temp);
            
            //delete I_c by ocall (delete later by batch ???)
            //ocall_del_M_c_value(_u_prime,_u_prime_size);      

            //reset
            //memset(_u_prime, 0, _u_prime_size * sizeof(unsigned char));
            //memset(_v_prime, 0, ENTRY_VALUE_LEN * sizeof(unsigned char));
            //_v_prime_size = 0;

            //free memory
            free(c_value_content);
        }
    }
    


    //free memory 
    free(_u_prime);
    free(_v_prime);

    std::vector<int> merged_st;

    //取两者的差集，操作完毕后将w中已经被删除文件id给去除，结果存在merged_st中
    std::set_difference(st_w_c.begin(), st_w_c.end(),
    		st_w_c_difference.begin(), st_w_c_difference.end(),
   			std::back_inserter(merged_st));

    //printf("----");
    size_t pair_no = merged_st.size();

    //declare query tokens for ocall
    int batch = pair_no / BATCH_SIZE;

    //存放一个批次的u，一个u的长度为 size_t len = ENTRY_HASH_KEY_LEN_128 + k_w.content_length;
    rand_t *Q_w_u_arr = (rand_t *) malloc(BATCH_SIZE * sizeof(rand_t));
    //存放一个批次的k_id,一个k_id的长度为ENTRY_HASH_KEY_LEN_128
    rand_t *Q_w_id_arr = (rand_t *) malloc(BATCH_SIZE * sizeof(rand_t));
    
    int index=0;

    size_t len = ENTRY_HASH_KEY_LEN_128 + k_w.content_length;
    unsigned char *k_id =  (unsigned char *) malloc(ENTRY_HASH_KEY_LEN_128); 

    // do batch process
    //假设pair_no = 15000
    for(int i = 0; i <= batch; i++) {
    	// determine the largest sequence no. in the current batch
        //本批次最大的一个id是哪个
    	int limit = BATCH_SIZE * (i + 1) > pair_no ? pair_no : BATCH_SIZE * (i + 1);

    	// determine the # of tokens in the current batch
        //本批次的长度
    	int length = BATCH_SIZE * (i + 1) > pair_no ? pair_no - BATCH_SIZE * i : BATCH_SIZE;

    	for(int j = BATCH_SIZE * i; j < limit; j++) {
    		//generate u token H2(k_w,c)
    		std::string c_str = std::to_string(merged_st[j]);
    		char const *c_char = c_str.c_str();

    		unsigned char *_u = (unsigned char *) malloc(len * sizeof(unsigned char));
            //生成u
    		hash_SHA128_key(k_w.content,k_w.content_length, c_char,c_str.length(),_u);

    		memcpy(Q_w_u_arr[j - BATCH_SIZE * i].content,_u,len);
            //includes u
    		Q_w_u_arr[j - BATCH_SIZE * i].content_length = len;

    		//generate k_id based on c
    		hash_SHA128(k_w.content,c_char,c_str.length(),k_id);

    		memcpy(Q_w_id_arr[j - BATCH_SIZE * i].content, k_id, ENTRY_HASH_KEY_LEN_128);
            //includes kid
    		Q_w_id_arr[j - BATCH_SIZE * i].content_length = ENTRY_HASH_KEY_LEN_128;

    		//reset k_id
    		memset(k_id, 0, ENTRY_HASH_KEY_LEN_128 * sizeof(unsigned char));

    		//free memory
    		free(_u);
    	}

    	//send Q_w to Server，在Server中会对于Q_w进行查询，然后输出对应的id
    	ocall_query_tokens_entries(Q_w_u_arr, Q_w_id_arr,
				length, sizeof(rand_t));
    }

    //delete w from D
    D.erase(keyword_str);

    free(k_id);

    //free memory
    free(k_w.content);
    free(k_c.content);

    free(Q_w_u_arr);
    free(Q_w_id_arr);
}
