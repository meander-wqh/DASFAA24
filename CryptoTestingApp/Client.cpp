#include "Client.h"
#include <string>
//#include <string.h> // memset(KF, 0, sizeof(KF));
#include "stdio.h"
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <sstream> //std::stringstream
#include <vector>
#include <algorithm> // for std::find
#include <iterator> // for std::begin, std::end
#include <cstring> 
#include <openssl/rand.h>


Client::Client(){
    //file_reading_counter=0;
    RAND_bytes(KF,ENC_KEY_SIZE); //随机产生一段random数组,文件密钥kF setup-1
    RAND_bytes(K_T,ENC_KEY_SIZE); 
    RAND_bytes(K_Z,ENC_KEY_SIZE); 
    RAND_bytes(K_X,ENC_KEY_SIZE); 
    std::cout<<"Client generate K_T, K_Z and K_X."<<std::endl;
}

void Client::getKFValue(unsigned char * outKey){
    memcpy(outKey,KF,ENC_KEY_SIZE);//复制KF 到 outKey
}
void Client::GetKTValue(unsigned char * outKey){
    memcpy(outKey,KF,ENC_KEY_SIZE);//复制KF 到 outKey
}
void Client::GetKZValue(unsigned char * outKey){
    memcpy(outKey,KF,ENC_KEY_SIZE);//复制KF 到 outKey
}
void Client::GetKXValue(unsigned char * outKey){
    memcpy(outKey,KF,ENC_KEY_SIZE);//复制KF 到 outKey
}


void Client::ReadNextDoc(docContent *content){//文档读取传入函数
    std::ifstream inFile;//读取文件
    std::stringstream strStream;//读取内容 根据空白切割字符串
    //docContent content;

    //increase counter
    file_reading_counter+=1;

    std::string fileName;
    fileName = std::to_string(file_reading_counter);

    /** convert fileId to char* and record length设置文件名和文件名长度*/
    int doc_id_size = fileName.length() +1; //字符数组最后要一个'/n'结尾
    
    content->id.doc_id = (char*) malloc(doc_id_size);
    memcpy(content->id.doc_id, fileName.c_str(),doc_id_size);
    content->id.id_length = doc_id_size;

    //read the file content
    inFile.open( raw_doc_dir + fileName); //存放的是地址
    strStream << inFile.rdbuf();//流重定向到strStream
    inFile.close();

    /** convert document content to char* and record length 设置文件内容以及文件内容长度*/
    std::string str = strStream.str(); //分割成多个字符
    int plaintext_len;
    plaintext_len = str.length()+1;

    content->content = (char*)malloc(plaintext_len);
    memcpy(content->content, str.c_str(),plaintext_len);//将 const string* 类型 转化为 cons char* 类型
    // std::cout << fileName << ":" << content->content << std::endl;////////////////////////////////////

    content->content_length = plaintext_len;

    strStream.clear();

}
// Client给定要删除文件id
void Client::Del_GivenDocIndex(const int del_index, docId* delV_i){
    
    std::string fileName;
    fileName = std::to_string(del_index); //文件id

    delV_i->id_length = fileName.length() +1; //文件id长度
    delV_i->doc_id = (char*)malloc(delV_i->id_length);
    memcpy(delV_i->doc_id,fileName.c_str(),delV_i->id_length);//计算出名字 然后分配内存 将名字塞到删除文件里

}

//删除一个序列
void Client::Del_GivenDocArray(const int * del_arr, docId* delV, int n){

    std::string fileName;
    for(int i = 0; i <n; i++){
        fileName = std::to_string(del_arr[i]);

        /** convert fileId to char* and record length */
        delV[i].id_length = fileName.length() +1;

        delV[i].doc_id = (char*)malloc(delV[i].id_length);
        memcpy(delV[i].doc_id,fileName.c_str(),delV[i].id_length);
    }
}

//加密数据 
void Client::EncryptDoc(const docContent* data, entry *encrypted_doc ){ //entry 是个pair 包含密钥与被加密信息？ 应该是包含文件 id 和文件内容的pair

    memcpy(encrypted_doc->first.content,data->id.doc_id,data->id.id_length);
    //用密钥KF将加密后的文档加入加密实体 encrypted_doc中
	encrypted_doc->second.message_length = enc_aes_gcm((unsigned char*)data->content,
                                                        data->content_length,KF,
                                                        (unsigned char*)encrypted_doc->second.message);
}

//解密数据
void Client::DecryptDocCollection(std::vector<std::string> Res){
    
    for(auto&& enc_doc: Res){

        int original_len;
	    unsigned char *plaintext =(unsigned char*)malloc((enc_doc.size() - AESGCM_MAC_SIZE - AESGCM_IV_SIZE)*sizeof(unsigned char));
	    original_len= dec_aes_gcm((unsigned char*)enc_doc.c_str(),enc_doc.size(),KF,plaintext);
      
        std::string doc_i((char*)plaintext,original_len);
        printf("Plain doc ==> %s\n",doc_i.c_str());
    
    }
}
