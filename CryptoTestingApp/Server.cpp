#include "Server.h"
#include <algorithm> // for std::find
#include <iterator> // for std::begin, std::end

Server::Server(){
  R_Doc.clear();
  M_I.clear();
  M_c.clear();
}

Server::~Server(){
  R_Doc.clear();
  M_I.clear();
  M_c.clear();

}

void Server::ReceiveEncDoc(entry *encrypted_doc){
    
    std::string id(encrypted_doc->first.content, encrypted_doc->first.content_length);
    std::string enc_content(encrypted_doc->second.message, encrypted_doc->second.message_length);
    R_Doc.insert(std::pair<std::string,std::string>(id,enc_content));
  
}

//server接受enclave传来的T1,T2
void Server::ReceiveTransactions(rand_t *t1_u_arr,rand_t *t1_v_arr,
                                 rand_t *t2_u_arr,rand_t *t2_v_arr,
                                 int pair_count){ 
	for(int indexTest = 0; indexTest < pair_count; indexTest++){

      std::string key1((char*)t1_u_arr[indexTest].content, t1_u_arr[indexTest].content_length);//注意！！！ unsigned char 转换成 char
      std::string value1((char*)t1_v_arr[indexTest].content, t1_v_arr[indexTest].content_length);

      M_I.insert(std::pair<std::string,std::string>(key1,value1)); //插入(u,v)到M_I

      std::string key2((char*)t2_u_arr[indexTest].content, t2_u_arr[indexTest].content_length);
      std::string value2((char*)t2_v_arr[indexTest].content, t2_v_arr[indexTest].content_length);

      M_c.insert(std::pair<std::string,std::string>(key2,value2)); //插入(u',v')到M_C
    }
}

std::string Server::Retrieve_Encrypted_Doc(std::string del_id_str){     //取出             
    return R_Doc.at(del_id_str);
}

void Server::Del_Encrypted_Doc(std::string del_id_str){  //删除
    R_Doc.erase(del_id_str); 
}

std::string Server::Retrieve_M_c(std::string u_prime_str){ //取出
    return M_c.at(u_prime_str);
}

void Server::Del_M_c_value(std::string del_u_prime){ //删除
    M_c.erase(del_u_prime);
}


std::vector<std::string> Server::retrieve_query_results(rand_t *Q_w_u_arr,rand_t *Q_w_id_arr,int pair_count){ //u与Kid

  std::vector<std::string> Res;

  //遍历Q_w
  for(int indexTest = 0; indexTest < pair_count; indexTest++){
      
      //获取u
      std::string u_i((char*)Q_w_u_arr[indexTest].content, Q_w_u_arr[indexTest].content_length);
      //取出Mi[ui]，这是加密后的文件id
      std::string value = M_I.at(u_i);

      unsigned char *key = (unsigned char*)malloc(ENC_KEY_SIZE*sizeof(unsigned char));
      //Q_w_id_arr is kid
      memcpy(key,Q_w_id_arr[indexTest].content,ENC_KEY_SIZE); //取出kid

      int original_len;
	    unsigned char *plaintext =(unsigned char*)malloc((value.size() - AESGCM_MAC_SIZE - AESGCM_IV_SIZE)*sizeof(unsigned char));
      //dec for id，id长度为original_len,明文为plaintext
	    original_len= dec_aes_gcm((unsigned char*)value.c_str(),value.size(),key,plaintext);//解密 在Utils里

      //doc_id明文
      std::string doc_i((char*)plaintext,original_len);
      printf("->%s",doc_i.c_str());//输出
      
      Res.push_back(R_Doc.at(doc_i));

      //free
      free(plaintext);
      free(key);


  }

  return Res;

}


//display utilities
void Server::Display_Repo(){

  printf("Display data in Repo\n");
  for ( auto it = R_Doc.begin(); it != R_Doc.end(); ++it ) {
    printf("Cipher\n");
    printf("%s\n", (it->first).c_str());
    print_bytes((uint8_t*)(it->second).c_str(),(uint32_t)it->second.length());
  }
}

void Server::Display_M_I(){

  std::unordered_map<std::string,std::string> ::iterator it;
  printf("Print data in M_I\n");
  for (it = M_I.begin(); it != M_I.end(); ++it){
      printf("u \n");
      print_bytes((uint8_t*)(it->first).c_str(),(uint32_t)it->first.length());
      printf("v \n");
      print_bytes((uint8_t*)(it->second).c_str(),(uint32_t)it->second.length());
  }
}

void Server::Display_M_c(){
  std::unordered_map<std::string,std::string>::iterator it;
  printf("Print data in M_c\n");
  for (it = M_c.begin(); it != M_c.end(); ++it){
      printf("u \n");
      print_bytes((uint8_t*)(it->first).c_str(),(uint32_t)it->first.length());
      printf("v \n");
      print_bytes((uint8_t*)(it->second).c_str(),(uint32_t)it->second.length());
  }
}
