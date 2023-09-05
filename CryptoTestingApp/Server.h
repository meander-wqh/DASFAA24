#ifndef SERVER_H
#define SERVER_H

#include "../common/data_type.h"
#include "compactedLDCF.h"
#include "Utils.h"

class Server{
    public:
        Server(); //构造函数 MIMC初始化
        ~Server();//析构函数 MIMC初始化
        void ReceiveEncDoc(entry *encrypted_doc);
        void ReceiveTransactions(rand_t *t1_u_arr,rand_t *t1_v_arr,
                                 rand_t *t2_u_arr,rand_t *t2_v_arr,
                                 int pair_count);
        std::string Retrieve_Encrypted_Doc(std::string del_id_str);
        std::string Retrieve_M_c(std::string u_prime_str);
        
        void Del_Encrypted_Doc(std::string del_id_str);
        void Del_M_c_value(std::string del_u_prime);

        void Display_Repo();
        void Display_M_I();
        void Display_M_c();

        std::vector<std::string> retrieve_query_results(
								rand_t *Q_w_u_arr,rand_t *Q_w_id_arr,
								int pair_count);

        std::string Get_Value(std::string config_buff);
        Config Read_Config(const std::string path);


        void UpdateTSet(unsigned char* stag, size_t stag_len, unsigned char* value, size_t value_len);
        void UpdateiTSet(unsigned char* ind, size_t ind_len, unsigned char* value, size_t value_len, size_t type);
        int UpdateXSet(unsigned char* CFId, size_t CFId_len, uint32_t fingerprint, size_t index, size_t type);
        std::string QueryTSet(std::string key);
        std::string QueryiTSet(std::string key);
        CuckooFilter* GetCF(std::string CFId);
        int GetCFNumber();
        int GetXSetItemNumber();
        float GetXSetMemory();
        float GetTSetMemory();

        
    private:
        std::unordered_map<std::string,std::string> M_I;
        std::unordered_map<std::string,std::string> M_c;
        std::unordered_map<std::string,std::string> R_Doc;
        std::unordered_map<std::string,std::string> TSet;
        std::unordered_map<std::string,std::string> iTSet;
        CompactedLogarithmicDynamicCuckooFilter* cldcf;
};
 
#endif
