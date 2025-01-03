
#include <string>
#include "stdio.h"
#include "stdlib.h"

#include "sgx_urts.h"
#include "CryptoEnclave_u.h"
#include "Server.h"
#include "Client.h"
#include "Utils.h"
#include <fstream>
#include <sstream>

//for measurement
#include <cstdint>
#include <chrono>
#include <iostream>
uint64_t timeSinceEpochMillisec() {//截取以纪元时间为单位获取当前时间戳，以毫秒为单位

  using namespace std::chrono;
  return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}
//end for measurement


#define ENCLAVE_FILE "CryptoEnclave.signed.so"

int total_file_no = (int)100000;//50000;//100000
int total_pair_no = (int)600000;//50000;//100000
int del_no = (int)0;//10000;//10000;

int capacity = ITEM_NUMBER;
int single_table_length = upperpower2(capacity/4.0/EXP_BLOCK_NUM);

int ocall_number = 0;

uint64_t load_CF_total_time = 0;
uint64_t load_CF_start_time;
uint64_t load_CF_end_time;

uint64_t ocall_start_timestamp;
uint64_t ocall_end_timestamp;

uint64_t maxTimeCost = 0;

/* 	Note 1: Enclave only recognises direct pointer with count*size, where count is the number of elements in the array, and size is the size of each element
		other further pointers of pointers should have fixed max length of array to eliminate ambiguity to Enclave (by using pointer [max_buf]).
	Note 2: In outcall, passing pointer [out] can only be modified/changed in the direct .cpp class declaring the ocall function.
	Note 3: If it is an int pointer pointing to a number-> using size=sizeof(int) to declare the size of the int pointer. That will be a larger range than using size_t in ocall
	Note 4: ensure when using openssl and sgxcrypto, plaintext data should be more lengthy than 4-5 characters; (each content in raw_doc should have lengthy characters)
			otherwise, random noise/padding will be auto added.
	Note 5: convert to int or length needs to total_filecome with pre-define length;otherwise, following random bytes can occur.

	memory leak note: 
	1-declare all temp variable outside forloop
	2-all func should return void, pass pointer to callee; caller should init mem and free pointer
	3-use const as input parameter in funcs if any variable is not changed 
	4-re-view both client/server in outside regarding above leak,
		 (docContent fetch_data = myClient->ReadNextDoc();, 

			//free memory 
			free(fetch_data.content);
			free(fetch_data.id.doc_id);)
	5-struct should use constructor and destructor (later)
	6-should use tool to check mem valgrind --leak-check=yes to test add function to see whether memory usage/leak before and after
	7-run with prerelease mode
	8-re generate new list test, but without using the list inside
 */

Client *myClient; //extern to separate ocall
Server *myServer; //extern to separate ocall

void ocall_start_time(){
	load_CF_start_time = timeSinceEpochMillisec();
}

void ocall_end_time(){
	load_CF_end_time = timeSinceEpochMillisec();
	load_CF_total_time += (load_CF_end_time - load_CF_start_time);
	// std::cout << "Total time: " <<timeSinceEpochMillisec() - timestamp << " ms" << std::endl;
}

void ocall_start_time_test(){
	ocall_start_timestamp = timeSinceEpochMillisec();
}

void ocall_end_time_test(){
	ocall_end_timestamp = timeSinceEpochMillisec();
	if(ocall_end_timestamp - ocall_start_timestamp > maxTimeCost){
		maxTimeCost = ocall_end_timestamp - ocall_start_timestamp;
	}
}

void ocall_print_string(const char *str) {
    printf("%s\n", str);
	//print_bytes((uint8_t*)str,strlen(str));
}

void ocall_print_int(int input){
	std::cout<<input<<std::endl;
}
void ocall_test(int* mint,char* mchar,char* mstring,int len) {
	//encrypt and send to Ser
    printf("int1为%d",mint[0]);
    printf("char1为%c",mchar[0]);
    printf("string1为%s",mstring);
}
void ocall_test2(char* encrypted_content, size_t length_content){
	std::string res(encrypted_content,length_content);
	std::vector<std::string> REs;
	REs.push_back(res); 
	myClient->DecryptDocCollection(REs);
}

//server接受enclave传来的T1,T2
void ocall_transfer_encrypted_entries(const void *_t1_u_arr,
									  const void *_t1_v_arr, 
									  const void *_t2_u_arr,
									  const void *_t2_v_arr,
									  int pair_count, int rand_size){

	myServer->ReceiveTransactions(
								(rand_t *)_t1_u_arr,(rand_t *)_t1_v_arr,
								(rand_t *)_t2_u_arr,(rand_t *)_t2_v_arr,
								pair_count);

}


void ocall_retrieve_encrypted_doc(const char *del_id, size_t del_id_len, 
                                  unsigned char *encrypted_content, size_t maxLen,
                                  int *length_content, size_t int_size){
								  
	std::string del_id_str(del_id,del_id_len);	
	std::string encrypted_entry = myServer->Retrieve_Encrypted_Doc(del_id_str);
    *length_content = (int)encrypted_entry.size();
	//later double check *length_content exceeds maxLen
    memcpy(encrypted_content, (unsigned char*)encrypted_entry.c_str(),encrypted_entry.size());
}

void ocall_del_encrypted_doc(const char *del_id, size_t del_id_len){
	std::string del_id_str(del_id,del_id_len);
	myServer->Del_Encrypted_Doc(del_id_str);
}

void ocall_retrieve_M_c(unsigned char * _u_prime, size_t _u_prime_size,
                              unsigned char *_v_prime, size_t maxLen,
                              int *_v_prime_size, size_t int_len){

	std::string u_prime_str((char*)_u_prime,_u_prime_size);
	std::string v_prime_str = myServer->Retrieve_M_c(u_prime_str);

	*_v_prime_size = (int)v_prime_str.size(); 
	memcpy(_v_prime,(unsigned char*)v_prime_str.c_str(),v_prime_str.size());

}

void ocall_Query_TSet(unsigned char* stag,size_t stag_len,unsigned char* value,size_t value_len){
	std::string sstag((const char*)stag,stag_len);
	std::string svalue = myServer->QueryTSet(sstag);
	memcpy(value,(unsigned char*)svalue.c_str(),svalue.length());
}

void ocall_Query_iTSet(unsigned char* ind,size_t ind_len,unsigned char* value,size_t value_len){
	std::string sind((const char*)ind,ind_len);
	std::string svalue = myServer->QueryiTSet(sind);
	memcpy(value,(unsigned char*)svalue.c_str(),svalue.length());
}

void ocall_del_M_c_value(const unsigned char *_u_prime, size_t _u_prime_size){

	std::string del_u_prime((char*)_u_prime,_u_prime_size);
	myServer->Del_M_c_value(del_u_prime);
}

void ocall_query_tokens_entries(const void *Q_w_u_arr,
                               const void *Q_w_id_arr,
                               int pair_count, int rand_size){
	
	std::vector<std::string> Res;
	Res = myServer->retrieve_query_results(
								(rand_t *)Q_w_u_arr,(rand_t *)Q_w_id_arr,
								pair_count);
	
	//give to Client for decryption
	myClient->DecryptDocCollection(Res);
}

void ocall_add_update(unsigned char* stag,size_t stag_len,unsigned char* C_id,size_t C_id_len, unsigned char* ind,size_t ind_len,
unsigned char* C_stag,size_t C_stag_len,uint32_t fingerprint, size_t index,unsigned char* CFId,size_t CFId_len,int* flag, size_t int_len){
	//std::cout<<fingerprint<<std::endl;
	myServer->UpdateTSet(stag,stag_len,C_id,C_id_len);
	myServer->UpdateiTSet(ind,ind_len,C_stag,C_stag_len,1);
	*flag = myServer->UpdateXSet(CFId,CFId_len,fingerprint,index,1);
}

void ocall_del_update(unsigned char* stag,size_t stag_len,unsigned char* stag_inverse,size_t stag_inverse_len, unsigned char* ind,size_t ind_len,
unsigned char* ind_inverse,size_t ind_inverse_len,uint32_t fingerprint, size_t index,unsigned char* CFId,size_t CFId_len){
	std::string sstag_inverse((const char*)stag_inverse,stag_inverse_len);
	myServer->UpdateTSet(stag,stag_len,(unsigned char*)myServer->QueryTSet(sstag_inverse).c_str(),myServer->QueryTSet(sstag_inverse).length());
	std::string sind((const char*)ind,ind_len);
	myServer->UpdateiTSet(ind,ind_len,(unsigned char*)myServer->QueryTSet(sind).c_str(),myServer->QueryTSet(sind).length(),0);
	myServer->UpdateXSet(CFId,CFId_len,fingerprint,index,0);
}

void ocall_send_stokenList(unsigned char* StokenList,size_t StokenList_len,int StokenListSize,unsigned char* ValList,size_t ValList_len,int* ValListSize, size_t int_len){
	ocall_number++;
	//std::cout<<StokenListSize<<std::endl;
	unsigned char* p = StokenList;
	std::string C_id = "";
	int size = 0;
	//print_bytes(StokenList,ENTRY_HASH_KEY_LEN_128*3); 
	for(int i=0;i<StokenListSize;i++){
		unsigned char stag[ENTRY_HASH_KEY_LEN_128];
		memcpy(stag,p,ENTRY_HASH_KEY_LEN_128);
		p+=ENTRY_HASH_KEY_LEN_128;
		
		//print_bytes(stag,ENTRY_HASH_KEY_LEN_128); 
		std::string temp = myServer->QueryTSet(std::string((char*)stag,ENTRY_HASH_KEY_LEN_128));
		if(temp != ""){
			size++;
			C_id += temp;
		}
	} 
	//std::cout<<C_id.length()<<std::endl;
	memcpy(ValList,(unsigned char*)C_id.c_str(),C_id.length());
	//std::cout<<strlen((char*)ValList)<<std::endl;
	*ValListSize = size;
}

void ocall_Get_CF(unsigned char* CFId, size_t CFId_len,uint32_t* fingerprint, size_t fingerprint_len, size_t len){
	ocall_number++;
	std::string sCFId((char*)CFId,CFId_len);
	CuckooFilter* CF = myServer->GetCF(sCFId);
	int index = 0;
	//len = single_table_length*4
	while(index<len){
		fingerprint[index] = CF->read(index/4,index%4);
		index++;
	}
	//std::cout<<fingerprint[63438]
}

void ocall_test_int(size_t test, uint32_t* fingerprint, size_t fingerprint_len,size_t len){
	if(test == 1){
		printf("test");
		for(int i=0;i<len;i++){
			fingerprint[i] = i;
		}
	}
}

void ocall_Get_Res(char* res,size_t res_len){
	for(int i=0;i<res_len;i++){
		std::cout<<res[i]<<std::endl;
	}
}

std::vector<std::string> GetFuzzyTokens(std::string input){
	std::vector<std::string> tokens;
	for(int i = 0;i <= input.length() - FuzzyCut; ++i) {
        std::string substring = input.substr(i, FuzzyCut);
		//std::cout<<substring<<std::endl;
        tokens.push_back(substring);
    }
	return tokens;
}

int GetFileLine(const char* path){
	int lineCount = 0;
	std::ifstream file(path);
	std::string line;
	while (std::getline(file, line)) {
        lineCount++;
    }
	file.close();
	return lineCount;
}

//main func
int main()
{
	/* Setup enclave */
	sgx_enclave_id_t eid; //sgx id
	sgx_status_t ret; //sgx状态类型
	sgx_launch_token_t token = { 0 };
	int token_updated = 0;

	/********************创建enclave环境****************************/
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &token_updated, &eid, NULL); //eid
	if (ret != SGX_SUCCESS)
	{
		printf("sgx_create_enclave failed: %#x\n", ret);
		return 1;
	}
	/**************************************************************/

	/* Setup Protocol*/
	//Client
	myClient= new Client();
	//Server	
	myServer= new Server();

	//Enclave
	unsigned char KFvalue[ENC_KEY_SIZE]; //文件密钥kF
	myClient->getKFValue(KFvalue);//赋值KFvalue到myClient对象中的KF，这里KFvalue被KF赋值，KFvalue其实用来生成kw和kc
	unsigned char K_T[ENC_KEY_SIZE];
	unsigned char K_Z[ENC_KEY_SIZE];
	unsigned char K_X[ENC_KEY_SIZE];
	myClient->GetKTValue(K_T);
	myClient->GetKZValue(K_Z);
	myClient->GetKXValue(K_X);
	/**********************初始化enclave中数据结构******************/
	//生成Kw kc
	//ecall_init(eid,KFvalue,(size_t)ENC_KEY_SIZE); 
	unsigned char key_array[3][16];
	memcpy(key_array[0],K_T,16);
	memcpy(key_array[1],K_Z,16);
	memcpy(key_array[2],K_X,16);
	ecall_init(eid,key_array);
	std::cout<<"SGX get K_T, K_Z and K_X."<<std::endl;
	long long int mem = 0;

	/*******************更新数据******************/

	const char* path = "./dataset/com-orkut.ungraph-1kw.txt";
	//const char* path = "./dataset/Email-Enron-new.txt";
	//const char* path = "./dataset/com-orkut.ungraph-200w.txt";

	std::ifstream file(path);
	// std::ifstream file("./dataset/Gowalla");

	// 检查文件是否成功打开
    if (!file.is_open()) {
        std::cerr << "无法打开文件" << std::endl;
        return 1;
    }
	int FileLine = GetFileLine(path);
	double ratio = 1;

	// //查看MostCFs
	// int MostCFs = 0;
	// ecall_get_MostCFs(eid,&MostCFs,sizeof(MostCFs));
	// std::cout<<"MostCFs:"<<MostCFs<<std::endl;



	// 逐行读取文件
    std::string line;
	uint64_t set_up_start_time =  timeSinceEpochMillisec();
	int fakeid = 0;
	int lineNumber = 0;

    while (std::getline(file, line)) {
		if(lineNumber>=FileLine*ratio){
			break;
		}
        // 使用字符串流将每行分割成元素item
        std::istringstream iss(line);
        std::string item;
        std::vector<std::string> items;
        while (iss >> item) {
            items.push_back(item);
        }
		std::string sw = "fd"+items[0];
		std::string sid = items[1];

		//Exact item
		const char* w = sw.c_str();
		size_t w_len = sw.length();
		const char* id = sid.c_str();
		size_t id_len = sid.length();
		//mem += (sw.length()+2);
		ecall_update_data(eid,w, w_len, id, id_len, 1);
		//std::cout<<mem<<std::endl;

		// //Fuzzy item
		// std::string sname1 = items[2];
		// std::string sname2 = items[3];
		// std::string sname = sname1+sname2;
		// const char* name = sname.c_str();
		// size_t name_len = sname.length();
		// std::vector<std::string> tokens = GetFuzzyTokens(sname);
		// std::stringstream ss;
		// ss<<fakeid;
		// sid = ss.str();
		// fakeid++;

		// for(int i = 0;i < tokens.size();i++){
		// 	ecall_update_data_Fuzzy(eid, tokens[i].c_str() ,tokens[i].length() , sid.c_str(), sid.length(), i ,1);
		// }
		lineNumber++;
    }
	file.close();
	uint64_t set_up_end_time =  timeSinceEpochMillisec();

	std::cout << "********Time for setup********" << std::endl;
    std::cout << "Total time: " <<set_up_end_time - set_up_start_time << " ms" << std::endl;

	// 检查XSet，TSet状态
	int CFNumber = myServer->GetCFNumber();
	int XSetItemNumber = myServer->GetXSetItemNumber();
	float XSetMemory = myServer->GetXSetMemory();
	float TSetMemory = myServer->GetTSetMemory();
	std::cout << "CFNumber: " << CFNumber << std::endl;
	std::cout << "XSetItemNumber: " << XSetItemNumber <<std::endl;
	std::cout << "XSetMemory: " << XSetMemory <<std::endl;
	std::cout << "TSetMemory: " << TSetMemory <<std::endl;


	std::cout<<std::endl;
	uint64_t start_time;
	uint64_t end_time;

	/*******************查询******************/

	// id: 263: count: 131
	// id: 284: count: 131
	// id: 489: count: 131
	// id: 492: count: 131
	// id: 498: count: 131
	// id: 462: count: 132
	// id: 504: count: 133
	// id: 560: count: 133
	// id: 261: count: 134
	// id: 1478: count: 134
	//
	//
	// id: 1568: count: 130
	// id: 10119: count: 130
	// id: 1698: count: 130
	// id: 1709: count: 130
	// id: 753: count: 130
	// id: 5205: count: 130
	// id: 5208: count: 130
	// id: 5272: count: 130
	// id: 6009: count: 130
	// id: 568: count: 130

	// id: 1229: count: 20
	// id: 1384: count: 20
	// id: 1397: count: 20
	// id: 1436: count: 20
	// id: 1662: count: 20
	// id: 1801: count: 20
	// id: 2503: count: 20
	// id: 2599: count: 20
	// id: 2706: count: 20
	// id: 2936: count: 20

	// id: 26736: count: 20
	// id: 6672: count: 20
	// id: 4357: count: 20
	// id: 71: count: 20
	// id: 920: count: 20
	// id: 1573: count: 20
	// id: 19961: count: 20
	// id: 10228: count: 20
	// id: 1734: count: 20
	// id: 5383: count: 20

	std::vector<std::string> ids = {"1568","10119","1698","1709","753","5205","5208","5272","6009","568"};
	//std::vector<std::string> ids = {"26736","6672","4357","71","920","1573","19961","10228","1734","5383"};
	//std::vector<std::string> ids = {"1229","1384","1397","1436","1662","1801","2503","2599","2706","2936"};
	//std::vector<std::string> ids = {"21392","7375"};

	std::string query_str = "";

	for(int i=0;i<10;i+=2){
		//cout<<i<<endl;
		if(query_str == ""){
			query_str += ("fd"+ids[i]+"&"+"fd"+ids[i+1]);
		}else{
			query_str += ("&fd"+ids[i]+"&"+"fd"+ids[i+1]);
		}
		// query_str = "fd1568&fd10119&fd1698&fd1709";
		// std::cout<<query_str<<std::endl;
		start_time =  timeSinceEpochMillisec();
		ecall_Conjunctive_Exact_Social_Search(eid,(char*)query_str.c_str());
		end_time =  timeSinceEpochMillisec();
		
		std::cout << "Time for search:"<< query_str << std::endl;
		std::cout << "Total time: " <<end_time - start_time << " ms" << std::endl;
		std::cout << "batch time: " <<maxTimeCost << " ms" << std::endl;

		std::cout << "ocall_number: "<<ocall_number<<std::endl;
		ocall_number = 0;

		// int ecall_number;
		// ecall_get_ecall_number(eid,&ecall_number,sizeof(ecall_number));
		// std::cout << "ecall_number: "<<ecall_number<<std::endl;

		//清除SGX中的CF
		ecall_clear_CFs(eid);
		std::cout << "load CF Total time: " <<load_CF_total_time<< " ms" << std::endl;
		load_CF_total_time = 0;
		maxTimeCost = 0;

		std::cout << std::endl;

	}

	//查看MostCFs
	int MostCFs = 0;
	ecall_get_MostCFs(eid,&MostCFs,sizeof(MostCFs));
	std::cout<<"MostCFs:"<<MostCFs<<std::endl;

	//std::cout << "ocall time test: " <<ocall_end_timestamp - ocall_start_timestamp<< " ms" << std::endl;
	
	// /****************************test******************************/
	// // //测试Stark
	// // std::string input = "Stark";
	// // std::vector<std::string> tokens;
	// // for(int i = 0;i <= input.length() - FuzzyCut; ++i) {
    // //     std::string substring = input.substr(i, FuzzyCut);
	// // 	std::cout<<substring<<std::endl;
    // //     tokens.push_back(substring);
    // // }
	// // std::string sid = "1001";
	// // for(int i = 0;i < tokens.size();i++){
	// // 	ecall_update_data_Fuzzy(eid, tokens[i].c_str() ,tokens[i].length() , sid.c_str(), sid.length(), i ,1);
	// // }

	// // std::string searchinput = "tark";
	// // ecall_Conjunctive_Fuzzy_Social_Search(eid,(char*)searchinput.c_str());


	// // //测试Update
	// // std::string sw = "friend:1";
	// // std::vector<std::string> sid = {"1001","1002","1003","1004"};

	// // for(int i=0;i<sid.size();i++){
	// // 	const char* w = sw.c_str();
	// // 	size_t w_len = sw.length();
	// // 	const char* id = sid[i].c_str();
	// // 	size_t id_len = sid[i].length(); 
	// // 	ecall_update_data(eid,w, w_len, id, id_len, 1);
	// // }
	

	// // std::string sw2 = "friend:2";
	// // std::vector<std::string> sid2 = {"1001","1005","1006"};
	// // for(int i=0;i<sid2.size();i++){
	// // 	const char* w2 = sw2.c_str();
	// // 	size_t w_len2 = sw2.length();
	// // 	const char* id2 = sid2[i].c_str();
	// // 	size_t id_len2 = sid2[i].length(); 
	// // 	ecall_update_data(eid,w2, w_len2, id2, id_len2, 1);
	// // }

	// // //测试Search
	// // std::string query_str = "friend:1&friend:2";
	// // ecall_Conjunctive_Exact_Social_Search(eid,(char*)query_str.c_str());


	// // size_t test = 1;
	// // ecall_test_int(eid,test);




	// // //测试hash256结果是否相同
	// // std::string xtag = "friend:123122";
	// // const char* cxtag = xtag.c_str();
	// // string outhash = HashFunc::sha256(cxtag);
	// // print_bytes((uint8_t*)outhash.c_str(),outhash.length());
	// // //为什么要＋1：sgx ecall需要吧终止符传入，不然里面data会多出一位
	// // ecall_hash_test(eid,cxtag,xtag.length()+1);
	// //
	return 0;
}

