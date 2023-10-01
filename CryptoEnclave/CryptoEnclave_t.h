#ifndef CRYPTOENCLAVE_T_H__
#define CRYPTOENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_init(unsigned char key[3][16]);
void ecall_addDoc(char* doc_id, size_t id_length, char* content, int content_length);
void ecall_delDoc(char* doc_id, size_t id_length);
void ecall_search(const char* keyword, size_t len);
void ecall_test(char* encrypted_content, size_t length_content);
void ecall_hash_test(const char* data, size_t len);
void ecall_update_data(const char* w, size_t w_len, const char* id, size_t id_len, size_t op);
void ecall_update_data_Fuzzy(const char* w, size_t w_len, const char* id, size_t id_len, size_t pos, size_t op);
void ecall_Conjunctive_Exact_Social_Search(char* str);
void ecall_Conjunctive_Fuzzy_Social_Search(char* str);
void ecall_test_int(size_t test);
void ecall_get_MostCFs(int* test, size_t int_size);
void ecall_get_ecall_number(int* test, size_t int_size);
void ecall_clear_CFs(void);

sgx_status_t SGX_CDECL ocall_start_time(void);
sgx_status_t SGX_CDECL ocall_end_time(void);
sgx_status_t SGX_CDECL ocall_start_time_test(void);
sgx_status_t SGX_CDECL ocall_end_time_test(void);
sgx_status_t SGX_CDECL ocall_test2(char* encrypted_content, size_t length_content);
sgx_status_t SGX_CDECL ocall_test(int* mint, char* mchar, char* mstring, int len);
sgx_status_t SGX_CDECL ocall_transfer_encrypted_entries(const void* t1_u_arr, const void* t1_v_arr, const void* t2_u_arr, const void* t2_v_arr, int pair_count, int rand_size);
sgx_status_t SGX_CDECL ocall_retrieve_encrypted_doc(const char* del_id, size_t del_id_len, unsigned char* encrypted_content, size_t maxLen, int* length_content, size_t int_len);
sgx_status_t SGX_CDECL ocall_del_encrypted_doc(const char* del_id, size_t del_id_len);
sgx_status_t SGX_CDECL ocall_retrieve_M_c(unsigned char* _u_prime, size_t _u_prime_size, unsigned char* _v_prime, size_t maxLen, int* _v_prime_size, size_t int_len);
sgx_status_t SGX_CDECL ocall_del_M_c_value(const unsigned char* _u_prime, size_t _u_prime_size);
sgx_status_t SGX_CDECL ocall_query_tokens_entries(const void* Q_w_u_arr, const void* Q_w_id_arr, int pair_count, int rand_size);
sgx_status_t SGX_CDECL ocall_add_update(unsigned char* stag, size_t stag_len, unsigned char* C_id, size_t C_id_len, unsigned char* ind, size_t ind_len, unsigned char* C_stag, size_t C_stag_len, uint32_t fingerprint, size_t index, unsigned char* CFId, size_t CFId_len, int* flag, size_t int_len);
sgx_status_t SGX_CDECL ocall_del_update(unsigned char* stag, size_t stag_len, unsigned char* stag_inverse, size_t stag_inverse_len, unsigned char* ind, size_t ind_len, unsigned char* ind_inverse, size_t ind_inverse_len, uint32_t fingerprint, size_t index, unsigned char* CFId, size_t CFId_len);
sgx_status_t SGX_CDECL ocall_Query_TSet(unsigned char* stag, size_t stag_len, unsigned char* value, size_t value_len);
sgx_status_t SGX_CDECL ocall_Query_iTSet(unsigned char* ind, size_t ind_len, unsigned char* value, size_t value_len);
sgx_status_t SGX_CDECL ocall_Get_CF(unsigned char* CFId, size_t CFId_len, uint32_t* fingerprint, size_t fingerprint_len, size_t len);
sgx_status_t SGX_CDECL ocall_send_stokenList(unsigned char* StokenList, size_t StokenList_len, int StokenListSize, unsigned char* ValList, size_t ValList_len, int* ValListSize, size_t int_len);
sgx_status_t SGX_CDECL ocall_print_int(int input);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_test_int(size_t test, uint32_t* fingerprint, size_t fingerprint_len, size_t len);
sgx_status_t SGX_CDECL ocall_Get_Res(char* res, size_t res_len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
