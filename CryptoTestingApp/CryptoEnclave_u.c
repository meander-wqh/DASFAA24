#include "CryptoEnclave_u.h"
#include <errno.h>

typedef struct ms_ecall_init_t {
	unsigned char* ms_key;
} ms_ecall_init_t;

typedef struct ms_ecall_addDoc_t {
	char* ms_doc_id;
	size_t ms_id_length;
	char* ms_content;
	int ms_content_length;
} ms_ecall_addDoc_t;

typedef struct ms_ecall_delDoc_t {
	char* ms_doc_id;
	size_t ms_id_length;
} ms_ecall_delDoc_t;

typedef struct ms_ecall_search_t {
	const char* ms_keyword;
	size_t ms_len;
} ms_ecall_search_t;

typedef struct ms_ecall_test_t {
	char* ms_encrypted_content;
	size_t ms_length_content;
} ms_ecall_test_t;

typedef struct ms_ecall_hash_test_t {
	const char* ms_data;
	size_t ms_len;
} ms_ecall_hash_test_t;

typedef struct ms_ecall_update_data_t {
	const char* ms_w;
	size_t ms_w_len;
	const char* ms_id;
	size_t ms_id_len;
	size_t ms_op;
} ms_ecall_update_data_t;

typedef struct ms_ecall_update_data_Fuzzy_t {
	const char* ms_w;
	size_t ms_w_len;
	const char* ms_id;
	size_t ms_id_len;
	size_t ms_pos;
	size_t ms_op;
} ms_ecall_update_data_Fuzzy_t;

typedef struct ms_ecall_Conjunctive_Exact_Social_Search_t {
	char* ms_str;
	size_t ms_str_len;
} ms_ecall_Conjunctive_Exact_Social_Search_t;

typedef struct ms_ecall_Conjunctive_Fuzzy_Social_Search_t {
	char* ms_str;
	size_t ms_str_len;
} ms_ecall_Conjunctive_Fuzzy_Social_Search_t;

typedef struct ms_ecall_test_int_t {
	size_t ms_test;
} ms_ecall_test_int_t;

typedef struct ms_ecall_get_MostCFs_t {
	int* ms_test;
	size_t ms_int_size;
} ms_ecall_get_MostCFs_t;

typedef struct ms_sl_init_switchless_t {
	sgx_status_t ms_retval;
	void* ms_sl_data;
} ms_sl_init_switchless_t;

typedef struct ms_sl_run_switchless_tworker_t {
	sgx_status_t ms_retval;
} ms_sl_run_switchless_tworker_t;

typedef struct ms_ocall_test2_t {
	char* ms_encrypted_content;
	size_t ms_length_content;
} ms_ocall_test2_t;

typedef struct ms_ocall_test_t {
	int* ms_mint;
	char* ms_mchar;
	char* ms_mstring;
	int ms_len;
} ms_ocall_test_t;

typedef struct ms_ocall_transfer_encrypted_entries_t {
	const void* ms_t1_u_arr;
	const void* ms_t1_v_arr;
	const void* ms_t2_u_arr;
	const void* ms_t2_v_arr;
	int ms_pair_count;
	int ms_rand_size;
} ms_ocall_transfer_encrypted_entries_t;

typedef struct ms_ocall_retrieve_encrypted_doc_t {
	const char* ms_del_id;
	size_t ms_del_id_len;
	unsigned char* ms_encrypted_content;
	size_t ms_maxLen;
	int* ms_length_content;
	size_t ms_int_len;
} ms_ocall_retrieve_encrypted_doc_t;

typedef struct ms_ocall_del_encrypted_doc_t {
	const char* ms_del_id;
	size_t ms_del_id_len;
} ms_ocall_del_encrypted_doc_t;

typedef struct ms_ocall_retrieve_M_c_t {
	unsigned char* ms__u_prime;
	size_t ms__u_prime_size;
	unsigned char* ms__v_prime;
	size_t ms_maxLen;
	int* ms__v_prime_size;
	size_t ms_int_len;
} ms_ocall_retrieve_M_c_t;

typedef struct ms_ocall_del_M_c_value_t {
	const unsigned char* ms__u_prime;
	size_t ms__u_prime_size;
} ms_ocall_del_M_c_value_t;

typedef struct ms_ocall_query_tokens_entries_t {
	const void* ms_Q_w_u_arr;
	const void* ms_Q_w_id_arr;
	int ms_pair_count;
	int ms_rand_size;
} ms_ocall_query_tokens_entries_t;

typedef struct ms_ocall_add_update_t {
	unsigned char* ms_stag;
	size_t ms_stag_len;
	unsigned char* ms_C_id;
	size_t ms_C_id_len;
	unsigned char* ms_ind;
	size_t ms_ind_len;
	unsigned char* ms_C_stag;
	size_t ms_C_stag_len;
	uint32_t ms_fingerprint;
	size_t ms_index;
	unsigned char* ms_CFId;
	size_t ms_CFId_len;
	int* ms_flag;
	size_t ms_int_len;
} ms_ocall_add_update_t;

typedef struct ms_ocall_del_update_t {
	unsigned char* ms_stag;
	size_t ms_stag_len;
	unsigned char* ms_stag_inverse;
	size_t ms_stag_inverse_len;
	unsigned char* ms_ind;
	size_t ms_ind_len;
	unsigned char* ms_ind_inverse;
	size_t ms_ind_inverse_len;
	uint32_t ms_fingerprint;
	size_t ms_index;
	unsigned char* ms_CFId;
	size_t ms_CFId_len;
} ms_ocall_del_update_t;

typedef struct ms_ocall_Query_TSet_t {
	unsigned char* ms_stag;
	size_t ms_stag_len;
	unsigned char* ms_value;
	size_t ms_value_len;
} ms_ocall_Query_TSet_t;

typedef struct ms_ocall_Query_iTSet_t {
	unsigned char* ms_ind;
	size_t ms_ind_len;
	unsigned char* ms_value;
	size_t ms_value_len;
} ms_ocall_Query_iTSet_t;

typedef struct ms_ocall_Get_CF_t {
	unsigned char* ms_CFId;
	size_t ms_CFId_len;
	uint32_t* ms_fingerprint;
	size_t ms_fingerprint_len;
	size_t ms_len;
} ms_ocall_Get_CF_t;

typedef struct ms_ocall_send_stokenList_t {
	unsigned char* ms_StokenList;
	size_t ms_StokenList_len;
	int ms_StokenListSize;
	unsigned char* ms_ValList;
	size_t ms_ValList_len;
	int* ms_ValListSize;
	size_t ms_int_len;
} ms_ocall_send_stokenList_t;

typedef struct ms_ocall_print_int_t {
	int ms_input;
} ms_ocall_print_int_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_test_int_t {
	size_t ms_test;
	uint32_t* ms_fingerprint;
	size_t ms_fingerprint_len;
	size_t ms_len;
} ms_ocall_test_int_t;

typedef struct ms_ocall_Get_Res_t {
	char* ms_res;
	size_t ms_res_len;
} ms_ocall_Get_Res_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_test2(void* pms)
{
	ms_ocall_test2_t* ms = SGX_CAST(ms_ocall_test2_t*, pms);
	ocall_test2(ms->ms_encrypted_content, ms->ms_length_content);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_test(void* pms)
{
	ms_ocall_test_t* ms = SGX_CAST(ms_ocall_test_t*, pms);
	ocall_test(ms->ms_mint, ms->ms_mchar, ms->ms_mstring, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_transfer_encrypted_entries(void* pms)
{
	ms_ocall_transfer_encrypted_entries_t* ms = SGX_CAST(ms_ocall_transfer_encrypted_entries_t*, pms);
	ocall_transfer_encrypted_entries(ms->ms_t1_u_arr, ms->ms_t1_v_arr, ms->ms_t2_u_arr, ms->ms_t2_v_arr, ms->ms_pair_count, ms->ms_rand_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_retrieve_encrypted_doc(void* pms)
{
	ms_ocall_retrieve_encrypted_doc_t* ms = SGX_CAST(ms_ocall_retrieve_encrypted_doc_t*, pms);
	ocall_retrieve_encrypted_doc(ms->ms_del_id, ms->ms_del_id_len, ms->ms_encrypted_content, ms->ms_maxLen, ms->ms_length_content, ms->ms_int_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_del_encrypted_doc(void* pms)
{
	ms_ocall_del_encrypted_doc_t* ms = SGX_CAST(ms_ocall_del_encrypted_doc_t*, pms);
	ocall_del_encrypted_doc(ms->ms_del_id, ms->ms_del_id_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_retrieve_M_c(void* pms)
{
	ms_ocall_retrieve_M_c_t* ms = SGX_CAST(ms_ocall_retrieve_M_c_t*, pms);
	ocall_retrieve_M_c(ms->ms__u_prime, ms->ms__u_prime_size, ms->ms__v_prime, ms->ms_maxLen, ms->ms__v_prime_size, ms->ms_int_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_del_M_c_value(void* pms)
{
	ms_ocall_del_M_c_value_t* ms = SGX_CAST(ms_ocall_del_M_c_value_t*, pms);
	ocall_del_M_c_value(ms->ms__u_prime, ms->ms__u_prime_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_query_tokens_entries(void* pms)
{
	ms_ocall_query_tokens_entries_t* ms = SGX_CAST(ms_ocall_query_tokens_entries_t*, pms);
	ocall_query_tokens_entries(ms->ms_Q_w_u_arr, ms->ms_Q_w_id_arr, ms->ms_pair_count, ms->ms_rand_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_add_update(void* pms)
{
	ms_ocall_add_update_t* ms = SGX_CAST(ms_ocall_add_update_t*, pms);
	ocall_add_update(ms->ms_stag, ms->ms_stag_len, ms->ms_C_id, ms->ms_C_id_len, ms->ms_ind, ms->ms_ind_len, ms->ms_C_stag, ms->ms_C_stag_len, ms->ms_fingerprint, ms->ms_index, ms->ms_CFId, ms->ms_CFId_len, ms->ms_flag, ms->ms_int_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_del_update(void* pms)
{
	ms_ocall_del_update_t* ms = SGX_CAST(ms_ocall_del_update_t*, pms);
	ocall_del_update(ms->ms_stag, ms->ms_stag_len, ms->ms_stag_inverse, ms->ms_stag_inverse_len, ms->ms_ind, ms->ms_ind_len, ms->ms_ind_inverse, ms->ms_ind_inverse_len, ms->ms_fingerprint, ms->ms_index, ms->ms_CFId, ms->ms_CFId_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_Query_TSet(void* pms)
{
	ms_ocall_Query_TSet_t* ms = SGX_CAST(ms_ocall_Query_TSet_t*, pms);
	ocall_Query_TSet(ms->ms_stag, ms->ms_stag_len, ms->ms_value, ms->ms_value_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_Query_iTSet(void* pms)
{
	ms_ocall_Query_iTSet_t* ms = SGX_CAST(ms_ocall_Query_iTSet_t*, pms);
	ocall_Query_iTSet(ms->ms_ind, ms->ms_ind_len, ms->ms_value, ms->ms_value_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_Get_CF(void* pms)
{
	ms_ocall_Get_CF_t* ms = SGX_CAST(ms_ocall_Get_CF_t*, pms);
	ocall_Get_CF(ms->ms_CFId, ms->ms_CFId_len, ms->ms_fingerprint, ms->ms_fingerprint_len, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_send_stokenList(void* pms)
{
	ms_ocall_send_stokenList_t* ms = SGX_CAST(ms_ocall_send_stokenList_t*, pms);
	ocall_send_stokenList(ms->ms_StokenList, ms->ms_StokenList_len, ms->ms_StokenListSize, ms->ms_ValList, ms->ms_ValList_len, ms->ms_ValListSize, ms->ms_int_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_print_int(void* pms)
{
	ms_ocall_print_int_t* ms = SGX_CAST(ms_ocall_print_int_t*, pms);
	ocall_print_int(ms->ms_input);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_test_int(void* pms)
{
	ms_ocall_test_int_t* ms = SGX_CAST(ms_ocall_test_int_t*, pms);
	ocall_test_int(ms->ms_test, ms->ms_fingerprint, ms->ms_fingerprint_len, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_Get_Res(void* pms)
{
	ms_ocall_Get_Res_t* ms = SGX_CAST(ms_ocall_Get_Res_t*, pms);
	ocall_Get_Res(ms->ms_res, ms->ms_res_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[23];
} ocall_table_CryptoEnclave = {
	23,
	{
		(void*)CryptoEnclave_ocall_test2,
		(void*)CryptoEnclave_ocall_test,
		(void*)CryptoEnclave_ocall_transfer_encrypted_entries,
		(void*)CryptoEnclave_ocall_retrieve_encrypted_doc,
		(void*)CryptoEnclave_ocall_del_encrypted_doc,
		(void*)CryptoEnclave_ocall_retrieve_M_c,
		(void*)CryptoEnclave_ocall_del_M_c_value,
		(void*)CryptoEnclave_ocall_query_tokens_entries,
		(void*)CryptoEnclave_ocall_add_update,
		(void*)CryptoEnclave_ocall_del_update,
		(void*)CryptoEnclave_ocall_Query_TSet,
		(void*)CryptoEnclave_ocall_Query_iTSet,
		(void*)CryptoEnclave_ocall_Get_CF,
		(void*)CryptoEnclave_ocall_send_stokenList,
		(void*)CryptoEnclave_ocall_print_int,
		(void*)CryptoEnclave_ocall_print_string,
		(void*)CryptoEnclave_ocall_test_int,
		(void*)CryptoEnclave_ocall_Get_Res,
		(void*)CryptoEnclave_sgx_oc_cpuidex,
		(void*)CryptoEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)CryptoEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)CryptoEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)CryptoEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_init(sgx_enclave_id_t eid, unsigned char key[3][16])
{
	sgx_status_t status;
	ms_ecall_init_t ms;
	ms.ms_key = (unsigned char*)key;
	status = sgx_ecall(eid, 0, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_addDoc(sgx_enclave_id_t eid, char* doc_id, size_t id_length, char* content, int content_length)
{
	sgx_status_t status;
	ms_ecall_addDoc_t ms;
	ms.ms_doc_id = doc_id;
	ms.ms_id_length = id_length;
	ms.ms_content = content;
	ms.ms_content_length = content_length;
	status = sgx_ecall(eid, 1, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_delDoc(sgx_enclave_id_t eid, char* doc_id, size_t id_length)
{
	sgx_status_t status;
	ms_ecall_delDoc_t ms;
	ms.ms_doc_id = doc_id;
	ms.ms_id_length = id_length;
	status = sgx_ecall(eid, 2, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_search(sgx_enclave_id_t eid, const char* keyword, size_t len)
{
	sgx_status_t status;
	ms_ecall_search_t ms;
	ms.ms_keyword = keyword;
	ms.ms_len = len;
	status = sgx_ecall(eid, 3, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_test(sgx_enclave_id_t eid, char* encrypted_content, size_t length_content)
{
	sgx_status_t status;
	ms_ecall_test_t ms;
	ms.ms_encrypted_content = encrypted_content;
	ms.ms_length_content = length_content;
	status = sgx_ecall(eid, 4, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_hash_test(sgx_enclave_id_t eid, const char* data, size_t len)
{
	sgx_status_t status;
	ms_ecall_hash_test_t ms;
	ms.ms_data = data;
	ms.ms_len = len;
	status = sgx_ecall(eid, 5, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_update_data(sgx_enclave_id_t eid, const char* w, size_t w_len, const char* id, size_t id_len, size_t op)
{
	sgx_status_t status;
	ms_ecall_update_data_t ms;
	ms.ms_w = w;
	ms.ms_w_len = w_len;
	ms.ms_id = id;
	ms.ms_id_len = id_len;
	ms.ms_op = op;
	status = sgx_ecall(eid, 6, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_update_data_Fuzzy(sgx_enclave_id_t eid, const char* w, size_t w_len, const char* id, size_t id_len, size_t pos, size_t op)
{
	sgx_status_t status;
	ms_ecall_update_data_Fuzzy_t ms;
	ms.ms_w = w;
	ms.ms_w_len = w_len;
	ms.ms_id = id;
	ms.ms_id_len = id_len;
	ms.ms_pos = pos;
	ms.ms_op = op;
	status = sgx_ecall(eid, 7, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_Conjunctive_Exact_Social_Search(sgx_enclave_id_t eid, char* str)
{
	sgx_status_t status;
	ms_ecall_Conjunctive_Exact_Social_Search_t ms;
	ms.ms_str = str;
	ms.ms_str_len = str ? strlen(str) + 1 : 0;
	status = sgx_ecall_switchless(eid, 8, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_Conjunctive_Fuzzy_Social_Search(sgx_enclave_id_t eid, char* str)
{
	sgx_status_t status;
	ms_ecall_Conjunctive_Fuzzy_Social_Search_t ms;
	ms.ms_str = str;
	ms.ms_str_len = str ? strlen(str) + 1 : 0;
	status = sgx_ecall(eid, 9, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_test_int(sgx_enclave_id_t eid, size_t test)
{
	sgx_status_t status;
	ms_ecall_test_int_t ms;
	ms.ms_test = test;
	status = sgx_ecall(eid, 10, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_get_MostCFs(sgx_enclave_id_t eid, int* test, size_t int_size)
{
	sgx_status_t status;
	ms_ecall_get_MostCFs_t ms;
	ms.ms_test = test;
	ms.ms_int_size = int_size;
	status = sgx_ecall(eid, 11, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t sl_init_switchless(sgx_enclave_id_t eid, sgx_status_t* retval, void* sl_data)
{
	sgx_status_t status;
	ms_sl_init_switchless_t ms;
	ms.ms_sl_data = sl_data;
	status = sgx_ecall(eid, 12, &ocall_table_CryptoEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sl_run_switchless_tworker(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_sl_run_switchless_tworker_t ms;
	status = sgx_ecall(eid, 13, &ocall_table_CryptoEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

