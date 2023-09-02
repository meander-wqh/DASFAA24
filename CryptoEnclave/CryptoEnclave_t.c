#include "CryptoEnclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_init_t* ms = SGX_CAST(ms_ecall_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_key = ms->ms_key;
	size_t _len_key = 48 * sizeof(unsigned char);
	unsigned char* _in_key = NULL;

	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_key != NULL && _len_key != 0) {
		if ( _len_key % sizeof(*_tmp_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_key = (unsigned char*)malloc(_len_key);
		if (_in_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_key, _len_key, _tmp_key, _len_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_init((unsigned char (*)[16])_in_key);

err:
	if (_in_key) free(_in_key);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_addDoc(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_addDoc_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_addDoc_t* ms = SGX_CAST(ms_ecall_addDoc_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_doc_id = ms->ms_doc_id;
	size_t _tmp_id_length = ms->ms_id_length;
	size_t _len_doc_id = _tmp_id_length;
	char* _in_doc_id = NULL;
	char* _tmp_content = ms->ms_content;
	int _tmp_content_length = ms->ms_content_length;
	size_t _len_content = _tmp_content_length;
	char* _in_content = NULL;

	CHECK_UNIQUE_POINTER(_tmp_doc_id, _len_doc_id);
	CHECK_UNIQUE_POINTER(_tmp_content, _len_content);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_doc_id != NULL && _len_doc_id != 0) {
		if ( _len_doc_id % sizeof(*_tmp_doc_id) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_doc_id = (char*)malloc(_len_doc_id);
		if (_in_doc_id == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_doc_id, _len_doc_id, _tmp_doc_id, _len_doc_id)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_content != NULL && _len_content != 0) {
		if ( _len_content % sizeof(*_tmp_content) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_content = (char*)malloc(_len_content);
		if (_in_content == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_content, _len_content, _tmp_content, _len_content)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_addDoc(_in_doc_id, _tmp_id_length, _in_content, _tmp_content_length);

err:
	if (_in_doc_id) free(_in_doc_id);
	if (_in_content) free(_in_content);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_delDoc(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_delDoc_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_delDoc_t* ms = SGX_CAST(ms_ecall_delDoc_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_doc_id = ms->ms_doc_id;
	size_t _tmp_id_length = ms->ms_id_length;
	size_t _len_doc_id = _tmp_id_length;
	char* _in_doc_id = NULL;

	CHECK_UNIQUE_POINTER(_tmp_doc_id, _len_doc_id);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_doc_id != NULL && _len_doc_id != 0) {
		if ( _len_doc_id % sizeof(*_tmp_doc_id) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_doc_id = (char*)malloc(_len_doc_id);
		if (_in_doc_id == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_doc_id, _len_doc_id, _tmp_doc_id, _len_doc_id)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_delDoc(_in_doc_id, _tmp_id_length);

err:
	if (_in_doc_id) free(_in_doc_id);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_search(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_search_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_search_t* ms = SGX_CAST(ms_ecall_search_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_keyword = ms->ms_keyword;
	size_t _tmp_len = ms->ms_len;
	size_t _len_keyword = _tmp_len;
	char* _in_keyword = NULL;

	CHECK_UNIQUE_POINTER(_tmp_keyword, _len_keyword);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_keyword != NULL && _len_keyword != 0) {
		if ( _len_keyword % sizeof(*_tmp_keyword) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_keyword = (char*)malloc(_len_keyword);
		if (_in_keyword == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_keyword, _len_keyword, _tmp_keyword, _len_keyword)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_search((const char*)_in_keyword, _tmp_len);

err:
	if (_in_keyword) free(_in_keyword);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_test(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_test_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_test_t* ms = SGX_CAST(ms_ecall_test_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_encrypted_content = ms->ms_encrypted_content;
	size_t _tmp_length_content = ms->ms_length_content;
	size_t _len_encrypted_content = _tmp_length_content;
	char* _in_encrypted_content = NULL;

	CHECK_UNIQUE_POINTER(_tmp_encrypted_content, _len_encrypted_content);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_encrypted_content != NULL && _len_encrypted_content != 0) {
		if ( _len_encrypted_content % sizeof(*_tmp_encrypted_content) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_encrypted_content = (char*)malloc(_len_encrypted_content);
		if (_in_encrypted_content == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_encrypted_content, _len_encrypted_content, _tmp_encrypted_content, _len_encrypted_content)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_test(_in_encrypted_content, _tmp_length_content);

err:
	if (_in_encrypted_content) free(_in_encrypted_content);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_hash_test(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_hash_test_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_hash_test_t* ms = SGX_CAST(ms_ecall_hash_test_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_data = ms->ms_data;
	size_t _tmp_len = ms->ms_len;
	size_t _len_data = _tmp_len;
	char* _in_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_data != NULL && _len_data != 0) {
		if ( _len_data % sizeof(*_tmp_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_data = (char*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_hash_test((const char*)_in_data, _tmp_len);

err:
	if (_in_data) free(_in_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_update_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_update_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_update_data_t* ms = SGX_CAST(ms_ecall_update_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_w = ms->ms_w;
	size_t _tmp_w_len = ms->ms_w_len;
	size_t _len_w = _tmp_w_len;
	char* _in_w = NULL;
	const char* _tmp_id = ms->ms_id;
	size_t _tmp_id_len = ms->ms_id_len;
	size_t _len_id = _tmp_id_len;
	char* _in_id = NULL;

	CHECK_UNIQUE_POINTER(_tmp_w, _len_w);
	CHECK_UNIQUE_POINTER(_tmp_id, _len_id);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_w != NULL && _len_w != 0) {
		if ( _len_w % sizeof(*_tmp_w) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_w = (char*)malloc(_len_w);
		if (_in_w == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_w, _len_w, _tmp_w, _len_w)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_id != NULL && _len_id != 0) {
		if ( _len_id % sizeof(*_tmp_id) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_id = (char*)malloc(_len_id);
		if (_in_id == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_id, _len_id, _tmp_id, _len_id)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_update_data((const char*)_in_w, _tmp_w_len, (const char*)_in_id, _tmp_id_len, ms->ms_op);

err:
	if (_in_w) free(_in_w);
	if (_in_id) free(_in_id);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_update_data_Fuzzy(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_update_data_Fuzzy_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_update_data_Fuzzy_t* ms = SGX_CAST(ms_ecall_update_data_Fuzzy_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_w = ms->ms_w;
	size_t _tmp_w_len = ms->ms_w_len;
	size_t _len_w = _tmp_w_len;
	char* _in_w = NULL;
	const char* _tmp_id = ms->ms_id;
	size_t _tmp_id_len = ms->ms_id_len;
	size_t _len_id = _tmp_id_len;
	char* _in_id = NULL;

	CHECK_UNIQUE_POINTER(_tmp_w, _len_w);
	CHECK_UNIQUE_POINTER(_tmp_id, _len_id);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_w != NULL && _len_w != 0) {
		if ( _len_w % sizeof(*_tmp_w) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_w = (char*)malloc(_len_w);
		if (_in_w == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_w, _len_w, _tmp_w, _len_w)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_id != NULL && _len_id != 0) {
		if ( _len_id % sizeof(*_tmp_id) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_id = (char*)malloc(_len_id);
		if (_in_id == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_id, _len_id, _tmp_id, _len_id)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_update_data_Fuzzy((const char*)_in_w, _tmp_w_len, (const char*)_in_id, _tmp_id_len, ms->ms_pos, ms->ms_op);

err:
	if (_in_w) free(_in_w);
	if (_in_id) free(_in_id);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_Conjunctive_Exact_Social_Search(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_Conjunctive_Exact_Social_Search_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_Conjunctive_Exact_Social_Search_t* ms = SGX_CAST(ms_ecall_Conjunctive_Exact_Social_Search_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	size_t _len_str = ms->ms_str_len ;
	char* _in_str = NULL;

	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_str != NULL && _len_str != 0) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str, _len_str, _tmp_str, _len_str)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str[_len_str - 1] = '\0';
		if (_len_str != strlen(_in_str) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ecall_Conjunctive_Exact_Social_Search(_in_str);

err:
	if (_in_str) free(_in_str);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_Conjunctive_Fuzzy_Social_Search(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_Conjunctive_Fuzzy_Social_Search_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_Conjunctive_Fuzzy_Social_Search_t* ms = SGX_CAST(ms_ecall_Conjunctive_Fuzzy_Social_Search_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	size_t _len_str = ms->ms_str_len ;
	char* _in_str = NULL;

	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_str != NULL && _len_str != 0) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str, _len_str, _tmp_str, _len_str)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str[_len_str - 1] = '\0';
		if (_len_str != strlen(_in_str) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ecall_Conjunctive_Fuzzy_Social_Search(_in_str);

err:
	if (_in_str) free(_in_str);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_test_int(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_test_int_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_test_int_t* ms = SGX_CAST(ms_ecall_test_int_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_test_int(ms->ms_test);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[11];
} g_ecall_table = {
	11,
	{
		{(void*)(uintptr_t)sgx_ecall_init, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_addDoc, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_delDoc, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_search, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_test, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_hash_test, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_update_data, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_update_data_Fuzzy, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_Conjunctive_Exact_Social_Search, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_Conjunctive_Fuzzy_Social_Search, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_test_int, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[23][11];
} g_dyn_entry_table = {
	23,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_test2(char* encrypted_content, size_t length_content)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_encrypted_content = length_content;

	ms_ocall_test2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_test2_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(encrypted_content, _len_encrypted_content);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (encrypted_content != NULL) ? _len_encrypted_content : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_test2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_test2_t));
	ocalloc_size -= sizeof(ms_ocall_test2_t);

	if (encrypted_content != NULL) {
		ms->ms_encrypted_content = (char*)__tmp;
		if (_len_encrypted_content % sizeof(*encrypted_content) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, encrypted_content, _len_encrypted_content)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_encrypted_content);
		ocalloc_size -= _len_encrypted_content;
	} else {
		ms->ms_encrypted_content = NULL;
	}
	
	ms->ms_length_content = length_content;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_test(int* mint, char* mchar, char* mstring, int len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_mint = 1 * sizeof(int);
	size_t _len_mchar = 1;
	size_t _len_mstring = len;

	ms_ocall_test_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_test_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(mint, _len_mint);
	CHECK_ENCLAVE_POINTER(mchar, _len_mchar);
	CHECK_ENCLAVE_POINTER(mstring, _len_mstring);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (mint != NULL) ? _len_mint : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (mchar != NULL) ? _len_mchar : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (mstring != NULL) ? _len_mstring : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_test_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_test_t));
	ocalloc_size -= sizeof(ms_ocall_test_t);

	if (mint != NULL) {
		ms->ms_mint = (int*)__tmp;
		if (_len_mint % sizeof(*mint) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, mint, _len_mint)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_mint);
		ocalloc_size -= _len_mint;
	} else {
		ms->ms_mint = NULL;
	}
	
	if (mchar != NULL) {
		ms->ms_mchar = (char*)__tmp;
		if (_len_mchar % sizeof(*mchar) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, mchar, _len_mchar)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_mchar);
		ocalloc_size -= _len_mchar;
	} else {
		ms->ms_mchar = NULL;
	}
	
	if (mstring != NULL) {
		ms->ms_mstring = (char*)__tmp;
		if (_len_mstring % sizeof(*mstring) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, mstring, _len_mstring)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_mstring);
		ocalloc_size -= _len_mstring;
	} else {
		ms->ms_mstring = NULL;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_transfer_encrypted_entries(const void* t1_u_arr, const void* t1_v_arr, const void* t2_u_arr, const void* t2_v_arr, int pair_count, int rand_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_t1_u_arr = pair_count * rand_size;
	size_t _len_t1_v_arr = pair_count * rand_size;
	size_t _len_t2_u_arr = pair_count * rand_size;
	size_t _len_t2_v_arr = pair_count * rand_size;

	ms_ocall_transfer_encrypted_entries_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_transfer_encrypted_entries_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(t1_u_arr, _len_t1_u_arr);
	CHECK_ENCLAVE_POINTER(t1_v_arr, _len_t1_v_arr);
	CHECK_ENCLAVE_POINTER(t2_u_arr, _len_t2_u_arr);
	CHECK_ENCLAVE_POINTER(t2_v_arr, _len_t2_v_arr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (t1_u_arr != NULL) ? _len_t1_u_arr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (t1_v_arr != NULL) ? _len_t1_v_arr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (t2_u_arr != NULL) ? _len_t2_u_arr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (t2_v_arr != NULL) ? _len_t2_v_arr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_transfer_encrypted_entries_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_transfer_encrypted_entries_t));
	ocalloc_size -= sizeof(ms_ocall_transfer_encrypted_entries_t);

	if (t1_u_arr != NULL) {
		ms->ms_t1_u_arr = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, t1_u_arr, _len_t1_u_arr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_t1_u_arr);
		ocalloc_size -= _len_t1_u_arr;
	} else {
		ms->ms_t1_u_arr = NULL;
	}
	
	if (t1_v_arr != NULL) {
		ms->ms_t1_v_arr = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, t1_v_arr, _len_t1_v_arr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_t1_v_arr);
		ocalloc_size -= _len_t1_v_arr;
	} else {
		ms->ms_t1_v_arr = NULL;
	}
	
	if (t2_u_arr != NULL) {
		ms->ms_t2_u_arr = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, t2_u_arr, _len_t2_u_arr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_t2_u_arr);
		ocalloc_size -= _len_t2_u_arr;
	} else {
		ms->ms_t2_u_arr = NULL;
	}
	
	if (t2_v_arr != NULL) {
		ms->ms_t2_v_arr = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, t2_v_arr, _len_t2_v_arr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_t2_v_arr);
		ocalloc_size -= _len_t2_v_arr;
	} else {
		ms->ms_t2_v_arr = NULL;
	}
	
	ms->ms_pair_count = pair_count;
	ms->ms_rand_size = rand_size;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_retrieve_encrypted_doc(const char* del_id, size_t del_id_len, unsigned char* encrypted_content, size_t maxLen, int* length_content, size_t int_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_del_id = del_id_len;
	size_t _len_encrypted_content = maxLen;
	size_t _len_length_content = int_len * sizeof(int);

	ms_ocall_retrieve_encrypted_doc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_retrieve_encrypted_doc_t);
	void *__tmp = NULL;

	void *__tmp_encrypted_content = NULL;
	void *__tmp_length_content = NULL;

	CHECK_ENCLAVE_POINTER(del_id, _len_del_id);
	CHECK_ENCLAVE_POINTER(encrypted_content, _len_encrypted_content);
	CHECK_ENCLAVE_POINTER(length_content, _len_length_content);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (del_id != NULL) ? _len_del_id : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (encrypted_content != NULL) ? _len_encrypted_content : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (length_content != NULL) ? _len_length_content : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_retrieve_encrypted_doc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_retrieve_encrypted_doc_t));
	ocalloc_size -= sizeof(ms_ocall_retrieve_encrypted_doc_t);

	if (del_id != NULL) {
		ms->ms_del_id = (const char*)__tmp;
		if (_len_del_id % sizeof(*del_id) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, del_id, _len_del_id)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_del_id);
		ocalloc_size -= _len_del_id;
	} else {
		ms->ms_del_id = NULL;
	}
	
	ms->ms_del_id_len = del_id_len;
	if (encrypted_content != NULL) {
		ms->ms_encrypted_content = (unsigned char*)__tmp;
		__tmp_encrypted_content = __tmp;
		if (_len_encrypted_content % sizeof(*encrypted_content) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_encrypted_content, 0, _len_encrypted_content);
		__tmp = (void *)((size_t)__tmp + _len_encrypted_content);
		ocalloc_size -= _len_encrypted_content;
	} else {
		ms->ms_encrypted_content = NULL;
	}
	
	ms->ms_maxLen = maxLen;
	if (length_content != NULL) {
		ms->ms_length_content = (int*)__tmp;
		__tmp_length_content = __tmp;
		if (_len_length_content % sizeof(*length_content) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_length_content, 0, _len_length_content);
		__tmp = (void *)((size_t)__tmp + _len_length_content);
		ocalloc_size -= _len_length_content;
	} else {
		ms->ms_length_content = NULL;
	}
	
	ms->ms_int_len = int_len;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (encrypted_content) {
			if (memcpy_s((void*)encrypted_content, _len_encrypted_content, __tmp_encrypted_content, _len_encrypted_content)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (length_content) {
			if (memcpy_s((void*)length_content, _len_length_content, __tmp_length_content, _len_length_content)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_del_encrypted_doc(const char* del_id, size_t del_id_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_del_id = del_id_len;

	ms_ocall_del_encrypted_doc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_del_encrypted_doc_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(del_id, _len_del_id);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (del_id != NULL) ? _len_del_id : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_del_encrypted_doc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_del_encrypted_doc_t));
	ocalloc_size -= sizeof(ms_ocall_del_encrypted_doc_t);

	if (del_id != NULL) {
		ms->ms_del_id = (const char*)__tmp;
		if (_len_del_id % sizeof(*del_id) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, del_id, _len_del_id)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_del_id);
		ocalloc_size -= _len_del_id;
	} else {
		ms->ms_del_id = NULL;
	}
	
	ms->ms_del_id_len = del_id_len;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_retrieve_M_c(unsigned char* _u_prime, size_t _u_prime_size, unsigned char* _v_prime, size_t maxLen, int* _v_prime_size, size_t int_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len__u_prime = _u_prime_size;
	size_t _len__v_prime = maxLen;
	size_t _len__v_prime_size = int_len * sizeof(int);

	ms_ocall_retrieve_M_c_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_retrieve_M_c_t);
	void *__tmp = NULL;

	void *__tmp__v_prime = NULL;
	void *__tmp__v_prime_size = NULL;

	CHECK_ENCLAVE_POINTER(_u_prime, _len__u_prime);
	CHECK_ENCLAVE_POINTER(_v_prime, _len__v_prime);
	CHECK_ENCLAVE_POINTER(_v_prime_size, _len__v_prime_size);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (_u_prime != NULL) ? _len__u_prime : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (_v_prime != NULL) ? _len__v_prime : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (_v_prime_size != NULL) ? _len__v_prime_size : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_retrieve_M_c_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_retrieve_M_c_t));
	ocalloc_size -= sizeof(ms_ocall_retrieve_M_c_t);

	if (_u_prime != NULL) {
		ms->ms__u_prime = (unsigned char*)__tmp;
		if (_len__u_prime % sizeof(*_u_prime) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, _u_prime, _len__u_prime)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len__u_prime);
		ocalloc_size -= _len__u_prime;
	} else {
		ms->ms__u_prime = NULL;
	}
	
	ms->ms__u_prime_size = _u_prime_size;
	if (_v_prime != NULL) {
		ms->ms__v_prime = (unsigned char*)__tmp;
		__tmp__v_prime = __tmp;
		if (_len__v_prime % sizeof(*_v_prime) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp__v_prime, 0, _len__v_prime);
		__tmp = (void *)((size_t)__tmp + _len__v_prime);
		ocalloc_size -= _len__v_prime;
	} else {
		ms->ms__v_prime = NULL;
	}
	
	ms->ms_maxLen = maxLen;
	if (_v_prime_size != NULL) {
		ms->ms__v_prime_size = (int*)__tmp;
		__tmp__v_prime_size = __tmp;
		if (_len__v_prime_size % sizeof(*_v_prime_size) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp__v_prime_size, 0, _len__v_prime_size);
		__tmp = (void *)((size_t)__tmp + _len__v_prime_size);
		ocalloc_size -= _len__v_prime_size;
	} else {
		ms->ms__v_prime_size = NULL;
	}
	
	ms->ms_int_len = int_len;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (_v_prime) {
			if (memcpy_s((void*)_v_prime, _len__v_prime, __tmp__v_prime, _len__v_prime)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (_v_prime_size) {
			if (memcpy_s((void*)_v_prime_size, _len__v_prime_size, __tmp__v_prime_size, _len__v_prime_size)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_del_M_c_value(const unsigned char* _u_prime, size_t _u_prime_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len__u_prime = _u_prime_size;

	ms_ocall_del_M_c_value_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_del_M_c_value_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(_u_prime, _len__u_prime);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (_u_prime != NULL) ? _len__u_prime : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_del_M_c_value_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_del_M_c_value_t));
	ocalloc_size -= sizeof(ms_ocall_del_M_c_value_t);

	if (_u_prime != NULL) {
		ms->ms__u_prime = (const unsigned char*)__tmp;
		if (_len__u_prime % sizeof(*_u_prime) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, _u_prime, _len__u_prime)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len__u_prime);
		ocalloc_size -= _len__u_prime;
	} else {
		ms->ms__u_prime = NULL;
	}
	
	ms->ms__u_prime_size = _u_prime_size;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_query_tokens_entries(const void* Q_w_u_arr, const void* Q_w_id_arr, int pair_count, int rand_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_Q_w_u_arr = pair_count * rand_size;
	size_t _len_Q_w_id_arr = pair_count * rand_size;

	ms_ocall_query_tokens_entries_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_query_tokens_entries_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(Q_w_u_arr, _len_Q_w_u_arr);
	CHECK_ENCLAVE_POINTER(Q_w_id_arr, _len_Q_w_id_arr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (Q_w_u_arr != NULL) ? _len_Q_w_u_arr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (Q_w_id_arr != NULL) ? _len_Q_w_id_arr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_query_tokens_entries_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_query_tokens_entries_t));
	ocalloc_size -= sizeof(ms_ocall_query_tokens_entries_t);

	if (Q_w_u_arr != NULL) {
		ms->ms_Q_w_u_arr = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, Q_w_u_arr, _len_Q_w_u_arr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_Q_w_u_arr);
		ocalloc_size -= _len_Q_w_u_arr;
	} else {
		ms->ms_Q_w_u_arr = NULL;
	}
	
	if (Q_w_id_arr != NULL) {
		ms->ms_Q_w_id_arr = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, Q_w_id_arr, _len_Q_w_id_arr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_Q_w_id_arr);
		ocalloc_size -= _len_Q_w_id_arr;
	} else {
		ms->ms_Q_w_id_arr = NULL;
	}
	
	ms->ms_pair_count = pair_count;
	ms->ms_rand_size = rand_size;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_add_update(unsigned char* stag, size_t stag_len, unsigned char* C_id, size_t C_id_len, unsigned char* ind, size_t ind_len, unsigned char* C_stag, size_t C_stag_len, uint32_t fingerprint, size_t index, unsigned char* CFId, size_t CFId_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_stag = stag_len;
	size_t _len_C_id = C_id_len;
	size_t _len_ind = ind_len;
	size_t _len_C_stag = C_stag_len;
	size_t _len_CFId = CFId_len;

	ms_ocall_add_update_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_add_update_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(stag, _len_stag);
	CHECK_ENCLAVE_POINTER(C_id, _len_C_id);
	CHECK_ENCLAVE_POINTER(ind, _len_ind);
	CHECK_ENCLAVE_POINTER(C_stag, _len_C_stag);
	CHECK_ENCLAVE_POINTER(CFId, _len_CFId);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (stag != NULL) ? _len_stag : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (C_id != NULL) ? _len_C_id : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ind != NULL) ? _len_ind : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (C_stag != NULL) ? _len_C_stag : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (CFId != NULL) ? _len_CFId : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_add_update_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_add_update_t));
	ocalloc_size -= sizeof(ms_ocall_add_update_t);

	if (stag != NULL) {
		ms->ms_stag = (unsigned char*)__tmp;
		if (_len_stag % sizeof(*stag) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, stag, _len_stag)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_stag);
		ocalloc_size -= _len_stag;
	} else {
		ms->ms_stag = NULL;
	}
	
	ms->ms_stag_len = stag_len;
	if (C_id != NULL) {
		ms->ms_C_id = (unsigned char*)__tmp;
		if (_len_C_id % sizeof(*C_id) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, C_id, _len_C_id)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_C_id);
		ocalloc_size -= _len_C_id;
	} else {
		ms->ms_C_id = NULL;
	}
	
	ms->ms_C_id_len = C_id_len;
	if (ind != NULL) {
		ms->ms_ind = (unsigned char*)__tmp;
		if (_len_ind % sizeof(*ind) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, ind, _len_ind)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ind);
		ocalloc_size -= _len_ind;
	} else {
		ms->ms_ind = NULL;
	}
	
	ms->ms_ind_len = ind_len;
	if (C_stag != NULL) {
		ms->ms_C_stag = (unsigned char*)__tmp;
		if (_len_C_stag % sizeof(*C_stag) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, C_stag, _len_C_stag)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_C_stag);
		ocalloc_size -= _len_C_stag;
	} else {
		ms->ms_C_stag = NULL;
	}
	
	ms->ms_C_stag_len = C_stag_len;
	ms->ms_fingerprint = fingerprint;
	ms->ms_index = index;
	if (CFId != NULL) {
		ms->ms_CFId = (unsigned char*)__tmp;
		if (_len_CFId % sizeof(*CFId) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, CFId, _len_CFId)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_CFId);
		ocalloc_size -= _len_CFId;
	} else {
		ms->ms_CFId = NULL;
	}
	
	ms->ms_CFId_len = CFId_len;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_del_update(unsigned char* stag, size_t stag_len, unsigned char* stag_inverse, size_t stag_inverse_len, unsigned char* ind, size_t ind_len, unsigned char* ind_inverse, size_t ind_inverse_len, uint32_t fingerprint, size_t index, unsigned char* CFId, size_t CFId_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_stag = stag_len;
	size_t _len_stag_inverse = stag_inverse_len;
	size_t _len_ind = ind_len;
	size_t _len_ind_inverse = ind_inverse_len;
	size_t _len_CFId = CFId_len;

	ms_ocall_del_update_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_del_update_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(stag, _len_stag);
	CHECK_ENCLAVE_POINTER(stag_inverse, _len_stag_inverse);
	CHECK_ENCLAVE_POINTER(ind, _len_ind);
	CHECK_ENCLAVE_POINTER(ind_inverse, _len_ind_inverse);
	CHECK_ENCLAVE_POINTER(CFId, _len_CFId);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (stag != NULL) ? _len_stag : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (stag_inverse != NULL) ? _len_stag_inverse : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ind != NULL) ? _len_ind : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ind_inverse != NULL) ? _len_ind_inverse : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (CFId != NULL) ? _len_CFId : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_del_update_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_del_update_t));
	ocalloc_size -= sizeof(ms_ocall_del_update_t);

	if (stag != NULL) {
		ms->ms_stag = (unsigned char*)__tmp;
		if (_len_stag % sizeof(*stag) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, stag, _len_stag)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_stag);
		ocalloc_size -= _len_stag;
	} else {
		ms->ms_stag = NULL;
	}
	
	ms->ms_stag_len = stag_len;
	if (stag_inverse != NULL) {
		ms->ms_stag_inverse = (unsigned char*)__tmp;
		if (_len_stag_inverse % sizeof(*stag_inverse) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, stag_inverse, _len_stag_inverse)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_stag_inverse);
		ocalloc_size -= _len_stag_inverse;
	} else {
		ms->ms_stag_inverse = NULL;
	}
	
	ms->ms_stag_inverse_len = stag_inverse_len;
	if (ind != NULL) {
		ms->ms_ind = (unsigned char*)__tmp;
		if (_len_ind % sizeof(*ind) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, ind, _len_ind)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ind);
		ocalloc_size -= _len_ind;
	} else {
		ms->ms_ind = NULL;
	}
	
	ms->ms_ind_len = ind_len;
	if (ind_inverse != NULL) {
		ms->ms_ind_inverse = (unsigned char*)__tmp;
		if (_len_ind_inverse % sizeof(*ind_inverse) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, ind_inverse, _len_ind_inverse)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ind_inverse);
		ocalloc_size -= _len_ind_inverse;
	} else {
		ms->ms_ind_inverse = NULL;
	}
	
	ms->ms_ind_inverse_len = ind_inverse_len;
	ms->ms_fingerprint = fingerprint;
	ms->ms_index = index;
	if (CFId != NULL) {
		ms->ms_CFId = (unsigned char*)__tmp;
		if (_len_CFId % sizeof(*CFId) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, CFId, _len_CFId)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_CFId);
		ocalloc_size -= _len_CFId;
	} else {
		ms->ms_CFId = NULL;
	}
	
	ms->ms_CFId_len = CFId_len;
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_Query_TSet(unsigned char* stag, size_t stag_len, unsigned char* value, size_t value_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_stag = stag_len;
	size_t _len_value = value_len;

	ms_ocall_Query_TSet_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_Query_TSet_t);
	void *__tmp = NULL;

	void *__tmp_value = NULL;

	CHECK_ENCLAVE_POINTER(stag, _len_stag);
	CHECK_ENCLAVE_POINTER(value, _len_value);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (stag != NULL) ? _len_stag : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (value != NULL) ? _len_value : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_Query_TSet_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_Query_TSet_t));
	ocalloc_size -= sizeof(ms_ocall_Query_TSet_t);

	if (stag != NULL) {
		ms->ms_stag = (unsigned char*)__tmp;
		if (_len_stag % sizeof(*stag) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, stag, _len_stag)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_stag);
		ocalloc_size -= _len_stag;
	} else {
		ms->ms_stag = NULL;
	}
	
	ms->ms_stag_len = stag_len;
	if (value != NULL) {
		ms->ms_value = (unsigned char*)__tmp;
		__tmp_value = __tmp;
		if (_len_value % sizeof(*value) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_value, 0, _len_value);
		__tmp = (void *)((size_t)__tmp + _len_value);
		ocalloc_size -= _len_value;
	} else {
		ms->ms_value = NULL;
	}
	
	ms->ms_value_len = value_len;
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (value) {
			if (memcpy_s((void*)value, _len_value, __tmp_value, _len_value)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_Query_iTSet(unsigned char* ind, size_t ind_len, unsigned char* value, size_t value_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ind = ind_len;
	size_t _len_value = value_len;

	ms_ocall_Query_iTSet_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_Query_iTSet_t);
	void *__tmp = NULL;

	void *__tmp_value = NULL;

	CHECK_ENCLAVE_POINTER(ind, _len_ind);
	CHECK_ENCLAVE_POINTER(value, _len_value);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ind != NULL) ? _len_ind : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (value != NULL) ? _len_value : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_Query_iTSet_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_Query_iTSet_t));
	ocalloc_size -= sizeof(ms_ocall_Query_iTSet_t);

	if (ind != NULL) {
		ms->ms_ind = (unsigned char*)__tmp;
		if (_len_ind % sizeof(*ind) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, ind, _len_ind)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ind);
		ocalloc_size -= _len_ind;
	} else {
		ms->ms_ind = NULL;
	}
	
	ms->ms_ind_len = ind_len;
	if (value != NULL) {
		ms->ms_value = (unsigned char*)__tmp;
		__tmp_value = __tmp;
		if (_len_value % sizeof(*value) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_value, 0, _len_value);
		__tmp = (void *)((size_t)__tmp + _len_value);
		ocalloc_size -= _len_value;
	} else {
		ms->ms_value = NULL;
	}
	
	ms->ms_value_len = value_len;
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (value) {
			if (memcpy_s((void*)value, _len_value, __tmp_value, _len_value)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_Get_CF(unsigned char* CFId, size_t CFId_len, uint32_t* fingerprint, size_t fingerprint_len, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_CFId = CFId_len;
	size_t _len_fingerprint = fingerprint_len * len;

	ms_ocall_Get_CF_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_Get_CF_t);
	void *__tmp = NULL;

	void *__tmp_fingerprint = NULL;

	CHECK_ENCLAVE_POINTER(CFId, _len_CFId);
	CHECK_ENCLAVE_POINTER(fingerprint, _len_fingerprint);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (CFId != NULL) ? _len_CFId : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (fingerprint != NULL) ? _len_fingerprint : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_Get_CF_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_Get_CF_t));
	ocalloc_size -= sizeof(ms_ocall_Get_CF_t);

	if (CFId != NULL) {
		ms->ms_CFId = (unsigned char*)__tmp;
		if (_len_CFId % sizeof(*CFId) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, CFId, _len_CFId)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_CFId);
		ocalloc_size -= _len_CFId;
	} else {
		ms->ms_CFId = NULL;
	}
	
	ms->ms_CFId_len = CFId_len;
	if (fingerprint != NULL) {
		ms->ms_fingerprint = (uint32_t*)__tmp;
		__tmp_fingerprint = __tmp;
		if (_len_fingerprint % sizeof(*fingerprint) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_fingerprint, 0, _len_fingerprint);
		__tmp = (void *)((size_t)__tmp + _len_fingerprint);
		ocalloc_size -= _len_fingerprint;
	} else {
		ms->ms_fingerprint = NULL;
	}
	
	ms->ms_fingerprint_len = fingerprint_len;
	ms->ms_len = len;
	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (fingerprint) {
			if (memcpy_s((void*)fingerprint, _len_fingerprint, __tmp_fingerprint, _len_fingerprint)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_send_stokenList(unsigned char* StokenList, size_t StokenList_len, int StokenListSize, unsigned char* ValList, size_t ValList_len, int* ValListSize, size_t int_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_StokenList = StokenList_len;
	size_t _len_ValList = ValList_len;
	size_t _len_ValListSize = int_len * sizeof(int);

	ms_ocall_send_stokenList_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_send_stokenList_t);
	void *__tmp = NULL;

	void *__tmp_ValList = NULL;
	void *__tmp_ValListSize = NULL;

	CHECK_ENCLAVE_POINTER(StokenList, _len_StokenList);
	CHECK_ENCLAVE_POINTER(ValList, _len_ValList);
	CHECK_ENCLAVE_POINTER(ValListSize, _len_ValListSize);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (StokenList != NULL) ? _len_StokenList : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ValList != NULL) ? _len_ValList : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ValListSize != NULL) ? _len_ValListSize : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_send_stokenList_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_send_stokenList_t));
	ocalloc_size -= sizeof(ms_ocall_send_stokenList_t);

	if (StokenList != NULL) {
		ms->ms_StokenList = (unsigned char*)__tmp;
		if (_len_StokenList % sizeof(*StokenList) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, StokenList, _len_StokenList)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_StokenList);
		ocalloc_size -= _len_StokenList;
	} else {
		ms->ms_StokenList = NULL;
	}
	
	ms->ms_StokenList_len = StokenList_len;
	ms->ms_StokenListSize = StokenListSize;
	if (ValList != NULL) {
		ms->ms_ValList = (unsigned char*)__tmp;
		__tmp_ValList = __tmp;
		if (_len_ValList % sizeof(*ValList) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_ValList, 0, _len_ValList);
		__tmp = (void *)((size_t)__tmp + _len_ValList);
		ocalloc_size -= _len_ValList;
	} else {
		ms->ms_ValList = NULL;
	}
	
	ms->ms_ValList_len = ValList_len;
	if (ValListSize != NULL) {
		ms->ms_ValListSize = (int*)__tmp;
		__tmp_ValListSize = __tmp;
		if (_len_ValListSize % sizeof(*ValListSize) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_ValListSize, 0, _len_ValListSize);
		__tmp = (void *)((size_t)__tmp + _len_ValListSize);
		ocalloc_size -= _len_ValListSize;
	} else {
		ms->ms_ValListSize = NULL;
	}
	
	ms->ms_int_len = int_len;
	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (ValList) {
			if (memcpy_s((void*)ValList, _len_ValList, __tmp_ValList, _len_ValList)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (ValListSize) {
			if (memcpy_s((void*)ValListSize, _len_ValListSize, __tmp_ValListSize, _len_ValListSize)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_int(int input)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_print_int_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_int_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_int_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_int_t));
	ocalloc_size -= sizeof(ms_ocall_print_int_t);

	ms->ms_input = input;
	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_test_int(size_t test, uint32_t* fingerprint, size_t fingerprint_len, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_fingerprint = fingerprint_len * len;

	ms_ocall_test_int_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_test_int_t);
	void *__tmp = NULL;

	void *__tmp_fingerprint = NULL;

	CHECK_ENCLAVE_POINTER(fingerprint, _len_fingerprint);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (fingerprint != NULL) ? _len_fingerprint : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_test_int_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_test_int_t));
	ocalloc_size -= sizeof(ms_ocall_test_int_t);

	ms->ms_test = test;
	if (fingerprint != NULL) {
		ms->ms_fingerprint = (uint32_t*)__tmp;
		__tmp_fingerprint = __tmp;
		if (_len_fingerprint % sizeof(*fingerprint) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_fingerprint, 0, _len_fingerprint);
		__tmp = (void *)((size_t)__tmp + _len_fingerprint);
		ocalloc_size -= _len_fingerprint;
	} else {
		ms->ms_fingerprint = NULL;
	}
	
	ms->ms_fingerprint_len = fingerprint_len;
	ms->ms_len = len;
	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
		if (fingerprint) {
			if (memcpy_s((void*)fingerprint, _len_fingerprint, __tmp_fingerprint, _len_fingerprint)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_Get_Res(char* res, size_t res_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_res = sizeof(char);

	ms_ocall_Get_Res_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_Get_Res_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(res, _len_res);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (res != NULL) ? _len_res : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_Get_Res_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_Get_Res_t));
	ocalloc_size -= sizeof(ms_ocall_Get_Res_t);

	if (res != NULL) {
		ms->ms_res = (char*)__tmp;
		if (_len_res % sizeof(*res) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, res, _len_res)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_res);
		ocalloc_size -= _len_res;
	} else {
		ms->ms_res = NULL;
	}
	
	ms->ms_res_len = res_len;
	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(18, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(19, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(20, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(21, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(22, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

