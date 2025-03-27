// Enclave/Enclave.cpp
#include "Enclave_t.h"
#include "sgx_trts.h"
#include "CKKS.h"
#include <string.h>

static CKKS* g_ckks = NULL;

sgx_status_t ecall_init_ckks(int polyDegree, double scale) {
    if (g_ckks != NULL) {
        delete g_ckks;
    }

    CKKSParams params;
    params.polyDegree = (uint32_t)polyDegree;
    params.scale = scale;
    params.slots = (uint32_t)(polyDegree / 2);

    g_ckks = new CKKS(params);
    return (g_ckks != NULL) ? SGX_SUCCESS : SGX_ERROR_OUT_OF_MEMORY;
}

sgx_status_t ecall_generate_keys() {
    return (g_ckks != NULL) ? g_ckks->keyGen() : SGX_ERROR_UNEXPECTED;
}

sgx_status_t ecall_encrypt(const double* msg_real, const double* msg_imag, 
                          uint32_t msg_len, int64_t* ciphertext, uint32_t ct_len) {
    return (g_ckks != NULL) ? g_ckks->encrypt(msg_real, msg_imag, msg_len, ciphertext, ct_len) : SGX_ERROR_UNEXPECTED;
}

sgx_status_t ecall_decrypt(const int64_t* ciphertext, uint32_t ct_len,
                          double* msg_real, double* msg_imag, uint32_t msg_len) {
    return (g_ckks != NULL) ? g_ckks->decrypt(ciphertext, ct_len, msg_real, msg_imag, msg_len) : SGX_ERROR_UNEXPECTED;
}

sgx_status_t ecall_add(const int64_t* ct1, uint32_t ct1_len,
                      const int64_t* ct2, uint32_t ct2_len,
                      int64_t* result, uint32_t result_len) {
    return (g_ckks != NULL) ? g_ckks->add(ct1, ct1_len, ct2, ct2_len, result, result_len) : SGX_ERROR_UNEXPECTED;
}

sgx_status_t ecall_multiply(const int64_t* ct1, uint32_t ct1_len,
                           const int64_t* ct2, uint32_t ct2_len,
                           int64_t* result, uint32_t result_len) {
    return (g_ckks != NULL) ? g_ckks->multiply(ct1, ct1_len, ct2, ct2_len, result, result_len) : SGX_ERROR_UNEXPECTED;
}
