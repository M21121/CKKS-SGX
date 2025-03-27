// App/App.cpp
#include "sgx_urts.h"
#include "Enclave_u.h"
#include <iostream>

sgx_enclave_id_t global_eid = 0;

int initialize_enclave() {
    sgx_launch_token_t token = {0};
    int updated = 0;
    sgx_status_t ret = sgx_create_enclave("./Enclave/enclave.signed.so", SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    return (ret == SGX_SUCCESS) ? 0 : -1;
}

int main() {
    if (initialize_enclave() < 0) {
        std::cerr << "Failed to initialize enclave." << std::endl;
        return -1;
    }

    int polyDegree = 8192;
    double scale = 1 << 30;
    int slots = polyDegree / 2;
    sgx_status_t ret, status;

    // Initialize CKKS
    status = ecall_init_ckks(global_eid, &ret, polyDegree, scale);
    if (status != SGX_SUCCESS || ret != SGX_SUCCESS) {
        std::cerr << "Failed to initialize CKKS" << std::endl;
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    // Generate keys
    status = ecall_generate_keys(global_eid, &ret);
    if (status != SGX_SUCCESS || ret != SGX_SUCCESS) {
        std::cerr << "Failed to generate keys" << std::endl;
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    // Prepare messages
    double* msg_real = new double[slots]();
    double* msg_imag = new double[slots]();
    msg_real[0] = 3.14159;
    msg_real[1] = 2.71828;

    double* msg2_real = new double[slots]();
    double* msg2_imag = new double[slots]();
    msg2_real[0] = 1.0;
    msg2_real[1] = 2.0;

    // Encrypt messages
    uint32_t ct_size = 2 * polyDegree;
    int64_t* ct1 = new int64_t[ct_size]();
    int64_t* ct2 = new int64_t[ct_size]();

    status = ecall_encrypt(global_eid, &ret, msg_real, msg_imag, slots, ct1, ct_size);
    status = ecall_encrypt(global_eid, &ret, msg2_real, msg2_imag, slots, ct2, ct_size);

    // Homomorphic operations
    int64_t* result_add = new int64_t[ct_size]();
    int64_t* result_mul = new int64_t[ct_size]();

    status = ecall_add(global_eid, &ret, ct1, ct_size, ct2, ct_size, result_add, ct_size);
    status = ecall_multiply(global_eid, &ret, ct1, ct_size, ct2, ct_size, result_mul, ct_size);

    // Decrypt results
    double* sum_real = new double[slots]();
    double* sum_imag = new double[slots]();
    double* product_real = new double[slots]();
    double* product_imag = new double[slots]();

    status = ecall_decrypt(global_eid, &ret, result_add, ct_size, sum_real, sum_imag, slots);
    status = ecall_decrypt(global_eid, &ret, result_mul, ct_size, product_real, product_imag, slots);

    // Print results
    std::cout << "Sum: " << sum_real[0] << ", " << sum_real[1] << std::endl;
    std::cout << "Expected sum: " << (msg_real[0] + msg2_real[0]) << ", " << (msg_real[1] + msg2_real[1]) << std::endl;
    std::cout << "Product: " << product_real[0] << ", " << product_real[1] << std::endl;
    std::cout << "Expected product: " << (msg_real[0] * msg2_real[0]) << ", " << (msg_real[1] * msg2_real[1]) << std::endl;

    // Cleanup
    delete[] msg_real; delete[] msg_imag;
    delete[] msg2_real; delete[] msg2_imag;
    delete[] ct1; delete[] ct2;
    delete[] result_add; delete[] result_mul;
    delete[] sum_real; delete[] sum_imag;
    delete[] product_real; delete[] product_imag;
    sgx_destroy_enclave(global_eid);
    return 0;
}

void ocall_print_string(const char* str) { std::cout << str; }
void ocall_print_int(int64_t value) { std::cout << value; }
void ocall_print_double(double value) { std::cout << value; }
