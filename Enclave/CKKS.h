// Enclave/CKKS.h
#ifndef _CKKS_H_
#define _CKKS_H_

#include "sgx_tcrypto.h"
#include <stdint.h>

#define MAX_POLY_DEGREE 8192

typedef struct {
    uint32_t polyDegree;
    double scale;
    uint32_t slots;
} CKKSParams;

typedef struct {
    double real;
    double imag;
} complex_t;

typedef struct {
    int64_t secretKey[MAX_POLY_DEGREE];
    int64_t publicKey[2 * MAX_POLY_DEGREE];
    int64_t evaluationKey[MAX_POLY_DEGREE];
} CKKSKeys;

class CKKS {
private:
    CKKSParams params;
    CKKSKeys keys;

    void fft(const complex_t* input, complex_t* output, uint32_t size, bool inverse);
    void polyMul(const int64_t* a, const int64_t* b, int64_t* result, uint32_t size);
    int64_t sampleTernary();
    int64_t sampleError();
    sgx_status_t encode(const double* msg_real, const double* msg_imag, uint32_t msg_len, 
                        int64_t* polynomial, uint32_t poly_capacity);
    sgx_status_t decode(const int64_t* polynomial, uint32_t poly_len,
                        double* msg_real, double* msg_imag, uint32_t msg_capacity);
    // New helper functions for multiplication
    void relinearize(const int64_t* c2, int64_t* result, uint32_t poly_size);
    void rescale(int64_t* ciphertext, uint32_t ct_size, double scale_factor);

public:
    CKKS(const CKKSParams& params);
    ~CKKS();

    sgx_status_t keyGen();
    sgx_status_t encrypt(const double* msg_real, const double* msg_imag, uint32_t msg_len, 
                         int64_t* ciphertext, uint32_t ct_capacity);
    sgx_status_t decrypt(const int64_t* ciphertext, uint32_t ct_len,
                         double* msg_real, double* msg_imag, uint32_t msg_capacity);
    sgx_status_t add(const int64_t* ct1, uint32_t ct1_len, const int64_t* ct2, uint32_t ct2_len,
                     int64_t* result, uint32_t result_capacity);
    sgx_status_t multiply(const int64_t* ct1, uint32_t ct1_len, const int64_t* ct2, uint32_t ct2_len,
                          int64_t* result, uint32_t result_capacity);
};

#endif // _CKKS_H_
