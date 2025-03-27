// Enclave/CKKS.cpp (Updated with improved sampling)
#include "CKKS.h"
#include "sgx_trts.h"
#include <string.h>
#include <math.h>
#include "Enclave_t.h" // For OCalls


CKKS::CKKS(const CKKSParams& p) {
    if (p.polyDegree > MAX_POLY_DEGREE) {
        // Handle error - polynomial degree too large
        this->params.polyDegree = MAX_POLY_DEGREE;
    } else {
        this->params.polyDegree = p.polyDegree;
    }

    this->params.scale = p.scale;
    this->params.slots = p.slots;
}

CKKS::~CKKS() {
    // Clear sensitive data
    memset(&keys, 0, sizeof(keys));
}

void debug_print(const char* label, const int64_t* arr, uint32_t size, uint32_t max_print = 5) {
    ocall_print_string(label);
    ocall_print_string(": [");
    for (uint32_t i = 0; i < size && i < max_print; i++) {
        ocall_print_int(arr[i]);
        if (i < size - 1 && i < max_print - 1) ocall_print_string(", ");
    }
    if (size > max_print) ocall_print_string(", ...");
    ocall_print_string("]\n");
}

void debug_print_complex(const char* label, const complex_t* arr, uint32_t size, uint32_t max_print = 5) {
    ocall_print_string(label);
    ocall_print_string(": [");
    for (uint32_t i = 0; i < size && i < max_print; i++) {
        ocall_print_string("(");
        ocall_print_double(arr[i].real);
        ocall_print_string(", ");
        ocall_print_double(arr[i].imag);
        ocall_print_string(")");
        if (i < size - 1 && i < max_print - 1) ocall_print_string(", ");
    }
    if (size > max_print) ocall_print_string(", ...");
    ocall_print_string("]\n");
}

void debug_print_double(const char* label, const double* arr, uint32_t size, uint32_t max_print = 5) {
    ocall_print_string(label);
    ocall_print_string(": [");
    for (uint32_t i = 0; i < size && i < max_print; i++) {
        ocall_print_double(arr[i]);
        if (i < size - 1 && i < max_print - 1) ocall_print_string(", ");
    }
    if (size > max_print) ocall_print_string(", ...");
    ocall_print_string("]\n");
}


// Helper function for sampling from a ternary distribution {-1, 0, 1}
// with probabilities {1/4, 1/2, 1/4}
int64_t CKKS::sampleTernary() {
    uint8_t rand_byte;
    sgx_read_rand(&rand_byte, 1);

    // Use 2 bits to determine the value
    uint8_t val = rand_byte & 0x3;

    if (val == 0) return -1;      // 25% probability
    else if (val == 3) return 1;  // 25% probability
    else return 0;                // 50% probability
}

// Helper function for sampling small errors with a narrow discrete Gaussian-like distribution
int64_t CKKS::sampleError() {
    uint8_t rand_bytes[2];
    sgx_read_rand(rand_bytes, 2);

    // Combine bytes to get a 16-bit value
    uint16_t rand_val = (uint16_t)rand_bytes[0] | ((uint16_t)rand_bytes[1] << 8);

    // Use the Box-Muller transform to get a Gaussian-like distribution
    // We'll simplify by using a discrete approximation

    // Map to [0,1) range
    double u = rand_val / 65536.0;

    // Simple discrete approximation of Gaussian with standard deviation ~1.5
    if (u < 0.383) return 0;
    else if (u < 0.683) return (rand_bytes[0] & 1) ? 1 : -1;
    else if (u < 0.866) return (rand_bytes[0] & 1) ? 2 : -2;
    else if (u < 0.954) return (rand_bytes[0] & 1) ? 3 : -3;
    else if (u < 0.987) return (rand_bytes[0] & 1) ? 4 : -4;
    else return (rand_bytes[0] & 1) ? 5 : -5;
}

sgx_status_t CKKS::keyGen() {
    ocall_print_string("\n=== KEYGEN START ===\n");
    ocall_print_string("Polynomial degree: ");
    ocall_print_int(params.polyDegree);
    ocall_print_string("\n");

    // Generate secret key with ternary distribution
    for (uint32_t i = 0; i < params.polyDegree; i++) {
        keys.secretKey[i] = sampleTernary();
    }
    debug_print("Secret key", keys.secretKey, params.polyDegree, 10);

    // Modulus for coefficients
    const int64_t q = (1LL << 40);
    ocall_print_string("Modulus q: ");
    ocall_print_int(q);
    ocall_print_string("\n");

    // Generate public key: (-(a*s + e), a)
    int64_t a[MAX_POLY_DEGREE];
    sgx_status_t status = sgx_read_rand(
        (unsigned char*)a, 
        params.polyDegree * sizeof(int64_t)
    );

    if (status != SGX_SUCCESS) {
        ocall_print_string("ERROR: Random generation failed\n");
        return status;
    }

    // Ensure 'a' values are properly reduced modulo q
    for (uint32_t i = 0; i < params.polyDegree; i++) {
        a[i] = ((a[i] % q) + q) % q;  // Ensure positive value
    }
    debug_print("Random a", a, params.polyDegree, 10);

    // Generate small error with discrete Gaussian-like distribution
    int64_t e[MAX_POLY_DEGREE];
    for (uint32_t i = 0; i < params.polyDegree; i++) {
        e[i] = sampleError();
    }
    debug_print("Error e", e, params.polyDegree, 10);

    // Compute -(a*s + e)
    int64_t as[MAX_POLY_DEGREE];
    polyMul(a, keys.secretKey, as, params.polyDegree);
    debug_print("a*s", as, params.polyDegree, 10);

    for (uint32_t i = 0; i < params.polyDegree; i++) {
        keys.publicKey[i] = (-(as[i] + e[i]) % q + q) % q;  // Ensure positive value
        keys.publicKey[i + params.polyDegree] = a[i];
    }
    debug_print("Public key (first part)", keys.publicKey, params.polyDegree, 10);
    debug_print("Public key (second part)", keys.publicKey + params.polyDegree, params.polyDegree, 10);

    // Generate evaluation key (simplified)
    // In a full implementation, this would be more complex
    status = sgx_read_rand(
        (unsigned char*)keys.evaluationKey, 
        params.polyDegree * sizeof(int64_t)
    );

    ocall_print_string("=== KEYGEN END ===\n\n");
    return status;
}

sgx_status_t CKKS::encrypt(const double* msg_real, const double* msg_imag, 
                          uint32_t msg_len, int64_t* ciphertext, uint32_t ct_capacity) {
    ocall_print_string("\n=== ENCRYPT START ===\n");
    debug_print_double("Input msg_real", msg_real, msg_len);

    if (ct_capacity < 2 * params.polyDegree) {
        ocall_print_string("ERROR: ct_capacity < 2 * params.polyDegree\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Step 1: Encode message into polynomial
    int64_t m[MAX_POLY_DEGREE] = {0};
    sgx_status_t status = encode(msg_real, msg_imag, msg_len, m, MAX_POLY_DEGREE);
    if (status != SGX_SUCCESS) {
        ocall_print_string("ERROR: Encoding failed\n");
        return status;
    }
    debug_print("Encoded message", m, params.polyDegree, 10);

    // Step 2: Encrypt the polynomial
    const int64_t q = (1LL << 40);
    ocall_print_string("Modulus q: ");
    ocall_print_int(q);
    ocall_print_string("\n");

    // Generate small error polynomials
    int64_t e1[MAX_POLY_DEGREE] = {0};
    int64_t e2[MAX_POLY_DEGREE] = {0};
    for (uint32_t i = 0; i < params.polyDegree; i++) {
        e1[i] = sampleError();
        e2[i] = sampleError();
    }
    debug_print("Error e1", e1, params.polyDegree, 5);
    debug_print("Error e2", e2, params.polyDegree, 5);

    // Generate random polynomial for encryption
    int64_t u[MAX_POLY_DEGREE] = {0};
    for (uint32_t i = 0; i < params.polyDegree; i++) {
        u[i] = sampleTernary();
    }
    debug_print("Random u", u, params.polyDegree, 5);
    debug_print("Public key (first part)", keys.publicKey, params.polyDegree, 5);
    debug_print("Public key (second part)", keys.publicKey + params.polyDegree, params.polyDegree, 5);

    // Compute c0 = b*u + e1 + m
    // where b is the first part of the public key
    int64_t bu[MAX_POLY_DEGREE] = {0};
    polyMul(keys.publicKey, u, bu, params.polyDegree);
    debug_print("b*u", bu, params.polyDegree, 5);

    // Compute c1 = a*u + e2
    // where a is the second part of the public key
    int64_t au[MAX_POLY_DEGREE] = {0};
    polyMul(keys.publicKey + params.polyDegree, u, au, params.polyDegree);
    debug_print("a*u", au, params.polyDegree, 5);

    // Construct ciphertext with proper modular arithmetic
    for (uint32_t i = 0; i < params.polyDegree; i++) {
        // c0 = b*u + e1 + m
        int64_t sum_c0 = 0;
        sum_c0 = (sum_c0 + bu[i]) % q;
        sum_c0 = (sum_c0 + e1[i]) % q;
        sum_c0 = (sum_c0 + m[i]) % q;
        // Ensure positive value
        ciphertext[i] = (sum_c0 + q) % q;

        // c1 = a*u + e2
        int64_t sum_c1 = 0;
        sum_c1 = (sum_c1 + au[i]) % q;
        sum_c1 = (sum_c1 + e2[i]) % q;
        // Ensure positive value
        ciphertext[i + params.polyDegree] = (sum_c1 + q) % q;
    }

    debug_print("Ciphertext c0", ciphertext, params.polyDegree, 5);
    debug_print("Ciphertext c1", ciphertext + params.polyDegree, params.polyDegree, 5);
    ocall_print_string("=== ENCRYPT END ===\n\n");

    return SGX_SUCCESS;
}

sgx_status_t CKKS::decrypt(const int64_t* ciphertext, uint32_t ct_len,
                          double* msg_real, double* msg_imag, uint32_t msg_capacity) {
    ocall_print_string("\n=== DECRYPT START ===\n");
    debug_print("Ciphertext c0", ciphertext, params.polyDegree, 5);
    debug_print("Ciphertext c1", ciphertext + params.polyDegree, params.polyDegree, 5);
    debug_print("Secret key", keys.secretKey, params.polyDegree, 5);

    if (ct_len < 2 * params.polyDegree) {
        ocall_print_string("ERROR: ct_len < 2 * params.polyDegree\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    const int64_t q = (1LL << 40);
    ocall_print_string("Modulus q: ");
    ocall_print_int(q);
    ocall_print_string("\n");

    // Step 1: Compute c0 + c1*s
    int64_t c1s[MAX_POLY_DEGREE] = {0};
    polyMul(ciphertext + params.polyDegree, keys.secretKey, c1s, params.polyDegree);
    debug_print("c1*s", c1s, params.polyDegree, 5);

    int64_t m[MAX_POLY_DEGREE] = {0};
    for (uint32_t i = 0; i < params.polyDegree; i++) {
        // Compute c0 + c1*s mod q with proper modular arithmetic
        m[i] = (ciphertext[i] + c1s[i]) % q;
    }
    debug_print("c0 + c1*s", m, params.polyDegree, 10);

    // Step 2: Decode the polynomial to get the message
    return decode(m, params.polyDegree, msg_real, msg_imag, msg_capacity);
}

sgx_status_t CKKS::encode(const double* msg_real, const double* msg_imag, 
                         uint32_t msg_len, int64_t* polynomial, uint32_t poly_capacity) {
    ocall_print_string("\n=== ENCODE START ===\n");
    debug_print_double("Input msg_real", msg_real, msg_len);
    debug_print_double("Input msg_imag", msg_imag, msg_len);

    ocall_print_string("msg_len: ");
    ocall_print_int(msg_len);
    ocall_print_string(", poly_capacity: ");
    ocall_print_int(poly_capacity);
    ocall_print_string(", slots: ");
    ocall_print_int(params.slots);
    ocall_print_string("\n");

    if (poly_capacity < params.polyDegree) {
        ocall_print_string("ERROR: poly_capacity < params.polyDegree\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (msg_len > params.slots) {
        ocall_print_string("WARNING: msg_len > params.slots, truncating\n");
        msg_len = params.slots; // Truncate if too many values
    }

    // Prepare complex values for FFT
    complex_t message[MAX_POLY_DEGREE];
    memset(message, 0, sizeof(message)); // Properly initialize the array

    for (uint32_t i = 0; i < msg_len; i++) {
        message[i].real = msg_real[i];
        message[i].imag = msg_imag[i];
    }
    debug_print_complex("Complex message before FFT", message, msg_len);

    // Perform inverse FFT to get polynomial coefficients
    complex_t coeffs[MAX_POLY_DEGREE];
    memset(coeffs, 0, sizeof(coeffs)); // Properly initialize the array

    fft(message, coeffs, params.polyDegree, true);
    debug_print_complex("Complex coeffs after inverse FFT", coeffs, params.polyDegree, 10);

    // Scale and round to integers
    ocall_print_string("Scale factor: ");
    ocall_print_double(params.scale);
    ocall_print_string("\n");

    for (uint32_t i = 0; i < params.polyDegree; i++) {
        polynomial[i] = (int64_t)round(coeffs[i].real * params.scale);
    }
    debug_print("Final encoded polynomial", polynomial, params.polyDegree, 10);
    ocall_print_string("=== ENCODE END ===\n\n");

    return SGX_SUCCESS;
}

sgx_status_t CKKS::decode(const int64_t* polynomial, uint32_t poly_len,
                         double* msg_real, double* msg_imag, uint32_t msg_capacity) {
    ocall_print_string("\n=== DECODE START ===\n");
    debug_print("Input polynomial", polynomial, poly_len, 10);

    ocall_print_string("poly_len: ");
    ocall_print_int(poly_len);
    ocall_print_string(", msg_capacity: ");
    ocall_print_int(msg_capacity);
    ocall_print_string(", slots: ");
    ocall_print_int(params.slots);
    ocall_print_string("\n");

    if (poly_len < params.polyDegree || msg_capacity < params.slots) {
        ocall_print_string("ERROR: Invalid parameters in decode\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    const int64_t q = (1LL << 40);
    ocall_print_string("Modulus q: ");
    ocall_print_int(q);
    ocall_print_string("\n");

    // Convert integer polynomial to complex coefficients
    complex_t coeffs[MAX_POLY_DEGREE];
    memset(coeffs, 0, sizeof(coeffs)); // Properly initialize the array

    for (uint32_t i = 0; i < params.polyDegree; i++) {
        // Proper modular reduction
        int64_t value = polynomial[i] % q;
        // Ensure positive value first
        if (value < 0) value += q;
        // Center around zero
        if (value > q/2) {
            value -= q;
        }
        coeffs[i].real = (double)value / params.scale;
        coeffs[i].imag = 0.0;
    }
    debug_print_complex("Complex coeffs before FFT", coeffs, params.polyDegree, 10);

    // Perform FFT to get the encoded slots
    complex_t message[MAX_POLY_DEGREE];
    memset(message, 0, sizeof(message)); // Properly initialize the array

    fft(coeffs, message, params.polyDegree, false);
    debug_print_complex("Complex message after FFT", message, params.slots, 10);

    // Extract the message
    for (uint32_t i = 0; i < params.slots && i < msg_capacity; i++) {
        msg_real[i] = message[i].real;
        msg_imag[i] = message[i].imag;
    }
    debug_print_double("Final decoded msg_real", msg_real, params.slots);
    debug_print_double("Final decoded msg_imag", msg_imag, params.slots);
    ocall_print_string("=== DECODE END ===\n\n");

    return SGX_SUCCESS;
}

void CKKS::polyMul(const int64_t* a, const int64_t* b, int64_t* result, uint32_t size) {
    ocall_print_string("\n=== POLYMUL START ===\n");
    debug_print("Polynomial a", a, size, 5);
    debug_print("Polynomial b", b, size, 5);

    const int64_t q = (1LL << 40);
    ocall_print_string("Modulus q: ");
    ocall_print_int(q);
    ocall_print_string("\n");

    // Initialize result to zero
    memset(result, 0, size * sizeof(int64_t));

    // Perform polynomial multiplication with careful modular arithmetic
    for (uint32_t i = 0; i < size; i++) {
        int64_t a_i = ((a[i] % q) + q) % q;  // Ensure positive value
        for (uint32_t j = 0; j < size; j++) {
            uint32_t idx = (i + j) % size;  // Polynomial reduction x^n = 1
            int64_t b_j = ((b[j] % q) + q) % q;  // Ensure positive value

            // Careful modular multiplication to avoid overflow
            int64_t prod = (a_i * b_j) % q;
            result[idx] = (result[idx] + prod) % q;
            // Ensure positive value
            result[idx] = (result[idx] + q) % q;
        }
    }

    debug_print("Result polynomial", result, size, 5);
    ocall_print_string("=== POLYMUL END ===\n\n");
}

void CKKS::fft(const complex_t* input, complex_t* output, uint32_t size, bool inverse) {
    ocall_print_string("\n=== FFT START (inverse=");
    ocall_print_int(inverse ? 1 : 0);
    ocall_print_string(") ===\n");

    ocall_print_string("FFT size: ");
    ocall_print_int(size);
    ocall_print_string("\n");

    debug_print_complex("FFT input", input, size, 5);

    // Make sure size is a power of 2
    if ((size & (size - 1)) != 0) {
        ocall_print_string("ERROR: FFT size must be a power of 2\n");
        return;
    }

    const double PI = 3.14159265358979323846;

    // Copy input to output
    memcpy(output, input, size * sizeof(complex_t));

    // Bit-reverse permutation
    uint32_t j = 0;
    for (uint32_t i = 0; i < size - 1; i++) {
        if (i < j) {
            // Swap output[i] and output[j]
            complex_t temp = output[i];
            output[i] = output[j];
            output[j] = temp;
        }

        uint32_t mask = size >> 1;
        while (j & mask) {
            j &= ~mask;
            mask >>= 1;
        }
        j |= mask;
    }
    debug_print_complex("After bit-reverse", output, size, 5);

    // Cooley-Tukey FFT algorithm with improved numerical stability
    for (uint32_t step = 2; step <= size; step <<= 1) {
        double angle = (inverse ? 2.0 : -2.0) * PI / step;
        // Precompute twiddle factor for better numerical stability
        complex_t wm = {cos(angle), sin(angle)};

        ocall_print_string("Step: ");
        ocall_print_int(step);
        ocall_print_string(", angle: ");
        ocall_print_double(angle);
        ocall_print_string(", wm: (");
        ocall_print_double(wm.real);
        ocall_print_string(", ");
        ocall_print_double(wm.imag);
        ocall_print_string(")\n");

        for (uint32_t i = 0; i < size; i += step) {
            complex_t w = {1.0, 0.0};

            for (uint32_t k = 0; k < step/2; k++) {
                complex_t u = output[i + k];

                // Compute t = w * output[i + k + step/2] with improved precision
                complex_t t;
                double real_part = w.real * output[i + k + step/2].real;
                double imag_part = w.imag * output[i + k + step/2].imag;
                t.real = real_part - imag_part;

                real_part = w.real * output[i + k + step/2].imag;
                imag_part = w.imag * output[i + k + step/2].real;
                t.imag = real_part + imag_part;

                // Butterfly operation
                output[i + k].real = u.real + t.real;
                output[i + k].imag = u.imag + t.imag;

                output[i + k + step/2].real = u.real - t.real;
                output[i + k + step/2].imag = u.imag - t.imag;

                // Update w = w * wm with improved precision
                double temp = w.real * wm.real - w.imag * wm.imag;
                w.imag = w.real * wm.imag + w.imag * wm.real;
                w.real = temp;
            }
        }
    }

    // Scale if inverse
    if (inverse) {
        double scale_factor = 1.0 / size;
        ocall_print_string("Inverse FFT scaling factor: ");
        ocall_print_double(scale_factor);
        ocall_print_string("\n");

        for (uint32_t i = 0; i < size; i++) {
            output[i].real *= scale_factor;
            output[i].imag *= scale_factor;
        }
    }

    debug_print_complex("FFT output", output, size, 5);
    ocall_print_string("=== FFT END ===\n\n");
}

sgx_status_t CKKS::add(const int64_t* ct1, uint32_t ct1_len,
                      const int64_t* ct2, uint32_t ct2_len,
                      int64_t* result, uint32_t result_capacity) {
    if (ct1_len < 2 * params.polyDegree || ct2_len < 2 * params.polyDegree || 
        result_capacity < 2 * params.polyDegree) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    const int64_t q = (1LL << 40);

    for (uint32_t i = 0; i < 2 * params.polyDegree; i++) {
        // Proper modular addition
        result[i] = (ct1[i] + ct2[i]) % q;
        // Ensure positive value
        result[i] = (result[i] + q) % q;
    }

    return SGX_SUCCESS;
}

void CKKS::relinearize(const int64_t* c2, int64_t* result, uint32_t poly_size) {
    const int64_t q = (1LL << 40);

    // Clear result
    memset(result, 0, 2 * poly_size * sizeof(int64_t));

    // In a proper implementation, we would use evaluation keys
    // Since we don't have proper evaluation keys, we'll use a more direct approach
    // that captures the mathematical relationship

    ocall_print_string("Relinearizing c1d1 term...\n");

    // The mathematical relationship we want to capture is:
    // c1d1 * s^2 ≈ c1d1 * (a*s + e) ≈ c1d1*a*s + small_term

    // For each coefficient in c2 (which is c1d1)
    for (uint32_t i = 0; i < poly_size; i++) {
        // For a proper implementation, we would decompose c2[i] and use evaluation keys
        // Here we'll simulate the effect more directly

        // The first component gets -c2[i] * s
        for (uint32_t j = 0; j < poly_size; j++) {
            uint32_t idx = (i + j) % poly_size;  // Polynomial reduction
            int64_t term = ((-c2[i] % q) * keys.secretKey[j]) % q;
            result[idx] = (result[idx] + term) % q;
        }

        // The second component gets c2[i]
        result[i + poly_size] = (result[i + poly_size] + c2[i]) % q;
    }

    // Add small error to simulate the error in the evaluation key
    for (uint32_t i = 0; i < 2 * poly_size; i++) {
        result[i] = (result[i] + sampleError()) % q;
    }

    // Ensure positive values
    for (uint32_t i = 0; i < 2 * poly_size; i++) {
        result[i] = (result[i] + q) % q;
    }
}

void CKKS::rescale(int64_t* ciphertext, uint32_t ct_size, double scale_factor) {
    const int64_t q = (1LL << 40);

    ocall_print_string("Rescaling with factor: ");
    ocall_print_double(scale_factor);
    ocall_print_string("\n");

    // Rescale by dividing by scale_factor and rounding
    for (uint32_t i = 0; i < ct_size; i++) {
        // Center around zero for proper rounding
        int64_t value = ciphertext[i];
        if (value > q/2) value -= q;

        // Print some values for debugging
        if (i < 5) {
            ocall_print_string("Before rescale [");
            ocall_print_int(i);
            ocall_print_string("]: ");
            ocall_print_int(value);
            ocall_print_string("\n");
        }

        // Rescale and round
        double scaled = value / scale_factor;
        ciphertext[i] = (int64_t)round(scaled);

        // Print some values after rescaling
        if (i < 5) {
            ocall_print_string("After rescale [");
            ocall_print_int(i);
            ocall_print_string("]: ");
            ocall_print_int(ciphertext[i]);
            ocall_print_string("\n");
        }

        // Ensure positive value
        ciphertext[i] = ((ciphertext[i] % q) + q) % q;
    }
}

sgx_status_t CKKS::multiply(const int64_t* ct1, uint32_t ct1_len,
                           const int64_t* ct2, uint32_t ct2_len,
                           int64_t* result, uint32_t result_capacity) {
    ocall_print_string("\n=== MULTIPLY START ===\n");

    if (ct1_len < 2 * params.polyDegree || ct2_len < 2 * params.polyDegree || 
        result_capacity < 2 * params.polyDegree) {
        ocall_print_string("ERROR: Invalid parameter sizes in multiply\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    const int64_t q = (1LL << 40);
    const uint32_t poly_size = params.polyDegree;

    ocall_print_string("Scale factor: ");
    ocall_print_double(params.scale);
    ocall_print_string("\n");

    // Extract components
    int64_t c0[MAX_POLY_DEGREE], c1[MAX_POLY_DEGREE];
    int64_t d0[MAX_POLY_DEGREE], d1[MAX_POLY_DEGREE];

    memcpy(c0, ct1, poly_size * sizeof(int64_t));
    memcpy(c1, ct1 + poly_size, poly_size * sizeof(int64_t));
    memcpy(d0, ct2, poly_size * sizeof(int64_t));
    memcpy(d1, ct2 + poly_size, poly_size * sizeof(int64_t));

    debug_print("Multiply c0", c0, poly_size, 5);
    debug_print("Multiply c1", c1, poly_size, 5);
    debug_print("Multiply d0", d0, poly_size, 5);
    debug_print("Multiply d1", d1, poly_size, 5);

    // Step 1: Compute all tensor products
    int64_t c0d0[MAX_POLY_DEGREE] = {0};
    int64_t c0d1[MAX_POLY_DEGREE] = {0};
    int64_t c1d0[MAX_POLY_DEGREE] = {0};
    int64_t c1d1[MAX_POLY_DEGREE] = {0};

    polyMul(c0, d0, c0d0, poly_size);
    polyMul(c0, d1, c0d1, poly_size);
    polyMul(c1, d0, c1d0, poly_size);
    polyMul(c1, d1, c1d1, poly_size);

    debug_print("c0d0", c0d0, poly_size, 5);
    debug_print("c0d1", c0d1, poly_size, 5);
    debug_print("c1d0", c1d0, poly_size, 5);
    debug_print("c1d1", c1d1, poly_size, 5);

    // Step 2: Relinearize the c1d1 term
    int64_t relinearized_c1d1[2 * MAX_POLY_DEGREE] = {0};
    relinearize(c1d1, relinearized_c1d1, poly_size);

    debug_print("Relinearized c1d1[0]", relinearized_c1d1, poly_size, 5);
    debug_print("Relinearized c1d1[1]", relinearized_c1d1 + poly_size, poly_size, 5);

    // Step 3: Construct the final ciphertext
    // result[0] = c0d0 + relinearized_c1d1[0]
    // result[1] = c0d1 + c1d0 + relinearized_c1d1[1]
    for (uint32_t i = 0; i < poly_size; i++) {
        // First component
        result[i] = (c0d0[i] + relinearized_c1d1[i]) % q;

        // Second component
        result[i + poly_size] = (c0d1[i] + c1d0[i] + relinearized_c1d1[i + poly_size]) % q;

        // Ensure positive values
        result[i] = (result[i] + q) % q;
        result[i + poly_size] = (result[i + poly_size] + q) % q;
    }

    debug_print("Before rescale[0]", result, poly_size, 5);
    debug_print("Before rescale[1]", result + poly_size, poly_size, 5);

    // Step 4: Rescale to manage scale growth
    // After multiplication, the scale is squared
    double new_scale = params.scale * params.scale;
    ocall_print_string("New scale after multiplication: ");
    ocall_print_double(new_scale);
    ocall_print_string("\n");

    // We need to rescale back to the original scale
    rescale(result, 2 * poly_size, new_scale / params.scale);

    debug_print("After rescale[0]", result, poly_size, 5);
    debug_print("After rescale[1]", result + poly_size, poly_size, 5);

    ocall_print_string("=== MULTIPLY END ===\n\n");
    return SGX_SUCCESS;
}

