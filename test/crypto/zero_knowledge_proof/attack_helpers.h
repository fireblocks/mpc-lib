#ifndef __ZKP_ATTACK_HELPERS_H__
#define __ZKP_ATTACK_HELPERS_H__

#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include <cstdint>
#include <cstring>
#include <vector>
#include <openssl/rand.h>

namespace attack_helpers {

// ============================================================================
// Identity / Special Element Helpers
// ============================================================================

// Fill a scalar with all zeros
inline void zero_scalar(elliptic_curve256_scalar_t* s) {
    memset(*s, 0, sizeof(elliptic_curve256_scalar_t));
}

// Fill a scalar with value 1 (big-endian)
inline void one_scalar(elliptic_curve256_scalar_t* s) {
    memset(*s, 0, sizeof(elliptic_curve256_scalar_t));
    (*s)[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 1;
}

// Fill a scalar with the curve order (from algebra context)
inline void order_scalar(const elliptic_curve256_algebra_ctx_t* algebra,
                         elliptic_curve256_scalar_t* s) {
    const uint8_t* order = algebra->order(algebra);
    memcpy(*s, order, sizeof(elliptic_curve256_scalar_t));
}

// Fill a scalar with order - 1
inline void order_minus_one_scalar(const elliptic_curve256_algebra_ctx_t* algebra,
                                   elliptic_curve256_scalar_t* s) {
    order_scalar(algebra, s);
    // Subtract 1 from big-endian number
    for (int i = ELLIPTIC_CURVE_FIELD_SIZE - 1; i >= 0; i--) {
        if ((*s)[i] > 0) {
            (*s)[i]--;
            break;
        }
        (*s)[i] = 0xFF;
    }
}

// Get the infinity point for a curve
inline void infinity_point(const elliptic_curve256_algebra_ctx_t* algebra,
                           elliptic_curve256_point_t* p) {
    const elliptic_curve256_point_t* inf = algebra->infinity_point(algebra);
    memcpy(*p, *inf, sizeof(elliptic_curve256_point_t));
}

// Fill a point with all zeros
inline void zero_point(elliptic_curve256_point_t* p) {
    memset(*p, 0, sizeof(elliptic_curve256_point_t));
}

// Get the generator point G (generator_mul with scalar 1)
inline void generator_point(elliptic_curve256_algebra_ctx_t* algebra,
                            elliptic_curve256_point_t* p) {
    elliptic_curve256_scalar_t one;
    one_scalar(&one);
    algebra->generator_mul(algebra, p, &one);
}

// Negate a compressed point (flip the y-coordinate parity byte)
// For secp256k1/r1: first byte is 0x02 or 0x03, flip to other
inline void negate_point(elliptic_curve256_point_t* p) {
    if ((*p)[0] == 0x02) {
        (*p)[0] = 0x03;
    } else if ((*p)[0] == 0x03) {
        (*p)[0] = 0x02;
    }
    // For ed25519, the sign bit is bit 7 of the last byte
    // This is a simplified negation that may not produce valid ed25519 negation
}

// ============================================================================
// Bit Manipulation Helpers
// ============================================================================

// Flip a single bit at the given byte and bit position
inline void flip_bit(uint8_t* data, size_t byte_pos, uint8_t bit_pos) {
    data[byte_pos] ^= (1 << bit_pos);
}

// Flip a random bit in a buffer
inline void flip_random_bit(uint8_t* data, size_t len) {
    uint32_t byte_pos;
    RAND_bytes((uint8_t*)&byte_pos, sizeof(byte_pos));
    byte_pos %= len;
    uint8_t bit_pos;
    RAND_bytes(&bit_pos, 1);
    bit_pos %= 8;
    flip_bit(data, byte_pos, bit_pos);
}

// Corrupt N random bytes in a buffer
inline void corrupt_random_bytes(uint8_t* data, size_t len, size_t num_bytes) {
    for (size_t i = 0; i < num_bytes; i++) {
        uint32_t pos;
        RAND_bytes((uint8_t*)&pos, sizeof(pos));
        pos %= len;
        uint8_t val;
        RAND_bytes(&val, 1);
        data[pos] = val;
    }
}

// Fill buffer with all 0xFF
inline void fill_ones(uint8_t* data, size_t len) {
    memset(data, 0xFF, len);
}

// Fill buffer with all 0x00
inline void fill_zeros(uint8_t* data, size_t len) {
    memset(data, 0x00, len);
}

// Create a truncated copy (remove last N bytes)
inline std::vector<uint8_t> truncate(const uint8_t* data, size_t len, size_t remove_bytes) {
    if (remove_bytes >= len) return {};
    return std::vector<uint8_t>(data, data + len - remove_bytes);
}

// Create an extended copy (append random bytes)
inline std::vector<uint8_t> extend(const uint8_t* data, size_t len, size_t extra_bytes) {
    std::vector<uint8_t> result(data, data + len);
    result.resize(len + extra_bytes);
    RAND_bytes(result.data() + len, (int)extra_bytes);
    return result;
}

// ============================================================================
// Scalar overflow helpers
// ============================================================================

// Set scalar to order + 1
inline void order_plus_one_scalar(const elliptic_curve256_algebra_ctx_t* algebra,
                                  elliptic_curve256_scalar_t* s) {
    order_scalar(algebra, s);
    // Add 1 to big-endian number
    for (int i = ELLIPTIC_CURVE_FIELD_SIZE - 1; i >= 0; i--) {
        if ((*s)[i] < 0xFF) {
            (*s)[i]++;
            break;
        }
        (*s)[i] = 0x00;
    }
}

// Fill with max value (all 0xFF)
inline void max_scalar(elliptic_curve256_scalar_t* s) {
    memset(*s, 0xFF, sizeof(elliptic_curve256_scalar_t));
}

// ============================================================================
// Proof manipulation helpers
// ============================================================================

// Swap two byte ranges of equal size
inline void swap_fields(uint8_t* field_a, uint8_t* field_b, size_t len) {
    std::vector<uint8_t> tmp(field_a, field_a + len);
    memcpy(field_a, field_b, len);
    memcpy(field_b, tmp.data(), len);
}

// Generate a valid random point on a curve (for cross-curve testing)
inline void random_point(elliptic_curve256_algebra_ctx_t* algebra,
                         elliptic_curve256_point_t* p) {
    elliptic_curve256_scalar_t s;
    algebra->rand(algebra, &s);
    algebra->generator_mul(algebra, p, &s);
}

// ============================================================================
// Alternative infinity encodings
// Used to test that implementations reject non-canonical infinity representations
// ============================================================================

// Type 1: 0x00 prefix with non-zero trailing bytes
inline void alt_infinity_nonzero_trailing(elliptic_curve256_point_t* p) {
    memset(*p, 0, sizeof(elliptic_curve256_point_t));
    (*p)[0] = 0x00;
    (*p)[ELLIPTIC_CURVE_COMPRESSED_POINT_LEN - 1] = 0x01;
}

// Type 2: 0x04 uncompressed format with all zeros
inline void alt_infinity_uncompressed_zeros(elliptic_curve256_point_t* p) {
    memset(*p, 0, sizeof(elliptic_curve256_point_t));
    (*p)[0] = 0x04;
}

// Type 3: Valid-looking prefix (0x02) but zero x-coordinate
inline void alt_infinity_valid_prefix_zero_x(elliptic_curve256_point_t* p) {
    memset(*p, 0, sizeof(elliptic_curve256_point_t));
    (*p)[0] = 0x02;
}

} // namespace attack_helpers

#endif // __ZKP_ATTACK_HELPERS_H__
