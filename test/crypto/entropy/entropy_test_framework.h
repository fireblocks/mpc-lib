#ifndef __ENTROPY_TEST_FRAMEWORK_H__
#define __ENTROPY_TEST_FRAMEWORK_H__

/// @file entropy_test_framework.h
/// @brief Statistical test suite for validating randomness quality of cryptographic RNGs.
///
/// This framework provides a battery of statistical tests based on NIST SP 800-22
/// recommendations and classical randomness metrics. It is designed to validate that
/// the RNG implementations used in BAM (secp256k1, secp256r1, ed25519, STARK curve
/// algebra->rand(), OpenSSL BN_rand, BN_rand_range) produce output with adequate
/// entropy for cryptographic operations.
///
/// ## Typical usage (see tests.cpp):
///
///   1. **Baseline validation** — Run loop_test() with OpenSSL RAND_bytes to confirm
///      the test framework itself works with a known-good source.
///
///   2. **Per-curve scalar tests** — For each elliptic curve algebra:
///      - `loop_test()` with a lambda that calls algebra->rand() and extracts the
///        lower bytes (skipping SCALAR_STAT_OFFSET top bytes to avoid order-bias).
///      - `count_scalar_duplicates()` to verify uniqueness over N iterations.
///      - `all_scalars_less_than_order()` to verify range correctness.
///      - Individual passes_*() tests on the collected byte stream.
///
///   3. **DRNG sanity** — Verify that the deterministic RNG (drng) is NOT random:
///      same seed → same output, different seed → different output.
///
///   4. **Cross-curve independence** — Interleave scalar generation from two curves
///      and verify each stream maintains statistical quality independently.
///
/// ## Important notes on scalar testing:
///
/// Elliptic curve scalars are sampled uniformly from [0, order). Since order < 2^256
/// for all supported curves, the most-significant bytes of a 32-byte scalar are NOT
/// uniformly distributed over [0, 255]. For example, ed25519 order ≈ 2^252 means
/// byte 0 is always in [0x00, 0x10]. Byte-level tests (chi-squared, mean, runs)
/// would fail on these top bytes even with a perfect RNG. Therefore, per-scalar
/// byte-level tests should skip the top SCALAR_STAT_OFFSET bytes (typically 8) and
/// only analyze bytes [offset, 32). The uniqueness and range tests use the full
/// 32-byte scalar.

#include <cstdint>
#include <cstddef>
#include <vector>
#include <functional>
#include <cmath>
#include <set>
#include <string>

namespace entropy_tests {

// Standard threshold constants for statistical tests.
// Use these when calling the individual passes_*() functions.
static constexpr double CHI_SQUARED_ALPHA = 0.01;        // 99% confidence
static constexpr double SERIAL_CORRELATION_THRESHOLD = 0.05;
static constexpr double MEAN_TOLERANCE = 5.0;            // |mean - 127.5| < 5.0
static constexpr double BIT_BIAS_MAX_DEVIATION = 0.05;   // |proportion - 0.5| < 0.05

/// Aggregated randomness statistics for a byte stream.
///
/// Populated by analyze_bytes(). The passed_all field is true only if ALL of
/// chi-squared, serial correlation, mean, and frequency tests pass simultaneously.
/// Monte Carlo Pi is computed for informational purposes but does not affect passed_all.
struct EntropyStats {
    double chi_squared;          // Chi-squared statistic over 256 byte bins
    double chi_squared_p_value;  // P-value from incomplete upper gamma; >0.01 = pass
    double serial_correlation;   // Lag-1 autocorrelation; |r| < 0.05 = pass
    double monte_carlo_pi;       // Pi estimate from byte-pair circle test (informational)
    double mean;                 // Mean byte value; expect ~127.5 for uniform bytes
    size_t sample_count;         // Total bytes analyzed
    bool passed_all;             // True iff chi_squared, serial_corr, mean, freq all pass
};

/// Run all statistical tests on a raw byte stream and return aggregated results.
///
/// Computes: byte-frequency chi-squared + p-value, lag-1 serial correlation,
/// Monte Carlo Pi estimate, mean byte value, and an overall pass/fail verdict.
/// The verdict (passed_all) requires passing chi-squared, serial correlation,
/// mean, AND frequency tests simultaneously.
///
/// @param data  Pointer to the byte buffer to analyze.
/// @param len   Number of bytes. Must be >= 256 for chi-squared to be meaningful.
/// @return      EntropyStats with all fields populated.
EntropyStats analyze_bytes(const uint8_t* data, size_t len);

/// NIST SP 800-22 monobit frequency test.
///
/// Counts total 1-bits across all bytes (Brian Kernighan's algorithm). Computes
/// a z-score against expected proportion 0.5. Fails if z > 4.0 standard deviations
/// (very conservative — NIST recommends ~1.96 for alpha=0.05).
///
/// @param data  Byte buffer.
/// @param len   Buffer length. Returns false if 0.
/// @return      True if bit proportion is within 4 sigma of 0.5.
bool passes_frequency_test(const uint8_t* data, size_t len);

/// NIST SP 800-22 runs test (byte-level variant).
///
/// Counts runs of consecutive identical bytes. For n IID Uniform(0..255) bytes,
/// P(transition) = 255/256, so E[runs] = 1 + (n-1)*255/256 and
/// Var[runs] = (n-1)*(255/256)*(1/256). Fails if z-score > 4.0.
///
/// @param data  Byte buffer.
/// @param len   Buffer length. Must be >= 2.
/// @return      True if run count is within 4 sigma of expected.
bool passes_runs_test(const uint8_t* data, size_t len);

/// Chi-squared goodness-of-fit test on byte distribution (256 bins).
///
/// Computes sum_i((observed_i - expected)^2 / expected) with expected = len/256.
/// Converts to p-value via regularized upper incomplete gamma Q(127.5, chi_sq/2)
/// where 127.5 = (256-1)/2 degrees of freedom. Rejects if p-value <= alpha.
///
/// @param data   Byte buffer.
/// @param len    Buffer length. Must be >= 256 (returns false otherwise).
/// @param alpha  Significance level (e.g., CHI_SQUARED_ALPHA = 0.01 for 99% confidence).
bool passes_chi_squared(const uint8_t* data, size_t len, double alpha);

/// Lag-1 serial correlation coefficient test.
///
/// Computes r = sum((x_i - mean)(x_{i+1} - mean)) / sum((x_i - mean)^2).
/// For truly random data, r ≈ 0. Fails if |r| >= threshold.
///
/// @param data       Byte buffer.
/// @param len        Buffer length. Must be >= 2.
/// @param threshold  Maximum acceptable |correlation| (e.g., SERIAL_CORRELATION_THRESHOLD = 0.05).
bool passes_serial_correlation(const uint8_t* data, size_t len, double threshold);

/// Mean byte value test.
///
/// For uniformly distributed bytes in [0, 255], expected mean = 127.5.
/// Fails if observed mean deviates by more than tolerance.
///
/// @param data       Byte buffer.
/// @param len        Buffer length. Returns false if 0.
/// @param tolerance  Maximum acceptable |mean - 127.5| (e.g., MEAN_TOLERANCE = 5.0).
bool passes_mean_test(const uint8_t* data, size_t len, double tolerance);

/// Per-bit-position bias test.
///
/// For each of 8 bit positions, counts how many bytes have that bit set.
/// For uniform random bytes, each bit has P(set) = 0.5. Fails if any bit
/// position's proportion deviates from 0.5 by more than max_deviation.
///
/// @param data           Byte buffer.
/// @param len            Buffer length. Returns false if 0.
/// @param max_deviation  Maximum acceptable |proportion - 0.5| per bit
///                       (e.g., BIT_BIAS_MAX_DEVIATION = 0.05).
bool passes_bit_bias_test(const uint8_t* data, size_t len, double max_deviation);

/// Count duplicate scalars in a collection.
///
/// Inserts all scalars into a std::set to find unique entries. Returns
/// (total - unique). For a proper 256-bit RNG with N=10000, duplicates
/// should be 0 (collision probability ≈ N^2 / 2^256 ≈ 0).
///
/// @param scalars  Vector of byte vectors, each representing one scalar.
/// @return         Number of duplicates (0 = all unique).
size_t count_scalar_duplicates(const std::vector<std::vector<uint8_t>>& scalars);

/// Verify all scalars are strictly less than a curve order (big-endian comparison).
///
/// Uses memcmp for big-endian byte-by-byte comparison. Also checks that each
/// scalar has exactly order_len bytes. Validates that algebra->rand() correctly
/// reduces output modulo the curve order — a scalar >= order would break ECDSA.
///
/// @param scalars    Vector of byte vectors to check.
/// @param order      Curve order in big-endian format.
/// @param order_len  Length of order in bytes (typically 32).
/// @return           True if ALL scalars have correct length and are < order.
bool all_scalars_less_than_order(const std::vector<std::vector<uint8_t>>& scalars,
                                  const uint8_t* order, size_t order_len);

/// Generate N random samples, concatenate, and run analyze_bytes().
///
/// Primary entry point for testing an RNG. The caller provides a generator
/// function that fills a buffer of sample_size bytes. loop_test() calls it
/// `iterations` times into a single (sample_size * iterations)-byte buffer,
/// then passes it to analyze_bytes().
///
/// Example:
///   auto stats = loop_test(
///       [](uint8_t* buf, size_t len) { RAND_bytes(buf, len); },
///       32, 10000);
///   REQUIRE(stats.passed_all);
///
/// @param generator    Callable: fills buf[0..len) with random bytes.
/// @param sample_size  Bytes per generator invocation.
/// @param iterations   Number of times to call generator.
/// @return             EntropyStats for the combined byte stream.
EntropyStats loop_test(std::function<void(uint8_t*, size_t)> generator,
                       size_t sample_size,
                       size_t iterations);

/// Regularized upper incomplete gamma function Q(s, x) = 1 - P(s, x).
///
/// Used internally by passes_chi_squared() and analyze_bytes() to convert
/// chi-squared statistics to p-values. For k=255 degrees of freedom:
///   p-value = Q(127.5, chi_sq / 2)
///
/// Algorithm: series expansion for P(s,x) when x < s+1 (returns 1-P),
/// Lentz's continued fraction for Q(s,x) when x >= s+1. Both converge
/// to 1e-12 relative tolerance within 200 iterations.
///
/// @param s  Shape parameter (= degrees_of_freedom / 2).
/// @param x  Integration bound (= chi_squared / 2).
/// @return   Q(s, x) in [0, 1]. Returns 1.0 for x <= 0.
double incomplete_gamma_upper(double s, double x);

} // namespace entropy_tests

#endif // __ENTROPY_TEST_FRAMEWORK_H__
