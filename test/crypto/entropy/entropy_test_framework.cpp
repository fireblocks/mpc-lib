/// @file entropy_test_framework.cpp
/// @brief Implementation of the entropy test suite.
///
/// All statistical tests operate on raw byte buffers. The typical data flow is:
///   1. Caller generates random bytes (via loop_test or manually).
///   2. analyze_bytes() or individual passes_*() functions test the byte stream.
///   3. Results indicate whether the RNG output is statistically consistent
///      with a uniform random source at conservative significance levels.
///
/// The test battery includes: chi-squared (byte distribution), monobit frequency,
/// runs (byte-level), serial correlation (lag-1), mean value, bit bias (per-position),
/// and Monte Carlo Pi estimation. Scalar-specific helpers (uniqueness, range) are
/// also provided for elliptic curve scalar testing.

#include "entropy_test_framework.h"
#include <cstring>
#include <algorithm>
#include <numeric>
#include <cassert>

namespace entropy_tests {

// Regularized upper incomplete gamma function Q(s, x).
//
// Two computation branches:
//   x < s+1: Series expansion for P(s,x), return 1-P.
//     P(s,x) = e^(-x) * x^s / Gamma(s) * sum_{n=0}^{inf} x^n / (s*(s+1)*...*(s+n))
//   x >= s+1: Lentz's continued fraction for Q(s,x) directly.
//     Q(s,x) = e^(-x) * x^s / Gamma(s) * CF(x, s)
//
// Both branches converge within 200 iterations to 1e-12 relative tolerance.
// Uses lgamma() to avoid overflow in Gamma(s) for large s (e.g., s=127.5).
double incomplete_gamma_upper(double s, double x) {
    if (x < 0.0) return 1.0;
    if (x == 0.0) return 1.0;

    // Use regularized gamma function: Q(s,x) = 1 - P(s,x)
    // For P(s,x), use series expansion when x < s+1
    // For Q(s,x), use continued fraction when x >= s+1

    if (x < s + 1.0) {
        // Series expansion for P(s,x), then return 1-P
        double term = 1.0 / s;
        double sum = term;
        for (int n = 1; n < 200; n++) {
            term *= x / (s + n);
            sum += term;
            if (std::abs(term) < 1e-12 * std::abs(sum)) break;
        }
        double log_gamma_s = std::lgamma(s);
        double p = sum * std::exp(-x + s * std::log(x) - log_gamma_s);
        return 1.0 - p;
    } else {
        // Continued fraction for Q(s,x) using Lentz's method
        double f = 1.0;
        double c = 1.0;
        double d = x - s + 1.0;
        if (std::abs(d) < 1e-30) d = 1e-30;
        d = 1.0 / d;
        f = d;

        for (int i = 1; i < 200; i++) {
            double an = -i * (i - s);
            double bn = x - s + 1.0 + 2.0 * i;
            d = bn + an * d;
            if (std::abs(d) < 1e-30) d = 1e-30;
            c = bn + an / c;
            if (std::abs(c) < 1e-30) c = 1e-30;
            d = 1.0 / d;
            double delta = c * d;
            f *= delta;
            if (std::abs(delta - 1.0) < 1e-12) break;
        }
        double log_gamma_s = std::lgamma(s);
        return f * std::exp(-x + s * std::log(x) - log_gamma_s);
    }
}

// Comprehensive randomness analysis: runs all byte-level tests and populates
// every field of EntropyStats. The four tests contributing to passed_all are:
//   1. Chi-squared byte distribution (256-bin, alpha=0.01)
//   2. Serial correlation (lag-1, threshold=0.05)
//   3. Mean value (tolerance=5.0 from 127.5)
//   4. Frequency / monobit (z < 4.0)
// Monte Carlo Pi is computed but does NOT affect passed_all.
EntropyStats analyze_bytes(const uint8_t* data, size_t len) {
    EntropyStats stats{};
    stats.sample_count = len;

    if (len == 0) {
        stats.passed_all = false;
        return stats;
    }

    // Pass 1: Count byte values and accumulate sum for mean
    size_t freq[256] = {};
    double sum = 0.0;
    for (size_t i = 0; i < len; i++) {
        freq[data[i]]++;
        sum += data[i];
    }

    stats.mean = sum / len;

    // Chi-squared statistic: sum((observed - expected)^2 / expected)
    // For 256 bins with uniform distribution, expected count = len / 256.
    // Degrees of freedom = 255. P-value via Q(127.5, chi_sq/2).
    double expected = (double)len / 256.0;
    stats.chi_squared = 0.0;
    for (int i = 0; i < 256; i++) {
        double diff = (double)freq[i] - expected;
        stats.chi_squared += (diff * diff) / expected;
    }
    stats.chi_squared_p_value = incomplete_gamma_upper(127.5, stats.chi_squared / 2.0);

    // Lag-1 serial correlation: r = Cov(x_i, x_{i+1}) / Var(x_i)
    // Numerator: sum of (x_i - mean)(x_{i+1} - mean) for i in [0, len-2]
    // Denominator: sum of (x_i - mean)^2 for all i in [0, len-1]
    if (len > 1) {
        double mean_val = stats.mean;
        double num = 0.0, denom = 0.0;
        for (size_t i = 0; i < len - 1; i++) {
            num += ((double)data[i] - mean_val) * ((double)data[i + 1] - mean_val);
            denom += ((double)data[i] - mean_val) * ((double)data[i] - mean_val);
        }
        denom += ((double)data[len - 1] - mean_val) * ((double)data[len - 1] - mean_val);
        stats.serial_correlation = (denom > 0) ? (num / denom) : 0.0;
    }

    // Monte Carlo Pi: map consecutive byte pairs to (x,y) in [-1,1]x[-1,1]
    // by centering on 127.5 and normalizing. Count fraction inside unit circle,
    // multiply by 4 to estimate Pi. For reference: Pi ≈ 3.14159.
    size_t inside = 0;
    size_t pairs = len / 2;
    for (size_t i = 0; i + 1 < len; i += 2) {
        double x = ((double)data[i] - 127.5) / 127.5;
        double y = ((double)data[i + 1] - 127.5) / 127.5;
        if (x * x + y * y <= 1.0) inside++;
    }
    stats.monte_carlo_pi = (pairs > 0) ? (4.0 * inside / pairs) : 0.0;

    // Overall verdict: all four core tests must pass with standard thresholds
    stats.passed_all = passes_chi_squared(data, len, CHI_SQUARED_ALPHA) &&
                       passes_serial_correlation(data, len, SERIAL_CORRELATION_THRESHOLD) &&
                       passes_mean_test(data, len, MEAN_TOLERANCE) &&
                       passes_frequency_test(data, len);

    return stats;
}

// NIST SP 800-22 monobit frequency test.
//
// Counts total 1-bits using Brian Kernighan's algorithm (byte &= byte - 1
// clears the lowest set bit each iteration). For N total bits, the proportion
// of ones should be ≈ 0.5. The z-score is:
//   z = |proportion - 0.5| / (0.5 / sqrt(N))
// We use a 4-sigma threshold (P ≈ 6.3e-5) which is very conservative —
// NIST uses ~1.96 sigma (alpha=0.05).
bool passes_frequency_test(const uint8_t* data, size_t len) {
    if (len == 0) return false;

    size_t ones = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t byte = data[i];
        while (byte) {
            ones++;
            byte &= byte - 1;
        }
    }

    size_t total_bits = len * 8;
    double proportion = (double)ones / total_bits;

    double expected = 0.5;
    double std_dev = 0.5 / std::sqrt((double)total_bits);
    double z = std::abs(proportion - expected) / std_dev;

    return z < 4.0;
}

// Byte-level runs test.
//
// A "run" is a maximal sequence of identical consecutive bytes. For n IID
// Uniform(0..255) bytes, each adjacent pair has P(different) = 255/256, so:
//   E[runs] = 1 + (n-1) * 255/256
//   Var[runs] = (n-1) * (255/256) * (1/256)
// A z-score > 4.0 indicates non-random clustering or spreading of byte values.
bool passes_runs_test(const uint8_t* data, size_t len) {
    if (len < 2) return false;

    size_t runs = 1;
    for (size_t i = 1; i < len; i++) {
        if (data[i] != data[i - 1]) runs++;
    }

    double p_transition = 255.0 / 256.0;
    double expected_runs = 1.0 + (len - 1.0) * p_transition;
    double variance = (len - 1.0) * p_transition * (1.0 / 256.0);
    double std_dev = std::sqrt(variance);

    if (std_dev == 0) return false;
    double z = std::abs((double)runs - expected_runs) / std_dev;

    return z < 4.0;
}

// Chi-squared goodness-of-fit on 256 byte-value bins.
//
// The chi-squared statistic measures how far the observed byte distribution
// deviates from uniform. For k=256 bins:
//   chi_sq = sum_i((freq_i - expected)^2 / expected),  expected = len / 256
// Degrees of freedom = 255. P-value = Q(127.5, chi_sq/2).
// Reject uniformity (return false) if p-value <= alpha.
// Requires >= 256 bytes so each bin has expected count >= 1.
bool passes_chi_squared(const uint8_t* data, size_t len, double alpha) {
    if (len < 256) return false;

    size_t freq[256] = {};
    for (size_t i = 0; i < len; i++) {
        freq[data[i]]++;
    }

    double expected = (double)len / 256.0;
    double chi_sq = 0.0;
    for (int i = 0; i < 256; i++) {
        double diff = (double)freq[i] - expected;
        chi_sq += (diff * diff) / expected;
    }

    double p_value = incomplete_gamma_upper(127.5, chi_sq / 2.0);

    return p_value > alpha;
}

// Lag-1 serial (auto)correlation test.
//
// Measures linear dependence between consecutive bytes:
//   r = sum((x_i - mean)(x_{i+1} - mean)) / sum((x_i - mean)^2)
// For IID data, r ≈ 0. A nonzero r indicates sequential patterns.
// Note: the denominator includes ALL elements (including the last), making
// it the full variance sum, while the numerator only covers pairs [0, len-2].
bool passes_serial_correlation(const uint8_t* data, size_t len, double threshold) {
    if (len < 2) return false;

    double sum = 0.0;
    for (size_t i = 0; i < len; i++) sum += data[i];
    double mean = sum / len;

    double num = 0.0, denom = 0.0;
    for (size_t i = 0; i < len - 1; i++) {
        num += ((double)data[i] - mean) * ((double)data[i + 1] - mean);
        denom += ((double)data[i] - mean) * ((double)data[i] - mean);
    }
    denom += ((double)data[len - 1] - mean) * ((double)data[len - 1] - mean);

    double corr = (denom > 0) ? (num / denom) : 0.0;
    return std::abs(corr) < threshold;
}

// Mean byte value test.
//
// For Uniform(0..255), E[byte] = 127.5. A skewed mean indicates bias in the
// byte distribution. Default tolerance of 5.0 corresponds to roughly ±3.9%
// of the [0,255] range, which is generous for N >= 10000*32 = 320000 bytes.
bool passes_mean_test(const uint8_t* data, size_t len, double tolerance) {
    if (len == 0) return false;

    double sum = 0.0;
    for (size_t i = 0; i < len; i++) sum += data[i];
    double mean = sum / len;

    return std::abs(mean - 127.5) < tolerance;
}

// Per-bit-position bias test.
//
// Checks each of the 8 bit positions independently. For each bit position b
// (0=LSB, 7=MSB), counts how many of the N bytes have bit b set. For uniform
// bytes, P(bit b set) = 0.5 exactly. If any position has proportion more than
// max_deviation from 0.5, the test fails. This catches biases that might be
// masked in byte-level tests (e.g., a stuck MSB would only shift the mean
// by ~64 but would show a 1.0 deviation in bit position 7).
bool passes_bit_bias_test(const uint8_t* data, size_t len, double max_deviation) {
    if (len == 0) return false;

    size_t bit_counts[8] = {};
    for (size_t i = 0; i < len; i++) {
        for (int bit = 0; bit < 8; bit++) {
            if (data[i] & (1 << bit)) bit_counts[bit]++;
        }
    }

    for (int bit = 0; bit < 8; bit++) {
        double proportion = (double)bit_counts[bit] / len;
        if (std::abs(proportion - 0.5) > max_deviation) return false;
    }

    return true;
}

// Scalar uniqueness test via set insertion.
// For 256-bit scalars, any duplicate in N=10000 samples indicates a catastrophic
// RNG failure (birthday collision probability ≈ N^2 / 2^256 ≈ 10^-69).
size_t count_scalar_duplicates(const std::vector<std::vector<uint8_t>>& scalars) {
    std::set<std::vector<uint8_t>> unique_set(scalars.begin(), scalars.end());
    return scalars.size() - unique_set.size();
}

// Range validation: every scalar must be < curve order (big-endian).
// memcmp returns <0 if scalar < order, 0 if equal, >0 if greater.
// We require strictly less-than (cmp < 0). Also rejects wrong-length scalars.
bool all_scalars_less_than_order(const std::vector<std::vector<uint8_t>>& scalars,
                                  const uint8_t* order, size_t order_len) {
    for (const auto& scalar : scalars) {
        if (scalar.size() != order_len) return false;
        int cmp = memcmp(scalar.data(), order, order_len);
        if (cmp >= 0) return false;
    }
    return true;
}

// Main test driver: calls generator() N times, concatenates all output into
// one contiguous buffer, then runs the full analysis suite via analyze_bytes().
// The generator is called with a pointer into the pre-allocated buffer, so
// there is no extra copying — each call writes directly at its offset.
EntropyStats loop_test(std::function<void(uint8_t*, size_t)> generator,
                       size_t sample_size,
                       size_t iterations) {
    std::vector<uint8_t> combined(sample_size * iterations);

    for (size_t i = 0; i < iterations; i++) {
        generator(combined.data() + i * sample_size, sample_size);
    }

    return analyze_bytes(combined.data(), combined.size());
}

} // namespace entropy_tests
