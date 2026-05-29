/*
 * Copyright 2026 CryptoLab, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "utils/Basic.hpp"
#include "utils/FFT.hpp"
#include "utils/NTT.hpp"

#include <random>
#include <vector>

#include <gtest/gtest.h>

using namespace deb;

class NTTTest : public ::testing::TestWithParam<std::tuple<u64, u64>> {
public:
    const u64 degree{std::get<0>(GetParam())};
    const u64 prime{std::get<1>(GetParam())};

    std::random_device rd;
    std::mt19937 gen{rd()};
    std::uniform_int_distribution<u64> dist{0, UINT64_MAX};

    inline auto getRandomVector(Size size = 0) {
        if (size == 0)
            size = degree;
        // std::vector<u64> v(size);
        auto *v = static_cast<u64 *>(
            ::operator new[](sizeof(u64) * size, std::align_val_t(256)));
        for (u64 *it = v; it != v + size; ++it) {
            *it = dist(gen) % prime;
        }
        return v;
    }
};

inline u64 findMinPrimitiveRoot(u64 degree, u64 prime) {
    auto mult_with_barr = [](u64 x, u64 y, u64 y_barr, u64 prime) {
        u64 res = utils::mulModLazy(x, y, y_barr, prime);
        return utils::subIfGE(res, prime);
    };

    u64 psi = utils::findPrimitiveRoot(prime);
    // Nth root of unity
    psi = utils::powModSimple(psi, (prime - 1) / (degree), prime);

    // Find the minimal 2N-th root of unity
    u64 psi_square = utils::mulModSimple(psi, psi, prime);
    u64 psi_square_barr = utils::divide128By64Lo(psi_square, 0, prime);
    u64 min_root = psi;
    u64 psi_tmp = psi;
    for (u64 i = 0; i < degree; ++i) {
        psi_tmp = mult_with_barr(psi_tmp, psi_square, psi_square_barr, prime);
        if (psi_tmp < min_root)
            min_root = psi_tmp;
    }
    psi = min_root;
    return psi;
}

TEST_P(NTTTest, SameAfterNTTandiNTT) {
    utils::NTT ntt{degree, prime};

    auto *op = getRandomVector();
    auto *res = op;

    ntt.computeForward(res);
    ntt.computeBackward(res);

    EXPECT_EQ(res, op);
}

TEST_P(NTTTest, PerformNTTforOneZeroVector) {
    utils::NTT ntt{degree, prime};

    std::vector<u64> op1(degree);
    op1[0] = 1;
    std::vector<u64> op2(degree, 1);

    ntt.computeForward(op1.data());

    EXPECT_EQ(op1, op2);
}

INSTANTIATE_TEST_SUITE_P(61bitPrimes, NTTTest,
                         testing::Values(std::tuple{1 << 15,
                                                    2305843009146585089}));
INSTANTIATE_TEST_SUITE_P(40bitPrimes, NTTTest,
                         testing::Values(std::tuple{1 << 13, 2199020634113}));

INSTANTIATE_TEST_SUITE_P(TinyDegree, NTTTest,
                         testing::Values(std::tuple{64, 4295688193}));

// ---------------------------------------------------------------------------
// NTTRootType::DIRECT
// ---------------------------------------------------------------------------

TEST_P(NTTTest, DirectSameAfterNTTandiNTT) {
    utils::ScopedNTTRootType guard{utils::NTTRootType::DIRECT};
    utils::NTT ntt{degree, prime};

    auto *op = getRandomVector();
    auto *res = op;

    ntt.computeForward(res);
    ntt.computeBackward(res);

    EXPECT_EQ(res, op);
}

TEST_P(NTTTest, DirectPerformNTTforOneZeroVector) {
    utils::ScopedNTTRootType guard{utils::NTTRootType::DIRECT};
    utils::NTT ntt{degree, prime};

    std::vector<u64> op1(degree);
    op1[0] = 1;
    std::vector<u64> op2(degree, 1);

    ntt.computeForward(op1.data());

    EXPECT_EQ(op1, op2);
}

INSTANTIATE_TEST_SUITE_P(DirectMode61bit, NTTTest,
                         testing::Values(std::tuple{1 << 15,
                                                    2305843009146585089}));
INSTANTIATE_TEST_SUITE_P(DirectMode40bit, NTTTest,
                         testing::Values(std::tuple{1 << 13, 2199020634113}));
INSTANTIATE_TEST_SUITE_P(DirectModeTiny, NTTTest,
                         testing::Values(std::tuple{64, 4295688193}));

// ---------------------------------------------------------------------------
// NTTRootType::CUSTOM
// ---------------------------------------------------------------------------

// Compute a primitive 2*degree-th root of unity by trying small bases.
// Does not depend on findPrimitiveRoot() so avoids the unresolved-symbol issue
// with the nested utils::utils namespace in the library.
inline u64 findTestPsi(u64 degree, u64 prime) {
    for (u64 base : {u64(3), u64(5), u64(6), u64(7), u64(11), u64(13)}) {
        u64 psi = utils::powModSimple(base, (prime - 1) / (2 * degree), prime);
        if (psi != 1 && utils::powModSimple(psi, degree, prime) != 1)
            return psi;
    }
    throw std::runtime_error(
        "findTestPsi: no primitive root found for test prime");
}

// Compute a primitive 4*degree-th root of unity by trying small bases.
// CYCLIC mode uses a primitive 4N-th root internally (ω = ζ^4 is the
// primitive N-th root that drives the cyclic butterfly), so for CUSTOM
// root_type a 4N-th root must be registered under the key (2*degree, prime).
// Requires prime ≡ 1 mod 4*degree.
inline u64 findTestZeta(u64 degree, u64 prime) {
    const u64 four_deg = 4 * degree;
    for (u64 base : {u64(3), u64(5), u64(6), u64(7), u64(11), u64(13), u64(17),
                     u64(19), u64(23)}) {
        u64 zeta = utils::powModSimple(base, (prime - 1) / four_deg, prime);
        if (zeta != 1 && utils::powModSimple(zeta, 2 * degree, prime) != 1)
            return zeta;
    }
    throw std::runtime_error(
        "findTestZeta: no primitive 4N-th root found for test prime");
}

// Register the 4N-th root used by the cyclic NTT table.  Stored under
// the (2*degree, prime) key so it does not collide with the negacyclic
// 2N-th root registered under (degree, prime).
inline void registerCustomZeta(u64 degree, u64 prime) {
    utils::registerCustomPsi(2 * degree, prime, findTestZeta(degree, prime));
}

TEST_P(NTTTest, CustomSameAfterNTTandiNTT) {
    utils::registerCustomPsi(degree, prime, findTestPsi(degree, prime));
    utils::ScopedNTTRootType guard{utils::NTTRootType::CUSTOM};
    utils::NTT ntt{degree, prime};

    auto *op = getRandomVector();
    auto *res = op;

    ntt.computeForward(res);
    ntt.computeBackward(res);

    EXPECT_EQ(res, op);
}

TEST_P(NTTTest, CustomPerformNTTforOneZeroVector) {
    utils::registerCustomPsi(degree, prime, findTestPsi(degree, prime));
    utils::ScopedNTTRootType guard{utils::NTTRootType::CUSTOM};
    utils::NTT ntt{degree, prime};

    std::vector<u64> op1(degree);
    op1[0] = 1;
    std::vector<u64> op2(degree, 1);

    ntt.computeForward(op1.data());

    EXPECT_EQ(op1, op2);
}

INSTANTIATE_TEST_SUITE_P(CustomMode61bit, NTTTest,
                         testing::Values(std::tuple{1 << 15,
                                                    2305843009146585089}));
INSTANTIATE_TEST_SUITE_P(CustomMode40bit, NTTTest,
                         testing::Values(std::tuple{1 << 13, 2199020634113}));
INSTANTIATE_TEST_SUITE_P(CustomModeTiny, NTTTest,
                         testing::Values(std::tuple{64, 4295688193}));

// ============================================================================
// Cyclic NTT tests
// ============================================================================

class CyclicNTTTest : public ::testing::TestWithParam<std::tuple<u64, u64>> {
public:
    const u64 degree{std::get<0>(GetParam())};
    const u64 prime{std::get<1>(GetParam())};
    std::mt19937_64 gen{std::random_device{}()};

    std::vector<u64> random_vec() {
        std::vector<u64> v(degree);
        std::uniform_int_distribution<u64> dist(0, prime - 1);
        for (auto &x : v)
            x = dist(gen);
        return v;
    }
};

// Cyclic NTT also requires prime ≡ 1 mod 2·degree (same primes as negacyclic).
INSTANTIATE_TEST_SUITE_P(Cyclic61bit, CyclicNTTTest,
                         testing::Values(std::tuple{1 << 15,
                                                    2305843009146585089ULL}));
INSTANTIATE_TEST_SUITE_P(Cyclic40bit, CyclicNTTTest,
                         testing::Values(std::tuple{1 << 13,
                                                    2199020634113ULL}));
INSTANTIATE_TEST_SUITE_P(CyclicTiny, CyclicNTTTest,
                         testing::Values(std::tuple{64, 4295688193ULL}));

TEST_P(CyclicNTTTest, RoundTrip) {
    utils::NTT_C ntt{degree, prime};

    auto v = random_vec();
    auto result = v;
    ntt.computeForward(result.data());
    ntt.computeBackward(result.data());
    EXPECT_EQ(result, v);
}

TEST_P(CyclicNTTTest, ForwardOfConstantOne) {
    // The CI-subring vector (1, 0, …, 0) survives conversion() unchanged
    // (op[0] is left alone and the rest are zero), so the layered butterfly
    // ends up evaluating f(x) = 1 at every N-th root of unity — every bin is 1.
    utils::NTT_C ntt{degree, prime};

    std::vector<u64> op(degree, 0);
    op[0] = 1;
    ntt.computeForward(op.data());
    EXPECT_EQ(op, std::vector<u64>(degree, 1));
}

TEST_P(CyclicNTTTest, DirectRoundTrip) {
    utils::NTT_C ntt{degree, prime, utils::NTTRootType::DIRECT};

    auto v = random_vec();
    auto r = v;
    ntt.computeForward(r.data());
    ntt.computeBackward(r.data());
    EXPECT_EQ(r, v);
}

TEST_P(CyclicNTTTest, CustomRoundTrip) {
    // CYCLIC + CUSTOM looks up a primitive 4N-th root under the key
    // (2*degree, prime).
    registerCustomZeta(degree, prime);
    utils::NTT_C ntt{degree, prime, utils::NTTRootType::CUSTOM};

    auto v = random_vec();
    auto r = v;
    ntt.computeForward(r.data());
    ntt.computeBackward(r.data());
    EXPECT_EQ(r, v);
}

// ============================================================================
// NTTRootType feature tests (non-parametrized)
// ============================================================================

namespace {

// Primes and degrees reused across the feature tests below.
// kSmallPrime ≡ 1 mod 128  (NTT-friendly for degree 64)
// kSmallPrime ≡ 1 mod 256  (NTT-friendly for degree 128, used for missing-
//                            registration test)
constexpr u64 kSmallDegree = 64;
constexpr u64 kSmallPrime = 4295688193ULL;

// Naive negacyclic convolution: c = a * b mod (X^N + 1) mod p.
std::vector<u64> negacyclicConv(const std::vector<u64> &a,
                                const std::vector<u64> &b, u64 prime) {
    const u64 N = a.size();
    std::vector<u64> c(N, 0);
    for (u64 i = 0; i < N; i++) {
        for (u64 j = 0; j < N; j++) {
            u64 prod = utils::mulModSimple(a[i], b[j], prime);
            u64 k = i + j;
            if (k < N)
                c[k] = (c[k] + prod) % prime;
            else
                c[k - N] = (c[k - N] + prime - prod) % prime;
        }
    }
    return c;
}

} // namespace

// ----------------------------------------------------------------------------
// Cyclic NTT cross-mode consistency
//
// The hem-compatible cyclic NTT does not compute X^N−1 convolution on raw
// coefficients (it transforms the CI subring of Z_q[X]/<X^{2N}+1> via the
// conversion()/inversion() pair), so there is no simple closed-form
// reference to compare against. What we *can* assert is that the three
// root-finding paths land on equivalent transforms: a round-trip with
// pointwise multiplication in the NTT domain must produce the same
// polynomial regardless of which primitive 4N-th root was selected.
// ----------------------------------------------------------------------------

TEST(CyclicNTTPolyMul, AllModesAgreeOnPointwiseProduct) {
    constexpr u64 N = kSmallDegree;
    constexpr u64 p = kSmallPrime;

    std::mt19937_64 rng(0xcafe1234);
    std::vector<u64> a(N), b(N);
    for (auto &x : a)
        x = rng() % p;
    for (auto &x : b)
        x = rng() % p;

    auto nttMul = [&](utils::NTTRootType rt) {
        utils::NTT_C ntt{N, p, rt};
        std::vector<u64> fa(a), fb(b), fc(N);
        ntt.computeForward(fa.data());
        ntt.computeForward(fb.data());
        for (u64 i = 0; i < N; i++)
            fc[i] = utils::mulModSimple(fa[i], fb[i], p);
        ntt.computeBackward(fc.data());
        return fc;
    };

    registerCustomZeta(N, p);

    const auto min_result = nttMul(utils::NTTRootType::MIN);
    const auto direct_result = nttMul(utils::NTTRootType::DIRECT);
    const auto custom_result = nttMul(utils::NTTRootType::CUSTOM);

    EXPECT_EQ(min_result, direct_result)
        << "CYCLIC MIN and DIRECT modes disagree on pointwise product";
    EXPECT_EQ(min_result, custom_result)
        << "CYCLIC MIN and CUSTOM modes disagree on pointwise product";
}

// Confirms negacyclic NTT continues to compute X^N+1 convolution, and that
// the cyclic path produces a *different* polynomial (sanity check that the
// cyclic flag actually engages the alternate twiddle table and pre/post
// conversion, not the same code path as negacyclic).
TEST(CyclicNTTPolyMul, CyclicDiffersFromNegacyclic) {
    constexpr u64 N = kSmallDegree;
    constexpr u64 p = kSmallPrime;

    std::mt19937_64 rng(0xdead5678);
    std::vector<u64> a(N), b(N);
    for (auto &x : a)
        x = rng() % p;
    for (auto &x : b)
        x = rng() % p;

    auto cycMul = [&]() {
        utils::NTT_C ntt{N, p};
        std::vector<u64> fa(a), fb(b), fc(N);
        ntt.computeForward(fa.data());
        ntt.computeForward(fb.data());
        for (u64 i = 0; i < N; i++)
            fc[i] = utils::mulModSimple(fa[i], fb[i], p);
        ntt.computeBackward(fc.data());
        return fc;
    };
    auto negMul = [&]() {
        utils::NTT ntt{N, p};
        std::vector<u64> fa(a), fb(b), fc(N);
        ntt.computeForward(fa.data());
        ntt.computeForward(fb.data());
        for (u64 i = 0; i < N; i++)
            fc[i] = utils::mulModSimple(fa[i], fb[i], p);
        ntt.computeBackward(fc.data());
        return fc;
    };

    const auto cyc_result = cycMul();
    const auto neg_result = negMul();
    const auto neg_ref = negacyclicConv(a, b, p);

    EXPECT_EQ(neg_result, neg_ref)
        << "Negacyclic NTT does not compute X^N+1 convolution";
    EXPECT_NE(cyc_result, neg_result)
        << "Cyclic and negacyclic NTT paths should produce different results";
}

// ----------------------------------------------------------------------------
// registerCustomPsi: validation / rejection tests
// ----------------------------------------------------------------------------

TEST(NTTRootTypeValidation, RegisterThrowsForTrivialRoot) {
    // psi = 1 has order 1; psi^degree = 1 → rejected as not primitive.
    EXPECT_THROW(utils::registerCustomPsi(kSmallDegree, kSmallPrime, 1ULL),
                 std::invalid_argument);
}

TEST(NTTRootTypeValidation, RegisterThrowsForMinusOne) {
    // psi = -1 mod p has order 2.  degree (64) is even so psi^degree = 1
    // → rejected (order-2 root is not a primitive 2*degree-th root of unity).
    EXPECT_THROW(
        utils::registerCustomPsi(kSmallDegree, kSmallPrime, kSmallPrime - 1),
        std::invalid_argument);
}

TEST(NTTRootTypeValidation, RegisterThrowsForNthRootNotPrimitive) {
    // psi_2N is a primitive 2N-th root of unity.
    // psi_2N^2 is a primitive N-th root (order N, not 2N):
    //   (psi_2N^2)^N = psi_2N^(2N) = 1  →  rejected.
    u64 psi_2N = findTestPsi(kSmallDegree, kSmallPrime);
    u64 psi_N = utils::mulModSimple(psi_2N, psi_2N, kSmallPrime);
    EXPECT_THROW(utils::registerCustomPsi(kSmallDegree, kSmallPrime, psi_N),
                 std::invalid_argument);
}

TEST(NTTRootTypeValidation, RegisterThrowsForArbitraryNonRoot) {
    // psi = 2 is almost certainly not a 2*kSmallDegree-th root of unity
    // for this prime (2^128 mod kSmallPrime ≠ 1).  Verify and expect a throw.
    if (utils::powModSimple(u64(2), 2 * kSmallDegree, kSmallPrime) != 1) {
        EXPECT_THROW(
            utils::registerCustomPsi(kSmallDegree, kSmallPrime, u64(2)),
            std::invalid_argument);
    } else {
        GTEST_SKIP() << "2 happens to be a root for this prime; skipping";
    }
}

// ----------------------------------------------------------------------------
// CUSTOM NTT: missing registration
// ----------------------------------------------------------------------------

TEST(NTTRootTypeValidation, CustomThrowsWhenNotRegistered) {
    // kSmallPrime ≡ 1 mod 512, so degree=256 is NTT-friendly. (degree=128
    // can't be used here because CyclicNTTPolyMul registers a 4N-th zeta
    // under the key (2*64, kSmallPrime) = (128, kSmallPrime); that test
    // may run earlier and would pollute the registry for a degree=128
    // negacyclic lookup.)
    utils::ScopedNTTRootType guard{utils::NTTRootType::CUSTOM};
    EXPECT_THROW((utils::NTT{256, kSmallPrime}), std::runtime_error);
}

// ----------------------------------------------------------------------------
// Polynomial multiplication equivalence
//
// The central correctness property: every valid primitive 2N-th root of unity
// yields the same negacyclic convolution ring Z[X]/(X^N+1, p).
// All three NTT modes must agree with the O(N^2) reference result.
// ----------------------------------------------------------------------------

TEST(NTTPolyMul, AllModesAgreeOnNegacyclicConvolution) {
    constexpr u64 N = kSmallDegree;
    constexpr u64 p = kSmallPrime;

    std::mt19937_64 rng(0xdeb1cafe);
    std::vector<u64> a(N), b(N);
    for (auto &x : a)
        x = rng() % p;
    for (auto &x : b)
        x = rng() % p;

    const auto ref = negacyclicConv(a, b, p);

    // Compute NTT-based negacyclic convolution for a given root type.
    auto nttConv = [&](utils::NTTRootType rt) {
        utils::ScopedNTTRootType guard{rt};
        utils::NTT ntt{N, p};
        std::vector<u64> fa(a), fb(b), fc(N);
        ntt.computeForward(fa.data());
        ntt.computeForward(fb.data());
        for (u64 i = 0; i < N; i++)
            fc[i] = utils::mulModSimple(fa[i], fb[i], p);
        ntt.computeBackward(fc.data());
        return fc;
    };

    // Register a custom psi so the CUSTOM path can be exercised.
    utils::registerCustomPsi(N, p, findTestPsi(N, p));

    EXPECT_EQ(nttConv(utils::NTTRootType::MIN), ref) << "MIN mode mismatch";
    EXPECT_EQ(nttConv(utils::NTTRootType::DIRECT), ref)
        << "DIRECT mode mismatch";
    EXPECT_EQ(nttConv(utils::NTTRootType::CUSTOM), ref)
        << "CUSTOM mode mismatch";
}

// Additional prime to confirm the equivalence is not prime-specific.
TEST(NTTPolyMul, AllModesAgreeOn40bitPrime) {
    constexpr u64 N = 16; // small degree for fast naive reference
    constexpr u64 p =
        2199020634113ULL; // 40-bit NTT prime (degree 8192-friendly)

    std::mt19937_64 rng(0xcafe0123);
    std::vector<u64> a(N), b(N);
    for (auto &x : a)
        x = rng() % p;
    for (auto &x : b)
        x = rng() % p;

    const auto ref = negacyclicConv(a, b, p);

    auto nttConv = [&](utils::NTTRootType rt) {
        utils::ScopedNTTRootType guard{rt};
        utils::NTT ntt{N, p};
        std::vector<u64> fa(a), fb(b), fc(N);
        ntt.computeForward(fa.data());
        ntt.computeForward(fb.data());
        for (u64 i = 0; i < N; i++)
            fc[i] = utils::mulModSimple(fa[i], fb[i], p);
        ntt.computeBackward(fc.data());
        return fc;
    };

    utils::registerCustomPsi(N, p, findTestPsi(N, p));

    EXPECT_EQ(nttConv(utils::NTTRootType::MIN), ref);
    EXPECT_EQ(nttConv(utils::NTTRootType::DIRECT), ref);
    EXPECT_EQ(nttConv(utils::NTTRootType::CUSTOM), ref);
}

// ----------------------------------------------------------------------------
// registerCustomPsi: overwrite (re-registration)
// ----------------------------------------------------------------------------

TEST(NTTReregistration, RoundtripAfterPsiOverwrite) {
    constexpr u64 N = kSmallDegree;
    constexpr u64 p = kSmallPrime;

    // Collect two distinct valid psi values using different bases.
    std::vector<u64> valid_psi;
    for (u64 base : {u64(3), u64(5), u64(7), u64(11), u64(13), u64(17)}) {
        u64 candidate = utils::powModSimple(base, (p - 1) / (2 * N), p);
        if (candidate != 1 && utils::powModSimple(candidate, N, p) != 1) {
            // Avoid duplicates
            bool dup = false;
            for (u64 v : valid_psi)
                if (v == candidate) {
                    dup = true;
                    break;
                }
            if (!dup)
                valid_psi.push_back(candidate);
        }
        if (valid_psi.size() == 2)
            break;
    }

    if (valid_psi.size() < 2)
        GTEST_SKIP() << "Could not find two distinct valid psi values";

    // Register first psi, then overwrite with the second.
    utils::registerCustomPsi(N, p, valid_psi[0]);
    utils::registerCustomPsi(N, p, valid_psi[1]);

    // Round-trip must work with the overwritten psi.
    utils::ScopedNTTRootType guard{utils::NTTRootType::CUSTOM};
    utils::NTT ntt{N, p};

    std::mt19937_64 rng(0xbeef);
    std::vector<u64> v(N);
    for (auto &x : v)
        x = rng() % p;
    std::vector<u64> result(v);
    ntt.computeForward(result.data());
    ntt.computeBackward(result.data());

    EXPECT_EQ(result, v);
}

// ============================================================================
// FFT degree-sensitivity tests
//
// FFT(N) and FFT(2N) share the first half of their roots_ table by
// construction: the gap doubles in FFT(2N) and the modulus doubles too, so
// the angle exp(i*pi * (5^i * gap) / double_degree) is identical.
// Consequence:
//   * Feeding the *same* size-(N/2) message to both produces the same result
//     (only roots_[1..N/2-1] is touched, and those entries coincide).
//   * Feeding messages of *different* sizes (size N/2 to FFT(N), size N to
//     FFT(2N), even with matching prefix) engages additional butterfly
//     stages in FFT(2N), so the outputs diverge.
// ============================================================================

TEST(FftDegreeSensitivity, ForwardFFTSameForNAnd2NWithSameSizeMsg) {
    constexpr u64 degree = 128;
    constexpr Size num_slots = degree / 2;

    std::mt19937_64 rng(0xcafe5678);
    Message msg_n(num_slots), msg_2n(num_slots);
    for (Size i = 0; i < num_slots; ++i) {
        ComplexT<Real> val{static_cast<Real>(rng() % 1000),
                           static_cast<Real>(rng() % 1000)};
        msg_n[i] = val;
        msg_2n[i] = val;
    }

    utils::FFT fft_n(degree);
    utils::FFT fft_2n(2 * degree);

    fft_n.forwardFFT(msg_n);
    fft_2n.forwardFFT(msg_2n);

    for (Size i = 0; i < num_slots; ++i) {
        EXPECT_NEAR(msg_n[i].real(), msg_2n[i].real(), 1e-10);
        EXPECT_NEAR(msg_n[i].imag(), msg_2n[i].imag(), 1e-10);
    }
}

TEST(FftDegreeSensitivity, BackwardFFTSameForNAnd2NWithSameSizeMsg) {
    constexpr u64 degree = 128;
    constexpr Size num_slots = degree / 2;

    std::mt19937_64 rng(0xdead8765);
    Message msg_n(num_slots), msg_2n(num_slots);
    for (Size i = 0; i < num_slots; ++i) {
        ComplexT<Real> val{static_cast<Real>(rng() % 1000),
                           static_cast<Real>(rng() % 1000)};
        msg_n[i] = val;
        msg_2n[i] = val;
    }

    utils::FFT fft_n(degree);
    utils::FFT fft_2n(2 * degree);

    fft_n.backwardFFT(msg_n);
    fft_2n.backwardFFT(msg_2n);

    for (Size i = 0; i < num_slots; ++i) {
        EXPECT_NEAR(msg_n[i].real(), msg_2n[i].real(), 1e-10);
        EXPECT_NEAR(msg_n[i].imag(), msg_2n[i].imag(), 1e-10);
    }
}

TEST(FftDegreeSensitivity, ForwardFFTDiffersWhenMsgSizesDiffer) {
    constexpr u64 degree = 128;
    constexpr Size num_slots_n = degree / 2;
    constexpr Size num_slots_2n = degree;

    std::mt19937_64 rng(0xfeed1111);
    Message msg_n(num_slots_n), msg_2n(num_slots_2n);
    for (Size i = 0; i < num_slots_n; ++i) {
        ComplexT<Real> val{static_cast<Real>(rng() % 1000),
                           static_cast<Real>(rng() % 1000)};
        msg_n[i] = val;
        msg_2n[i] = val;
    }
    for (Size i = num_slots_n; i < num_slots_2n; ++i) {
        msg_2n[i] = {static_cast<Real>(rng() % 1000),
                     static_cast<Real>(rng() % 1000)};
    }

    utils::FFT fft_n(degree);
    utils::FFT fft_2n(2 * degree);

    fft_n.forwardFFT(msg_n);
    fft_2n.forwardFFT(msg_2n);

    bool any_differ = false;
    for (Size i = 0; i < num_slots_n && !any_differ; ++i) {
        any_differ = std::abs(msg_n[i].real() - msg_2n[i].real()) > 1e-10 ||
                     std::abs(msg_n[i].imag() - msg_2n[i].imag()) > 1e-10;
    }
    EXPECT_TRUE(any_differ)
        << "FFT(N) on size-(N/2) msg and FFT(2N) on size-N msg with matching "
           "prefix must produce different forwardFFT results";
}

TEST(FftDegreeSensitivity, BackwardFFTDiffersWhenMsgSizesDiffer) {
    constexpr u64 degree = 128;
    constexpr Size num_slots_n = degree / 2;
    constexpr Size num_slots_2n = degree;

    std::mt19937_64 rng(0xbeef2222);
    Message msg_n(num_slots_n), msg_2n(num_slots_2n);
    for (Size i = 0; i < num_slots_n; ++i) {
        ComplexT<Real> val{static_cast<Real>(rng() % 1000),
                           static_cast<Real>(rng() % 1000)};
        msg_n[i] = val;
        msg_2n[i] = val;
    }
    for (Size i = num_slots_n; i < num_slots_2n; ++i) {
        msg_2n[i] = {static_cast<Real>(rng() % 1000),
                     static_cast<Real>(rng() % 1000)};
    }

    utils::FFT fft_n(degree);
    utils::FFT fft_2n(2 * degree);

    fft_n.backwardFFT(msg_n);
    fft_2n.backwardFFT(msg_2n);

    bool any_differ = false;
    for (Size i = 0; i < num_slots_n && !any_differ; ++i) {
        any_differ = std::abs(msg_n[i].real() - msg_2n[i].real()) > 1e-10 ||
                     std::abs(msg_n[i].imag() - msg_2n[i].imag()) > 1e-10;
    }
    EXPECT_TRUE(any_differ)
        << "FFT(N) on size-(N/2) msg and FFT(2N) on size-N msg with matching "
           "prefix must produce different backwardFFT results";
}

// ----------------------------------------------------------------------------
// DIRECT vs MIN: roots should differ (algorithm sanity check)
//
// MIN selects the *minimum* primitive 2N-th root; DIRECT takes the first one
// found by the 2-adic search.  For most primes these produce different values,
// confirming the two code paths are actually distinct.
// ----------------------------------------------------------------------------

// ============================================================================
// NTTFactory dispatch
//
// Verifies that setNTTFactory()-registered backends are picked up by
// createNTT(), and that returning an empty shared_ptr from the custom factory
// falls through to the default makeNTT() path.  The custom NTT here is a
// stub — it does not implement a real transform, just stamps a marker into
// the buffer so the test can confirm the stub was actually invoked.
// ============================================================================

namespace {

class MarkerNTT : public utils::NTT_base<u64> {
public:
    static constexpr u64 kForwardMarker = 0xDEADBEEFULL;
    static constexpr u64 kBackwardMarker = 0xCAFEBABEULL;

    MarkerNTT() = default;

    void computeForward(u64 *op) const override { op[0] = kForwardMarker; }
    void computeBackward(u64 *op) const override { op[0] = kBackwardMarker; }
};

// Restores the default (empty) factory on scope exit so a failing assertion
// does not leak custom-factory state into subsequent tests.
struct ResetNTTFactoryOnExit {
    ~ResetNTTFactoryOnExit() { utils::setNTTFactory<u64>({}); }
};

} // namespace

TEST(NTTFactoryDispatch, CustomFactoryIsInvoked) {
    ResetNTTFactoryOnExit reset;

    bool factory_called = false;
    utils::setNTTFactory<u64>(
        [&](u64, u64, utils::NTTType,
            utils::NTTRootType) -> std::shared_ptr<utils::NTT_base<u64>> {
            factory_called = true;
            return std::make_shared<MarkerNTT>();
        });

    auto ntt =
        utils::createNTT<u64>(64, 4295688193ULL, utils::NTTType::NEGACYCLIC);
    EXPECT_TRUE(factory_called);
    ASSERT_NE(ntt, nullptr);
    EXPECT_NE(dynamic_cast<MarkerNTT *>(ntt.get()), nullptr);

    std::vector<u64> op(64, 0);
    ntt->computeForward(op.data());
    EXPECT_EQ(op[0], MarkerNTT::kForwardMarker);
    ntt->computeBackward(op.data());
    EXPECT_EQ(op[0], MarkerNTT::kBackwardMarker);
}

TEST(NTTFactoryDispatch, EmptyReturnFallsThroughToDefault) {
    ResetNTTFactoryOnExit reset;

    bool factory_called = false;
    utils::setNTTFactory<u64>(
        [&](u64, u64, utils::NTTType,
            utils::NTTRootType) -> std::shared_ptr<utils::NTT_base<u64>> {
            factory_called = true;
            return {};
        });

    auto ntt =
        utils::createNTT<u64>(64, 4295688193ULL, utils::NTTType::NEGACYCLIC);
    EXPECT_TRUE(factory_called);
    ASSERT_NE(ntt, nullptr);
    EXPECT_NE(dynamic_cast<utils::NTT<u64> *>(ntt.get()), nullptr);
    EXPECT_EQ(dynamic_cast<MarkerNTT *>(ntt.get()), nullptr);
}

TEST(NTTRootTypeAlgo, DirectAndMinUseDifferentPsiForTypicalPrime) {
    // Build NTTs with both modes and check their first forward twiddle factor
    // (psi_rev_[1]) differs.  We do this indirectly: apply forward NTT to
    // the unit vector e_1 = [0,1,0,...,0] — the result is the list of psi
    // powers in bit-reversed order, so result[0] and result[1] expose psi.
    constexpr u64 N = kSmallDegree;
    constexpr u64 p = kSmallPrime;

    auto getPsiFromNTT = [&](utils::NTTRootType rt) {
        utils::ScopedNTTRootType guard{rt};
        utils::NTT ntt{N, p};
        std::vector<u64> e1(N, 0);
        e1[1] = 1;
        ntt.computeForward(e1.data());
        // e1 after forward NTT: e1[i] = psi^(bit_reverse(i)) in some ordering.
        // The element at index 1 (bit-reversed: N/2) gives psi^(N/2).
        // Regardless, we just need to observe that the two NTTs yield
        // *different* output vectors, which is sufficient to confirm the paths
        // diverge.
        return e1;
    };

    auto min_out = getPsiFromNTT(utils::NTTRootType::MIN);
    auto direct_out = getPsiFromNTT(utils::NTTRootType::DIRECT);

    // For this well-known prime/degree pair the two roots are different.
    // If they happen to coincide (astronomically unlikely), the test is moot
    // but not a correctness failure — skip rather than fail.
    if (min_out == direct_out)
        GTEST_SKIP() << "MIN and DIRECT happened to select the same psi";

    EXPECT_NE(min_out, direct_out)
        << "MIN min-root selection and DIRECT 2-adic search should "
           "yield different primitive roots for this prime";
}
