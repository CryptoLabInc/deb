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

/**
 * @file U32-test.cpp
 * @brief Unit tests for the u32 coefficient word type support.
 *
 * Tests cover:
 *  - UnitTypeTraits<u32> / UnitTypeTraits<u64> type properties
 *  - NTT<u32>: round-trip and convolution identity
 *  - ModArith<1, u32>: Barrett reduction, mul, pow, inverse
 *  - ModArith vector operations: constMult, mulVector
 *  - PolyUnitT<u32>: construction, data access, deep copy
 *  - computeShoup<u32>: Shoup precomputation
 *
 * All 30-bit primes satisfy prime < 2^30 so that butterfly intermediates
 * (up to 4·prime) remain representable in a u32.
 */

#include "CKKSTypes.hpp"
#include "KeyGenerator.hpp"
#include "TestBase.hpp"
#include "utils/Basic.hpp"
#include "utils/ModArith.hpp"
#include "utils/NTT.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <numeric>
#include <random>
#include <vector>

using namespace deb;
using namespace deb::utils;

// -------------------------------------------------------------------------
// Test constants
// -------------------------------------------------------------------------

// 998244353 = 119 * 2^23 + 1  (< 2^30, max NTT degree = 2^22)
static constexpr u64 PRIME_A = 998244353;
// 469762049 = 7   * 2^26 + 1  (< 2^30, max NTT degree = 2^25)
static constexpr u64 PRIME_B = 469762049;
// 786433    = 3   * 2^18 + 1  (< 2^20, max NTT degree = 2^17) — small prime
static constexpr u64 PRIME_C = 786433;

static constexpr Size DEGREE = 2048;

// Reference modular multiply using 128-bit arithmetic (correctness baseline).
static u64 ref_mulmod(u64 a, u64 b, u64 p) {
    return static_cast<u64>((static_cast<u128>(a) * b) % p);
}

// =========================================================================
// UnitTypeTraits
// =========================================================================

class UnitTypeTraitsTest : public ::testing::Test {};

TEST_F(UnitTypeTraitsTest, U32Bits) {
    EXPECT_EQ(UnitTypeTraits<u32>::bits, 32u);
}

TEST_F(UnitTypeTraitsTest, U64Bits) {
    EXPECT_EQ(UnitTypeTraits<u64>::bits, 64u);
}

TEST_F(UnitTypeTraitsTest, U32WideSizeIsU64) {
    // Wide of u32 must be u64 (8 bytes)
    static_assert(sizeof(typename UnitTypeTraits<u32>::Wide) == 8,
                  "Wide of u32 must be u64");
    SUCCEED();
}

TEST_F(UnitTypeTraitsTest, U64WideSizeIsU128) {
    // Wide of u64 must be u128 (16 bytes)
    static_assert(sizeof(typename UnitTypeTraits<u64>::Wide) == 16,
                  "Wide of u64 must be u128");
    SUCCEED();
}

TEST_F(UnitTypeTraitsTest, U32SuperWideSizeIsU128) {
    static_assert(sizeof(typename UnitTypeTraits<u32>::SuperWide) == 16,
                  "SuperWide of u32 must be u128");
    SUCCEED();
}

// =========================================================================
// computeShoup<U>
// =========================================================================

class ComputeShoupTest : public ::testing::TestWithParam<u64> {};

TEST_P(ComputeShoupTest, U64ShoupMatchesManual) {
    const u64 prime = GetParam();
    const u64 val = prime / 3 + 7; // arbitrary value < prime
    u64 shoup = computeShoup<u64>(val, prime);
    // shoup = floor(val * 2^64 / prime)
    u128 expected = (static_cast<u128>(val) << 64) / prime;
    EXPECT_EQ(shoup, static_cast<u64>(expected));
}

TEST_P(ComputeShoupTest, U32ShoupMatchesManual) {
    const u64 prime = GetParam();
    const u32 val32 = static_cast<u32>(prime / 3 + 7);
    u32 shoup = computeShoup<u32>(val32, prime);
    // shoup = floor(val * 2^32 / prime)
    u64 expected = (static_cast<u64>(val32) << 32) / prime;
    EXPECT_EQ(shoup, static_cast<u32>(expected));
}

INSTANTIATE_TEST_SUITE_P(ShoupPrimes, ComputeShoupTest,
                         testing::Values(PRIME_A, PRIME_B, PRIME_C));

// =========================================================================
// NTT<u32>
// =========================================================================

class NTTU32Test : public ::testing::TestWithParam<std::tuple<u64, u64>> {
public:
    u64 degree{std::get<0>(GetParam())};
    u64 prime{std::get<1>(GetParam())};

    std::mt19937 gen{42};

    std::vector<u32> randomVector(Size n = 0) {
        if (n == 0)
            n = static_cast<Size>(degree);
        std::uniform_int_distribution<u32> dist{0, static_cast<u32>(prime) - 1};
        std::vector<u32> v(n);
        for (auto &x : v)
            x = dist(gen);
        return v;
    }
};

TEST_P(NTTU32Test, RoundTrip) {
    utils::NTT<u32> ntt{degree, prime};

    auto orig = randomVector();
    auto v = orig;

    ntt.computeForward(v.data());
    ntt.computeBackward(v.data());

    EXPECT_EQ(v, orig);
}

TEST_P(NTTU32Test, OneZeroVector) {
    // NTT([1, 0, 0, ...]) == [1, 1, 1, ...]
    utils::NTT<u32> ntt{degree, prime};

    std::vector<u32> op(degree, 0);
    op[0] = 1;
    std::vector<u32> expected(degree, 1);

    ntt.computeForward(op.data());
    EXPECT_EQ(op, expected);
}

TEST_P(NTTU32Test, ConvolutionViaPointwiseMul) {
    // For negacyclic NTT: NTT(a) * NTT(b) == NTT(a * b mod (X^N + 1)).
    // Verify that a simple polynomial product through NTT is consistent.
    utils::NTT<u32> ntt{degree, prime};

    const Size N = static_cast<Size>(degree);
    const u32 p = static_cast<u32>(prime);

    std::uniform_int_distribution<u32> dist{0, p - 1};
    std::vector<u32> a = randomVector(), b = randomVector();
    std::vector<u32> na = a, nb = b;

    ntt.computeForward(na.data());
    ntt.computeForward(nb.data());

    // Pointwise multiply in NTT domain
    std::vector<u32> nc(N);
    for (Size i = 0; i < N; ++i) {
        nc[i] = static_cast<u32>((static_cast<u64>(na[i]) * nb[i]) % prime);
    }

    ntt.computeBackward(nc.data());

    // Direct negacyclic convolution in coefficient domain
    std::vector<u32> direct(N, 0);
    for (Size i = 0; i < N; ++i) {
        for (Size j = 0; j < N; ++j) {
            u64 prod = static_cast<u64>(a[i]) * b[j] % prime;
            Size idx = (i + j) % N;
            if (i + j >= N)
                direct[idx] =
                    static_cast<u32>((prime + direct[idx] - prod) % prime);
            else
                direct[idx] = static_cast<u32>((direct[idx] + prod) % prime);
        }
    }
    EXPECT_EQ(nc, direct);
}

#ifdef DEB_U64
TEST_P(NTTU32Test, CompareU64) {
    utils::NTT<u32> ntt32{degree, prime};
    utils::NTT<u64> ntt64{degree, prime};

    auto orig = randomVector();
    auto v = orig;
    std::vector<u64> v64(degree), v32_to_64(degree);
    for (Size i = 0; i < degree; ++i) {
        v64[i] = static_cast<u64>(orig[i]);
    }

    ntt32.computeForward(v.data());
    ntt64.computeForward(v64.data());
    for (Size i = 0; i < degree; ++i) {
        v32_to_64[i] = static_cast<u64>(v[i]);
    }
    EXPECT_EQ(v32_to_64, v64);
    ntt32.computeBackward(v.data());

    EXPECT_EQ(v, orig);
}
#endif

INSTANTIATE_TEST_SUITE_P(
    U32NTTParams, NTTU32Test,
    testing::Values(std::tuple<u64, u64>{DEGREE, PRIME_A},
                    std::tuple<u64, u64>{DEGREE, PRIME_B},
                    std::tuple<u64, u64>{DEGREE, PRIME_C},
                    std::tuple<u64, u64>{2 * DEGREE, PRIME_A},
                    std::tuple<u64, u64>{2 * DEGREE, 1073692673},
                    std::tuple<u64, u64>{2 * DEGREE, 1073668097}));

// =========================================================================
// ModArith<1, u32>
// =========================================================================

class ModArithU32Test : public ::testing::TestWithParam<u64> {
public:
    u64 prime{GetParam()};
    ModArith<1, u32> ma{DEGREE, prime};

    std::mt19937 gen{123};

    u32 rand_val() {
        std::uniform_int_distribution<u32> dist{0, static_cast<u32>(prime) - 1};
        return dist(gen);
    }
};

TEST_P(ModArithU32Test, GetPrime) {
    EXPECT_EQ(static_cast<u64>(ma.getPrime()), prime);
}

TEST_P(ModArithU32Test, BarrettReduceU32_Zero) {
    EXPECT_EQ(ma.reduceBarrett(u32(0)), u32(0));
}

TEST_P(ModArithU32Test, BarrettReduceU32_InRange) {
    // reduceBarrett(U) handles op in [0, 2*prime).
    // Input in [0, prime) should be returned unchanged (quotient = 0).
    std::uniform_int_distribution<u32> d2prime{0,
                                               2 * static_cast<u32>(prime) - 1};
    for (int i = 0; i < 500; ++i) {
        u32 v = d2prime(gen);
        u32 reduced = ma.reduceBarrett(v);
        ASSERT_LT(reduced, static_cast<u32>(prime));
        ASSERT_EQ(reduced, v % static_cast<u32>(prime));
    }
}

TEST_P(ModArithU32Test, MulMatchesReference) {
    for (int i = 0; i < 2000; ++i) {
        u32 a = rand_val();
        u32 b = rand_val();
        u32 got = ma.mul<1>(a, b);
        u32 exp = static_cast<u32>(ref_mulmod(a, b, prime));
        ASSERT_EQ(got, exp) << "a=" << a << " b=" << b << " prime=" << prime;
    }
}

TEST_P(ModArithU32Test, MulOutputModFactor4_InRange) {
    // Default OutputModFactor=4: result < 4 * prime
    for (int i = 0; i < 500; ++i) {
        u32 a = rand_val();
        u32 b = rand_val();
        u32 got = ma.mul(a, b); // default OutputModFactor = 4
        ASSERT_LT(static_cast<u64>(got), 4 * prime);
    }
}

TEST_P(ModArithU32Test, PowFermatLittleTheorem) {
    // base^(prime-1) ≡ 1 (mod prime) for any base != 0
    for (int i = 0; i < 10; ++i) {
        u32 base = rand_val();
        if (base == 0)
            base = 1;
        u32 result = ma.pow(base, static_cast<u32>(prime - 1));
        ASSERT_EQ(result, u32(1))
            << "Fermat failed for base=" << base << " prime=" << prime;
    }
}

TEST_P(ModArithU32Test, InverseCorrectness) {
    for (int i = 0; i < 10; ++i) {
        u32 val = rand_val();
        if (val == 0)
            val = 1;
        u32 inv = ma.inverse(val);
        u32 product = ma.mul<1>(val, inv);
        ASSERT_EQ(product, u32(1))
            << "inverse failed for val=" << val << " prime=" << prime;
    }
}

INSTANTIATE_TEST_SUITE_P(U32ModArithPrimes, ModArithU32Test,
                         testing::Values(PRIME_A, PRIME_B, PRIME_C));

// =========================================================================
// ModArith<1, u32> vector operations
// =========================================================================

class ModArithU32VecTest : public ::testing::Test {
public:
    static constexpr u64 prime = PRIME_A;
    static constexpr Size N = DEGREE;

    ModArith<1, u32> ma{N, prime};
    std::mt19937 gen{7};

    std::vector<u32> randomVec() {
        std::uniform_int_distribution<u32> dist{0, static_cast<u32>(prime) - 1};
        std::vector<u32> v(N);
        for (auto &x : v)
            x = dist(gen);
        return v;
    }
};

TEST_F(ModArithU32VecTest, ConstMultMatchesReference) {
    auto op1 = randomVec();
    u32 scalar = static_cast<u32>(prime / 5 + 3);
    std::vector<u32> res(N);

    ma.constMult(op1.data(), scalar, res.data(), N);

    for (Size i = 0; i < N; ++i) {
        u32 expected = static_cast<u32>(ref_mulmod(op1[i], scalar, prime));
        ASSERT_EQ(res[i], expected) << "index " << i;
    }
}

TEST_F(ModArithU32VecTest, ConstMultInPlaceMatchesReference) {
    auto op1 = randomVec();
    u32 scalar = static_cast<u32>(prime / 7 + 11);
    auto copy = op1;

    ma.constMultInPlace(copy.data(), scalar);

    for (Size i = 0; i < N; ++i) {
        u32 expected = static_cast<u32>(ref_mulmod(op1[i], scalar, prime));
        ASSERT_EQ(copy[i], expected) << "index " << i;
    }
}

TEST_F(ModArithU32VecTest, MulVectorMatchesReference) {
    auto a = randomVec(), b = randomVec();
    std::vector<u32> res(N);

    ma.mulVector(res.data(), a.data(), b.data(), N);

    for (Size i = 0; i < N; ++i) {
        u32 expected = static_cast<u32>(ref_mulmod(a[i], b[i], prime));
        ASSERT_EQ(res[i], expected) << "index " << i;
    }
}

// =========================================================================
// PolyUnitT<u32>
// =========================================================================

class PolyUnitU32Test : public ::testing::Test {
public:
    static constexpr u64 prime = PRIME_A;
    static constexpr Size deg = DEGREE;

    std::mt19937 gen{55};

    std::vector<u32> randomData() {
        std::uniform_int_distribution<u32> dist{0, static_cast<u32>(prime) - 1};
        std::vector<u32> v(deg);
        for (auto &x : v)
            x = dist(gen);
        return v;
    }
};

TEST_F(PolyUnitU32Test, ConstructionMetadata) {
    PolyUnitT<u32> pu(prime, deg);
    EXPECT_EQ(static_cast<u64>(pu.prime()), prime);
    EXPECT_EQ(pu.degree(), deg);
    EXPECT_FALSE(pu.isNTT());
}

TEST_F(PolyUnitU32Test, DataReadWrite) {
    PolyUnitT<u32> pu(prime, deg);
    auto src = randomData();
    std::copy(src.begin(), src.end(), pu.data());
    for (Size i = 0; i < deg; ++i) {
        ASSERT_EQ(pu[i], src[i]);
    }
}

TEST_F(PolyUnitU32Test, DeepCopy) {
    PolyUnitT<u32> pu(prime, deg);
    auto src = randomData();
    std::copy(src.begin(), src.end(), pu.data());

    auto copy = pu.deepCopy();
    EXPECT_EQ(copy.prime(), pu.prime());
    EXPECT_EQ(copy.degree(), pu.degree());
    for (Size i = 0; i < deg; ++i) {
        ASSERT_EQ(copy[i], pu[i]);
    }

    // Mutating the copy must not affect the original
    copy[0] = copy[0] ^ 0xFFFFu;
    EXPECT_NE(copy[0], pu[0]);
}

TEST_F(PolyUnitU32Test, SetPrime) {
    PolyUnitT<u32> pu(prime, deg);
    pu.setPrime(PRIME_B);
    EXPECT_EQ(static_cast<u64>(pu.prime()), PRIME_B);
}

TEST_F(PolyUnitU32Test, SetNTTFlag) {
    PolyUnitT<u32> pu(prime, deg);
    EXPECT_FALSE(pu.isNTT());
    pu.setNTT(utils::NTTType::NEGACYCLIC);
    EXPECT_TRUE(pu.isNTT());
    pu.setNTT(utils::NTTType::NONNTT);
    EXPECT_FALSE(pu.isNTT());
}

// =========================================================================
// NTT<u32> vs NTT<u64> consistency (same prime, same input)
// =========================================================================

#ifdef DEB_U64
class NTTU32vsU64Test : public ::testing::Test {
public:
    static constexpr u64 prime = PRIME_A;
    static constexpr Size degree = DEGREE;

    std::mt19937 gen{99};

    std::vector<u32> randomVecU32() {
        std::uniform_int_distribution<u32> dist{0, static_cast<u32>(prime) - 1};
        std::vector<u32> v(degree);
        for (auto &x : v)
            x = dist(gen);
        return v;
    }
};

TEST_F(NTTU32vsU64Test, ForwardNTTMatchesU64) {
    utils::NTT<u32> ntt32{degree, prime};
    utils::NTT<u64> ntt64{degree, prime};

    auto src32 = randomVecU32();
    std::vector<u64> src64(src32.begin(), src32.end());

    ntt32.computeForward(src32.data());
    ntt64.computeForward(src64.data());

    for (Size i = 0; i < degree; ++i) {
        ASSERT_EQ(static_cast<u64>(src32[i]), src64[i])
            << "Forward NTT mismatch at index " << i;
    }
}

TEST_F(NTTU32vsU64Test, BackwardNTTMatchesU64) {
    utils::NTT<u32> ntt32{degree, prime};
    utils::NTT<u64> ntt64{degree, prime};

    auto orig32 = randomVecU32();
    auto fwd32 = orig32;
    std::vector<u64> fwd64(orig32.begin(), orig32.end());

    ntt32.computeForward(fwd32.data());
    ntt64.computeForward(fwd64.data());

    ntt32.computeBackward(fwd32.data());
    ntt64.computeBackward(fwd64.data());

    for (Size i = 0; i < degree; ++i) {
        ASSERT_EQ(static_cast<u64>(fwd32[i]), fwd64[i])
            << "Backward NTT mismatch at index " << i;
    }
}

#endif // DEB_U64

// =========================================================================
// ModArith<1, u32> vs ModArith<1, u64> — same prime, same inputs
// =========================================================================

#ifdef DEB_U64
class ModArithU32vsU64Test : public ::testing::TestWithParam<u64> {
public:
    u64 prime{GetParam()};
    ModArith<1, u32> ma32{DEGREE, prime};
    ModArith<1, u64> ma64{DEGREE, prime};

    std::mt19937 gen{321};
    u32 rand_val32() {
        std::uniform_int_distribution<u32> d{0, static_cast<u32>(prime) - 1};
        return d(gen);
    }
};

TEST_P(ModArithU32vsU64Test, MulConsistency) {
    for (int i = 0; i < 2000; ++i) {
        u32 a = rand_val32(), b = rand_val32();
        u32 r32 = ma32.mul<1>(a, b);
        u64 r64 = ma64.mul<1>(static_cast<u64>(a), static_cast<u64>(b));
        ASSERT_EQ(static_cast<u64>(r32), r64)
            << "a=" << a << " b=" << b << " prime=" << prime;
    }
}

TEST_P(ModArithU32vsU64Test, PowConsistency) {
    for (int i = 0; i < 20; ++i) {
        u32 base = rand_val32();
        if (base == 0)
            base = 1;
        u32 exp32 = static_cast<u32>(prime) - 1;

        u32 r32 = ma32.pow(base, exp32);
        u64 r64 = ma64.pow(static_cast<u64>(base), static_cast<u64>(exp32));
        ASSERT_EQ(static_cast<u64>(r32), r64)
            << "base=" << base << " prime=" << prime;
    }
}

INSTANTIATE_TEST_SUITE_P(CrossCheckPrimes, ModArithU32vsU64Test,
                         testing::Values(PRIME_A, PRIME_B, PRIME_C));
#endif // DEB_U64

// =========================================================================
// Encrypt / Decrypt with PRESET_IP2 (32-bit dedicated preset)
// =========================================================================

class Endecrypt32Test : public ::testing::TestWithParam<Preset> {
public:
    const Preset preset{GetParam()};
    const Size num_slots{get_num_slots(preset)};
    const Size num_secret{get_num_secret(preset)};

    Encryptor32 encryptor{preset};
    Decryptor32 decryptor{preset};

    std::mt19937 gen{std::random_device{}()};
    std::uniform_real_distribution<double> dist{-1.0, 1.0};

    const double log_error =
        static_cast<double>(utils::bitWidth(get_primes(preset)[0])) / 6.0;
    const double sk_err = std::pow(2.0, -10 - log_error);
    const double enc_err = std::pow(2.0, -5 - log_error);

    MSGS gen_random_msg() {
        MSGS msg;
        for (Size i = 0; i < num_secret; ++i) {
            Message m(num_slots);
            for (Size j = 0; j < num_slots; ++j) {
                m[j].real(dist(gen));
                m[j].imag(dist(gen));
            }
            msg.emplace_back(std::move(m));
        }
        return msg;
    }

    MSGS gen_empty_msg() {
        MSGS msg;
        for (Size i = 0; i < num_secret; ++i)
            msg.emplace_back(num_slots);
        return msg;
    }

    MSGS scale_msg(MSGS &msg, Size level) {
        const double scale = get_scale_factors(preset)[level];
        if (scale == 0.0) {
            const double s =
                std::pow(2.0, utils::bitWidth(get_primes(preset)[0]) - 4);
            MSGS scaled = gen_empty_msg();
            for (Size i = 0; i < num_secret; ++i)
                for (Size j = 0; j < num_slots; ++j) {
                    scaled[i][j].real(msg[i][j].real() * s);
                    scaled[i][j].imag(msg[i][j].imag() * s);
                }
            return scaled;
        }
        return msg;
    }

    double scale_err(double err, Size level) {
        const double scale = get_scale_factors(preset)[level];
        if (scale == 0.0) {
            const double s =
                std::pow(2.0, utils::bitWidth(get_primes(preset)[0]) - 4);
            return err * s;
        }
        return err;
    }

    void compare_msg(MSGS &msg1, MSGS &msg2, double tol) {
        for (Size i = 0; i < num_secret; ++i)
            for (Size j = 0; j < num_slots; ++j) {
                ASSERT_NEAR(msg1[i][j].real(), msg2[i][j].real(), tol);
                ASSERT_NEAR(msg1[i][j].imag(), msg2[i][j].imag(), tol);
            }
    }
};

TEST_P(Endecrypt32Test, EncryptAndDecryptWithSecretKey) {
    MSGS msg = gen_random_msg();

    SecretKeyT<u32> sk = SecretKeyGenerator32::GenSecretKey(preset);
    MSGS decrypted_msg = gen_empty_msg();

    for (Size l = 0; l < std::min(2U, get_encryption_level(preset)); ++l) {
        CiphertextT<u32> ctxt(preset, l);
        MSGS scaled_msg = scale_msg(msg, l);
        encryptor.encrypt(scaled_msg, sk, ctxt, EncryptOptions().Level(l));
        decryptor.decrypt(ctxt, sk, decrypted_msg);

        compare_msg(scaled_msg, decrypted_msg, scale_err(sk_err, l));
    }
}

TEST_P(Endecrypt32Test, EncryptAndDecryptWithEncKey) {
    MSGS msg = gen_random_msg();

    SecretKey32 sk = SecretKeyGenerator32::GenSecretKey(preset);
    KeyGenerator32 keygen(preset);
    SwitchKey32 enckey = keygen.genEncKey(sk);
    MSGS decrypted_msg = gen_empty_msg();

    for (Size l = 0; l < std::min(2U, get_encryption_level(preset)); ++l) {
        Ciphertext32 ctxt(preset, l);
        MSGS scaled_msg = scale_msg(msg, l);
        encryptor.encrypt(scaled_msg, enckey, ctxt, EncryptOptions().Level(l));
        decryptor.decrypt(ctxt, sk, decrypted_msg);

        compare_msg(scaled_msg, decrypted_msg, scale_err(enc_err, l));
    }
}

#define X32(PRESET) Preset::PRESET_##PRESET,
const std::vector<Preset> all_presets32 = {PRESET_LIST_U32
#undef X32
};
INSTANTIATE_TEST_SUITE_P(Presets, Endecrypt32Test,
                         testing::ValuesIn(all_presets32));

// =========================================================================
// KeyGenerator32: switching-key generation for u32 presets.
//
// Mirrors KeyGen-test.cpp (u64) but exercises KeyGeneratorT<PRESET_EMPTY, u32>
// against the u32-dedicated preset(s). Verifies that each genXxxKey API:
//  - runs without exceptions (functional + Inplace forms),
//  - produces switching keys of the expected ax/bx dimensions for the preset.
// =========================================================================

class KeyGen32Test : public ::testing::TestWithParam<Preset> {
public:
    const Preset preset{GetParam()};
    const Size num_slots{get_num_slots(preset)};
    const Size num_secret{get_num_secret(preset)};
    const Size degree{get_degree(preset)};
    const Size gadget_rank{get_gadget_rank(preset)};
    const Size num_p{get_num_p(preset)};

    KeyGenerator32 keygen{preset};
    SecretKey32 sk{SecretKeyGenerator32::GenSecretKey(preset)};

    std::mt19937 gen{std::random_device{}()};
    std::uniform_int_distribution<u64> dist_u64{0, UINT64_MAX};
};

TEST_P(KeyGen32Test, GenEncryptionKey) {
    SwitchKey32 enckey(preset, SwitchKeyKind::SWK_ENC);
    ASSERT_NO_THROW(enckey = keygen.genEncKey(sk));
    ASSERT_NO_THROW(keygen.genEncKeyInplace(enckey, sk));

    ASSERT_EQ(enckey.axSize(), 1);
    ASSERT_EQ(enckey.bxSize(), num_secret);
    ASSERT_EQ(enckey.ax().size(), num_p);
    ASSERT_EQ(enckey.bx().size(), num_p);
}

TEST_P(KeyGen32Test, GenMultiplicationKey) {
    SwitchKey32 mulkey(preset, SwitchKeyKind::SWK_MULT);
    ASSERT_NO_THROW(mulkey = keygen.genMultKey(sk));
    ASSERT_NO_THROW(keygen.genMultKeyInplace(mulkey, sk));

    ASSERT_EQ(mulkey.axSize(), gadget_rank);
    ASSERT_EQ(mulkey.bxSize(), gadget_rank * num_secret);
    ASSERT_EQ(mulkey.ax().size(), num_p);
    ASSERT_EQ(mulkey.bx().size(), num_p);
}

TEST_P(KeyGen32Test, GenConjugationKey) {
    SwitchKey32 conjkey(preset, SwitchKeyKind::SWK_CONJ);
    ASSERT_NO_THROW(conjkey = keygen.genConjKey(sk));
    ASSERT_NO_THROW(keygen.genConjKeyInplace(conjkey, sk));

    ASSERT_EQ(conjkey.axSize(), gadget_rank);
    ASSERT_EQ(conjkey.bxSize(), gadget_rank * num_secret);
    ASSERT_EQ(conjkey.ax().size(), num_p);
    ASSERT_EQ(conjkey.bx().size(), num_p);
}

TEST_P(KeyGen32Test, GenRotationKeys) {
    const Size rot = dist_u64(gen) % (num_slots - 1) + 1;

    SwitchKey32 left_rotkey(preset, SwitchKeyKind::SWK_ROT, rot);
    ASSERT_NO_THROW(left_rotkey = keygen.genLeftRotKey(rot, sk));
    ASSERT_NO_THROW(keygen.genLeftRotKeyInplace(rot, left_rotkey, sk));

    SwitchKey32 right_rotkey(preset, SwitchKeyKind::SWK_ROT, num_slots - rot);
    ASSERT_NO_THROW(right_rotkey = keygen.genRightRotKey(num_slots - rot, sk));
    ASSERT_NO_THROW(
        keygen.genRightRotKeyInplace(num_slots - rot, right_rotkey, sk));

    ASSERT_EQ(left_rotkey.axSize(), gadget_rank);
    ASSERT_EQ(left_rotkey.bxSize(), gadget_rank * num_secret);
    ASSERT_EQ(left_rotkey.ax().size(), num_p);
    ASSERT_EQ(left_rotkey.bx().size(), num_p);

    ASSERT_EQ(right_rotkey.axSize(), gadget_rank);
    ASSERT_EQ(right_rotkey.bxSize(), gadget_rank * num_secret);
    ASSERT_EQ(right_rotkey.ax().size(), num_p);
    ASSERT_EQ(right_rotkey.bx().size(), num_p);
}

TEST_P(KeyGen32Test, GenAutomorphismKey) {
    const Size sig = dist_u64(gen) % (degree - 1) + 1;
    SwitchKey32 autokey(preset, SwitchKeyKind::SWK_AUTO);
    ASSERT_NO_THROW(autokey = keygen.genAutoKey(sig, sk));
    ASSERT_NO_THROW(keygen.genAutoKeyInplace(sig, autokey, sk));

    ASSERT_EQ(autokey.axSize(), gadget_rank);
    ASSERT_EQ(autokey.bxSize(), gadget_rank * num_secret);
    ASSERT_EQ(autokey.ax().size(), num_p);
    ASSERT_EQ(autokey.bx().size(), num_p);
}

TEST_P(KeyGen32Test, GenModPackKey) {
    if (num_secret != 1) {
        GTEST_SKIP() << "MODPACK key generation is only for single secret.";
    }
    std::vector<SwitchKey32> modkey;
    ASSERT_NO_THROW(modkey = keygen.genModPackKeyBundle(sk, sk));
    ASSERT_NO_THROW(keygen.genModPackKeyBundleInplace(sk, sk, modkey));
}

TEST_P(KeyGen32Test, GenModPackKeySelf) {
    if (num_secret != 1) {
        GTEST_SKIP()
            << "MODPACK_SELF key generation is only for single secret.";
    }
    const Size pad_rank = 1U << (dist_u64(gen) % (get_log_degree(preset) / 2));
    SwitchKey32 modkey(preset, SwitchKeyKind::SWK_MODPACK_SELF);
    ASSERT_NO_THROW(modkey = keygen.genModPackKeyBundle(pad_rank, sk));
    ASSERT_NO_THROW(keygen.genModPackKeyBundleInplace(pad_rank, modkey, sk));

    ASSERT_EQ(modkey.axSize(), pad_rank);
    ASSERT_EQ(modkey.bxSize(), pad_rank * num_secret);
    ASSERT_EQ(modkey.ax().size(), num_p);
    ASSERT_EQ(modkey.bx().size(), num_p);
}

INSTANTIATE_TEST_SUITE_P(Presets, KeyGen32Test,
                         testing::ValuesIn(all_presets32));
