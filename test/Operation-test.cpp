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
#include "utils/Macro.hpp"

#include <gtest/gtest.h>
#include <random>

using namespace deb;
using namespace deb::utils;

// RNG helpers
static std::mt19937_64 rng{std::random_device{}()};
static u128 randomU128() {
    return (static_cast<u128>(rng()) << 64) | static_cast<u128>(rng());
}
static i128 randomI128() { return static_cast<i128>(randomU128()); }

// ---------------------------------------------
// U128 tests
// ---------------------------------------------
class U128ArithTest : public ::testing::Test {};

// KAT tests
TEST_F(U128ArithTest, KAT_HiLo) {
    constexpr u128 val =
        (static_cast<u128>(UINT64_C(0xDEADBEEFCAFEBABE)) << 64) |
        UINT64_C(0x0102030405060708);
    EXPECT_EQ(u128Hi(val), UINT64_C(0xDEADBEEFCAFEBABE));
    EXPECT_EQ(u128Lo(val), UINT64_C(0x0102030405060708));
}

TEST_F(U128ArithTest, KAT_HiLo_Zero) {
    EXPECT_EQ(u128Hi(static_cast<u128>(0)), UINT64_C(0));
    EXPECT_EQ(u128Lo(static_cast<u128>(0)), UINT64_C(0));
}

TEST_F(U128ArithTest, KAT_Mul64To128_MaxTimesMax) {
    // UINT64_MAX * UINT64_MAX = (2^64-1)^2 = 2^128 - 2*2^64 + 1
    //   hi = UINT64_MAX - 1,  lo = 1
    u128 result = mul64To128(UINT64_MAX, UINT64_MAX);
    EXPECT_EQ(u128Hi(result), UINT64_MAX - 1);
    EXPECT_EQ(u128Lo(result), UINT64_C(1));
}

TEST_F(U128ArithTest, KAT_Mul64To128_PowersOfTwo) {
    // (1 << 63) * 2 = 2^64  =>  hi = 1, lo = 0
    u128 result = mul64To128(UINT64_C(1) << 63, UINT64_C(2));
    EXPECT_EQ(u128Hi(result), UINT64_C(1));
    EXPECT_EQ(u128Lo(result), UINT64_C(0));
}

TEST_F(U128ArithTest, KAT_Mul64To128_ZeroOperand) {
    EXPECT_EQ(mul64To128(UINT64_C(0), UINT64_MAX), static_cast<u128>(0));
    EXPECT_EQ(mul64To128(UINT64_MAX, UINT64_C(0)), static_cast<u128>(0));
}

TEST_F(U128ArithTest, KAT_Mul64To128Hi) {
    EXPECT_EQ(mul64To128Hi(UINT64_MAX, UINT64_MAX), UINT64_MAX - 1);
    // (2^32) * (2^32) = 2^64  =>  hi = 1
    EXPECT_EQ(mul64To128Hi(UINT64_C(1) << 32, UINT64_C(1) << 32), UINT64_C(1));
    EXPECT_EQ(mul64To128Hi(UINT64_C(0), UINT64_MAX), UINT64_C(0));
}

TEST_F(U128ArithTest, KAT_Divide128By64Lo_Simple) {
    // 100 / 10 = 10
    EXPECT_EQ(divide128By64Lo(UINT64_C(0), UINT64_C(100), UINT64_C(10)),
              UINT64_C(10));
    // 2^64 / 2 = 2^63
    EXPECT_EQ(divide128By64Lo(UINT64_C(1), UINT64_C(0), UINT64_C(2)),
              UINT64_C(1) << 63);
}

// Edge-value tests
TEST_F(U128ArithTest, Edge_Zero) {
    constexpr u128 zero = static_cast<u128>(0);
    EXPECT_EQ(u128Hi(zero), UINT64_C(0));
    EXPECT_EQ(u128Lo(zero), UINT64_C(0));
    EXPECT_EQ(mul64To128(UINT64_C(0), UINT64_C(0)), zero);
    EXPECT_EQ(mul64To128Hi(UINT64_C(0), UINT64_C(0)), UINT64_C(0));
}

TEST_F(U128ArithTest, Edge_MaxValue) {
    // ~0 : all 128 bits set — hi = UINT64_MAX, lo = UINT64_MAX
    constexpr u128 u128_max = ~static_cast<u128>(0);
    EXPECT_EQ(u128Hi(u128_max), UINT64_MAX);
    EXPECT_EQ(u128Lo(u128_max), UINT64_MAX);
    // wraps to 0 on +1
    EXPECT_EQ(u128_max + static_cast<u128>(1), static_cast<u128>(0));
    // wraps to u128_max on -1
    EXPECT_EQ(static_cast<u128>(0) - static_cast<u128>(1), u128_max);
}

TEST_F(U128ArithTest, Edge_Boundary64) {
    // 2^64 - 1 : hi = 0, lo = UINT64_MAX
    constexpr u128 just_below = static_cast<u128>(UINT64_MAX);
    EXPECT_EQ(u128Hi(just_below), UINT64_C(0));
    EXPECT_EQ(u128Lo(just_below), UINT64_MAX);
    // 2^64 : hi = 1, lo = 0
    constexpr u128 exactly_2_64 = just_below + static_cast<u128>(1);
    EXPECT_EQ(u128Hi(exactly_2_64), UINT64_C(1));
    EXPECT_EQ(u128Lo(exactly_2_64), UINT64_C(0));
}

TEST_F(U128ArithTest, Edge_Mul64To128_OneTimesOne) {
    u128 result = mul64To128(UINT64_C(1), UINT64_C(1));
    EXPECT_EQ(u128Hi(result), UINT64_C(0));
    EXPECT_EQ(u128Lo(result), UINT64_C(1));
}

TEST_F(U128ArithTest, Edge_Mul64To128_OneTimesMaxHi) {
    // 1 * UINT64_MAX : no carry into hi
    u128 result = mul64To128(UINT64_C(1), UINT64_MAX);
    EXPECT_EQ(u128Hi(result), UINT64_C(0));
    EXPECT_EQ(u128Lo(result), UINT64_MAX);
    EXPECT_EQ(mul64To128Hi(UINT64_C(1), UINT64_MAX), UINT64_C(0));
}

TEST_F(U128ArithTest, Edge_Divide128By64Lo_DivideZero) {
    // 0 / nonzero = 0
    EXPECT_EQ(divide128By64Lo(UINT64_C(0), UINT64_C(0), UINT64_MAX),
              UINT64_C(0));
    EXPECT_EQ(divide128By64Lo(UINT64_C(0), UINT64_C(0), UINT64_C(1)),
              UINT64_C(0));
}

TEST_F(U128ArithTest, Edge_Divide128By64Lo_DivideByOne) {
    // (0 : lo) / 1 = lo
    EXPECT_EQ(divide128By64Lo(UINT64_C(0), UINT64_C(0), UINT64_C(1)),
              UINT64_C(0));
    EXPECT_EQ(divide128By64Lo(UINT64_C(0), UINT64_MAX, UINT64_C(1)),
              UINT64_MAX);
}

// Random tests
TEST_F(U128ArithTest, Random_HiLoReconstruct) {
    for (int i = 0; i < 1000; ++i) {
        u128 val = randomU128();
        u128 reconstructed = (static_cast<u128>(u128Hi(val)) << 64) |
                             static_cast<u128>(u128Lo(val));
        EXPECT_EQ(val, reconstructed);
    }
}

TEST_F(U128ArithTest, Random_Mul64To128_HiMatchesHiFunc) {
    for (int i = 0; i < 1000; ++i) {
        u64 a = rng(), b = rng();
        u128 full = mul64To128(a, b);
        EXPECT_EQ(u128Hi(full), mul64To128Hi(a, b));
    }
}

TEST_F(U128ArithTest, Random_Mul64To128_Commutativity) {
    for (int i = 0; i < 1000; ++i) {
        u64 a = rng(), b = rng();
        EXPECT_EQ(mul64To128(a, b), mul64To128(b, a));
    }
}

TEST_F(U128ArithTest, Random_Divide128By64Lo_InverseOfMul) {
    // Use a 32-bit divisor so that a*b always fits (hi word < b is guaranteed)
    for (int i = 0; i < 1000; ++i) {
        u64 b = (rng() & 0xFFFFFFFF) + 1; // 32-bit non-zero divisor
        u64 a = rng() >> 1;               // 63-bit quotient
        u128 product = static_cast<u128>(a) * b;
        EXPECT_EQ(divide128By64Lo(u128Hi(product), u128Lo(product), b), a);
    }
}

TEST_F(U128ArithTest, Random_Mul64To128_MultiplyByOne) {
    // a * 1 = a  (hi = 0, lo = a)
    for (int i = 0; i < 200; ++i) {
        u64 a = rng();
        u128 result = mul64To128(a, UINT64_C(1));
        EXPECT_EQ(u128Hi(result), UINT64_C(0));
        EXPECT_EQ(u128Lo(result), a);
    }
}

// ---------------------------------------------
// I128 tests
// ---------------------------------------------
class I128ArithTest : public ::testing::Test {};

// KAT tests
TEST_F(I128ArithTest, KAT_SignedOverflowBeyond64Bit) {
    i128 a = static_cast<i128>(INT64_MAX);
    i128 result = a + 1;
    // 2^63 doesn't fit in i64, but is positive in i128
    EXPECT_GT(result, a);
    EXPECT_EQ(result, static_cast<i128>(1) << 63);
}

TEST_F(I128ArithTest, KAT_NegativeMultiplication) {
    // (-1) * INT64_MIN  =>  positive value, beyond i64 range
    i128 neg_one = static_cast<i128>(-1);
    i128 imin = static_cast<i128>(INT64_MIN);
    EXPECT_EQ(neg_one * imin, -imin);
    EXPECT_GT(neg_one * imin, static_cast<i128>(0));
}

TEST_F(I128ArithTest, KAT_LargeNegativeExtension) {
    // One step below INT64_MIN must remain negative and smaller
    i128 a = static_cast<i128>(INT64_MIN) - 1;
    EXPECT_LT(a, static_cast<i128>(INT64_MIN));
}

TEST_F(I128ArithTest, KAT_AddSubInverse) {
    i128 a = static_cast<i128>(INT64_MAX) + 1; // 2^63
    i128 b = static_cast<i128>(INT64_MIN);     // -2^63
    EXPECT_EQ(a + b, static_cast<i128>(0));
}

TEST_F(I128ArithTest, KAT_NegationAndDoubling) {
    i128 val = static_cast<i128>(INT64_C(0x123456789ABCDEF0));
    EXPECT_EQ(val + (-val), static_cast<i128>(0));
    EXPECT_EQ(val * 2, val + val);
}

// Edge-value tests
// I128_MAX = 0x7FFF...FFFF,  I128_MIN = 0x8000...0000
static constexpr i128 I128_MAX = static_cast<i128>(~static_cast<u128>(0) >> 1);
static constexpr i128 I128_MIN = static_cast<i128>(static_cast<u128>(1) << 127);

TEST_F(I128ArithTest, Edge_Zero) {
    constexpr i128 zero = static_cast<i128>(0);
    EXPECT_EQ(zero + zero, zero);
    EXPECT_EQ(zero * I128_MAX, zero);
    EXPECT_EQ(zero * I128_MIN, zero);
    EXPECT_EQ(-zero, zero);
}

TEST_F(I128ArithTest, Edge_One_NegOne) {
    constexpr i128 one = static_cast<i128>(1);
    constexpr i128 neg_one = static_cast<i128>(-1);
    EXPECT_GT(one, static_cast<i128>(0));
    EXPECT_LT(neg_one, static_cast<i128>(0));
    EXPECT_EQ(one + neg_one, static_cast<i128>(0));
    EXPECT_EQ(one * neg_one, neg_one);
    EXPECT_EQ(neg_one * neg_one, one);
}

TEST_F(I128ArithTest, Edge_MaxValue) {
    // I128_MAX is positive and greater than INT64_MAX
    EXPECT_GT(I128_MAX, static_cast<i128>(INT64_MAX));
    EXPECT_EQ(I128_MAX - I128_MAX, static_cast<i128>(0));
    EXPECT_EQ(I128_MAX * static_cast<i128>(1), I128_MAX);
    EXPECT_EQ(I128_MAX * static_cast<i128>(-1), -I128_MAX);
    // One below max is still positive
    EXPECT_GT(I128_MAX - static_cast<i128>(1), static_cast<i128>(0));
}

TEST_F(I128ArithTest, Edge_MinValue) {
    // I128_MIN is negative and less than INT64_MIN
    EXPECT_LT(I128_MIN, static_cast<i128>(INT64_MIN));
    EXPECT_EQ(I128_MIN - I128_MIN, static_cast<i128>(0));
    EXPECT_LT(I128_MIN + static_cast<i128>(1), static_cast<i128>(0));
    EXPECT_EQ(I128_MIN * static_cast<i128>(1), I128_MIN);
}

TEST_F(I128ArithTest, Edge_MaxPlusMinIsNegOne) {
    // I128_MAX + I128_MIN = (2^127 - 1) + (-2^127) = -1
    EXPECT_EQ(I128_MAX + I128_MIN, static_cast<i128>(-1));
}

TEST_F(I128ArithTest, Edge_MaxMinusMinIsAllOnes) {
    // I128_MAX - I128_MIN wraps: (2^127-1) - (-2^127) = 2^128-1 ≡ -1 mod 2^128
    // cast back to i128 → -1 (wraps)
    EXPECT_EQ(I128_MAX - I128_MIN, static_cast<i128>(-1));
}

// Random tests
TEST_F(I128ArithTest, Random_AddSubInverse) {
    for (int i = 0; i < 1000; ++i) {
        i128 a = randomI128(), b = randomI128();
        EXPECT_EQ((a + b) - b, a);
    }
}

TEST_F(I128ArithTest, Random_AddCommutativity) {
    for (int i = 0; i < 1000; ++i) {
        i128 a = randomI128(), b = randomI128();
        EXPECT_EQ(a + b, b + a);
    }
}

TEST_F(I128ArithTest, Random_MulCommutativity) {
    for (int i = 0; i < 1000; ++i) {
        i128 a = randomI128(), b = randomI128();
        EXPECT_EQ(a * b, b * a);
    }
}

TEST_F(I128ArithTest, Random_NegationAddInverse) {
    for (int i = 0; i < 1000; ++i) {
        i128 a = randomI128();
        EXPECT_EQ(a + (-a), static_cast<i128>(0));
    }
}

TEST_F(I128ArithTest, Random_MulByOne) {
    for (int i = 0; i < 200; ++i) {
        i128 a = randomI128();
        EXPECT_EQ(a * static_cast<i128>(1), a);
        EXPECT_EQ(a * static_cast<i128>(-1), -a);
    }
}

// ---------------------------------------------
// Zeroization tests
// ---------------------------------------------
class ZeroizationTest : public ::testing::Test {};

TEST_F(ZeroizationTest, U64Array) {
    constexpr std::size_t N = 16;
    u64 *arr = new u64[N];
    for (Size i = 0; i < N; ++i)
        arr[i] = UINT64_MAX; // all bits set
#if defined(DEB_SECURE_ZERO_LIBSODIUM)
    sodium_memzero(arr, N * sizeof(u64));
    for (Size i = 0; i < N; ++i) {
        EXPECT_EQ(arr[i], static_cast<u64>(0));
        arr[i] = UINT64_MAX;
    }
#elif defined(DEB_SECURE_ZERO_OPENSSL)
    OPENSSL_cleanse(arr, N * sizeof(u64));
    for (Size i = 0; i < N; ++i) {
        EXPECT_EQ(arr[i], static_cast<u64>(0));
        arr[i] = UINT64_MAX;
    }
#elif defined(DEB_SECURE_ZERO_NATIVE)
#if defined(DEB_HAVE_SECURE_ZERO_MEMORY)
    SecureZeroMemory(arr, N * sizeof(u64));
#elif defined(DEB_HAVE_EXPLICIT_BZERO)
    explicit_bzero(arr, N * sizeof(u64));
#elif defined(DEB_HAVE_MEMSET_S)
    memset_s(arr, N * sizeof(u64), 0, N * sizeof(u64));
#else
    // volatile byte loop — best-effort against compiler optimisation
    volatile u64 *p = static_cast<volatile u64 *>(arr);
    for (Size i = 0; i < N; ++i)
        p[i] = 0;
#endif
    for (Size i = 0; i < N; ++i)
        EXPECT_EQ(arr[i], static_cast<u64>(0));
#endif
    delete[] arr;
}

TEST_F(ZeroizationTest, NullptrIsNoOp) {
    EXPECT_NO_FATAL_FAILURE(deb_secure_zero(nullptr, 0));
    EXPECT_NO_FATAL_FAILURE(deb_secure_zero(nullptr, 16));
}

TEST_F(ZeroizationTest, ZeroLengthIsNoOp) {
    u64 val = ~static_cast<u64>(0);
    deb_secure_zero(&val, 0);
    EXPECT_NE(val, static_cast<u64>(0)); // must NOT have been cleared
}

TEST_F(ZeroizationTest, PartialOverwrite) {
    // Zeroing only the first sizeof(u64) bytes should affect exactly those
    // bytes
    u64 val[2] = {UINT64_C(0xAAAAAAAAAAAAAAAA), UINT64_C(0xBBBBBBBBBBBBBBBB)};
    deb_secure_zero(val, sizeof(u64));

    unsigned char raw[sizeof(u64)];
    std::memcpy(raw, val, sizeof(u64));
    bool any_zero = false;
    for (std::size_t i = 0; i < sizeof(u64); ++i)
        any_zero |= (raw[i] == 0);
#if defined(DEB_SECURE_ZERO_LIBSODIUM) || defined(DEB_SECURE_ZERO_OPENSSL) ||  \
    defined(DEB_SECURE_ZERO_NATIVE)
    EXPECT_TRUE(any_zero);
#endif
}
