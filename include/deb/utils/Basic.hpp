/*
 * Copyright 2025 CryptoLab, Inc.
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

#pragma once

#include "CKKSTypes.hpp"

#include <algorithm>

namespace deb::utils {

using u128 = unsigned __int128;
using i128 = __int128;

/**
 * @brief Returns the upper 64 bits of a 128-bit integer.
 * @param value 128-bit value.
 */
inline u64 u128Hi(const u128 value) { return static_cast<u64>(value >> 64); }
/**
 * @brief Returns the lower 64 bits of a 128-bit integer.
 * @param value 128-bit value.
 */
inline u64 u128Lo(const u128 value) { return static_cast<u64>(value); }

/**
 * @brief Multiplies two 64-bit integers yielding a 128-bit product.
 * @param op1 Multiplicand.
 * @param op2 Multiplier.
 * @return 128-bit product.
 */
inline u128 mul64To128(const u64 op1, const u64 op2) {
    return static_cast<u128>(op1) * op2;
}

/**
 * @brief Returns the upper 64 bits of the 128-bit product of two 64-bit
 * operands.
 */
inline u64 mul64To128Hi(const u64 op1, const u64 op2) {
    u128 mul = mul64To128(op1, op2);
    return u128Hi(mul);
}

/**
 * @brief Divides a 128-bit value specified by hi/lo words by a 64-bit divisor
 * and returns the truncated quotient.
 */
inline u64 divide128By64Lo(const u64 op1_hi, const u64 op1_lo, const u64 op2) {
    return static_cast<u64>(
        ((static_cast<u128>(op1_hi) << 64) | static_cast<u128>(op1_lo)) / op2);
}

/**
 * @brief Computes (op1 * op2) mod mod using 128-bit intermediate precision.
 */
inline u64 mulModSimple(const u64 op1, const u64 op2, const u64 mod) {
    return static_cast<u64>(mul64To128(op1, op2) % mod);
}

/**
 * @brief Computes modular exponentiation via square-and-multiply.
 */
inline u64 powModSimple(u64 base, u64 expo, const u64 mod) {
    u64 res = 1;
    while (expo > 0) {
        if ((expo & 1) == 1) // if odd
            res = mulModSimple(res, base, mod);
        base = mulModSimple(base, base, mod);
        expo >>= 1;
    }

    return res;
}

inline u64 mulModLazy(const u64 op1, const u64 op2, const u64 op2_barrett,
                      const u64 mod) {
    return op1 * op2 - mul64To128Hi(op1, op2_barrett) * mod;
}

/**
 * @brief Bit-reversal helper specialized for 32-bit inputs.
 */
inline Size bitReverse32(Size x) {
    x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1));
    x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2));
    x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4));
    x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8));
    return ((x >> 16) | (x << 16));
}

inline Size bitReverse(Size x, u64 max_digits) {
    return bitReverse32(x) >> (32 - max_digits);
}

/**
 * @brief Counts the number of leading zero bits in a 64-bit value.
 */
inline u64 countLeftZeroes(u64 op) {
#ifndef __has_builtin
#define __has_builtin(arg) 0
#endif
#if __has_builtin(__builtin_clzll)
    return static_cast<u64>(__builtin_clzll(op));
#elif _MSC_VER
    return static_cast<u64>(__lzcnt64(op));
#else
    // Algorithm: see "Hacker's delight" 2nd ed., section 5.13, algorithm 5-12.
    u64 n = 64;
    u64 tmp = op >> 32;
    if (tmp != 0) {
        n = n - 32;
        op = tmp;
    }
    tmp = op >> 16;
    if (tmp != 0) {
        n = n - 16;
        op = tmp;
    }
    tmp = op >> 8;
    if (tmp != 0) {
        n = n - 8;
        op = tmp;
    }
    tmp = op >> 4;
    if (tmp != 0) {
        n = n - 4;
        op = tmp;
    }
    tmp = op >> 2;
    if (tmp != 0) {
        n = n - 2;
        op = tmp;
    }
    tmp = op >> 1;
    if (tmp != 0)
        return n - 2;
    return n - op;
#endif
}

inline u64 bitWidth(const u64 op) {
#ifdef __cpp_lib_int_pow2
    return std::bit_width(op);
#else
    return op ? UINT64_C(64) - countLeftZeroes(op) : UINT64_C(0);
#endif
}

// Integral log2 with log2floor(0) := 0
inline u64 log2floor(const u64 op) {
    return op ? bitWidth(op) - 1 : UINT64_C(0);
}

/**
 * @brief Checks whether op is a non-zero power of two.
 */
inline bool isPowerOfTwo(u64 op) { return op && (!(op & (op - 1))); }

/**
 * @brief Applies in-place bit reversal permutation to a power-of-two array.
 * @param data Pointer to array contents.
 * @param n Number of elements; must be power of two.
 */
template <typename T> void bitReverseArray(T *data, u64 n) {
    if (!(isPowerOfTwo(n)))
        return;

    for (u64 i = UINT64_C(1), j = UINT64_C(0); i < n; ++i) {
        u64 bit = n >> 1;
        for (; j >= bit; bit >>= 1)
            j -= bit;

        j += bit;
        if (i < j)
            std::swap(data[i], data[j]);
    }
}

/**
 * @brief Subtracts b from a when a is greater or equal, otherwise returns a.
 */
inline u64 subIfGE(u64 a, u64 b) { return (a >= b ? a - b : a); }

/**
 * @brief Computes a modular inverse using Fermat's little theorem.
 */
inline u64 invModSimple(u64 a, u64 prime) {
    return powModSimple(a, prime - 2, prime);
}

/**
 * @brief Adjusts x toward the nearest integer by ±0.5.
 */
inline Real addZeroPointFive(Real x) { return x > 0 ? x + 0.5 : x - 0.5; }
} // namespace deb::utils
