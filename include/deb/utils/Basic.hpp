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

#pragma once

#include "CKKSTypes.hpp"
#include <algorithm>

#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace deb::utils {

// ---------------------------------------------------------------------------
// 128-bit integer types
//
// GCC/Clang provide __int128 natively.  MSVC does not, so we supply
// lightweight struct wrappers that expose the same set of operations used
// throughout deb (arithmetic, shifts, comparisons, casts).
// ---------------------------------------------------------------------------
#ifdef _MSC_VER

struct i128; // forward declaration

struct u128 {
    u64 lo;
    u64 hi;

    constexpr u128() : lo(0), hi(0) {}
    constexpr u128(u64 val) : lo(val), hi(0) {} // NOLINT(implicit)
    constexpr u128(u64 hi_, u64 lo_) : lo(lo_), hi(hi_) {}

    constexpr explicit operator u64() const { return lo; }
    constexpr explicit operator bool() const { return lo || hi; }

    // u128 -> double (used by Decryptor: static_cast<Real>(u128_val))
    explicit operator Real() const {
        constexpr Real two64 = 18446744073709551616.0; // 2^64
        return static_cast<Real>(hi) * two64 + static_cast<Real>(lo);
    }

    // -- shifts -----------------------------------------------------------
    constexpr u128 operator>>(u64 n) const {
        if (n == 0)
            return *this;
        if (n >= 128)
            return u128();
        if (n >= 64)
            return u128(0, hi >> (n - 64));
        return u128(hi >> n, (lo >> n) | (hi << (64 - n)));
    }
    constexpr u128 operator<<(u64 n) const {
        if (n == 0)
            return *this;
        if (n >= 128)
            return u128();
        if (n >= 64)
            return u128(lo << (n - 64), 0);
        return u128((hi << n) | (lo >> (64 - n)), lo << n);
    }

    // -- bitwise ----------------------------------------------------------
    constexpr u128 operator|(const u128 &o) const {
        return u128(hi | o.hi, lo | o.lo);
    }
    constexpr u128 operator&(const u128 &o) const {
        return u128(hi & o.hi, lo & o.lo);
    }
    constexpr u128 operator^(const u128 &o) const {
        return u128(hi ^ o.hi, lo ^ o.lo);
    }
    constexpr u128 operator~() const { return u128(~hi, ~lo); }

    // -- arithmetic -------------------------------------------------------
    constexpr u128 operator+(const u128 &o) const {
        u64 r = lo + o.lo;
        return u128(hi + o.hi + (r < lo ? 1 : 0), r);
    }
    constexpr u128 operator-(const u128 &o) const {
        u64 r = lo - o.lo;
        return u128(hi - o.hi - (lo < o.lo ? 1 : 0), r);
    }

    // Multiplication – schoolbook 32-bit (constexpr-compatible).
    constexpr u128 operator*(const u128 &o) const {
        u64 a0 = lo & 0xFFFFFFFF, a1 = lo >> 32;
        u64 b0 = o.lo & 0xFFFFFFFF, b1 = o.lo >> 32;
        u64 p00 = a0 * b0;
        u64 p01 = a0 * b1;
        u64 p10 = a1 * b0;
        u64 p11 = a1 * b1;
        u64 mid = (p00 >> 32) + (p01 & 0xFFFFFFFF) + (p10 & 0xFFFFFFFF);
        u64 l = (p00 & 0xFFFFFFFF) | ((mid & 0xFFFFFFFF) << 32);
        u64 h = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
        h += lo * o.hi + hi * o.lo;
        return u128(h, l);
    }

    // Division and modulo by u64 – binary long division (constexpr-compatible).
    constexpr u128 operator/(u64 d) const {
        if (hi == 0)
            return u128(0, lo / d);
        u64 qh = hi / d;
        u64 rem = hi % d;
        u64 ql = 0;
        for (int i = 63; i >= 0; i--) {
            bool overflow = (rem >> 63) != 0;
            rem = (rem << 1) | ((lo >> i) & 1);
            if (overflow || rem >= d) {
                rem -= d;
                ql |= (u64(1) << i);
            }
        }
        return u128(qh, ql);
    }
    constexpr u128 operator%(u64 d) const {
        if (hi == 0)
            return u128(0, lo % d);
        u64 rem = hi % d;
        for (int i = 63; i >= 0; i--) {
            bool overflow = (rem >> 63) != 0;
            rem = (rem << 1) | ((lo >> i) & 1);
            if (overflow || rem >= d) {
                rem -= d;
            }
        }
        return u128(0, rem);
    }

    // -- comparisons ------------------------------------------------------
    constexpr bool operator==(const u128 &o) const {
        return hi == o.hi && lo == o.lo;
    }
    constexpr bool operator!=(const u128 &o) const { return !(*this == o); }
    constexpr bool operator<(const u128 &o) const {
        return hi < o.hi || (hi == o.hi && lo < o.lo);
    }
    constexpr bool operator>(const u128 &o) const { return o < *this; }
    constexpr bool operator<=(const u128 &o) const { return !(o < *this); }
    constexpr bool operator>=(const u128 &o) const { return !(*this < o); }
};

struct i128 {
    u64 lo;
    i64 hi; // signed

    constexpr i128() : lo(0), hi(0) {}
    constexpr i128(int val) // NOLINT(implicit)
        : lo(static_cast<u64>(static_cast<i64>(val))),
          hi(val < 0 ? i64(-1) : i64(0)) {}
    constexpr i128(i64 val) // NOLINT(implicit)
        : lo(static_cast<u64>(val)), hi(val < 0 ? i64(-1) : i64(0)) {}
    constexpr i128(u64 val) // NOLINT(implicit)
        : lo(val), hi(0) {}
    constexpr i128(i64 hi_, u64 lo_) : lo(lo_), hi(hi_) {}
    constexpr i128(u128 val) : lo(val.lo), hi(static_cast<i64>(val.hi)) {}

    // double -> i128 (used in CKKS encoding: static_cast<i128>(double))
    i128(Real val) { // NOLINT(implicit)
        bool neg = val < 0;
        Real a = neg ? -val : val;
        constexpr Real two64 = 18446744073709551616.0;
        u64 h = (a >= two64) ? static_cast<u64>(a / two64) : 0;
        u64 l = static_cast<u64>(a - static_cast<Real>(h) * two64);
        if (neg) {
            l = ~l + 1;
            h = ~h + (l == 0 ? 1 : 0);
        }
        lo = l;
        hi = static_cast<i64>(h);
    }

    constexpr explicit operator u64() const { return lo; }

    // Reinterpret as unsigned.
    constexpr explicit operator u128() const {
        return u128(static_cast<u64>(hi), lo);
    }

    // Arithmetic right shift (sign-extending).
    constexpr i128 operator>>(u64 n) const {
        if (n == 0)
            return *this;
        if (n >= 128)
            return i128(hi < 0 ? i64(-1) : i64(0));
        if (n >= 64) {
            i64 s = hi >> static_cast<int>(n - 64); // arithmetic
            return i128(hi < 0 ? i64(-1) : i64(0), static_cast<u64>(s));
        }
        return i128(hi >> static_cast<int>(n),
                    (lo >> n) | (static_cast<u64>(hi) << (64 - n)));
    }
    constexpr i128 operator<<(u64 n) const {
        if (n == 0)
            return *this;
        if (n >= 128)
            return i128(0, 0);
        if (n >= 64)
            return i128(static_cast<i64>(lo << (n - 64)), 0);
        return i128((hi << n) | (lo >> (64 - n)), lo << n);
    }

    // -- arithmetic -------------------------------------------------------
    constexpr i128 operator+(const i128 &o) const {
        u64 r = lo + o.lo;
        return i128(hi + o.hi + (r < lo ? 1 : 0), r);
    }
    constexpr i128 operator-(const i128 &o) const {
        u64 r = lo - o.lo;
        return i128(hi - o.hi - (lo < o.lo ? 1 : 0), r);
    }
    constexpr i128 operator*(const i128 &o) const {
        return static_cast<i128>(static_cast<u128>(*this) *
                                 static_cast<u128>(o));
    }
    constexpr i128 operator-() const {
        u64 nl = ~lo + 1;
        return i128(static_cast<i64>(~static_cast<u64>(hi) + (nl == 0 ? 1 : 0)),
                    nl);
    }

    // -- comparisons ------------------------------------------------------
    constexpr bool operator==(const i128 &o) const {
        return hi == o.hi && lo == o.lo;
    }
    constexpr bool operator!=(const i128 &o) const { return !(*this == o); }
    constexpr bool operator<(const i128 &o) const {
        return hi < o.hi || (hi == o.hi && lo < o.lo);
    }
    constexpr bool operator>(const i128 &o) const { return o < *this; }
    constexpr bool operator<=(const i128 &o) const { return !(o < *this); }
    constexpr bool operator>=(const i128 &o) const { return !(*this < o); }
};

#else // GCC / Clang

using u128 = unsigned __int128;
using i128 = __int128;

#endif

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
    return op ? UINT64_C(64) - countLeftZeroes(op) : UINT64_C(0);
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
inline u64 subIfGE(u64 a, u64 b) { return (a >= b) ? (a - b) : a; }

inline u64 subIfGEConst(u64 a, u64 b) {
    // mask is 0xFFFFFFFF if a >= b, 0x0 if a < b
    const u64 mask = ((a - b) >> 63) - 1;
    return a - (b & mask);
}

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
