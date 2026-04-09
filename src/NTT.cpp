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

#include "utils/NTT.hpp"
#include "utils/Basic.hpp"

#include <algorithm>
#include <array>
#ifdef DEB_OPENMP
#include <omp.h>
#endif

namespace deb::utils {

namespace utils {

void findPrimeFactors(std::set<u64> &s, u64 n) {
    s.clear();

    while (n % 2 == 0) {
        s.insert(2);
        n /= 2;
    }

    for (u64 i = 3; i * i <= n; i += 2) {
        while (n % i == 0) {
            s.insert(i);
            n /= i;
        }
    }

    if (n > 2)
        s.insert(n);
}

u64 findPrimitiveRoot(u64 prime) {
    std::set<u64> s;
    u64 phi = prime - 1;
    findPrimeFactors(s, phi);
    for (u64 r = 2; r <= phi; r++) {
        bool passed = true;
        for (unsigned long it : s) {
            if (powModSimple(r, phi / it, prime) == 1) {
                passed = false;
                break;
            }
        }

        if (passed)
            return r;
    }

    return 0; // failed to find
}

} // namespace utils

// ---------------------------------------------------------------------------
// Butterfly operations -- templated on U
// ---------------------------------------------------------------------------
namespace {

template <typename U>
static inline void butterfly(U &x, U &y, U w, U ws, U p1, U p2) {
    const U ty = mulModLazy(y, w, ws, p1);
    x = subIfGE(x, p2);
    if constexpr (std::is_same_v<U, u32>) {
        u64 x64 = static_cast<u64>(x);
        u64 ty64 = static_cast<u64>(ty);
        u64 p2_64 = static_cast<u64>(p2);
        u64 sum = x64 + ty64;
        u64 diff = x64 + p2_64 - ty64;
        x = static_cast<U>(subIfGE<u64>(sum, p2_64));
        y = static_cast<U>(subIfGE<u64>(diff, p2_64));
    } else {
        y = static_cast<U>(x + p2 - ty);
        x = static_cast<U>(x + ty);
    }
}

template <typename U>
static inline void butterflyInv(U &x, U &y, U w, U ws, U p1, U p2) {
    if constexpr (std::is_same_v<U, u32>) {
        u64 x64 = static_cast<u64>(subIfGE(x, p2));
        u64 y64 = static_cast<u64>(subIfGE(y, p2));
        u64 p2_64 = static_cast<u64>(p2);
        U tx = static_cast<U>(subIfGE<u64>(x64 + y64, p2_64));
        y = mulModLazy(static_cast<U>(subIfGE<u64>(x64 + p2_64 - y64, p2_64)),
                       w, ws, p1);
        x = tx;
    } else {
        const U tx = subIfGE(static_cast<U>(x + y), p2);
        y = mulModLazy(static_cast<U>(x + p2 - y), w, ws, p1);
        x = tx;
    }
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// NTT<U> constructor
// ---------------------------------------------------------------------------

template <typename U>
NTT<U>::NTT(u64 degree, u64 prime)
    : prime_(static_cast<U>(prime)), two_prime_(static_cast<U>(prime * 2)),
      degree_(degree), psi_rev_(degree_), psi_inv_rev_(degree_),
      psi_rev_shoup_(degree_), psi_inv_rev_shoup_(degree_) {

    const u64 num_roots = degree_;

    if (prime % (2 * num_roots) != 1)
        throw std::runtime_error("[NTT] Not an NTT-friendly prime given.");

    if (!isPowerOfTwo(degree_))
        throw std::runtime_error("[NTT] degree must be a power of two.");

    // All construction arithmetic uses u64 for precision; narrowed to U when
    // stored in the twiddle-factor vectors.
    auto mult_with_barr = [](u64 x, u64 y, u64 y_barr, u64 prime_mod) {
        u64 res = mulModLazy<u64>(x, y, y_barr, prime_mod);
        return subIfGE<u64>(res, prime_mod);
    };

    u64 psi = utils::findPrimitiveRoot(prime);
    psi = powModSimple(psi, (prime - 1) / (2 * num_roots), prime);

    // Find the minimal 2N-th root of unity
    u64 psi_square = mulModSimple(psi, psi, prime);
    u64 psi_square_barr = divide128By64Lo(psi_square, 0, prime);
    u64 min_root = psi;
    u64 psi_tmp = psi;
    for (u64 i = 0; i < num_roots; ++i) {
        psi_tmp = mult_with_barr(psi_tmp, psi_square, psi_square_barr, prime);
        if (psi_tmp < min_root)
            min_root = psi_tmp;
    }
    psi = min_root;

    u64 psi_inv = invModSimple(psi, prime);
    psi_rev_[0] = U(1);
    psi_inv_rev_[0] = U(1);

    u64 idx = 0;
    u64 previdx = 0;
    u64 max_digits = log2floor(degree_);
    u64 psi_barr = divide128By64Lo(psi, 0, prime);
    u64 psi_inv_barr = divide128By64Lo(psi_inv, 0, prime);
    for (u64 i = 1; i < degree_; i++) {
        idx = bitReverse(static_cast<Size>(i), max_digits);
        psi_rev_[idx] = static_cast<U>(mult_with_barr(
            static_cast<u64>(psi_rev_[previdx]), psi, psi_barr, prime));
        psi_inv_rev_[idx] = static_cast<U>(
            mult_with_barr(static_cast<u64>(psi_inv_rev_[previdx]), psi_inv,
                           psi_inv_barr, prime));
        previdx = idx;
    }

    std::vector<U> tmp(degree_);
    tmp[0] = psi_inv_rev_[0];
    Size idx2 = 1;
    for (u64 m = (degree_ >> 1); m > 0; m >>= 1) {
        for (u64 i = 0; i < m; i++) {
            tmp[idx2] = psi_inv_rev_[m + i];
            idx2++;
        }
    }
    psi_inv_rev_ = std::move(tmp);

    // Compute Shoup precomputed values using computeShoup<U>
    for (u64 i = 0; i < degree_; i++) {
        psi_rev_shoup_[i] = computeShoup<U>(psi_rev_[i], prime_);
        psi_inv_rev_shoup_[i] = computeShoup<U>(psi_inv_rev_[i], prime_);
    }

    // Variables for last step of backward NTT
    degree_inv_ = static_cast<U>(invModSimple(degree_, prime));
    degree_inv_barrett_ = computeShoup<U>(degree_inv_, prime_);
    degree_inv_w_ = static_cast<U>(
        mulModSimple(static_cast<u64>(degree_inv_),
                     static_cast<u64>(psi_inv_rev_[degree_ - 1]), prime));
    degree_inv_w_barrett_ = computeShoup<U>(degree_inv_w_, prime_);
}

// ---------------------------------------------------------------------------
// Forward NTT -- single butterfly pass
// ---------------------------------------------------------------------------

template <typename U>
void NTT<U>::computeForwardNativeSingleStep(U *op, const u64 t) const {
    const u64 degree = this->degree_;
    const U prime = this->prime_;
    const U two_prime = this->two_prime_;

    const u64 m = (degree >> 1) / t;
    const U *w_ptr = psi_rev_.data() + m;
    const U *ws_ptr = psi_rev_shoup_.data() + m;

    switch (t) {
    case 1:
        DEB_LOOP_UNROLL_8
        for (u64 i = 0; i < (degree >> 3); ++i) {
            butterfly(op[8 * i + 0], op[8 * i + 1], w_ptr[4 * i], ws_ptr[4 * i],
                      prime, two_prime);
            butterfly(op[8 * i + 2], op[8 * i + 3], w_ptr[4 * i + 1],
                      ws_ptr[4 * i + 1], prime, two_prime);
            butterfly(op[8 * i + 4], op[8 * i + 5], w_ptr[4 * i + 2],
                      ws_ptr[4 * i + 2], prime, two_prime);
            butterfly(op[8 * i + 6], op[8 * i + 7], w_ptr[4 * i + 3],
                      ws_ptr[4 * i + 3], prime, two_prime);
        }
        break;
    case 2:
        DEB_LOOP_UNROLL_8
        for (u64 i = 0; i < (degree >> 3); ++i) {
            butterfly(op[8 * i + 0], op[8 * i + 2], w_ptr[2 * i], ws_ptr[2 * i],
                      prime, two_prime);
            butterfly(op[8 * i + 1], op[8 * i + 3], w_ptr[2 * i], ws_ptr[2 * i],
                      prime, two_prime);
            butterfly(op[8 * i + 4], op[8 * i + 6], w_ptr[2 * i + 1],
                      ws_ptr[2 * i + 1], prime, two_prime);
            butterfly(op[8 * i + 5], op[8 * i + 7], w_ptr[2 * i + 1],
                      ws_ptr[2 * i + 1], prime, two_prime);
        }
        break;
    case 4:
        DEB_LOOP_UNROLL_8
        for (u64 i = 0; i < (degree >> 3); ++i) {
            butterfly(op[8 * i + 0], op[8 * i + 4], w_ptr[i], ws_ptr[i], prime,
                      two_prime);
            butterfly(op[8 * i + 1], op[8 * i + 5], w_ptr[i], ws_ptr[i], prime,
                      two_prime);
            butterfly(op[8 * i + 2], op[8 * i + 6], w_ptr[i], ws_ptr[i], prime,
                      two_prime);
            butterfly(op[8 * i + 3], op[8 * i + 7], w_ptr[i], ws_ptr[i], prime,
                      two_prime);
        }
        break;
    case 8:
        DEB_LOOP_UNROLL_8
        for (u64 i = 0; i < (degree >> 4); ++i) {
            butterfly(op[16 * i + 0], op[16 * i + 8], w_ptr[i], ws_ptr[i],
                      prime, two_prime);
            butterfly(op[16 * i + 1], op[16 * i + 9], w_ptr[i], ws_ptr[i],
                      prime, two_prime);
            butterfly(op[16 * i + 2], op[16 * i + 10], w_ptr[i], ws_ptr[i],
                      prime, two_prime);
            butterfly(op[16 * i + 3], op[16 * i + 11], w_ptr[i], ws_ptr[i],
                      prime, two_prime);
            butterfly(op[16 * i + 4], op[16 * i + 12], w_ptr[i], ws_ptr[i],
                      prime, two_prime);
            butterfly(op[16 * i + 5], op[16 * i + 13], w_ptr[i], ws_ptr[i],
                      prime, two_prime);
            butterfly(op[16 * i + 6], op[16 * i + 14], w_ptr[i], ws_ptr[i],
                      prime, two_prime);
            butterfly(op[16 * i + 7], op[16 * i + 15], w_ptr[i], ws_ptr[i],
                      prime, two_prime);
        }
        break;
    default:
        U *x_ptr = op;
        U *y_ptr = op + t;

        for (u64 i = m; i > 0; --i) {
            const U w = *w_ptr++;
            const U ws = *ws_ptr++;

            DEB_LOOP_UNROLL_8
            for (u64 j = 0; j < (t >> 3); ++j) {
                butterfly(x_ptr[8 * j], y_ptr[8 * j], w, ws, prime, two_prime);
                butterfly(x_ptr[8 * j + 1], y_ptr[8 * j + 1], w, ws, prime,
                          two_prime);
                butterfly(x_ptr[8 * j + 2], y_ptr[8 * j + 2], w, ws, prime,
                          two_prime);
                butterfly(x_ptr[8 * j + 3], y_ptr[8 * j + 3], w, ws, prime,
                          two_prime);

                butterfly(x_ptr[8 * j + 4], y_ptr[8 * j + 4], w, ws, prime,
                          two_prime);
                butterfly(x_ptr[8 * j + 5], y_ptr[8 * j + 5], w, ws, prime,
                          two_prime);
                butterfly(x_ptr[8 * j + 6], y_ptr[8 * j + 6], w, ws, prime,
                          two_prime);
                butterfly(x_ptr[8 * j + 7], y_ptr[8 * j + 7], w, ws, prime,
                          two_prime);
            }
            x_ptr += 2 * t;
            y_ptr += 2 * t;
        }
    }
}

template <typename U> void NTT<U>::computeForward(U *op) const {
    const u64 degree = this->degree_;

    for (u64 t = (degree >> 1); t > 0; t >>= 1)
        computeForwardNativeSingleStep(op, t);

    const U prime = this->prime_;
    const U two_prime = this->two_prime_;
#if DEB_ALINAS_LEN == 0
    PRAGMA_OMP(omp simd)
#else
    PRAGMA_OMP(omp simd aligned(op : DEB_ALINAS_LEN))
#endif
    for (u64 i = 0; i < degree; i++) {
        op[i] = subIfGE(op[i], two_prime);
        op[i] = subIfGE(op[i], prime);
    }
}

// ---------------------------------------------------------------------------
// Inverse NTT -- single butterfly pass
// ---------------------------------------------------------------------------

template <typename U>
void NTT<U>::computeBackwardNativeSingleStep(U *op, const u64 t) const {
    const u64 degree = this->degree_;
    const U prime = this->prime_;
    const U two_prime = this->two_prime_;

    const u64 m = (degree >> 1) / t;
    const u64 root_idx = 1 + degree - (degree / t);
    const U *w_ptr = psi_inv_rev_.data() + root_idx;
    const U *ws_ptr = psi_inv_rev_shoup_.data() + root_idx;

    switch (t) {
    case 1:
        DEB_LOOP_UNROLL_8
        for (u64 i = 0; i < (degree >> 3); ++i) {
            butterflyInv(op[8 * i + 0], op[8 * i + 1], w_ptr[4 * i],
                         ws_ptr[4 * i], prime, two_prime);
            butterflyInv(op[8 * i + 2], op[8 * i + 3], w_ptr[4 * i + 1],
                         ws_ptr[4 * i + 1], prime, two_prime);
            butterflyInv(op[8 * i + 4], op[8 * i + 5], w_ptr[4 * i + 2],
                         ws_ptr[4 * i + 2], prime, two_prime);
            butterflyInv(op[8 * i + 6], op[8 * i + 7], w_ptr[4 * i + 3],
                         ws_ptr[4 * i + 3], prime, two_prime);
        }
        break;
    case 2:
        DEB_LOOP_UNROLL_8
        for (u64 i = 0; i < (degree >> 3); ++i) {
            butterflyInv(op[8 * i + 0], op[8 * i + 2], w_ptr[2 * i],
                         ws_ptr[2 * i], prime, two_prime);
            butterflyInv(op[8 * i + 1], op[8 * i + 3], w_ptr[2 * i],
                         ws_ptr[2 * i], prime, two_prime);
            butterflyInv(op[8 * i + 4], op[8 * i + 6], w_ptr[2 * i + 1],
                         ws_ptr[2 * i + 1], prime, two_prime);
            butterflyInv(op[8 * i + 5], op[8 * i + 7], w_ptr[2 * i + 1],
                         ws_ptr[2 * i + 1], prime, two_prime);
        }
        break;
    case 4:
        DEB_LOOP_UNROLL_8
        for (u64 i = 0; i < (degree >> 3); ++i) {
            butterflyInv(op[8 * i + 0], op[8 * i + 4], w_ptr[i], ws_ptr[i],
                         prime, two_prime);
            butterflyInv(op[8 * i + 1], op[8 * i + 5], w_ptr[i], ws_ptr[i],
                         prime, two_prime);
            butterflyInv(op[8 * i + 2], op[8 * i + 6], w_ptr[i], ws_ptr[i],
                         prime, two_prime);
            butterflyInv(op[8 * i + 3], op[8 * i + 7], w_ptr[i], ws_ptr[i],
                         prime, two_prime);
        }
        break;
    case 8:
        DEB_LOOP_UNROLL_8
        for (u64 i = 0; i < (degree >> 4); ++i) {
            butterflyInv(op[16 * i + 0], op[16 * i + 8], w_ptr[i], ws_ptr[i],
                         prime, two_prime);
            butterflyInv(op[16 * i + 1], op[16 * i + 9], w_ptr[i], ws_ptr[i],
                         prime, two_prime);
            butterflyInv(op[16 * i + 2], op[16 * i + 10], w_ptr[i], ws_ptr[i],
                         prime, two_prime);
            butterflyInv(op[16 * i + 3], op[16 * i + 11], w_ptr[i], ws_ptr[i],
                         prime, two_prime);
            butterflyInv(op[16 * i + 4], op[16 * i + 12], w_ptr[i], ws_ptr[i],
                         prime, two_prime);
            butterflyInv(op[16 * i + 5], op[16 * i + 13], w_ptr[i], ws_ptr[i],
                         prime, two_prime);
            butterflyInv(op[16 * i + 6], op[16 * i + 14], w_ptr[i], ws_ptr[i],
                         prime, two_prime);
            butterflyInv(op[16 * i + 7], op[16 * i + 15], w_ptr[i], ws_ptr[i],
                         prime, two_prime);
        }
        break;
    default:
        U *x_ptr = op;
        U *y_ptr = op + t;

        for (u64 i = m; i > 0; --i) {
            const U w = *w_ptr++;
            const U ws = *ws_ptr++;

            DEB_LOOP_UNROLL_8
            for (u64 j = 0; j < (t >> 3); ++j) {
                butterflyInv(x_ptr[8 * j], y_ptr[8 * j], w, ws, prime,
                             two_prime);
                butterflyInv(x_ptr[8 * j + 1], y_ptr[8 * j + 1], w, ws, prime,
                             two_prime);
                butterflyInv(x_ptr[8 * j + 2], y_ptr[8 * j + 2], w, ws, prime,
                             two_prime);
                butterflyInv(x_ptr[8 * j + 3], y_ptr[8 * j + 3], w, ws, prime,
                             two_prime);

                butterflyInv(x_ptr[8 * j + 4], y_ptr[8 * j + 4], w, ws, prime,
                             two_prime);
                butterflyInv(x_ptr[8 * j + 5], y_ptr[8 * j + 5], w, ws, prime,
                             two_prime);
                butterflyInv(x_ptr[8 * j + 6], y_ptr[8 * j + 6], w, ws, prime,
                             two_prime);
                butterflyInv(x_ptr[8 * j + 7], y_ptr[8 * j + 7], w, ws, prime,
                             two_prime);
            }
            x_ptr += 2 * t;
            y_ptr += 2 * t;
        }
    }
}

template <typename U> void NTT<U>::computeBackwardNativeLast(U *op) const {
    const u64 degree = this->degree_;
    const U prime = this->prime_;
    const U two_prime = this->two_prime_;

    const U degree_inv = this->degree_inv_;
    const U degree_inv_br = this->degree_inv_barrett_;
    const U degree_inv_w = this->degree_inv_w_;
    const U degree_inv_w_br = this->degree_inv_w_barrett_;

    auto butterfly_inv_degree = [&](U &x, U &y) {
        if constexpr (std::is_same_v<U, u32>) {
            u64 x64 = static_cast<u64>(subIfGE(x, two_prime));
            u64 y64 = static_cast<u64>(subIfGE(y, two_prime));
            u64 p2_64 = static_cast<u64>(two_prime);
            U tx = static_cast<U>(subIfGE<u64>(x64 + y64, p2_64));
            U ty = static_cast<U>(subIfGE<u64>(x64 + p2_64 - y64, p2_64));
            x = mulModLazy(tx, degree_inv, degree_inv_br, prime);
            y = mulModLazy(ty, degree_inv_w, degree_inv_w_br, prime);
        } else {
            U tx = static_cast<U>(x + y);
            U ty = static_cast<U>(x + two_prime - y);
            tx = subIfGE(tx, two_prime);
            x = mulModLazy(tx, degree_inv, degree_inv_br, prime);
            y = mulModLazy(ty, degree_inv_w, degree_inv_w_br, prime);
        }
    };

    U *x_ptr = op;
    U *y_ptr = op + (degree >> 1);

    DEB_LOOP_UNROLL_8
    for (u64 i = 0; i < (degree >> 4); ++i) {
        butterfly_inv_degree(x_ptr[8 * i], y_ptr[8 * i]);
        butterfly_inv_degree(x_ptr[8 * i + 1], y_ptr[8 * i + 1]);
        butterfly_inv_degree(x_ptr[8 * i + 2], y_ptr[8 * i + 2]);
        butterfly_inv_degree(x_ptr[8 * i + 3], y_ptr[8 * i + 3]);
        butterfly_inv_degree(x_ptr[8 * i + 4], y_ptr[8 * i + 4]);
        butterfly_inv_degree(x_ptr[8 * i + 5], y_ptr[8 * i + 5]);
        butterfly_inv_degree(x_ptr[8 * i + 6], y_ptr[8 * i + 6]);
        butterfly_inv_degree(x_ptr[8 * i + 7], y_ptr[8 * i + 7]);
    }
}

template <typename U> void NTT<U>::computeBackward(U *op) const {

    const u64 degree = this->degree_;
    const u64 half_degree = degree >> 1;

    for (u64 t = 1; t < half_degree; t <<= 1)
        computeBackwardNativeSingleStep(op, t);

    computeBackwardNativeLast(op);

    const U prime = this->prime_;
#if DEB_ALINAS_LEN == 0
    PRAGMA_OMP(omp simd)
#else
    PRAGMA_OMP(omp simd aligned(op : DEB_ALINAS_LEN))
#endif
    for (u64 i = 0; i < degree; i++)
        op[i] = subIfGE(op[i], prime);
}

// Explicit instantiations
#ifdef DEB_U64
template class NTT<u64>;
#endif
#ifdef DEB_U32
template class NTT<u32>;
#endif

} // namespace deb::utils
