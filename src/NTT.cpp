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
namespace {

inline void butterfly(u64 &x, u64 &y, const u64 w, const u64 ws, const u64 p1,
                      const u64 p2) {
    u64 tx = subIfGE(x, p2);
    u64 ty = mulModLazy(y, w, ws, p1);
    x = tx + ty;
    y = tx + p2 - ty;
}

inline void butterflyInv(u64 &x, u64 &y, const u64 w, const u64 ws,
                         const u64 p1, const u64 p2) {
    u64 tx = x + y;
    u64 ty = x + p2 - y;
    x = subIfGE(tx, p2);
    y = mulModLazy(ty, w, ws, p1);
}

} // anonymous namespace

NTT::NTT(u64 degree, u64 prime)
    : prime_(prime), two_prime_(prime_ << 1), degree_(degree),
      psi_rev_(degree_), psi_inv_rev_(degree_), psi_rev_shoup_(degree_),
      psi_inv_rev_shoup_(degree_) {

    const u64 num_roots = degree;

    if (prime % (2 * num_roots) != 1)
        throw std::runtime_error("Not an NTT-friendly prime given.");

    if (!isPowerOfTwo(degree_))
        throw std::runtime_error("[NTT] degree must be a power of two.");

    auto mult_with_barr = [](u64 x, u64 y, u64 y_barr, u64 prime_mod) {
        u64 res = mulModLazy(x, y, y_barr, prime_mod);
        return subIfGE(res, prime_mod);
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
    psi_rev_[0] = 1;
    psi_inv_rev_[0] = 1;

    u64 idx = 0;
    u64 previdx = 0;
    u64 max_digits = log2floor(degree_);
    u64 psi_barr = divide128By64Lo(psi, 0, prime);
    u64 psi_inv_barr = divide128By64Lo(psi_inv, 0, prime);
    for (u64 i = 1; i < degree_; i++) {
        idx = bitReverse(static_cast<Size>(i), max_digits);
        psi_rev_[idx] = mult_with_barr(psi_rev_[previdx], psi, psi_barr, prime);
        psi_inv_rev_[idx] =
            mult_with_barr(psi_inv_rev_[previdx], psi_inv, psi_inv_barr, prime);
        previdx = idx;
    }

    std::vector<u64> tmp(degree_);
    tmp[0] = psi_inv_rev_[0];
    Size idx2 = 1;
    for (u64 m = (degree_ >> 1); m > 0; m >>= 1) {
        for (u64 i = 0; i < m; i++) {
            tmp[idx2] = psi_inv_rev_[m + i];
            idx2++;
        }
    }
    psi_inv_rev_ = std::move(tmp);

    for (u64 i = 0; i < degree_; i++) {
        psi_rev_shoup_[i] = divide128By64Lo(psi_rev_[i], 0, prime);
        psi_inv_rev_shoup_[i] = divide128By64Lo(psi_inv_rev_[i], 0, prime);
    }

    // variables for last step of backward NTT
    degree_inv_ = invModSimple(degree_, prime_);
    degree_inv_barrett_ = divide128By64Lo(degree_inv_, 0, prime_);
    degree_inv_w_ =
        mulModSimple(degree_inv_, psi_inv_rev_[degree_ - 1], prime_);
    degree_inv_w_barrett_ = divide128By64Lo(degree_inv_w_, 0, prime_);

    // Only up to one of them will be hit. This mandates the NTT object
    // can only be run on cores that has the same detected feature during
    // construction time.
}

void NTT::computeForwardNativeSingleStep(u64 *op, const u64 t) const {
    const u64 degree = this->degree_;
    const u64 prime = this->prime_;
    const u64 two_prime = this->two_prime_;

    const u64 m = (degree >> 1) / t;
    const u64 *w_ptr = psi_rev_.data() + m;
    const u64 *ws_ptr = psi_rev_shoup_.data() + m;

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
        u64 *x_ptr = op;
        u64 *y_ptr = op + t;

        for (u64 i = m; i > 0; --i) {
            const u64 w = *w_ptr++;
            const u64 ws = *ws_ptr++;

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

void NTT::computeForward(u64 *op) const {
    // fallback
    const u64 degree = this->degree_;

    for (u64 t = (degree >> 1); t > 0; t >>= 1)
        computeForwardNativeSingleStep(op, t);

    const u64 prime = this->prime_;
    const u64 two_prime = this->two_prime_;
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

void NTT::computeBackwardNativeSingleStep(u64 *op, const u64 t) const {
    const u64 degree = this->degree_;
    const u64 prime = this->prime_;
    const u64 two_prime = this->two_prime_;

    const u64 m = (degree >> 1) / t;
    const u64 root_idx = 1 + degree - (degree / t);
    const u64 *w_ptr = psi_inv_rev_.data() + root_idx;
    const u64 *ws_ptr = psi_inv_rev_shoup_.data() + root_idx;

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
        u64 *x_ptr = op;
        u64 *y_ptr = op + t;

        for (u64 i = m; i > 0; --i) {
            const u64 w = *w_ptr++;
            const u64 ws = *ws_ptr++;

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

void NTT::computeBackwardNativeLast(u64 *op) const {
    const u64 degree = this->degree_;
    const u64 prime = this->prime_;
    const u64 two_prime = this->two_prime_;

    const u64 degree_inv = this->degree_inv_;
    const u64 degree_inv_br = this->degree_inv_barrett_;
    const u64 degree_inv_w = this->degree_inv_w_;
    const u64 degree_inv_w_br = this->degree_inv_w_barrett_;

    auto butterfly_inv_degree = [&](u64 &x, u64 &y) {
        u64 tx = x + y;
        u64 ty = x + two_prime - y;
        tx = subIfGE(tx, two_prime);
        x = mulModLazy(tx, degree_inv, degree_inv_br, prime);
        y = mulModLazy(ty, degree_inv_w, degree_inv_w_br, prime);
    };

    u64 *x_ptr = op;
    u64 *y_ptr = op + (degree >> 1);

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

void NTT::computeBackward(u64 *op) const {

    const u64 degree = this->degree_;
    const u64 half_degree = degree >> 1;

    for (u64 t = 1; t < half_degree; t <<= 1)
        computeBackwardNativeSingleStep(op, t);

    computeBackwardNativeLast(op);

    const u64 prime = this->prime_;
#if DEB_ALINAS_LEN == 0
    PRAGMA_OMP(omp simd)
#else
    PRAGMA_OMP(omp simd aligned(op : DEB_ALINAS_LEN))
#endif
    for (u64 i = 0; i < degree; i++)
        op[i] = subIfGE(op[i], prime);
}

} // namespace deb::utils
