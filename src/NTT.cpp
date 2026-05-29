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
#include <cstdio>
#include <mutex>
#include <stdexcept>
#include <utility>
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

// ---------------------------------------------------------------------------
// Root selection helpers (shared between NTT and NTT_C constructors)
// ---------------------------------------------------------------------------

// Direct primitive-root search: finds a primitive (2*num_roots_log_param)-th
// root of unity modulo prime without the min-root selection step.
u64 findPrimitiveRootDirect(u64 prime, u64 degree) {
    const u32 log_order = static_cast<u32>(log2floor(degree)) + 1u;

    u64 odd_factor = prime - 1;
    u32 max_two_exp = 0;
    while ((odd_factor & u64(1)) == 0) {
        odd_factor >>= 1;
        max_two_exp++;
    }

    if (log_order > max_two_exp)
        throw std::runtime_error("[NTT(DIRECT)] findPrimitiveRootDirect: "
                                 "log_order > max_two_exp; "
                                 "prime is not NTT-friendly for this degree.");

    const u64 last_pow = u64(1) << (max_two_exp - log_order);
    const u64 max_base = std::min((prime - 1) / 2, u64(10000));

    for (u64 base = 2; base <= max_base; base += (base == 2 ? 1 : 2)) {
        if (base != 3 && (base % 3) == 0)
            continue;

        u64 psi = powModSimple(base, odd_factor, prime);
        if (psi == 1)
            continue;

        u32 exp = 0;
        u64 psi_pow = psi;
        while (psi_pow != prime - 1 && exp < max_two_exp) {
            psi_pow = mulModSimple(psi_pow, psi_pow, prime);
            exp++;
        }

        if (exp == max_two_exp - 1)
            return powModSimple(psi, last_pow, prime);
    }

    throw std::runtime_error("[NTT(DIRECT)] findPrimitiveRootDirect: no "
                             "primitive root found within base search range.");
}

// Iterates over the (num_roots) primitive root conjugates and returns the
// numerically smallest one.  Shared between the negacyclic 2N-th-root and
// cyclic 4N-th-root searches.
u64 selectMinRoot(u64 prime, u64 num_roots, u64 root_seed) {
    u64 root_sq = mulModSimple(root_seed, root_seed, prime);
    u64 root_sq_barr = divide128By64Lo(root_sq, 0, prime);
    u64 min_root = root_seed;
    u64 cur = root_seed;
    for (u64 i = 0; i < num_roots; ++i) {
        cur = mulModLazy<u64>(cur, root_sq, root_sq_barr, prime);
        cur = subIfGE<u64>(cur, prime);
        if (cur < min_root)
            min_root = cur;
    }
    return min_root;
}

// ---------------------------------------------------------------------------
// Butterfly primitives
// ---------------------------------------------------------------------------

template <typename U> inline void butterfly(U &x, U &y, U w, U ws, U p1, U p2) {
    // Precondition: prime < 2^30 for u32 (4·prime < 2^32), prime < 2^61 for
    // u64 (4·prime < 2^63). Forward butterfly emits [0, 4·prime) lazy form;
    // the prefix subIfGE on x absorbs that into [0, 2·prime) before the
    // additions, so x + ty and x + p2 - ty stay in [0, 4·prime) — fits both
    // word widths. The next butterfly's mulModLazy on y just requires op1
    // to fit U, which 4·prime does. computeForward's final canonical-reduce
    // pass brings the array back to [0, prime) before computeBackward sees
    // it, so butterflyInv's tighter [0, 2·prime) invariant is preserved.
    const U ty = mulModLazy(y, w, ws, p1);
    x = subIfGE(x, p2);
    y = static_cast<U>(x + p2 - ty);
    x = static_cast<U>(x + ty);
}

template <typename U>
inline void butterflyInv(U &x, U &y, U w, U ws, U p1, U p2) {
    // Invariant: inputs in [0, p2) for u32 (preserved by butterfly() and
    // by butterflyInv() itself), in [0, 2·p2) for u64 (the looser lazy
    // form the u64 forward path emits). For u32 with prime < 2^30 this
    // gives x + y, x + p2 - y both in [0, 2·p2) = [0, 4·prime) < 2^32 —
    // no prefix reduction needed; the u32 and u64 bodies collapse to the
    // same code. mulModLazy<u32> only requires op1 to fit a u32.
    const U tx = subIfGE(static_cast<U>(x + y), p2);
    y = mulModLazy(static_cast<U>(x + p2 - y), w, ws, p1);
    x = tx;
}

// ---------------------------------------------------------------------------
// Forward / Backward single-step butterfly passes
//
// The twiddle table layout is identical for negacyclic and cyclic NTT
// (only the stored values differ), so these helpers take the table base
// pointers explicitly.
// ---------------------------------------------------------------------------

template <typename U>
void forwardSingleStep(U *op, u64 degree, U prime, U two_prime, u64 t,
                       const U *w_base, const U *ws_base) {
    const u64 m = (degree >> 1) / t;
    const U *w_ptr = w_base + m;
    const U *ws_ptr = ws_base + m;

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

template <typename U>
void backwardSingleStep(U *op, u64 degree, U prime, U two_prime, u64 t,
                        const U *w_base, const U *ws_base) {
    const u64 m = (degree >> 1) / t;
    const u64 root_idx = 1 + degree - (degree / t);
    const U *w_ptr = w_base + root_idx;
    const U *ws_ptr = ws_base + root_idx;

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

template <typename U>
void backwardLast(U *op, u64 degree, U prime, U two_prime, U deg_inv,
                  U deg_inv_barr, U deg_inv_w, U deg_inv_w_barr) {
    auto butterfly_inv_degree = [&](U &x, U &y) {
        // Inputs come from the previous backwardSingleStep / butterflyInv,
        // which preserves the [0, 2·prime) invariant for u32 (and the looser
        // u64 invariant for u64). Either way x + y and x + 2p - y stay
        // within the word width when prime < 2^30 (u32) / prime < 2^61 (u64),
        // so the u32 and u64 bodies are the same — no prefix reduction and
        // no u64 promotion.
        U tx = static_cast<U>(x + y);
        U ty = static_cast<U>(x + two_prime - y);
        tx = subIfGE(tx, two_prime);
        x = mulModLazy(tx, deg_inv, deg_inv_barr, prime);
        y = mulModLazy(ty, deg_inv_w, deg_inv_w_barr, prime);
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

// Applies the stack-style inverse-psi reshuffle that iNTT requires.
// In-place transform of psi_inv_rev_ from bit-reversed layout into the
// stage-prefix layout the backward butterfly walks.
template <typename U>
void reshuffleInversePsi(std::vector<U> &psi_inv_rev, u64 degree) {
    std::vector<U> tmp(degree);
    tmp[0] = psi_inv_rev[0];
    Size idx = 1;
    for (u64 m = (degree >> 1); m > 0; m >>= 1) {
        for (u64 i = 0; i < m; ++i) {
            tmp[idx] = psi_inv_rev[m + i];
            ++idx;
        }
    }
    psi_inv_rev = std::move(tmp);
}

inline u64 multBarr(u64 x, u64 y, u64 y_barr, u64 prime_mod) {
    u64 res = mulModLazy<u64>(x, y, y_barr, prime_mod);
    return subIfGE<u64>(res, prime_mod);
}

} // namespace

// ---------------------------------------------------------------------------
// NTT_base — common state initialization
// ---------------------------------------------------------------------------

template <typename U>
NTT_base<U>::NTT_base(u64 degree, u64 prime, NTTType type,
                      NTTRootType root_type)
    : prime_(static_cast<U>(prime)), two_prime_(static_cast<U>(prime * 2)),
      degree_(degree), type_(type), root_type_(root_type) {
    if (!isPowerOfTwo(degree_))
        throw std::runtime_error("[NTT] degree must be a power of two.");
    if (prime % (2 * degree_) != 1)
        throw std::runtime_error(
            "[NTT] Not an NTT-friendly prime given "
            "(prime must satisfy prime ≡ 1 mod 2·degree).");
}

// ---------------------------------------------------------------------------
// NTT — negacyclic constructor
// ---------------------------------------------------------------------------

template <typename U>
NTT<U>::NTT(u64 degree, u64 prime, NTTRootType root_type)
    : NTT_base<U>(degree, prime, NTTType::NEGACYCLIC, root_type),
      psi_rev_(degree), psi_inv_rev_(degree), psi_rev_shoup_(degree),
      psi_inv_rev_shoup_(degree) {

    const u64 num_roots = degree_;

    degree_inv_ = static_cast<U>(invModSimple(degree_, prime));
    degree_inv_barrett_ = computeShoup<U>(degree_inv_, prime_);

    // Find primitive 2N-th root ψ.
    u64 psi;
    switch (root_type) {
    case NTTRootType::MIN: {
        psi = utils::findPrimitiveRoot(prime);
        psi = powModSimple(psi, (prime - 1) / (2 * num_roots), prime);
        psi = selectMinRoot(prime, num_roots, psi);
        break;
    }
    case NTTRootType::DIRECT:
        psi = findPrimitiveRootDirect(prime, num_roots);
        break;
    case NTTRootType::CUSTOM:
        psi = detail::lookupCustomPsi(degree, prime, "NTT(NEGACYCLIC)");
        break;
    default:
        throw std::runtime_error("[NTT(NEGACYCLIC)] Unknown NTTRootType.");
    }

    u64 psi_inv = invModSimple(psi, prime);
    psi_rev_[0] = U(1);
    psi_inv_rev_[0] = U(1);

    const u64 max_digits = log2floor(degree_);
    const u64 psi_barr = divide128By64Lo(psi, 0, prime);
    const u64 psi_inv_barr = divide128By64Lo(psi_inv, 0, prime);
    u64 idx = 0;
    u64 previdx = 0;
    for (u64 i = 1; i < degree_; i++) {
        idx = bitReverse(static_cast<Size>(i), max_digits);
        psi_rev_[idx] = static_cast<U>(multBarr(
            static_cast<u64>(psi_rev_[previdx]), psi, psi_barr, prime));
        psi_inv_rev_[idx] =
            static_cast<U>(multBarr(static_cast<u64>(psi_inv_rev_[previdx]),
                                    psi_inv, psi_inv_barr, prime));
        previdx = idx;
    }

    reshuffleInversePsi(psi_inv_rev_, degree_);

    for (u64 i = 0; i < degree_; i++) {
        psi_rev_shoup_[i] = computeShoup<U>(psi_rev_[i], prime_);
        psi_inv_rev_shoup_[i] = computeShoup<U>(psi_inv_rev_[i], prime_);
    }

    degree_inv_w_ = static_cast<U>(
        mulModSimple(static_cast<u64>(degree_inv_),
                     static_cast<u64>(psi_inv_rev_[degree_ - 1]), prime));
    degree_inv_w_barrett_ = computeShoup<U>(degree_inv_w_, prime_);
}

template <typename U> void NTT<U>::computeForward(U *op) const {
    for (u64 t = (degree_ >> 1); t > 0; t >>= 1)
        forwardSingleStep<U>(op, degree_, prime_, two_prime_, t,
                             psi_rev_.data(), psi_rev_shoup_.data());

#if DEB_ALINAS_LEN == 0
    PRAGMA_OMP(omp simd)
#else
    PRAGMA_OMP(omp simd aligned(op : DEB_ALINAS_LEN))
#endif
    for (u64 i = 0; i < degree_; i++) {
        op[i] = subIfGE(op[i], two_prime_);
        op[i] = subIfGE(op[i], prime_);
    }
}

template <typename U> void NTT<U>::computeBackward(U *op) const {
    const u64 half_degree = degree_ >> 1;

    for (u64 t = 1; t < half_degree; t <<= 1)
        backwardSingleStep<U>(op, degree_, prime_, two_prime_, t,
                              psi_inv_rev_.data(), psi_inv_rev_shoup_.data());

    backwardLast<U>(op, degree_, prime_, two_prime_, degree_inv_,
                    degree_inv_barrett_, degree_inv_w_, degree_inv_w_barrett_);

#if DEB_ALINAS_LEN == 0
    PRAGMA_OMP(omp simd)
#else
    PRAGMA_OMP(omp simd aligned(op : DEB_ALINAS_LEN))
#endif
    for (u64 i = 0; i < degree_; i++)
        op[i] = subIfGE(op[i], prime_);
}

// ---------------------------------------------------------------------------
// NTT_C — cyclic constructor
// ---------------------------------------------------------------------------

template <typename U>
NTT_C<U>::NTT_C(u64 degree, u64 prime, NTTRootType root_type)
    : NTT_base<U>(degree, prime, NTTType::CYCLIC, root_type), psi_rev_(degree),
      psi_inv_rev_(degree), psi_rev_shoup_(degree), psi_inv_rev_shoup_(degree) {

    const u64 num_roots_cyc = 2 * degree_; // primitive (4N)-th root
    if (prime % (2 * num_roots_cyc) != 1)
        throw std::runtime_error(
            "[NTT(CYCLIC)] CYCLIC mode requires prime ≡ 1 mod 4·degree "
            "(no primitive 4N-th root of unity exists otherwise).");

    degree_inv_ = static_cast<U>(invModSimple(degree_, prime));
    degree_inv_barrett_ = computeShoup<U>(degree_inv_, prime_);

    // Find primitive 4N-th root ζ.
    u64 zeta;
    switch (root_type) {
    case NTTRootType::MIN: {
        zeta = utils::findPrimitiveRoot(prime);
        zeta = powModSimple(zeta, (prime - 1) / (2 * num_roots_cyc), prime);
        zeta = selectMinRoot(prime, num_roots_cyc, zeta);
        break;
    }
    case NTTRootType::DIRECT:
        zeta = findPrimitiveRootDirect(prime, num_roots_cyc);
        break;
    case NTTRootType::CUSTOM:
        zeta = detail::lookupCustomPsi(2 * degree, prime, "NTT(CYCLIC)");
        break;
    default:
        throw std::runtime_error("[NTT(CYCLIC)] Unknown NTTRootType.");
    }

    // Build a full [1, ζ, ζ², …, ζ^{2N-1}] table; we need every 4th entry
    // for the layered psi_rev table plus the first N entries for roots_.
    std::vector<u64> zeta_pow(2 * degree_);
    zeta_pow[0] = 1;
    if (2 * degree_ > 1) {
        zeta_pow[1] = zeta;
        const u64 zeta_barr = divide128By64Lo(zeta, 0, prime);
        for (u64 i = 2; i < 2 * degree_; ++i)
            zeta_pow[i] = multBarr(zeta_pow[i - 1], zeta, zeta_barr, prime);
    }

    // CI <-> cyclic ring conversion tables.
    roots_.assign(degree_, U(0));
    roots_inv_.assign(degree_ + 1, U(0));
    for (u64 i = 0; i < degree_; ++i)
        roots_[i] = static_cast<U>(zeta_pow[i]);
    roots_inv_[0] = U(1);
    for (u64 i = 1; i <= degree_; ++i)
        roots_inv_[i] = static_cast<U>(prime - zeta_pow[2 * degree_ - i]);
    roots_shoup_.resize(degree_);
    roots_inv_shoup_.resize(degree_ + 1);
    for (u64 i = 0; i < degree_; ++i)
        roots_shoup_[i] = computeShoup<U>(roots_[i], prime_);
    for (u64 i = 0; i <= degree_; ++i)
        roots_inv_shoup_[i] = computeShoup<U>(roots_inv_[i], prime_);

    // Build the layered psi_rev table from ω = ζ^4 (primitive N-th root).
    psi_rev_[0] = U(1);
    psi_inv_rev_[0] = U(1);
    const u64 half_deg = degree_ >> 1;

    if (half_deg > 0) {
        std::vector<u64> psi_half(half_deg);
        std::vector<u64> psi_inv_half(half_deg);
        psi_half[0] = 1;
        psi_inv_half[0] = 1;
        for (u64 i = 1; i < half_deg; ++i) {
            psi_half[i] = zeta_pow[i * 4];
            psi_inv_half[i] = prime - zeta_pow[2 * degree_ - i * 4];
        }
        // Bit-reverse in place over length half_deg.
        const u64 hd_bits = log2floor(half_deg);
        for (u64 i = 0; i < half_deg; ++i) {
            u64 j = static_cast<u64>(
                bitReverse(static_cast<Size>(i), static_cast<u64>(hd_bits)));
            if (j > i) {
                std::swap(psi_half[i], psi_half[j]);
                std::swap(psi_inv_half[i], psi_inv_half[j]);
            }
        }

        for (u64 i = 0; i < half_deg; ++i) {
            psi_rev_[half_deg + i] = static_cast<U>(psi_half[i]);
            psi_inv_rev_[half_deg + i] = static_cast<U>(psi_inv_half[i]);
        }
        for (u64 m = (half_deg >> 1); m != 0; m >>= 1) {
            for (u64 i = 0; i < m; ++i) {
                psi_rev_[m + i] = static_cast<U>(psi_half[i]);
                psi_inv_rev_[m + i] = static_cast<U>(psi_inv_half[i]);
            }
        }
    }

    reshuffleInversePsi(psi_inv_rev_, degree_);

    for (u64 k = 0; k < degree_; ++k) {
        psi_rev_shoup_[k] = computeShoup<U>(psi_rev_[k], prime_);
        psi_inv_rev_shoup_[k] = computeShoup<U>(psi_inv_rev_[k], prime_);
    }

    degree_inv_w_ = static_cast<U>(
        mulModSimple(static_cast<u64>(degree_inv_),
                     static_cast<u64>(psi_inv_rev_[degree_ - 1]), prime));
    degree_inv_w_barrett_ = computeShoup<U>(degree_inv_w_, prime_);
}

// Z_q[X + X^{-1}]/<X^{2N}+1>  ->  Z_q[X]/<X^N − 1>     (in place).
template <typename U> void NTT_C<U>::conversion(U *op) const {
    const U prime = this->prime_;
    const U two_prime = this->two_prime_;
    const u64 degree = this->degree_;

    U *op_ptr = op + 1;
    U *op_ptr_back = op + degree - 1;
    U *res_ptr = op + 1;
    U *res_ptr_back = op + degree - 1;

    const U *roots_ptr = roots_.data() + 1;
    const U *roots_ptr_back = roots_.data() + degree - 1;
    const U *roots_sh_ptr = roots_shoup_.data() + 1;
    const U *roots_sh_ptr_back = roots_shoup_.data() + degree - 1;
    const U root_const = roots_inv_[degree];
    const U root_const_sh = roots_inv_shoup_[degree];

    while (op_ptr != op_ptr_back) {
        const U op1 = *op_ptr++, op2 = *op_ptr_back--;
        U tmp1 = op1 + mulModLazy(op2, root_const, root_const_sh, prime);
        U tmp2 = op2 + mulModLazy(op1, root_const, root_const_sh, prime);
        tmp1 = subIfGE(tmp1, two_prime);
        tmp2 = subIfGE(tmp2, two_prime);
        *res_ptr++ = mulModLazy(tmp1, *roots_ptr++, *roots_sh_ptr++, prime);
        *res_ptr_back-- =
            mulModLazy(tmp2, *roots_ptr_back--, *roots_sh_ptr_back--, prime);
    }
    const U op1 = *op_ptr;
    U tmp = op1 + mulModLazy(op1, root_const, root_const_sh, prime);
    tmp = subIfGE(tmp, two_prime);
    *res_ptr = mulModLazy(tmp, *roots_ptr, *roots_sh_ptr, prime);
}

template <typename U> void NTT_C<U>::inversion(U *op) const {
    const U prime = this->prime_;
    const U two_prime = this->two_prime_;
    const u64 degree = this->degree_;

    U *op_ptr = op + 1;
    U *op_ptr_back = op + degree - 1;
    U *res_ptr = op + 1;
    U *res_ptr_back = op + degree - 1;

    const U *roots_ptr = roots_.data() + 1;
    const U *roots_ptr_back = roots_.data() + degree - 1;
    const U *roots_sh_ptr = roots_shoup_.data() + 1;
    const U *roots_sh_ptr_back = roots_shoup_.data() + degree - 1;
    const U *roots_inv_ptr = roots_inv_.data() + 1;
    const U *roots_inv_ptr_back = roots_inv_.data() + degree - 1;
    const U *roots_inv_sh_ptr = roots_inv_shoup_.data() + 1;
    const U *roots_inv_sh_ptr_back = roots_inv_shoup_.data() + degree - 1;

    while (op_ptr != op_ptr_back) {
        const U op1 = *op_ptr++, op2 = *op_ptr_back--;
        *res_ptr++ =
            mulModLazy(op1, *roots_inv_ptr++, *roots_inv_sh_ptr++, prime) +
            mulModLazy(op2, *roots_ptr++, *roots_sh_ptr++, prime);
        *res_ptr_back-- =
            mulModLazy(op2, *roots_inv_ptr_back--, *roots_inv_sh_ptr_back--,
                       prime) +
            mulModLazy(op1, *roots_ptr_back--, *roots_sh_ptr_back--, prime);
    }
    *res_ptr = mulModLazy(*op_ptr, *roots_inv_ptr, *roots_inv_sh_ptr, prime) +
               mulModLazy(*op_ptr, *roots_ptr, *roots_sh_ptr, prime);

    // Halve (mod prime) each non-zero coefficient.  Reduce to canonical [0, p)
    // first so the (v+p)/2 branch never leaves the canonical range.
    for (u64 i = 1; i < degree; ++i) {
        U v = subIfGE(op[i], two_prime);
        v = subIfGE(v, prime);
        v = (v & U(1)) ? static_cast<U>(v + prime) : v;
        op[i] = static_cast<U>(v >> 1);
    }
}

template <typename U> void NTT_C<U>::computeForward(U *op) const {
    conversion(op);

    for (u64 t = (degree_ >> 1); t > 0; t >>= 1)
        forwardSingleStep<U>(op, degree_, prime_, two_prime_, t,
                             psi_rev_.data(), psi_rev_shoup_.data());

#if DEB_ALINAS_LEN == 0
    PRAGMA_OMP(omp simd)
#else
    PRAGMA_OMP(omp simd aligned(op : DEB_ALINAS_LEN))
#endif
    for (u64 i = 0; i < degree_; i++) {
        op[i] = subIfGE(op[i], two_prime_);
        op[i] = subIfGE(op[i], prime_);
    }
}

template <typename U> void NTT_C<U>::computeBackward(U *op) const {
    const u64 half_degree = degree_ >> 1;

    for (u64 t = 1; t < half_degree; t <<= 1)
        backwardSingleStep<U>(op, degree_, prime_, two_prime_, t,
                              psi_inv_rev_.data(), psi_inv_rev_shoup_.data());

    backwardLast<U>(op, degree_, prime_, two_prime_, degree_inv_,
                    degree_inv_barrett_, degree_inv_w_, degree_inv_w_barrett_);

#if DEB_ALINAS_LEN == 0
    PRAGMA_OMP(omp simd)
#else
    PRAGMA_OMP(omp simd aligned(op : DEB_ALINAS_LEN))
#endif
    for (u64 i = 0; i < degree_; i++)
        op[i] = subIfGE(op[i], prime_);

    inversion(op);
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

template <typename U>
std::unique_ptr<NTT_base<U>> makeNTT(u64 degree, u64 prime, NTTType type,
                                     NTTRootType root_type) {
    switch (type) {
    case NTTType::NEGACYCLIC:
        return std::make_unique<NTT<U>>(degree, prime, root_type);
    case NTTType::CYCLIC:
        return std::make_unique<NTT_C<U>>(degree, prime, root_type);
    default:
        throw std::runtime_error(
            "[makeNTT] NTTType must be NEGACYCLIC or CYCLIC.");
    }
}

// Explicit instantiations
#ifdef DEB_U64
template class NTT_base<u64>;
template class NTT<u64>;
template class NTT_C<u64>;
template std::unique_ptr<NTT_base<u64>> makeNTT<u64>(u64, u64, NTTType,
                                                     NTTRootType);
#endif
#ifdef DEB_U32
template class NTT_base<u32>;
template class NTT<u32>;
template class NTT_C<u32>;
template std::unique_ptr<NTT_base<u32>> makeNTT<u32>(u64, u64, NTTType,
                                                     NTTRootType);
#endif

// ---------------------------------------------------------------------------
// NTT factory dispatch
// ---------------------------------------------------------------------------

namespace {
template <typename U> struct NTTFactoryStorage {
    static inline std::mutex mu;
    static inline NTTFactory<U> factory;
};
} // namespace

template <typename U> void setNTTFactory(NTTFactory<U> factory) {
    std::lock_guard<std::mutex> lock(NTTFactoryStorage<U>::mu);
    NTTFactoryStorage<U>::factory = std::move(factory);
}

template <typename U>
std::shared_ptr<NTT_base<U>> createNTT(u64 degree, u64 prime, NTTType type,
                                       NTTRootType root_type) {
    NTTFactory<U> factory_copy;
    {
        std::lock_guard<std::mutex> lock(NTTFactoryStorage<U>::mu);
        factory_copy = NTTFactoryStorage<U>::factory;
    }
    if (factory_copy) {
        if (auto custom = factory_copy(degree, prime, type, root_type)) {
            return custom;
        }
        // Factory returned an empty shared_ptr — fall through to default.
    }
    return std::shared_ptr<NTT_base<U>>(
        makeNTT<U>(degree, prime, type, root_type));
}

#ifdef DEB_U32
template void setNTTFactory<u32>(NTTFactory<u32>);
template std::shared_ptr<NTT_base<u32>> createNTT<u32>(u64, u64, NTTType,
                                                       NTTRootType);
#endif
#ifdef DEB_U64
template void setNTTFactory<u64>(NTTFactory<u64>);
template std::shared_ptr<NTT_base<u64>> createNTT<u64>(u64, u64, NTTType,
                                                       NTTRootType);
#endif

} // namespace deb::utils
