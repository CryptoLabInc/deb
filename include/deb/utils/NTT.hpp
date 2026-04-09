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
#include "utils/Basic.hpp"

#include <cstdint>
#include <set>
#include <vector>

namespace deb::utils {

/**
 * @brief Factorizes n into its distinct prime factors.
 * @param s Output set receiving prime factors.
 * @param n Number to factor.
 */
void findPrimeFactors(std::set<u64> &s, u64 n);
/**
 * @brief Finds a primitive root modulo prime.
 * @param prime Prime modulus.
 * @return Primitive root suitable for NTT.
 */
u64 findPrimitiveRoot(u64 prime);

/**
 * @brief Implements forward and inverse number-theoretic transforms.
 *
 * @tparam U Coefficient word type (u32 or u64, default u64).
 *           All twiddle-factor storage and coefficient arrays use type U.
 *           The constructor always accepts u64 arguments (prime and degree)
 *           for compatibility with preset tables; values are narrowed to U
 *           internally when U = u32.
 *           Note: for U = u32, the prime must be < 2^30 so that intermediate
 *           butterfly values (up to 4·prime) fit in a u32.
 */
template <typename U = u64> class NTT {
public:
    NTT() = default;
    /**
     * @brief Creates an NTT instance for a modulus and degree.
     * @param degree Polynomial degree (must be a power of two).
     * @param prime  NTT-friendly prime (prime ≡ 1 mod 2·degree).
     */
    NTT(u64 degree, u64 prime);

    /**
     * @brief Performs an in-place forward NTT on the supplied data.
     * @param op Pointer to coefficient array of length degree.
     */
    void computeForward(U *op) const;

    /**
     * @brief Performs an in-place inverse NTT on the supplied data.
     * @param op Pointer to coefficient array of length degree.
     */
    void computeBackward(U *op) const;

private:
    U prime_;
    U two_prime_;
    u64 degree_; ///< degree stays u64 (used as loop bounds / array sizes)

    // Roots of unity (bit-reversed order), stored as U
    std::vector<U> psi_rev_;
    std::vector<U> psi_inv_rev_;
    std::vector<U>
        psi_rev_shoup_; ///< Shoup precomputed: floor(psi · 2^bits / prime)
    std::vector<U> psi_inv_rev_shoup_;

    // Precomputed values for the last (combined degree-inverse) step of iNTT
    U degree_inv_;
    U degree_inv_barrett_;
    U degree_inv_w_;
    U degree_inv_w_barrett_;

    void computeForwardNativeSingleStep(U *op, u64 t) const;
    void computeBackwardNativeSingleStep(U *op, u64 t) const;
    void computeBackwardNativeLast(U *op) const;
};

// Explicit instantiation declarations
#ifdef DEB_U32
extern template class NTT<u32>;
#endif
#ifdef DEB_U64
extern template class NTT<u64>;
#endif

} // namespace deb::utils
