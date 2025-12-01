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
 */
class NTT {
public:
    NTT() = default;
    /**
     * @brief Creates an NTT instance for a modulus and degree.
     * @param degree Polynomial degree.
     * @param prime Prime modulus.
     */
    NTT(u64 degree, u64 prime);

    /**
     * @brief Performs an in-place forward NTT on the supplied data.
     * @param op Pointer to coefficient array sized per degree.
     */
    void computeForward(u64 *op) const;

    /**
     * @brief Performs an in-place inverse NTT on the supplied data.
     * @param op Pointer to coefficient array sized per degree.
     */
    void computeBackward(u64 *op) const;

private:
    u64 prime_;
    u64 two_prime_;
    u64 degree_;

    // TODO(juny): make support constexpr for NTT
    // roots of unity (bit reversed)
    std::vector<u64> psi_rev_;
    std::vector<u64> psi_inv_rev_;
    std::vector<u64> psi_rev_shoup_;
    std::vector<u64> psi_inv_rev_shoup_;

    // variables for last step of backward NTT
    u64 degree_inv_;
    u64 degree_inv_barrett_;
    u64 degree_inv_w_;
    u64 degree_inv_w_barrett_;

    void computeForwardNativeSingleStep(u64 *op, const u64 t) const;
    void computeBackwardNativeSingleStep(u64 *op, const u64 t) const;
    void computeBackwardNativeLast(u64 *op) const;
};
} // namespace deb::utils
