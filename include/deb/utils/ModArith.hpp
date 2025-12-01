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
#include "Macro.hpp"
#include "utils/Basic.hpp"
#include "utils/NTT.hpp"

#include <algorithm>
#include <memory>

namespace deb::utils {

/**
 * @brief Provides modular arithmetic utilities bound to a specific modulus.
 */
class ModArith {
public:
    explicit ModArith() = default;
    /**
     * @brief Initializes precomputed tables for a modulus and vector size.
     * @param size Default vector size (poly degree).
     * @param prime Prime modulus.
     */
    explicit ModArith(Size size, u64 prime);

    /**
     * @brief Returns the modulus associated with this instance.
     */
    inline u64 getPrime() const { return prime_; }

    // InputModFactor: input value must be in the range
    //                [0, InputModFactor * prime).
    // OutputModFactor: output value will be in the range
    //                [0, OutputModFactor * prime).
    template <int InputModFactor = 4, int OutputModFactor = 1>
    /**
     * @brief Reduces an operand in-place based on input/output modular ranges.
     * @param op Value to reduce.
     */
    inline void reduceModFactor(u64 &op) const {
        static_assert((InputModFactor == 1) || (InputModFactor == 2) ||
                          (InputModFactor == 4),
                      "InputModFactor must be 1, 2 or 4");
        static_assert((OutputModFactor == 1) || (OutputModFactor == 2) ||
                          (OutputModFactor == 4),
                      "OutputModFactor must be 1, 2 or 4");

        if constexpr (InputModFactor > 2 && OutputModFactor <= 2)
            op = subIfGE(op, two_prime_);

        if constexpr (InputModFactor > 1 && OutputModFactor == 1)
            op = subIfGE(op, prime_);
    }

    // Barrett Parameters:
    //    1. exponent: 64 (implicit)
    //    2. ratio   : 2^64 / prime (barrettRatiofor64)
    // Rough algorithm description:
    //    1. Compute approximate value for the quotient (op * ratio) >> exponent
    //    2. res = op - approxQuotient * prime is in range [0, 2 * prime)
    //    3. Whenever OutputModFactor == 1, res additionally gets reduced if
    //      necessary.
    template <int OutputModFactor = 1> u64 reduceBarrett(u64 op) const {
        static_assert((OutputModFactor == 1) || (OutputModFactor == 2),
                      "OutputModFactor must be 1 or 2");

        u64 approx_quotient = mul64To128Hi(op, barrett_ratio_for_u64_);
        u64 res = op - approx_quotient * prime_;
        // res in [0, 2*prime)

        reduceModFactor<2, OutputModFactor>(res);
        return res;
    }

    // Basic Assumption:
    //     4 * prime < 2^64
    // Precomputation:
    //     1. twoTo64 = 2^64 modulo prime
    //     2. twoTo64Shoup = Scaled approximation to twoTo64 / prime,
    //       in the fashion of Shoup's modular multiplication.
    // Rough algorithm description:
    //     1. Decompose the 128-bit integer (op) into (hi) * 2^64 + (lo).
    //     2. Do modular multiplication (hi) * 2^64 in Shoup's way, using the
    //       precomputed values.
    //     3. Do Barret reduction (lo) which is a 64-bit integer.
    //     4. Add two results of step 2 and step 3.
    template <int OutputModFactor = 1> u64 reduceBarrett(u128 op) const {
        static_assert((OutputModFactor == 1) || (OutputModFactor == 2) ||
                          (OutputModFactor == 4),
                      "OutputModFactor must be 1, 2 or 4");

        u64 hi = u128Hi(op);
        u64 lo = u128Lo(op);

        u64 quot = mul64To128Hi(hi, two_to_64_shoup_) +
                   mul64To128Hi(lo, barrett_ratio_for_u64_);
        u64 res = hi * two_to_64_ + lo;
        res -= quot * prime_;

        reduceModFactor<4, OutputModFactor>(res);
        return res;
    }

    template <int OutputModFactor = 4> u64 mul(u64 op1, u64 op2) const {
        return reduceBarrett<OutputModFactor>(mul64To128(op1, op2));
    }

    /**
     * @brief Raises base to expt mod prime using square-and-multiply.
     * @param base Base value.
     * @param expt Exponent value.
     * @return Resulting modular power.
     */
    u64 pow(u64 base, u64 expt) const {
        u64 res = 1;
        while (expt > 0) {
            if (expt & 1) // if odd
                res = mul(res, base);
            base = mul(base, base);
            expt >>= 1;
        }

        reduceModFactor(res);

        return res;
    }

    /**
     * @brief Computes a multiplicative inverse modulo the configured prime.
     */
    u64 inverse(u64 op) const { return pow(op, prime_ - 2); }

    /**
     * @brief Multiplies each element of @p op1 by @p op2 modulo the prime.
     * @param op1 Input operand array.
     * @param op2 Scalar multiplier.
     * @param res Output array receiving the result.
     * @param array_size Number of elements to process.
     */
    void constMult(const u64 *op1, const u64 op2, u64 *res,
                   Size array_size) const;

    /**
     * @brief Multiplies op1 by a scalar in-place.
     */
    void constMult(const u64 *op1, const u64 op2, u64 *res) const {
        constMult(op1, op2, res, default_array_size_);
    }

    /**
     * @brief Multiplies op1 by a scalar, storing the result back into op1.
     */
    void constMultInPlace(u64 *op1, const u64 op2) const {
        constMult(op1, op2, op1);
    }

    /**
     * @brief Element-wise modular multiplication of two arrays.
     * @param res Output array.
     * @param op1 First operand array.
     * @param op2 Second operand array.
     * @param array_size Number of elements to process.
     */
    void mulVector(u64 *res, const u64 *op1, const u64 *op2,
                   Size array_size) const;

    /**
     * @brief Multiplies two vectors element-wise using the default size.
     */
    void mulVector(u64 *res, const u64 *op1, const u64 *op2) const {
        mulVector(res, op1, op2, default_array_size_);
    }

    /**
     * @brief Applies the forward NTT, copying data when op and res differ.
     */
    inline void forwardNTT(u64 *op, u64 *res) const {
        // TODO: implement out-of-place version.
        if (op != res)
            std::copy_n(op, default_array_size_, res);
        forwardNTT(res);
    }

    /**
     * @brief Applies the forward NTT in-place.
     */
    inline void forwardNTT(u64 *op) const { ntt_->computeForward(op); }

    /**
     * @brief Applies the inverse NTT, copying data when op and res differ.
     */
    inline void backwardNTT(u64 *op, u64 *res) const {
        // TODO: implement out-of-place version.
        if (op != res)
            std::copy_n(op, default_array_size_, res);
        backwardNTT(res);
    }

    /**
     * @brief Applies the inverse NTT in-place.
     */
    inline void backwardNTT(u64 *op) const { ntt_->computeBackward(op); }

    /**
     * @brief Returns the default vector size configured for this instance.
     */
    Size get_default_size() const { return default_array_size_; }
    /**
     * @brief Returns the Barrett exponent used for reduction.
     */
    u64 get_barrett_expt() const { return barrett_expt_; }
    /**
     * @brief Returns the Barrett ratio used for reduction.
     */
    u64 get_barrett_ratio() const { return barrett_ratio_; }

private:
    u64 prime_;
    u64 two_prime_;
    u64 barrett_expt_; // 2^(K-1) < prime < 2^K
    u64 barrett_ratio_;

    Size default_array_size_; // degree or dimension

    u64 barrett_ratio_for_u64_;
    u64 two_to_64_;
    u64 two_to_64_shoup_;

    std::shared_ptr<NTT> ntt_ = nullptr;
};

/**
 * @brief Applies the forward NTT to each PolyUnit in @p poly.
 * @param modarith Per-prime modular arithmetic helpers.
 * @param poly Polynomial to transform.
 * @param num_polyunit Optional cap on processed units (0 = all).
 * @param expected_ntt_state Hint used to avoid redundant transforms.
 */
void forwardNTT(const std::vector<ModArith> &modarith, Polynomial &poly,
                Size num_polyunit = 0,
                [[maybe_unused]] bool expected_ntt_state = false);

/**
 * @brief Applies the inverse NTT to each PolyUnit.
 * @param modarith Per-prime modular arithmetic helpers.
 * @param poly Polynomial to transform.
 * @param num_polyunit Optional cap on processed units.
 * @param expected_ntt_state Hint used to avoid redundant transforms.
 */
void backwardNTT(const std::vector<ModArith> &modarith, Polynomial &poly,
                 Size num_polyunit = 0,
                 [[maybe_unused]] bool expected_ntt_state = true);

/**
 * @brief Adds two polynomials coefficient-wise.
 * @param modarith Per-prime helpers.
 * @param op1 First operand.
 * @param op2 Second operand.
 * @param res Result polynomial.
 * @param num_polyunit Optional cap on processed units.
 */
void addPoly(const std::vector<ModArith> &modarith, const Polynomial &op1,
             const Polynomial &op2, Polynomial &res, Size num_polyunit = 0);
/**
 * @brief Subtracts @p op2 from @p op1 coefficient-wise.
 * @param modarith Per-prime helpers.
 * @param op1 Minuend polynomial.
 * @param op2 Subtrahend polynomial.
 * @param res Result polynomial.
 * @param num_polyunit Optional cap on processed units.
 */
void subPoly(const std::vector<ModArith> &modarith, const Polynomial &op1,
             const Polynomial &op2, Polynomial &res, Size num_polyunit = 0);
/**
 * @brief Multiplies two polynomials in the NTT domain.
 * @param modarith Per-prime helpers.
 * @param op1 First operand.
 * @param op2 Second operand.
 * @param res Result polynomial.
 * @param num_polyunit Optional cap on processed units.
 */
void mulPoly(const std::vector<ModArith> &modarith, const Polynomial &op1,
             const Polynomial &op2, Polynomial &res, Size num_polyunit = 0);
/**
 * @brief Multiplies a polynomial by a scalar vector within index range.
 * @param modarith Per-prime helpers.
 * @param op1 Polynomial operand.
 * @param op2 Scalar vector pointer.
 * @param res Result polynomial.
 * @param s_id Start index.
 * @param e_id End index (exclusive).
 */
void constMulPoly(const std::vector<ModArith> &modarith, const Polynomial &op1,
                  const u64 *op2, Polynomial &res, Size s_id, Size e_id);

} // namespace deb::utils
