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
#include "utils/Macro.hpp"
#include "utils/NTT.hpp"

#include <algorithm>
#include <memory>
#include <mutex>
#include <type_traits>
#include <utility>

namespace deb::utils {

template <Size D> struct DegreeTrait {
    static constexpr Size degree = D;
    DegreeTrait() = default;
    DegreeTrait(Size) {}
};
template <> struct DegreeTrait<1> {
    Size degree;
    DegreeTrait() = default;
    DegreeTrait(Size deg) : degree(deg) {}
};

/**
 * @brief Provides modular arithmetic utilities bound to a specific modulus.
 *
 * @tparam D Compile-time polynomial degree (1 = dynamic).
 * @tparam U Coefficient word type (u32 or u64, default u64).
 *           All coefficient arrays and the stored prime use type U.
 *           Barrett precomputation values are always stored as u64 because
 *           they represent floor(2^64 / prime) regardless of U.
 */
template <Size D = 1, typename U = u64> class ModArith : public DegreeTrait<D> {
    using DegreeTrait<D>::degree;

public:
    explicit ModArith() = default;
    /**
     * @brief Initializes precomputed tables for a modulus and vector size.
     *
     * The prime is accepted as u64 for compatibility with preset tables; it is
     * narrowed to U internally.
     *
     * @param degree Polynomial degree.
     * @param prime Prime modulus (must fit in U for correctness).
     * @param default_ntt_is_cyclic Whether the default NTT should be cyclic.
     */
    explicit ModArith(u64 prime, bool default_ntt_is_cyclic = false);
    explicit ModArith(Size degree, u64 prime,
                      bool default_ntt_is_cyclic = false);

    /**
     * @brief Returns the modulus associated with this instance.
     */
    inline U getPrime() const { return prime_; }

    // Returns the negacyclic NTT or the cyclic NTT.
    // The cyclic-true path requires the stored prime to be
    // 4N-friendly; the negacyclic path requires 2N-friendly.
    inline std::shared_ptr<NTT_base<U>> getNTT(const NTTType ntt_type) const {
        if (ntt_type == NTTType::CYCLIC) {
            ensureCyclicNTT();
            return cyclic_ntt_;
        } else if (ntt_type == NTTType::NEGACYCLIC) {
            ensureNegacyclicNTT();
            return ntt_;
        } else {
            throw std::runtime_error("[ModArith::getNTT] Unsupported NTT type");
        }
    };

    /**
     * @brief Returns the NTT root-finding algorithm this ModArith uses
     *        when constructing its NTT objects.
     */
    inline NTTRootType getNTTRootType() const noexcept { return root_type_; }

    /**
     * @brief Sets a per-instance NTT root-finding algorithm override.
     *
     * If the root type is changed from the current value, any existing NTT
     * objects are discarded and will be rebuilt. This allows different ModArith
     * instances to use different root-finding algorithms and/or custom roots at
     * runtime.
     */
    void setNTTRootType(NTTRootType rt = getGlobalNTTRootType()) {
        if (root_type_ != rt) {
            root_type_ = rt;
            if (ntt_) {
                ntt_.reset();
                ensureNegacyclicNTT(); // Rebuild with new root type.
            }
            if (cyclic_ntt_) {
                cyclic_ntt_.reset();
                ensureCyclicNTT(); // Rebuild with new root type.
            }
        }
    }
    /**
     * @brief Returns the precomputed Barrett ratio floor(2^64 / prime).
     *
     * Used in Barrett reduction of 64-bit products.
     */
    inline u64 get_barrett_ratio_for_u64() const {
        return barrett_ratio_for_u64_;
    }

    // InputModFactor: input value must be in the range
    //                [0, InputModFactor * prime).
    // OutputModFactor: output value will be in the range
    //                [0, OutputModFactor * prime).
    template <int InputModFactor = 4, int OutputModFactor = 1>
    /**
     * @brief Reduces an operand in-place based on input/output modular ranges.
     * @param op Value to reduce (type U).
     */
    inline void reduceModFactor(U &op) const {
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

    /**
     * @brief Barrett reduction of a U-wide value (single word).
     *
     * Reduces op ∈ [0, 2^bits) to [0, OutputModFactor·prime) using
     * precomputed floor(2^64 / prime).
     */
    template <int OutputModFactor = 1> U reduceBarrett(U op) const {
        static_assert((OutputModFactor == 1) || (OutputModFactor == 2),
                      "OutputModFactor must be 1 or 2");
        U approx_quotient;
        if constexpr (std::is_same_v<U, u64>) {
            // floor(op * floor(2^64/prime) / 2^64) ≈ floor(op / prime)
            approx_quotient = static_cast<u64>(
                (static_cast<u128>(op) * barrett_ratio_for_u64_) >> 64);
        } else {
            // U = u32: use the 32-bit Barrett ratio floor(2^32/prime) so that
            // floor(op * ratio / 2^32) ≈ floor(op / prime).
            approx_quotient = static_cast<u32>(
                (static_cast<u64>(op) * barrett_ratio_for_u32_) >> 32);
        }
        U res = static_cast<U>(op - approx_quotient * prime_);
        reduceModFactor<2, OutputModFactor>(res);
        return res;
    }

    /**
     * @brief Barrett reduction of a u128 value.
     *
     * For U = u64 this uses the full two-step 128-bit Barrett algorithm.
     * For U = u32 it reduces the 128-bit value to 64 bits first, then to U.
     */
    template <int OutputModFactor = 1> U reduceBarrett(u128 op) const {
        static_assert((OutputModFactor == 1) || (OutputModFactor == 2) ||
                          (OutputModFactor == 4),
                      "OutputModFactor must be 1, 2 or 4");

        if constexpr (std::is_same_v<U, u64>) {
            u64 hi = u128Hi(op);
            u64 lo = u128Lo(op);

            u64 quot = mul64To128Hi(hi, two_to_64_shoup_) +
                       mul64To128Hi(lo, barrett_ratio_for_u64_);
            u64 res = hi * two_to_64_ + lo;
            res -= quot * prime_;

            reduceModFactor<4, OutputModFactor>(res);
            return res;
        } else {
            // U = u32: reduce 128-bit → 64-bit, then exact mod → u32.
            u64 hi = u128Hi(op);
            u64 lo = u128Lo(op);
            // Reduce hi * 2^64 mod prime:  hi * (2^64 mod prime)
            u64 hi_red = mulModSimple(hi % static_cast<u64>(prime_),
                                      two_to_64_ % static_cast<u64>(prime_),
                                      static_cast<u64>(prime_));
            u64 combined = hi_red + lo;
            // Handle potential overflow from hi_red + lo.
            if (combined < lo)                                  // overflow
                combined = combined + static_cast<u64>(prime_); // won't wrap
            // Result is in [0, prime) — satisfies any OutputModFactor >= 1.
            return static_cast<U>(combined % static_cast<u64>(prime_));
        }
    }

    template <int OutputModFactor = 4> U mul(U op1, U op2) const {
        using Wide = typename UnitTypeTraits<U>::Wide;
        return reduceBarrett<OutputModFactor>(
            static_cast<u128>(static_cast<Wide>(op1) * static_cast<Wide>(op2)));
    }

    /**
     * @brief Raises base to expt mod prime using square-and-multiply.
     */
    U pow(U base, U expt) const {
        U res = U(1);
        while (expt > 0) {
            if (expt & 1)
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
    U inverse(U op) const { return pow(op, static_cast<U>(prime_ - 2)); }

    /**
     * @brief Multiplies each element of op1 by op2 modulo the prime.
     */
    void constMult(const U *op1, const U op2, U *res, Size array_size) const;

    /**
     * @brief Multiplies op1 by a scalar using the default array size.
     */
    void constMult(const U *op1, const U op2, U *res) const {
        constMult(op1, op2, res, default_array_size_);
    }

    /**
     * @brief Multiplies op1 by a scalar in-place.
     */
    void constMultInPlace(U *op1, const U op2) const {
        constMult(op1, op2, op1);
    }

    /**
     * @brief Element-wise modular multiplication of two arrays.
     */
    void mulVector(U *res, const U *op1, const U *op2, Size array_size) const;

    /**
     * @brief Multiplies two vectors element-wise using the default size.
     */
    void mulVector(U *res, const U *op1, const U *op2) const {
        mulVector(res, op1, op2, default_array_size_);
    }

    /**
     * @brief Applies the forward NTT, copying data when op and res differ.
     */
    inline void forwardNTT(U *op, U *res,
                           const NTTType ntt_type = NTTType::NEGACYCLIC) const {
        if (op != res)
            std::copy_n(op, default_array_size_, res);
        forwardNTT(res, ntt_type);
    }

    /**
     * @brief Applies the forward NTT in-place.  When @p cyclic is true the
     * cyclic NTT object is constructed on first use; this requires the
     * stored prime to be 4N-friendly.
     */
    inline void forwardNTT(U *op,
                           const NTTType ntt_type = NTTType::NEGACYCLIC) const {
        getNTT(ntt_type)->computeForward(op);
    }

    /**
     * @brief Applies the inverse NTT, copying data when op and res differ.
     */
    inline void
    backwardNTT(U *op, U *res,
                const NTTType ntt_type = NTTType::NEGACYCLIC) const {
        if (op != res)
            std::copy_n(op, default_array_size_, res);
        backwardNTT(res, ntt_type);
    }

    /**
     * @brief Applies the inverse NTT in-place.  See forwardNTT for the
     * lazy-construction note on @p cyclic.
     */
    inline void
    backwardNTT(U *op, const NTTType ntt_type = NTTType::NEGACYCLIC) const {
        getNTT(ntt_type)->computeBackward(op);
    }

    /**
     * @brief Returns the default vector size configured for this instance.
     */
    Size get_default_size() const { return default_array_size_; }
    /**
     * @brief Returns the Barrett exponent used for reduction.
     */
    u64 get_barrett_expt() const { return barrett_expt_; }
    /**
     * @brief Returns the Barrett ratio used for reduction (for mulVector).
     */
    u64 get_barrett_ratio() const { return barrett_ratio_; }

private:
    U prime_;
    U two_prime_;
    u64 barrett_expt_; // 2^(K-1) < prime < 2^K  (K = bit width)
    u64 barrett_ratio_;

    Size default_array_size_; // degree or dimension

    // floor(2^64 / prime) – used in reduceBarrett(U) for U=u64 and in
    // reduceBarrett(u128) for both types (via mul64To128Hi).
    u64 barrett_ratio_for_u64_;
    // floor(2^32 / prime) – used only in reduceBarrett(U) for U=u32.
    u32 barrett_ratio_for_u32_;
    // The following two fields are only used when U = u64
    // (reduceBarrett(u128)).
    u64 two_to_64_;       // 2^64 mod prime
    u64 two_to_64_shoup_; // floor(two_to_64 * 2^64 / prime)

    // Per-instance root_type override.
    NTTRootType root_type_;

    // Both NTT objects are built lazily on first use. This lets ModArith
    // instances constructed for primes that satisfy only one of the
    // congruence requirements (2N-friendly vs 4N-friendly) survive
    // construction; the mismatched mode only fails when it is actually
    // accessed. Construction tables (~degree-sized vectors) are also a
    // non-trivial cost, so deferring them helps when the caller never
    // exercises one of the modes.
    //
    // Held by base-class pointer so a user-registered NTTFactory<U> can
    // return any subclass (custom NTT backend) and still slot into both
    // negacyclic and cyclic accessor paths.
    mutable std::shared_ptr<NTT_base<U>> ntt_ = nullptr;
    mutable std::shared_ptr<NTT_base<U>> cyclic_ntt_ = nullptr;

    void ensureNegacyclicNTT() const {
        if (!ntt_) {
            ntt_ = createNTT<U>(default_array_size_, static_cast<u64>(prime_),
                                NTTType::NEGACYCLIC, getNTTRootType());
        }
    }

    void ensureCyclicNTT() const {
        if (!cyclic_ntt_) {
            cyclic_ntt_ =
                createNTT<U>(default_array_size_, static_cast<u64>(prime_),
                             NTTType::CYCLIC, getNTTRootType());
        }
    }
};

/**
 * @brief Applies the forward NTT to each PolyUnit in poly.
 */
template <Size D, typename U = u64>
void forwardNTT(const std::vector<ModArith<D, U>> &modarith,
                PolynomialT<U> &poly, Size num_polyunit = 0,
                NTTType ntt_type = utils::NTTType::NEGACYCLIC,
                [[maybe_unused]] bool expected_ntt_state = false);

/**
 * @brief Applies the inverse NTT to each PolyUnit.
 */
template <Size D, typename U = u64>
void backwardNTT(const std::vector<ModArith<D, U>> &modarith,
                 PolynomialT<U> &poly, Size num_polyunit = 0,
                 NTTType ntt_type = utils::NTTType::NEGACYCLIC,
                 [[maybe_unused]] bool expected_ntt_state = true);

/**
 * @brief Adds two polynomials coefficient-wise.
 */
template <Size D, typename U = u64>
void addPoly(const std::vector<ModArith<D, U>> &modarith,
             const PolynomialT<U> &op1, const PolynomialT<U> &op2,
             PolynomialT<U> &res, Size num_polyunit = 0);

template <Size D, typename U = u64>
void addPolyConst(const std::vector<ModArith<D, U>> &modarith,
                  const PolynomialT<U> &op1, const PolynomialT<U> &op2,
                  PolynomialT<U> &res, Size num_polyunit = 0);

/**
 * @brief Subtracts op2 from op1 coefficient-wise.
 */
template <Size D, typename U = u64>
void subPoly(const std::vector<ModArith<D, U>> &modarith,
             const PolynomialT<U> &op1, const PolynomialT<U> &op2,
             PolynomialT<U> &res, Size num_polyunit = 0);

/**
 * @brief Multiplies two polynomials in the NTT domain.
 */
template <Size D, typename U = u64>
void mulPoly(const std::vector<ModArith<D, U>> &modarith,
             const PolynomialT<U> &op1, const PolynomialT<U> &op2,
             PolynomialT<U> &res, Size num_polyunit = 0);

template <Size D, typename U = u64>
void mulPolyConst(const std::vector<ModArith<D, U>> &modarith,
                  const PolynomialT<U> &op1, const PolynomialT<U> &op2,
                  PolynomialT<U> &res, Size num_polyunit = 0);

/**
 * @brief Multiplies a polynomial by a scalar vector within index range.
 */
template <Size D, typename U = u64>
void constMulPoly(const std::vector<ModArith<D, U>> &modarith,
                  const PolynomialT<U> &op1, const U *op2, PolynomialT<U> &res,
                  Size s_id, Size e_id);

// ---------------------------------------------------------------------------
// Compile-time-prime polynomial kernels (u64)
//
// For a compile-time preset the whole modulus chain is a `static constexpr`
// array (PS::primes[]), but ModArith stores each prime as a runtime member, so
// the Barrett reduction in mulPoly/mulPolyConst reloads the modulus, ratio and
// shift as runtime values.  These header-only templates instead dispatch each
// polyunit's runtime prime to a loop body specialized on that *constant*
// prime, turning the modulus, Barrett ratio and shift amount into immediates.
// That is a measurable (~1.25-1.3x) win for the 64x64->128 Barrett multiply,
// and the per-polyunit dispatch (a short compare chain over the constexpr
// prime list) is amortized over the degree-long inner loop.
//
// PS is a trait type exposing `static constexpr u64 primes[]` and
// `static constexpr Size num_p`; PresetTraits<P, U> for a non-EMPTY P
// satisfies this through its preset base struct.  Any prime not found in the
// list falls back to the runtime Barrett path, so correctness never depends on
// the dispatch matching.
// ---------------------------------------------------------------------------

// Portable constexpr Barrett precomputation (mirrors ModArith's runtime ctor).
constexpr u64 ctBitWidth(u64 x) {
    u64 n = 0;
    while (x) {
        x >>= 1;
        ++n;
    }
    return n;
}
constexpr u64 ctBarrettExpt(u64 prime) { return ctBitWidth(prime) - 1; }
constexpr u64 ctBarrettRatio(u64 prime) {
    return static_cast<u64>(
        (static_cast<u128>(1) << (ctBarrettExpt(prime) + 63)) / prime);
}

// Walks PS::primes[] at compile time; when one matches the runtime prime it
// invokes f with that prime as an integral_constant (so the body specializes
// on it) and reports the match.
template <typename PS, Size I, typename Fn>
inline bool dispatchPrimeCT(u64 prime, Fn &&f) {
    if constexpr (I < static_cast<Size>(PS::num_p)) {
        constexpr u64 candidate = static_cast<u64>(PS::primes[I]);
        if (prime == candidate) {
            f(std::integral_constant<u64, candidate>{});
            return true;
        }
        return dispatchPrimeCT<PS, I + 1>(prime, std::forward<Fn>(f));
    } else {
        (void)prime;
        return false;
    }
}

// op1 * op2 in the NTT domain, with the Barrett modulus chosen at compile time
// per polyunit.  `LazyConstSub` selects subIfGEConst (branch-free) like
// mulPolyConst; otherwise subIfGE like mulPoly.
template <typename PS, bool LazyConstSub, Size D, typename U>
void mulPolyCTImpl(const std::vector<ModArith<D, U>> &modarith,
                   const PolynomialT<U> &op1, const PolynomialT<U> &op2,
                   PolynomialT<U> &res, Size num_polyunit) {
    static_assert(std::is_same_v<U, u64>,
                  "mulPolyCTImpl is only specialized for u64");
    PRAGMA_OMP(omp single) {
        res.setNTT(op1[0].getNTTType(), op1[0].getNTTRootType());
    }
    const auto degree = res[0].degree();
    num_polyunit = num_polyunit ? num_polyunit : res.size();

    PRAGMA_OMP(omp for schedule(static))
    for (Size i = 0; i < num_polyunit; ++i) {
        const U *a = op1[i].data();
        const U *b = op2[i].data();
        U *r = res[i].data();
        const u64 prime_rt = static_cast<u64>(modarith[i].getPrime());

        const bool matched = dispatchPrimeCT<PS, 0>(prime_rt, [&](auto pc) {
            constexpr u64 prime = decltype(pc)::value;
            constexpr u64 barr = ctBarrettRatio(prime);
            constexpr int shift = static_cast<int>(ctBarrettExpt(prime)) - 1;
            for (Size j = 0; j < degree; ++j) {
                u128 prod = mul64To128(a[j], b[j]);
                u64 c1 = u128Lo(prod >> shift);
                u64 c2 = mul64To128Hi(c1, barr);
                u64 c3 = u128Lo(prod) - c2 * prime;
                if constexpr (LazyConstSub)
                    r[j] = subIfGEConst(c3, prime);
                else
                    r[j] = subIfGE(c3, prime);
            }
        });

        if (!matched) {
            const u64 prime = prime_rt;
            const u64 barr = modarith[i].get_barrett_ratio();
            const int shift =
                static_cast<int>(modarith[i].get_barrett_expt()) - 1;
            for (Size j = 0; j < degree; ++j) {
                u128 prod = mul64To128(a[j], b[j]);
                u64 c1 = u128Lo(prod >> shift);
                u64 c2 = mul64To128Hi(c1, barr);
                u64 c3 = u128Lo(prod) - c2 * prime;
                if constexpr (LazyConstSub)
                    r[j] = subIfGEConst(c3, prime);
                else
                    r[j] = subIfGE(c3, prime);
            }
        }
    }
}

template <typename PS, Size D, typename U>
inline void mulPolyCT(const std::vector<ModArith<D, U>> &modarith,
                      const PolynomialT<U> &op1, const PolynomialT<U> &op2,
                      PolynomialT<U> &res, Size num_polyunit = 0) {
    mulPolyCTImpl<PS, /*LazyConstSub=*/false>(modarith, op1, op2, res,
                                              num_polyunit);
}

template <typename PS, Size D, typename U>
inline void mulPolyConstCT(const std::vector<ModArith<D, U>> &modarith,
                           const PolynomialT<U> &op1, const PolynomialT<U> &op2,
                           PolynomialT<U> &res, Size num_polyunit = 0) {
    mulPolyCTImpl<PS, /*LazyConstSub=*/true>(modarith, op1, op2, res,
                                             num_polyunit);
}

// ---------------------------------------------------------------------------
// Explicit-instantiation declaration macros
// ---------------------------------------------------------------------------

#define DECL_MODARITH_HELPER(degree, u_type, prefix)                           \
    prefix template class ModArith<degree, u_type>;                            \
    prefix template void forwardNTT(                                           \
        const std::vector<ModArith<degree, u_type>> &, PolynomialT<u_type> &,  \
        Size, NTTType, bool);                                                  \
    prefix template void backwardNTT(                                          \
        const std::vector<ModArith<degree, u_type>> &, PolynomialT<u_type> &,  \
        Size, NTTType, bool);                                                  \
    prefix template void addPoly(                                              \
        const std::vector<ModArith<degree, u_type>> &,                         \
        const PolynomialT<u_type> &, const PolynomialT<u_type> &,              \
        PolynomialT<u_type> &, Size);                                          \
    prefix template void addPolyConst(                                         \
        const std::vector<ModArith<degree, u_type>> &,                         \
        const PolynomialT<u_type> &, const PolynomialT<u_type> &,              \
        PolynomialT<u_type> &, Size);                                          \
    prefix template void subPoly(                                              \
        const std::vector<ModArith<degree, u_type>> &,                         \
        const PolynomialT<u_type> &, const PolynomialT<u_type> &,              \
        PolynomialT<u_type> &, Size);                                          \
    prefix template void mulPoly(                                              \
        const std::vector<ModArith<degree, u_type>> &,                         \
        const PolynomialT<u_type> &, const PolynomialT<u_type> &,              \
        PolynomialT<u_type> &, Size);                                          \
    prefix template void mulPolyConst(                                         \
        const std::vector<ModArith<degree, u_type>> &,                         \
        const PolynomialT<u_type> &, const PolynomialT<u_type> &,              \
        PolynomialT<u_type> &, Size);                                          \
    prefix template void constMulPoly(                                         \
        const std::vector<ModArith<degree, u_type>> &,                         \
        const PolynomialT<u_type> &, const u_type *, PolynomialT<u_type> &,    \
        Size, Size);

// Declare for u64 (default)
#ifdef DEB_U64
#define D(degree) DECL_MODARITH_HELPER(degree, u64, extern)
DEGREE_SET
#undef D
#endif

// Declare for u32
#ifdef DEB_U32
DECL_MODARITH_HELPER(1, u32, extern)
#endif

} // namespace deb::utils
