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
#include "utils/NTTConfig.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <set>
#include <vector>

namespace deb::utils {

void findPrimeFactors(std::set<u64> &s, u64 n);
u64 findPrimitiveRoot(u64 prime);

// ---------------------------------------------------------------------------
// NTT class hierarchy
// ---------------------------------------------------------------------------

/**
 * @brief Abstract base for number-theoretic transform implementations.
 *
 * Two concrete subclasses ship below: NTT<U> (negacyclic, evaluates at odd
 * powers of a primitive 2N-th root) and NTT_C<U> (cyclic, hem-compatible —
 * evaluates the CI subring of Z_q[X]/<X^{2N}+1> via an internal
 * conversion()/inversion() pair built on a primitive 4N-th root).
 *
 * Users may also derive their own subclass to plug in a custom NTT (e.g. an
 * SIMD variant or hardware-accelerated kernel) and register it via
 * setNTTFactory(); ModArith and friends will pick it up through createNTT().
 *
 * @tparam U Coefficient word type (u32 or u64).  For U = u32 the prime must
 *           be < 2^30 so intermediate butterfly values (up to 4·prime) fit.
 */
template <typename U = u64> class NTT_base {
public:
    virtual ~NTT_base() = default;

    NTT_base(const NTT_base &) = delete;
    NTT_base &operator=(const NTT_base &) = delete;
    NTT_base(NTT_base &&) = default;
    NTT_base &operator=(NTT_base &&) = default;

    /**
     * @brief Performs an in-place forward NTT on the supplied data.
     * @param op Pointer to coefficient array of length degree.
     */
    virtual void computeForward(U *op) const = 0;

    /**
     * @brief Performs an in-place inverse NTT on the supplied data.
     * @param op Pointer to coefficient array of length degree.
     */
    virtual void computeBackward(U *op) const = 0;

    NTTType getType() const noexcept { return type_; }
    NTTRootType getRootType() const noexcept { return root_type_; }
    u64 getDegree() const noexcept { return degree_; }
    U getPrime() const noexcept { return prime_; }

protected:
    NTT_base() = default;
    NTT_base(u64 degree, u64 prime, NTTType type, NTTRootType root_type);

    U prime_{};
    U two_prime_{};
    u64 degree_{0};
    NTTType type_{NTTType::NONNTT};
    NTTRootType root_type_{NTTRootType::MIN};
};

/**
 * @brief Negacyclic NTT — evaluates at odd powers of a primitive 2N-th root.
 *
 * Requires `prime ≡ 1 mod 2·degree`.
 */
template <typename U = u64> class NTT : public NTT_base<U> {
public:
    NTT() = default;

    /**
     * @brief Builds the negacyclic twiddle tables for (degree, prime).
     *
     * @param degree    Polynomial degree (must be a power of two).
     * @param prime     NTT-friendly prime (prime ≡ 1 mod 2·degree).
     * @param root_type Root-finding algorithm (defaults to current global).
     * @throws std::runtime_error if parameters are invalid or the requested
     *                            CUSTOM psi is missing.
     */
    NTT(u64 degree, u64 prime, NTTRootType root_type = getGlobalNTTRootType());

    void computeForward(U *op) const override;
    void computeBackward(U *op) const override;

private:
    using NTT_base<U>::prime_;
    using NTT_base<U>::two_prime_;
    using NTT_base<U>::degree_;

    std::vector<U> psi_rev_;
    std::vector<U> psi_inv_rev_;
    std::vector<U> psi_rev_shoup_;
    std::vector<U> psi_inv_rev_shoup_;

    U degree_inv_{};
    U degree_inv_barrett_{};
    U degree_inv_w_{};
    U degree_inv_w_barrett_{};
};

/**
 * @brief Cyclic, hem-compatible NTT.
 *
 * Picks a primitive 4N-th root ζ and builds the layered twiddle tables that
 * hem::NTT::CYCLIC uses, so deb and hem land on the same NTT-domain bins
 * for the same (prime, degree).
 *
 * Requires `prime ≡ 1 mod 4·degree`.
 */
template <typename U = u64> class NTT_C : public NTT_base<U> {
public:
    NTT_C() = default;

    /**
     * @brief Builds the cyclic twiddle tables for (degree, prime).
     *
     * @param degree    Polynomial degree (must be a power of two).
     * @param prime     NTT-friendly prime (prime ≡ 1 mod 4·degree).
     * @param root_type Root-finding algorithm (defaults to current global).
     *                  For CUSTOM, a 4N-th root must be registered under the
     *                  key (2*degree, prime).
     * @throws std::runtime_error if parameters are invalid or the requested
     *                            CUSTOM zeta is missing.
     */
    NTT_C(u64 degree, u64 prime,
          NTTRootType root_type = getGlobalNTTRootType());

    void computeForward(U *op) const override;
    void computeBackward(U *op) const override;

private:
    using NTT_base<U>::prime_;
    using NTT_base<U>::two_prime_;
    using NTT_base<U>::degree_;

    std::vector<U> psi_rev_;
    std::vector<U> psi_inv_rev_;
    std::vector<U> psi_rev_shoup_;
    std::vector<U> psi_inv_rev_shoup_;

    U degree_inv_{};
    U degree_inv_barrett_{};
    U degree_inv_w_{};
    U degree_inv_w_barrett_{};

    // CI <-> cyclic ring conversion tables (powers of the 4N-th root ζ).
    std::vector<U> roots_;
    std::vector<U> roots_inv_;
    std::vector<U> roots_shoup_;
    std::vector<U> roots_inv_shoup_;

    void conversion(U *op) const;
    void inversion(U *op) const;
};

/**
 * @brief Factory returning an NTT_base owning the appropriate concrete type.
 *
 * Use this only when the transform type must be chosen at runtime. When the
 * type is known at compile time, construct NTT<U> or NTT_C<U> directly.
 */
template <typename U = u64>
std::unique_ptr<NTT_base<U>>
makeNTT(u64 degree, u64 prime, NTTType type,
        NTTRootType root_type = getGlobalNTTRootType());

// Explicit instantiation declarations
#ifdef DEB_U32
extern template class NTT_base<u32>;
extern template class NTT<u32>;
extern template class NTT_C<u32>;
extern template std::unique_ptr<NTT_base<u32>> makeNTT<u32>(u64, u64, NTTType,
                                                            NTTRootType);
#endif
#ifdef DEB_U64
extern template class NTT_base<u64>;
extern template class NTT<u64>;
extern template class NTT_C<u64>;
extern template std::unique_ptr<NTT_base<u64>> makeNTT<u64>(u64, u64, NTTType,
                                                            NTTRootType);
#endif

// ---------------------------------------------------------------------------
// User-overridable NTT factory
// ---------------------------------------------------------------------------

/**
 * @brief Factory signature for producing NTT instances.
 *
 * Custom implementations should construct an object that satisfies
 * NTT_base<U> for the given (degree, prime, type, root_type) and return it
 * wrapped in a shared_ptr. Return an empty shared_ptr to delegate to the
 * default implementation for that particular combination (useful when the
 * custom backend only handles a subset of NTTType / NTTRootType values).
 */
template <typename U = u64>
using NTTFactory = std::function<std::shared_ptr<NTT_base<U>>(
    u64 degree, u64 prime, NTTType type, NTTRootType root_type)>;

/**
 * @brief Registers a custom NTT factory for word type @p U.
 *
 * Pass an empty/`nullptr` factory to revert to the default (makeNTT<U>).
 * Thread-safe.
 */
template <typename U = u64> void setNTTFactory(NTTFactory<U> factory);

/**
 * @brief Builds an NTT instance, dispatching through the registered factory
 *        (if any) or falling back to the default makeNTT<U>().
 *
 * Used internally by ModArith and friends so that a registered custom NTT
 * is honored everywhere a transform object is needed. If the registered
 * factory returns an empty shared_ptr the call also falls through to the
 * default — letting partial-coverage factories ignore types they don't
 * implement.
 */
template <typename U = u64>
std::shared_ptr<NTT_base<U>>
createNTT(u64 degree, u64 prime, NTTType type,
          NTTRootType root_type = getGlobalNTTRootType());

#ifdef DEB_U32
extern template void setNTTFactory<u32>(NTTFactory<u32>);
extern template std::shared_ptr<NTT_base<u32>> createNTT<u32>(u64, u64, NTTType,
                                                              NTTRootType);
#endif
#ifdef DEB_U64
extern template void setNTTFactory<u64>(NTTFactory<u64>);
extern template std::shared_ptr<NTT_base<u64>> createNTT<u64>(u64, u64, NTTType,
                                                              NTTRootType);
#endif

} // namespace deb::utils
