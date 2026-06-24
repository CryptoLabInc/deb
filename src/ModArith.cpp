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

#include "utils/ModArith.hpp"

#include <algorithm>
#include <cmath>

#ifdef DEB_OPENMP
#include <omp.h>
#endif

namespace deb::utils {

// ---------------------------------------------------------------------------
// ModArith<D, U> constructors
// ---------------------------------------------------------------------------

template <Size D, typename U>
ModArith<D, U>::ModArith(u64 prime, bool default_ntt_is_cyclic)
    : prime_(static_cast<U>(prime)), two_prime_(static_cast<U>(prime << 1)),
      barrett_expt_(bitWidth(prime) - 1),
      barrett_ratio_(static_cast<u64>(
          (static_cast<u128>(1) << (barrett_expt_ + 63)) / prime)),
      default_array_size_(D),
      barrett_ratio_for_u64_(divide128By64Lo(UINT64_C(1), UINT64_C(0), prime)),
      barrett_ratio_for_u32_(
          static_cast<u32>((static_cast<u64>(1) << 32) / prime)),
      two_to_64_(powModSimple(2, 64, prime)),
      two_to_64_shoup_(divide128By64Lo(two_to_64_, UINT64_C(0), prime)),
      root_type_(getGlobalNTTRootType()) {
    if constexpr (D == 1) {
        throw std::runtime_error("[ModArith] Degree template parameter must be "
                                 "non-zero when degree is not specified");
    }
    if (default_ntt_is_cyclic) {
        ensureCyclicNTT();
    } else {
        ensureNegacyclicNTT();
    }
}

template <Size D, typename U>
ModArith<D, U>::ModArith(Size actual_degree, u64 prime,
                         bool default_ntt_is_cyclic)
    : DegreeTrait<D>(actual_degree), prime_(static_cast<U>(prime)),
      two_prime_(static_cast<U>(prime << 1)),
      barrett_expt_(bitWidth(prime) - 1),
      barrett_ratio_(static_cast<u64>(
          (static_cast<u128>(1) << (barrett_expt_ + 63)) / prime)),
      default_array_size_(actual_degree),
      barrett_ratio_for_u64_(divide128By64Lo(UINT64_C(1), UINT64_C(0), prime)),
      barrett_ratio_for_u32_(
          static_cast<u32>((static_cast<u64>(1) << 32) / prime)),
      two_to_64_(powModSimple(2, 64, prime)),
      two_to_64_shoup_(divide128By64Lo(two_to_64_, UINT64_C(0), prime)),
      root_type_(getGlobalNTTRootType()) {
    if (default_ntt_is_cyclic) {
        ensureCyclicNTT();
    } else {
        ensureNegacyclicNTT();
    }
}

// ---------------------------------------------------------------------------
// constMult
// ---------------------------------------------------------------------------

template <Size D, typename U>
void ModArith<D, U>::constMult(const U *op1, const U op2_big, U *res,
                               Size array_size) const {
    const U op2 = reduceBarrett(op2_big);

    // Compute Shoup precomputed value for op2
    const U op2_shoup = computeShoup(op2, prime_);

    DEB_LOOP_UNROLL_4
    for (u64 i = 0; i < array_size; ++i) {
        res[i] = mulModLazy(op1[i], op2, op2_shoup, prime_);
        res[i] = subIfGE(res[i], prime_);
    }
}

// ---------------------------------------------------------------------------
// mulVector
// ---------------------------------------------------------------------------

template <Size D, typename U>
void ModArith<D, U>::mulVector(U *res, const U *op1, const U *op2,
                               Size array_size) const {
    if constexpr (std::is_same_v<U, u64>) {
        // Existing 128-bit Barrett algorithm
        const auto barr = this->barrett_ratio_;
        const int k_1 = static_cast<int>(this->barrett_expt_) - 1;

        for (u64 i = 0; i < array_size; ++i) {
            u128 prod = mul64To128(op1[i], op2[i]);
            u64 c1 = u128Lo(prod >> (k_1));
            u64 c2 = mul64To128Hi(c1, barr);
            u64 c3 = u128Lo(prod) - c2 * prime_;
            res[i] = subIfGEConst(c3, prime_);
        }
    } else {
        // U = u32: product fits in u64; use 64-bit Barrett with precomputed
        // floor(2^64 / prime).
        const u64 barr = this->barrett_ratio_for_u64_;
        const u64 prime64 = static_cast<u64>(prime_);

        for (u64 i = 0; i < array_size; ++i) {
            u64 prod = static_cast<u64>(op1[i]) * op2[i];
            u64 q = mul64To128Hi(prod, barr); // approx quotient
            u64 r = prod - q * prime64;
            res[i] = static_cast<U>(subIfGE<u64>(r, prime64));
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: iterate over each PolyUnit applying a unary function
// ---------------------------------------------------------------------------
namespace {
template <Size D, typename U, typename Func, typename... Args>
inline void for_each_modarith(const std::vector<ModArith<D, U>> &modarith,
                              Func func, Size size, Args... args) {
    PRAGMA_OMP(omp for schedule(static))
    for (Size i = 0; i < size; ++i) {
        func(modarith[i], getData(std::forward<Args>(args), i)...);
    }
};
} // namespace

// ---------------------------------------------------------------------------
// forwardNTT / backwardNTT
// ---------------------------------------------------------------------------

template <Size D, typename U>
void forwardNTT(const std::vector<ModArith<D, U>> &modarith,
                PolynomialT<U> &poly, Size num_polyunit, NTTType ntt_type,
                [[maybe_unused]] bool expected_ntt_state) {
    deb_assert(poly[0].isNTT() == expected_ntt_state,
               "[forwardNTT] NTT state mismatch");
    deb_assert(ntt_type != NTTType::NONNTT,
               "[forwardNTT] Invalid NTT type: NONNTT");
    num_polyunit = num_polyunit ? num_polyunit : poly.size();
    for_each_modarith(
        modarith,
        [ntt_type](const ModArith<D, U> &ma, U *p) {
            ma.forwardNTT(p, ntt_type);
        },
        num_polyunit, poly);
    for (Size i = 0; i < num_polyunit; ++i) {
        poly[i].setNTT(modarith[i].getNTT(ntt_type)->getType(),
                       modarith[i].getNTT(ntt_type)->getRootType());
    }
}

template <Size D, typename U>
void backwardNTT(const std::vector<ModArith<D, U>> &modarith,
                 PolynomialT<U> &poly, Size num_polyunit, NTTType ntt_type,
                 [[maybe_unused]] bool expected_ntt_state) {
    deb_assert(poly[0].isNTT() == expected_ntt_state,
               "[backwardNTT] NTT state mismatch");
    deb_assert(
        ntt_type == poly[0].getNTTType(),
        "[backwardNTT] NTT type mismatch between ModArith and polynomial");
    num_polyunit = num_polyunit ? num_polyunit : poly.size();
    for_each_modarith(
        modarith,
        [ntt_type](const ModArith<D, U> &ma, U *p) {
            ma.backwardNTT(p, ntt_type);
        },
        num_polyunit, poly);
    for (Size i = 0; i < num_polyunit; ++i) {
        poly[i].setNTT(utils::NTTType::NONNTT);
    }
}

// ---------------------------------------------------------------------------
// Polynomial arithmetic
// ---------------------------------------------------------------------------

// Shared body for addPoly / addPolyConst.  They differ only in the modular
// reduction: `LazyConstSub` selects the branch-free subIfGEConst
// (addPolyConst), otherwise the branching subIfGE (addPoly).  Selection is a
// compile-time constant resolved by `if constexpr`, so each instantiation
// generates the same machine code as a hand-written separate function.
template <bool LazyConstSub, Size D, typename U>
static void addPolyImpl(const std::vector<ModArith<D, U>> &modarith,
                        const PolynomialT<U> &op1, const PolynomialT<U> &op2,
                        PolynomialT<U> &res, Size num_polyunit) {
    deb_assert(op1[0].isNTT() == op2[0].isNTT(),
               "[addPoly] operands NTT state mismatch");
    PRAGMA_OMP(omp single) {
        res.setNTT(op1[0].getNTTType(), op1[0].getNTTRootType());
    }

    const auto degree = res[0].degree();
    num_polyunit = num_polyunit ? num_polyunit : res.size();

    // Outer worksharing over polyunits; the inner coefficient loop is a clean
    // affine loop over raw pointers with the prime hoisted, so it
    // auto-vectorizes (collapse(2) defeats that and forces per-element index
    // recovery).
    PRAGMA_OMP(omp for schedule(static))
    for (Size i = 0; i < num_polyunit; ++i) {
        const U prime = modarith[i].getPrime();
        const U *a = op1[i].data();
        const U *b = op2[i].data();
        U *r = res[i].data();
        for (Size j = 0; j < degree; ++j) {
            if constexpr (LazyConstSub)
                r[j] = subIfGEConst(static_cast<U>(a[j] + b[j]), prime);
            else
                r[j] = subIfGE(static_cast<U>(a[j] + b[j]), prime);
        }
    }
}

template <Size D, typename U>
void addPoly(const std::vector<ModArith<D, U>> &modarith,
             const PolynomialT<U> &op1, const PolynomialT<U> &op2,
             PolynomialT<U> &res, Size num_polyunit) {
    addPolyImpl</*LazyConstSub=*/false>(modarith, op1, op2, res, num_polyunit);
}

template <Size D, typename U>
void addPolyConst(const std::vector<ModArith<D, U>> &modarith,
                  const PolynomialT<U> &op1, const PolynomialT<U> &op2,
                  PolynomialT<U> &res, Size num_polyunit) {
    addPolyImpl</*LazyConstSub=*/true>(modarith, op1, op2, res, num_polyunit);
}

template <Size D, typename U>
void subPoly(const std::vector<ModArith<D, U>> &modarith,
             const PolynomialT<U> &op1, const PolynomialT<U> &op2,
             PolynomialT<U> &res, Size num_polyunit) {
    deb_assert(op1[0].isNTT() == op2[0].isNTT(),
               "[subPoly] operands NTT state mismatch");
    PRAGMA_OMP(omp single) {
        res.setNTT(op1[0].getNTTType(), op1[0].getNTTRootType());
    }

    const auto degree = res[0].degree();
    num_polyunit = num_polyunit ? num_polyunit : res.size();

    PRAGMA_OMP(omp for schedule(static))
    for (Size i = 0; i < num_polyunit; ++i) {
        const U prime = modarith[i].getPrime();
        const U *a = op1[i].data();
        const U *b = op2[i].data();
        U *r = res[i].data();
        for (Size j = 0; j < degree; ++j) {
            const U tmp = static_cast<U>(a[j] - b[j]);
            // mask is all-ones if a[j] < b[j], 0 otherwise
            const U mask = static_cast<U>(
                ~((tmp >> (UnitTypeTraits<U>::bits - 1)) - U(1)));
            r[j] = static_cast<U>(tmp + (prime & mask));
        }
    }
}

// Shared body for mulPoly / mulPolyConst.  The two differ only in the final
// modular reduction: `LazyConstSub` selects the branch-free subIfGEConst
// (mulPolyConst), otherwise the branching subIfGE (mulPoly).  Selection is a
// compile-time constant resolved by `if constexpr`, so each instantiation
// generates the same machine code as a hand-written separate function.
template <bool LazyConstSub, Size D, typename U>
static void mulPolyImpl(const std::vector<ModArith<D, U>> &modarith,
                        const PolynomialT<U> &op1, const PolynomialT<U> &op2,
                        PolynomialT<U> &res, Size num_polyunit) {
    deb_assert(op1[0].isNTT() == op2[0].isNTT(),
               "[mulPoly] operands NTT state mismatch");
    PRAGMA_OMP(omp single) {
        res.setNTT(op1[0].getNTTType(), op1[0].getNTTRootType());
    }

    const auto degree = res[0].degree();
    num_polyunit = num_polyunit ? num_polyunit : res.size();

    if constexpr (std::is_same_v<U, u64>) {
        PRAGMA_OMP(omp for schedule(static))
        for (Size i = 0; i < num_polyunit; ++i) {
            const u64 prime = static_cast<u64>(modarith[i].getPrime());
            const u64 barr = modarith[i].get_barrett_ratio();
            const int shift =
                static_cast<int>(modarith[i].get_barrett_expt()) - 1;
            const U *a = op1[i].data();
            const U *b = op2[i].data();
            U *r = res[i].data();
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
    } else {
        // U = u32
        PRAGMA_OMP(omp for schedule(static))
        for (Size i = 0; i < num_polyunit; ++i) {
            const u64 barr = modarith[i].get_barrett_ratio_for_u64();
            const u64 prime64 = static_cast<u64>(modarith[i].getPrime());
            const U *a = op1[i].data();
            const U *b = op2[i].data();
            U *r = res[i].data();
            for (Size j = 0; j < degree; ++j) {
                u64 prod = static_cast<u64>(a[j]) * b[j];
                u64 q = mul64To128Hi(prod, barr);
                u64 rr = prod - q * prime64;
                if constexpr (LazyConstSub)
                    r[j] = static_cast<U>(subIfGEConst<u64>(rr, prime64));
                else
                    r[j] = static_cast<U>(subIfGE<u64>(rr, prime64));
            }
        }
    }
}

template <Size D, typename U>
void mulPoly(const std::vector<ModArith<D, U>> &modarith,
             const PolynomialT<U> &op1, const PolynomialT<U> &op2,
             PolynomialT<U> &res, Size num_polyunit) {
    mulPolyImpl</*LazyConstSub=*/false>(modarith, op1, op2, res, num_polyunit);
}

template <Size D, typename U>
void mulPolyConst(const std::vector<ModArith<D, U>> &modarith,
                  const PolynomialT<U> &op1, const PolynomialT<U> &op2,
                  PolynomialT<U> &res, Size num_polyunit) {
    mulPolyImpl</*LazyConstSub=*/true>(modarith, op1, op2, res, num_polyunit);
}

template <Size D, typename U>
void constMulPoly(const std::vector<ModArith<D, U>> &modarith,
                  const PolynomialT<U> &op1, const U *op2, PolynomialT<U> &res,
                  Size s_id, Size e_id) {
    PRAGMA_OMP(omp single) {
        res.setNTT(op1[0].getNTTType(), op1[0].getNTTRootType());
    }

    PRAGMA_OMP(omp for schedule(static))
    for (Size i = s_id; i < e_id; ++i) {
        modarith[i].constMult(op1[i].data(), op2[i], res[i].data());
    }
}

// ---------------------------------------------------------------------------
// Explicit instantiations
// ---------------------------------------------------------------------------
// Define for u64 (default)
#ifdef DEB_U64
#define D(degree) DECL_MODARITH_HELPER(degree, u64, )
DEGREE_SET
#undef D
#endif

// Define for u32
#ifdef DEB_U32
DECL_MODARITH_HELPER(1, u32, )
#endif

} // namespace deb::utils
