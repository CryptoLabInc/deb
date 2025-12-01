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

#include "utils/ModArith.hpp"
#include "Macro.hpp"
#include "utils/Basic.hpp"

#include <algorithm>
#include <cmath>

#ifdef DEB_OPENMP
#include <omp.h>
#endif

namespace deb::utils {

ModArith::ModArith(Size size, u64 prime)
    : prime_(prime), two_prime_(prime << 1), barrett_expt_(bitWidth(prime) - 1),
      barrett_ratio_(static_cast<u64>(
          (static_cast<u128>(1) << (barrett_expt_ + 63)) / prime)),
      default_array_size_(size),
      barrett_ratio_for_u64_(divide128By64Lo(UINT64_C(1), UINT64_C(0), prime)),
      two_to_64_(powModSimple(2, 64, prime)),
      two_to_64_shoup_(divide128By64Lo(two_to_64_, UINT64_C(0), prime)),
      ntt_(std::make_unique<NTT>(size, prime)) {}

void ModArith::constMult(const u64 *op1, const u64 op2_big, u64 *res,
                         Size array_size) const {
    const u64 op2 = reduceBarrett(op2_big);

    u64 approx_quotient = divide128By64Lo(op2, UINT64_C(0), prime_);
    DEB_LOOP_UNROLL_4
    for (u64 i = 0; i < array_size; ++i) {
        res[i] = mulModLazy(op1[i], op2, approx_quotient, prime_);
        res[i] = subIfGE(res[i], prime_);
    }
}

void ModArith::mulVector(u64 *res, const u64 *op1, const u64 *op2,
                         Size array_size) const {
    const auto barr = this->barrett_ratio_;
    const int k_1 = static_cast<int>(this->barrett_expt_) - 1;

    for (u64 i = 0; i < array_size; ++i) {
        u128 prod = mul64To128(op1[i], op2[i]);
        u64 c1 = u128Lo(prod >> (k_1));
        u64 c2 = mul64To128Hi(c1, barr);
        u64 c3 = u128Lo(prod) - c2 * prime_;
        res[i] = subIfGE(c3, prime_);
    }
}

namespace {
template <typename Func, typename... Args>
inline void for_each_modarith(const std::vector<ModArith> &modarith, Func func,
                              Size size, Args... args) {
    PRAGMA_OMP(omp for schedule(static))
    for (Size i = 0; i < size; ++i) {
        func(modarith[i], getData(std::forward<Args>(args), i)...);
    }
};
} // namespace

void forwardNTT(const std::vector<ModArith> &modarith, Polynomial &poly,
                Size num_polyunit, [[maybe_unused]] bool expected_ntt_state) {
    deb_assert(poly[0].isNTT() == expected_ntt_state,
               "[forwardNTT] NTT state mismatch");
    num_polyunit = num_polyunit ? num_polyunit : poly.size();
    for_each_modarith(
        modarith, [](const ModArith &ma, u64 *p) { ma.forwardNTT(p); },
        num_polyunit, poly);
    for (Size i = 0; i < num_polyunit; ++i) {
        poly[i].setNTT(true);
    }
}

void backwardNTT(const std::vector<ModArith> &modarith, Polynomial &poly,
                 Size num_polyunit, [[maybe_unused]] bool expected_ntt_state) {
    deb_assert(poly[0].isNTT() == expected_ntt_state,
               "[backwardNTT] NTT state mismatch");
    num_polyunit = num_polyunit ? num_polyunit : poly.size();
    for_each_modarith(
        modarith, [](const ModArith &ma, u64 *p) { ma.backwardNTT(p); },
        num_polyunit, poly);
    for (Size i = 0; i < num_polyunit; ++i) {
        poly[i].setNTT(false);
    }
}

void addPoly(const std::vector<ModArith> &modarith, const Polynomial &op1,
             const Polynomial &op2, Polynomial &res, Size num_polyunit) {
    deb_assert(op1[0].isNTT() == op2[0].isNTT(),
               "[addPoly] operands NTT state mismatch");
    res.setNTT(op1[0].isNTT());

    const auto degree = res[0].degree();
    num_polyunit = num_polyunit ? num_polyunit : res.size();

    PRAGMA_OMP(omp for collapse(2) schedule(static))
    for (Size i = 0; i < num_polyunit; ++i) {
        for (Size j = 0; j < degree; ++j) {
            res[i][j] = subIfGE(op1[i][j] + op2[i][j], modarith[i].getPrime());
        }
    }
}

void subPoly(const std::vector<ModArith> &modarith, const Polynomial &op1,
             const Polynomial &op2, Polynomial &res, Size num_polyunit) {
    deb_assert(op1[0].isNTT() == op2[0].isNTT(),
               "[subPoly] operands NTT state mismatch");
    res.setNTT(op1[0].isNTT());

    const auto degree = res[0].degree();
    num_polyunit = num_polyunit ? num_polyunit : res.size();

    PRAGMA_OMP(omp for collapse(2) schedule(static))
    for (Size i = 0; i < num_polyunit; ++i) {
        for (Size j = 0; j < degree; ++j) {
            res[i][j] = (op1[i][j] >= op2[i][j])
                            ? op1[i][j] - op2[i][j]
                            : modarith[i].getPrime() - op2[i][j] + op1[i][j];
        }
    }
}

void mulPoly(const std::vector<ModArith> &modarith, const Polynomial &op1,
             const Polynomial &op2, Polynomial &res, Size num_polyunit) {
    deb_assert(op1[0].isNTT() == op2[0].isNTT(),
               "[mulPoly] operands NTT state mismatch");
    res.setNTT(op1[0].isNTT());

    const auto degree = res[0].degree();
    num_polyunit = num_polyunit ? num_polyunit : res.size();

    PRAGMA_OMP(omp for collapse(2) schedule(static))
    for (Size i = 0; i < num_polyunit; ++i) {
        for (Size j = 0; j < degree; ++j) {
            u128 prod = mul64To128(op1[i][j], op2[i][j]);
            u64 c1 = u128Lo(prod >> (modarith[i].get_barrett_expt() - 1));
            u64 c2 = mul64To128Hi(c1, modarith[i].get_barrett_ratio());
            u64 c3 = u128Lo(prod) - c2 * modarith[i].getPrime();
            res[i][j] = subIfGE(c3, modarith[i].getPrime());
        }
    }
}

void constMulPoly(const std::vector<ModArith> &modarith, const Polynomial &op1,
                  const u64 *op2, Polynomial &res, Size s_id, Size e_id) {
    res.setNTT(op1[0].isNTT());

    PRAGMA_OMP(omp for schedule(static))
    for (Size i = s_id; i < e_id; ++i) {
        modarith[i].constMult(op1[i].data(), op2[i], res[i].data());
    }
}
} // namespace deb::utils
