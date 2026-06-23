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

#include "utils/ModArith.hpp"

namespace deb {

template <Preset, typename U = u64> struct PresetTraits;
#define X(preset)                                                              \
    template <typename U>                                                      \
    struct PresetTraits<PRESET_##preset, U> : public preset {                  \
        PresetTraits() = delete;                                               \
        PresetTraits([[maybe_unused]] Preset p) {}                             \
        std::vector<utils::ModArith<preset::degree, U>> modarith;              \
    };
PRESET_LIST
#undef X

template <typename U> struct PresetTraits<PRESET_EMPTY, U> {
#define CV(type, var_name) type var_name;
    CONST_LIST
#undef CV
    PresetTraits() = delete;
    PresetTraits(Preset p) {
#define CV(type, var_name) this->var_name = get_##var_name(p);
        CONST_LIST
#undef CV
    }
    std::vector<utils::ModArith<1, U>> modarith;
};

// ---------------------------------------------------------------------------
// Preset-aware polynomial-multiply dispatch
//
// For a compile-time preset (P != PRESET_EMPTY) on u64, route the Barrett
// multiply kernels through the compile-time-prime specializations, which fold
// each polyunit's modulus/Barrett-ratio/shift into immediates.  The runtime
// preset (PRESET_EMPTY) and u32 keep the existing runtime kernels.  The
// `if constexpr` guard ensures the u128-bodied CT kernel is only instantiated
// for u64.  PresetTraits<P, U> supplies the constexpr `primes[]`/`num_p`.
// ---------------------------------------------------------------------------
template <Preset P, Size D, typename U>
inline void mulPolyP(const std::vector<utils::ModArith<D, U>> &modarith,
                     const PolynomialT<U> &op1, const PolynomialT<U> &op2,
                     PolynomialT<U> &res, Size num_polyunit = 0) {
    if constexpr (P != PRESET_EMPTY && std::is_same_v<U, u64>)
        utils::mulPolyCT<PresetTraits<P, U>>(modarith, op1, op2, res,
                                             num_polyunit);
    else
        utils::mulPoly(modarith, op1, op2, res, num_polyunit);
}

template <Preset P, Size D, typename U>
inline void mulPolyConstP(const std::vector<utils::ModArith<D, U>> &modarith,
                          const PolynomialT<U> &op1, const PolynomialT<U> &op2,
                          PolynomialT<U> &res, Size num_polyunit = 0) {
    if constexpr (P != PRESET_EMPTY && std::is_same_v<U, u64>)
        utils::mulPolyConstCT<PresetTraits<P, U>>(modarith, op1, op2, res,
                                                  num_polyunit);
    else
        utils::mulPolyConst(modarith, op1, op2, res, num_polyunit);
}

} // namespace deb
