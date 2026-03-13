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

#include "DebParam.hpp"
#include "Types.hpp"
#include "utils/Macro.hpp"

#include <memory>
#include <unordered_map>
#include <variant>

// Define preset values and precomputed values from preset values.
#define CONST_LIST                                                             \
    CV(Preset, preset)                                                         \
    CV(Preset, parent)                                                         \
    CV(const char *, preset_name)                                              \
    CV(Size, rank)                                                             \
    CV(Size, num_secret)                                                       \
    CV(Size, log_degree)                                                       \
    CV(Size, degree)                                                           \
    CV(Size, num_slots)                                                        \
    CV(Size, gadget_rank)                                                      \
    CV(Size, num_base)                                                         \
    CV(Size, num_qp)                                                           \
    CV(Size, num_tp)                                                           \
    CV(Size, num_p)                                                            \
    CV(Size, encryption_level)                                                 \
    CV(Size, hamming_weight)                                                   \
    CV(Real, gaussian_error_stdev)                                             \
    CV(const u64 *, primes)                                                    \
    CV(const Real *, scale_factors)

namespace deb {

using PresetVariant = std::variant<
#define X(p) p,
    PRESET_LIST
#undef X
        EMPTY>;

inline std::unordered_map<Preset, PresetVariant> preset_map = {
#define X(p) {PRESET_##p, p{}},
    PRESET_LIST_WITH_EMPTY
#undef X
};

// Getter functions for constant values from presets.
#define CV(type, var_name) type get_##var_name(Preset preset);
CONST_LIST
#undef CV

} // namespace deb
