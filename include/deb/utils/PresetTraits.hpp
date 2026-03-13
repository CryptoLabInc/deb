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

template <Preset> struct PresetTraits;
#define X(preset)                                                              \
    template <> struct PresetTraits<PRESET_##preset> : public preset {         \
        PresetTraits() = delete;                                               \
        PresetTraits([[maybe_unused]] Preset p) {}                             \
        std::vector<utils::ModArith<preset::degree>> modarith;                 \
    };
PRESET_LIST
#undef X

template <> struct PresetTraits<PRESET_EMPTY> {
#define CV(type, var_name) type var_name;
    CONST_LIST
#undef CV
    PresetTraits() = delete;
    PresetTraits(Preset p) {
#define CV(type, var_name) this->var_name = get_##var_name(p);
        CONST_LIST
#undef CV
    }
    std::vector<utils::ModArith<1>> modarith;
};

} // namespace deb
