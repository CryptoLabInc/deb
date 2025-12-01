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

#include "Types.hpp"

#include "DebParam.hpp"
#include "Macro.hpp"
#include "utils/Span.hpp"

#include <memory>
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

/**
 * @brief Compile-time context wrapper exposing preset constants via accessors.
 */
template <typename PRESET> struct ContextT : public PRESET {
#define CV(type, var_name)                                                     \
    static constexpr type get_##var_name() { return PRESET::var_name; }
    CONST_LIST
#undef CV
};

/**
 * @brief Variant capable of holding any preset-specific context view.
 */
using VariantCtx = std::variant<
#define X(PRESET) ContextT<PRESET>,
    PRESET_LIST
#undef X
        ContextT<EMPTY>>;

/**
 * @brief Runtime context content that dispatches to preset-specific variants.
 */
struct ContextContent {
    VariantCtx v;
#define CV(type, var_name)                                                     \
    constexpr type get_##var_name() const {                                    \
        return std::visit(                                                     \
            [](auto &&ctx) -> type { return ctx.get_##var_name(); }, v);       \
    }
    CONST_LIST
#undef CV
};

/**
 * @brief Shared pointer alias referencing runtime context data.
 */
using Context = std::shared_ptr<ContextContent>;

// Singleton ContextPool to manage Context instances
/**
 * @brief Provides singleton access to preset contexts.
 */
class ContextPool {
public:
    /**
     * @brief Accesses the singleton context pool.
     * @return Reference to the singleton instance.
     */
    static ContextPool &GetInstance() {
        static ContextPool instance;
        return instance;
    }

    /**
     * @brief Retrieves the shared context for a preset.
     * @param preset Requested preset.
     * @return Shared context pointer.
     * @throws std::runtime_error When the preset is unknown.
     */
    Context get(Preset preset) {
        if (auto it = map_.find(preset); it != map_.end()) {
            return it->second;
        }
        throw std::runtime_error("Preset not found in ContextPool");
    }

private:
    ContextPool() {
#define X(PRESET)                                                              \
    map_[PRESET_##PRESET] = std::make_shared<ContextContent>(                  \
        ContextContent{VariantCtx{ContextT<PRESET>{}}});
        PRESET_LIST
#undef X
    }
    std::unordered_map<Preset, Context> map_;
};

/**
 * @brief Retrieves the shared context for a preset.
 * @param preset Requested preset.
 * @return Shared context pointer.
 */
Context getContext(Preset preset);

/**
 * @brief Checks whether a preset enum value is supported.
 * @param preset Preset to validate.
 * @return True if the preset exists.
 */
bool isValidPreset(Preset preset);

/**
 * @brief Sets an OpenMP thread limit for the current process.
 * @param max_threads Maximum number of threads; implementation-defined.
 */
void setOmpThreadLimit(int max_threads);
/**
 * @brief Removes any OpenMP thread limit previously applied.
 */
void unsetOmpThreadLimit();

} // namespace deb
