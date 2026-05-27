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

#include "utils/NTTConfig.hpp"

#include "utils/Basic.hpp"

#include <atomic>
#include <map>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>

namespace deb::utils {

namespace {
// Default global root type is MIN, can be overridden by setGlobalNTTRootType().
std::atomic<NTTRootType> s_root_type{NTTRootType::MIN};
std::mutex s_custom_psi_mutex;
std::map<std::pair<u64, u64>, u64> s_custom_psi_registry;
} // namespace

void setGlobalNTTRootType(NTTRootType type) {
    s_root_type.store(type, std::memory_order_relaxed);
}

NTTRootType getGlobalNTTRootType() {
    return s_root_type.load(std::memory_order_relaxed);
}

void registerCustomPsi(u64 degree, u64 prime, u64 psi) {
    if (powModSimple(psi, 2 * degree, prime) != 1)
        throw std::invalid_argument("[NTT(CUSTOM)] registerCustomPsi: "
                                    "psi^(2*degree) != 1 mod prime.");
    if (powModSimple(psi, degree, prime) == 1)
        throw std::invalid_argument("[NTT(CUSTOM)] registerCustomPsi: psi "
                                    "is not a primitive 2*degree-th root "
                                    "(psi^degree == 1).");
    std::lock_guard<std::mutex> lock(s_custom_psi_mutex);
    s_custom_psi_registry[{degree, prime}] = psi;
}

namespace detail {
u64 lookupCustomPsi(u64 registry_key_degree, u64 prime, const char *ctx) {
    std::lock_guard<std::mutex> lock(s_custom_psi_mutex);
    auto it = s_custom_psi_registry.find({registry_key_degree, prime});
    if (it == s_custom_psi_registry.end())
        throw std::runtime_error(
            std::string("[NTT(CUSTOM)] ") + ctx +
            ": no custom root registered. Call registerCustomPsi() first.");
    return it->second;
}
} // namespace detail

} // namespace deb::utils
