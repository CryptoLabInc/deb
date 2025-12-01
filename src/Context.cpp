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

#include "Context.hpp"
#include "utils/Basic.hpp"

#include <cmath>
#ifdef DEB_OPENMP
#include <omp.h>
#endif

namespace deb {
// Mapping from preset enum to preset struct
Context getContext(Preset preset) {
    return ContextPool::GetInstance().get(preset);
}

bool isValidPreset([[maybe_unused]] Preset preset) {
#ifdef DEB_RESOURCE_CHECK
    switch (preset) {
#define X(NAME) case PRESET_##NAME:
        PRESET_LIST
        return true;
#undef X
    case PRESET_EMPTY:
    default:
        return false;
    }
    return false;
#else
    return true;
#endif
}

void setOmpThreadLimit([[__maybe_unused__]] int max_threads) {
#ifdef DEB_OPENMP
    int current = omp_get_max_threads();
    if (max_threads < current) {
        omp_set_num_threads(max_threads);
    }
#endif
}

void unsetOmpThreadLimit() {
#ifdef DEB_OPENMP
    omp_set_num_threads(omp_get_max_threads());
#endif
}

} // namespace deb
