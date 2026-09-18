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

#include "utils/OmpUtils.hpp"

#include <cstdlib>
#ifdef DEB_OPENMP
#include <omp.h>
#endif

namespace deb::utils {
#ifdef DEB_OPENMP
// Only the OpenMP paths below touch this; declaring it unconditionally makes it
// an unused variable in a build without OpenMP.
static thread_local int tl_omp_threads = -1;
#endif

void setOmpThreadLimit([[maybe_unused]] int max_threads) {
#ifdef DEB_OPENMP
    int current = omp_get_max_threads();
    if (tl_omp_threads == -1) {
        tl_omp_threads = current;
    }
    if (max_threads < current) {
        omp_set_num_threads(max_threads);
    }
#endif
}

void unsetOmpThreadLimit() {
#ifdef DEB_OPENMP
    if (tl_omp_threads != -1) {
        omp_set_num_threads(tl_omp_threads);
        tl_omp_threads = -1;
    } else {
        const char *env_p = std::getenv("OMP_NUM_THREADS");
        if (env_p != nullptr) {
            int env_threads = std::atoi(env_p);
            omp_set_num_threads(env_threads);
        }
    }
#endif
}

namespace {
// Thin wrappers that keep the #ifdef out of OmpThreadLimitGuard, so the guard
// reads both of its members in every build configuration. Guarding the member
// accesses instead would leave them untouched without OpenMP, and silencing
// that needs [[maybe_unused]] on a non-static data member -- which GCC ignores
// with a warning.
int currentThreadCount() {
#ifdef DEB_OPENMP
    return omp_get_max_threads();
#else
    return 0;
#endif
}

void applyThreadCount([[maybe_unused]] int threads) {
#ifdef DEB_OPENMP
    omp_set_num_threads(threads);
#endif
}
} // namespace

OmpThreadLimitGuard::OmpThreadLimitGuard(int max_threads)
    : prev_(currentThreadCount()), applied_(false) {
    // Without OpenMP the current count reads as 0, so no limit is ever applied
    // and the guard is inert.
    if (max_threads < prev_) {
        applied_ = true;
        applyThreadCount(max_threads);
    }
}

OmpThreadLimitGuard::~OmpThreadLimitGuard() {
    if (applied_) {
        applyThreadCount(prev_);
    }
}

} // namespace deb::utils
