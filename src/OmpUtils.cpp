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
static int g_omp_threads = -1;

void setOmpThreadLimit([[__maybe_unused__]] int max_threads) {
#ifdef DEB_OPENMP
    int current = omp_get_max_threads();
    if (g_omp_threads == -1) {
        g_omp_threads = current;
    }
    if (max_threads < current) {
        omp_set_num_threads(max_threads);
    }
#endif
}

void unsetOmpThreadLimit() {
#ifdef DEB_OPENMP
    if (g_omp_threads != -1) {
        omp_set_num_threads(g_omp_threads);
        g_omp_threads = -1;
    } else {
        const char *env_p = std::getenv("OMP_NUM_THREADS");
        if (env_p != nullptr) {
            int env_threads = std::atoi(env_p);
            omp_set_num_threads(env_threads);
        }
    }
#endif
}

} // namespace deb::utils
