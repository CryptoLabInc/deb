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

namespace deb::utils {
/**
 * @brief Sets an OpenMP thread limit for the current process.
 * @param max_threads Maximum number of threads; implementation-defined.
 */
void setOmpThreadLimit(int max_threads);
/**
 * @brief Removes any OpenMP thread limit previously applied.
 */
void unsetOmpThreadLimit();

/**
 * @brief Scope guard applying an OpenMP thread limit for its lifetime.
 *
 * The limit is applied only when @p max_threads is below the number of
 * threads in effect at construction. Each guard remembers the value that
 * was in effect when it was constructed and restores exactly that value in
 * its destructor, so nested guards unwind correctly and an exception thrown
 * inside the guarded region cannot leave the limit applied.
 */
class OmpThreadLimitGuard {
public:
    /**
     * @brief Applies the thread limit if it is lower than the current one.
     * @param max_threads Maximum number of threads; implementation-defined.
     */
    explicit OmpThreadLimitGuard(int max_threads);
    /**
     * @brief Restores the thread count in effect at construction, if the
     * guard applied a limit. Does not throw.
     */
    ~OmpThreadLimitGuard();

    OmpThreadLimitGuard(const OmpThreadLimitGuard &) = delete;
    OmpThreadLimitGuard &operator=(const OmpThreadLimitGuard &) = delete;

private:
    /// Thread count to restore; meaningful only when applied_ is true.
    int prev_;
    /// Whether this guard actually changed the thread count.
    bool applied_;
};

} // namespace deb::utils
