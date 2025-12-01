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

#include <array>
#include <cstdint>
#include <vector>

namespace deb {
/**
 * @brief Lightweight view over contiguous memory similar to std::span.
 * @tparam T Element type.
 */
template <typename T> class span {
public:
    /**
     * @brief Creates a span pointing to @p ptr with @p size elements.
     */
    constexpr span(const T *ptr, std::size_t size) noexcept
        : ptr_(ptr), size_(size) {}

    /**
     * @brief Creates a single-element span around @p ptr.
     */
    constexpr span(const T *ptr) : ptr_(ptr), size_(1) {}

    /**
     * @brief Creates a span that views the contents of a std::vector.
     */
    constexpr span(const std::vector<T> &vec)
        : ptr_(vec.data()), size_(vec.size()) {}

    template <uint32_t N>
    /**
     * @brief Creates a span over a std::array with @p N elements.
     */
    constexpr span(const std::array<T, N> &arr) noexcept
        : ptr_(arr.data()), size_(N) {}

    /**
     * @brief Returns a const iterator to the first element.
     */
    constexpr const T *begin() const noexcept { return ptr_; }
    /**
     * @brief Returns a const iterator past the last element.
     */
    constexpr const T *end() const noexcept { return ptr_ + size_; }

    /**
     * @brief Returns a mutable iterator to the first element.
     */
    constexpr T *begin() noexcept { return const_cast<T *>(ptr_); }
    /**
     * @brief Returns a mutable iterator past the last element.
     */
    constexpr T *end() noexcept { return const_cast<T *>(ptr_ + size_); }

    /**
     * @brief Number of elements referenced by the span.
     */
    constexpr std::size_t size() const noexcept { return size_; }

    /**
     * @brief Provides mutable element access with no bounds checks.
     */
    constexpr T &operator[](std::size_t index) {
        return const_cast<T &>(ptr_[index]);
    }

    /**
     * @brief Provides read-only element access with no bounds checks.
     */
    const T &operator[](std::size_t index) const { return ptr_[index]; }

    /**
     * @brief Returns the underlying pointer.
     */
    constexpr T *data() const noexcept { return const_cast<T *>(ptr_); }

    /**
     * @brief Returns a subspan starting at @p offset with at most @p count
     * elements.
     * @param offset Starting index relative to this span.
     * @param count Maximum number of elements to include (-1 for remainder).
     * @return Span referencing the requested region (may be empty).
     */
    constexpr span<T>
    subspan(std::size_t offset,
            std::size_t count = static_cast<std::size_t>(-1)) const {
        if (offset >= size_)
            return span<T>(ptr_, 0);
        std::size_t new_size =
            (count == static_cast<std::size_t>(-1)) ? (size_ - offset) : count;
        return span<T>(ptr_ + offset, std::min(new_size, size_ - offset));
    }

private:
    const T *ptr_;
    const std::size_t size_;
};
} // namespace deb
