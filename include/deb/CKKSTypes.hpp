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

#include "Preset.hpp"
#include "SeedGenerator.hpp"
#include "utils/NTTConfig.hpp"

#include <algorithm>
#include <complex>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace deb {

/**
 * @brief Complex number alias parameterized by scalar type.
 */
template <typename DataT> using ComplexT = std::complex<DataT>;
/**
 * @brief Default complex type using @ref Real (double) precision.
 */
using Complex = ComplexT<Real>;

/**
 * @brief Generic container for messages parameterized by encoding and scalar
 * type.
 *
 * @tparam EncodeT Selects the domain layout (slot or coefficient).
 * @tparam DataT Underlying scalar representation (e.g., double, float) for
 * stored values.
 */
template <EncodingType EncodeT, typename DataT> class MessageBase {
public:
    MessageBase() = delete;
    /**
     * @brief Allocates storage according to preset dimension metadata.
     * @param preset Target preset that governs sizing.
     */
    explicit MessageBase(const Preset preset) {
        if constexpr (EncodeT == EncodingType::SLOT) {
            data_.resize(get_num_slots(preset));
        } else if constexpr (EncodeT == EncodingType::COEFF) {
            data_.resize(get_degree(preset));
        }
    }
    /**
     * @brief Allocates a message with a specific size.
     * @param size Number of elements.
     */
    explicit MessageBase(const Size size);
    /**
     * @brief Allocates and initializes every element with @p init.
     * @param size Number of elements.
     * @param init Initial value per element.
     */
    explicit MessageBase(const Size size, const DataT &init);
    /**
     * @brief Copies content from an existing array.
     * @param size Number of elements.
     * @param array Pointer to source data of length @p size.
     */
    explicit MessageBase(const Size size, const DataT *array);
    /**
     * @brief Initializes content from an std::vector.
     * @param data Vector to copy into the message.
     */
    explicit MessageBase(std::vector<DataT> data);
    /**
     * @brief Returns mutable element access without bounds checks.
     * @param index Zero-based index; must be < size().
     */
    DataT &operator[](Size index) noexcept;
    /**
     * @brief Returns read-only element access without bounds checks.
     * @param index Zero-based index; must be < size().
     */
    DataT operator[](Size index) const noexcept;
    /**
     * @brief Returns a mutable pointer to the underlying data.
     */
    DataT *data() noexcept;
    /**
     * @brief Returns a const pointer to the underlying data.
     */
    const DataT *data() const noexcept;
    /**
     * @brief Number of elements stored in the message.
     */
    Size size() const noexcept;

private:
    std::vector<DataT> data_;
};

template <typename T>
using MessageImpl = MessageBase<EncodingType::SLOT, ComplexT<T>>;
template <typename DataT>
using CoeffMessageImpl = MessageBase<EncodingType::COEFF, DataT>;

using Message = MessageImpl<Real>;
using FMessage = MessageImpl<float>;
using CoeffMessage = CoeffMessageImpl<Real>;
using FCoeffMessage = CoeffMessageImpl<float>;

#define DECL_MESSAGE_TEMPLATE(encode_t, data_t, prefix)                        \
    prefix template MessageBase<encode_t, data_t>::MessageBase(                \
        const Size size);                                                      \
    prefix template MessageBase<encode_t, data_t>::MessageBase(                \
        const Size size, const data_t &init);                                  \
    prefix template MessageBase<encode_t, data_t>::MessageBase(                \
        const Size size, const data_t *array);                                 \
    prefix template MessageBase<encode_t, data_t>::MessageBase(                \
        std::vector<data_t> data);                                             \
    prefix template data_t *MessageBase<encode_t, data_t>::data() noexcept;    \
    prefix template const data_t *MessageBase<encode_t, data_t>::data()        \
        const noexcept;                                                        \
    prefix template data_t &MessageBase<encode_t, data_t>::operator[](         \
        Size index) noexcept;                                                  \
    prefix template data_t MessageBase<encode_t, data_t>::operator[](          \
        Size index) const noexcept;                                            \
    prefix template Size MessageBase<encode_t, data_t>::size() const noexcept;

#define MESSAGE_TYPE_TEMPLATE(prefix)                                          \
    DECL_MESSAGE_TEMPLATE(EncodingType::SLOT, ComplexT<Real>, prefix)          \
    DECL_MESSAGE_TEMPLATE(EncodingType::SLOT, ComplexT<float>, prefix)         \
    DECL_MESSAGE_TEMPLATE(EncodingType::COEFF, Real, prefix)                   \
    DECL_MESSAGE_TEMPLATE(EncodingType::COEFF, float, prefix)

MESSAGE_TYPE_TEMPLATE(extern)

// =========================================================================
// PolyUnitT<U>
// =========================================================================

/**
 * @brief Represents a per-prime polynomial segment used inside ciphertexts or
 * keys.
 *
 * @tparam U Coefficient word type (u32 or u64, default u64).
 */
template <typename U = u64> class PolyUnitT {
public:
    PolyUnitT() = delete;
    /**
     * @brief Initializes the unit for a preset at a specific modulus level.
     * @param preset Preset describes modulus chain metadata.
     * @param level Target modulus index.
     * @param alloc True to allocate storage, false to create a zero-allocated
     * object.
     */
    explicit PolyUnitT(const Preset preset, const Size level,
                       const bool alloc = true);

    /**
     * @brief Constructs a unit with explicit modulus and degree configuration.
     *
     * The prime is accepted as u64 for compatibility with preset tables; it is
     * narrowed to U internally.
     *
     * @param prime Prime modulus value.
     * @param degree Number of coefficients.
     * @param alloc True to allocate storage.
     */
    explicit PolyUnitT(u64 prime, Size degree, const bool alloc = true);

    /**
     * @brief Creates a full copy of the unit including coefficient storage.
     */
    PolyUnitT deepCopy() const;
    /**
     * @brief Updates the active modulus.
     * @param prime New prime modulus (u64, narrowed to U).
     */
    void setPrime(u64 prime) noexcept;
    /**
     * @brief Returns the current modulus.
     */
    U prime() const noexcept;
    /**
     * @brief Marks the coefficient representation as NTT, recording both the
     * cyclic kind and the root-finding algorithm used.
     */
    void setNTT(const utils::NTTType ntt_type,
                const utils::NTTRootType root_type =
                    utils::getGlobalNTTRootType()) noexcept;
    /**
     * @brief Returns true if the unit is in NTT domain.
     */
    bool isNTT() const noexcept;
    /**
     * @brief Returns the NTT type (NEGACYCLIC or CYCLIC). Meaningful only when
     * isNTT() is true.
     */
    utils::NTTType getNTTType() const noexcept;
    /**
     * @brief Returns the root-finding algorithm used when the NTT was applied.
     * Meaningful only when isNTT() is true.
     */
    utils::NTTRootType getNTTRootType() const noexcept;
    /**
     * @brief Number of coefficients available in this unit.
     */
    Size degree() const noexcept;
    /**
     * @brief Mutable coefficient accessor without bounds checks.
     */
    U &operator[](Size index) noexcept { return data_ptr_.get()[index]; }
    /**
     * @brief Const coefficient accessor without bounds checks.
     */
    U operator[](Size index) const noexcept { return data_ptr_.get()[index]; }
    /**
     * @brief Returns a mutable pointer to coefficient storage.
     */
    U *data() const noexcept { return data_ptr_.get(); }
    /**
     * @brief Sets an externally managed storage buffer.
     */
    void setData(U *new_data, Size size);

private:
    U prime_;
    // NTTType: NONNTT, NEGACYCLIC, CYCLIC
    utils::NTTType ntt_type_;
    // NTTRootType: MIN, DIRECT, CUSTOM
    utils::NTTRootType ntt_root_type_;
    Size degree_;
    std::shared_ptr<U[]> data_ptr_;
};

// =========================================================================
// PolynomialT<U>
// =========================================================================

/**
 * @brief Collection of PolyUnitT instances representing a multi-level
 * polynomial.
 *
 * @tparam U Coefficient word type (u32 or u64, default u64).
 */
template <typename U = u64> class PolynomialT {
public:
    PolynomialT() = delete;
    /**
     * @brief Constructs a polynomial for a preset with optional full level
     * allocation.
     */
    explicit PolynomialT(const Preset preset, const bool full_level = false);
    /**
     * @brief Constructs with a custom number of PolyUnitT entries.
     */
    explicit PolynomialT(const Preset preset, const Size custom_size);
    /**
     * @brief Copies slices of another polynomial.
     */
    explicit PolynomialT(const PolynomialT<U> &other, Size others_idx,
                         Size custom_size = 1);
    /**
     * @brief Produces a deep copy optionally limited to a prefix of units.
     */
    PolynomialT<U>
    deepCopy(std::optional<Size> num_polyunit = std::nullopt) const;
    /**
     * @brief Marks every unit as NTT, recording the cyclic kind and root
     * algorithm.
     */
    void setNTT(const utils::NTTType ntt_type,
                const utils::NTTRootType root_type =
                    utils::getGlobalNTTRootType()) noexcept;
    /**
     * @brief Updates current level metadata.
     */
    void setLevel(Preset preset, Size level);
    /**
     * @brief Current level index.
     */
    Size level() const noexcept;
    /**
     * @brief Adjusts the number of active PolyUnitT entries.
     */
    void setSize(Preset preset, Size size);
    /**
     * @brief Current number of PolyUnitT entries.
     */
    Size size() const noexcept;
    /**
     * @brief Mutable PolyUnitT accessor.
     */
    PolyUnitT<U> &operator[](size_t index) noexcept {
        return polyunits_[index];
    }
    /**
     * @brief Read-only PolyUnitT accessor.
     */
    const PolyUnitT<U> &operator[](size_t index) const noexcept {
        return polyunits_[index];
    }
    /**
     * @brief Mutable pointer to the first PolyUnitT.
     */
    PolyUnitT<U> *data() noexcept { return polyunits_.data(); }
    /**
     * @brief Const pointer to the first PolyUnitT.
     */
    const PolyUnitT<U> *data() const noexcept { return polyunits_.data(); }

private:
    std::vector<PolyUnitT<U>> polyunits_;

    /**
     * @brief Consecutive data pointer allocated and deallocated by this
     * PolynomialT. If nullptr, data is managed externally (or by polyunits_
     * themselves).
     */
    std::shared_ptr<U[]> dealloc_ptr_;
};

// =========================================================================
// CiphertextT<U>
// =========================================================================

/**
 * @brief Container for encrypted polynomials across modulus levels.
 *
 * @tparam U Coefficient word type (u32 or u64, default u64).
 */
template <typename U = u64> class CiphertextT {
public:
    CiphertextT() = delete;
    /**
     * @brief Allocates ciphertext metadata for a preset with default level.
     */
    explicit CiphertextT(const Preset preset);
    /**
     * @brief Allocates ciphertext with explicit level and number of
     * polynomials.
     */
    explicit CiphertextT(const Preset preset, const Size level,
                         std::optional<Size> num_poly = std::nullopt);
    /**
     * @brief Copies a subset of another ciphertext.
     */
    explicit CiphertextT(const CiphertextT<U> &other, Size others_idx);

    /**
     * @brief Produces a deep copy optionally restricted to some PolyUnitT
     * entries.
     */
    CiphertextT<U>
    deepCopy(std::optional<Size> num_polyunit = std::nullopt) const;

    /**
     * @brief Returns associated preset metadata.
     */
    Preset preset() const noexcept;
    /**
     * @brief Changes encoding metadata between slot and coefficient domains.
     */
    void setEncoding(EncodingType encoding);
    /**
     * @brief Current encoding metadata.
     */
    EncodingType encoding() const noexcept;
    /**
     * @brief Checks if ciphertext is in slot domain.
     */
    bool isSlot() const noexcept;
    /**
     * @brief Checks if ciphertext is in coefficient domain.
     */
    bool isCoeff() const noexcept;
    /**
     * @brief Sets NTT state for every polynomial.
     */
    void setNTT(const utils::NTTType ntt_type,
                const utils::NTTRootType root_type =
                    utils::getGlobalNTTRootType()) noexcept;
    /**
     * @brief Updates level metadata.
     */
    void setLevel(Size level);
    /**
     * @brief Current level index.
     */
    Size level() const noexcept;
    /**
     * @brief Resizes number of polynomials.
     */
    void setNumPolyunit(Size size);
    /**
     * @brief Returns number of component polynomials.
     */
    Size numPoly() const noexcept;
    /**
     * @brief Mutable polynomial accessor.
     */
    PolynomialT<U> &operator[](size_t index) noexcept { return polys_[index]; }
    /**
     * @brief Const polynomial accessor.
     */
    const PolynomialT<U> &operator[](size_t index) const noexcept {
        return polys_[index];
    }
    /**
     * @brief Mutable pointer to polynomial storage.
     */
    PolynomialT<U> *data() noexcept { return polys_.data(); }
    /**
     * @brief Const pointer to polynomial storage.
     */
    const PolynomialT<U> *data() const noexcept { return polys_.data(); }

private:
    Preset preset_;
    EncodingType encoding_;
    std::vector<PolynomialT<U>> polys_;
};

// =========================================================================
// SecretKeyT<U>
// =========================================================================

/**
 * @brief Holds secret key coefficients and polynomial decompositions.
 *
 * @tparam U Coefficient word type (u32 or u64, default u64).
 */
template <typename U = u64> class SecretKeyT {
public:
    SecretKeyT() = delete;
    SecretKeyT(const SecretKeyT<U> &other) = delete;
    SecretKeyT<U> &operator=(const SecretKeyT<U> &other) = delete;

    explicit SecretKeyT(Preset preset, const RNGSeed seed);
    explicit SecretKeyT(Preset preset, bool embedding = true);

    SecretKeyT(SecretKeyT<U> &&) noexcept;
    SecretKeyT<U> &operator=(SecretKeyT<U> &&) noexcept;

    ~SecretKeyT() noexcept;

    Preset preset() const noexcept;
    bool hasSeed() const noexcept;
    RNGSeed getSeed() const noexcept;
    void setSeed(const RNGSeed &seed) noexcept;
    void flushSeed() noexcept;

    /**
     * @brief Securely zeroes all sensitive key material in place.
     */
    void zeroize() noexcept;

    Size coeffsSize() const noexcept;
    void allocCoeffs();
    i8 &coeff(Size index) noexcept;
    i8 coeff(Size index) const noexcept;
    i8 *coeffs() noexcept;
    const i8 *coeffs() const noexcept;
    Size numPoly() const noexcept;
    void allocPolys(std::optional<Size> num_polyunit = std::nullopt);

    PolynomialT<U> &operator[](Size index) { return polys_[index]; }
    const PolynomialT<U> &operator[](Size index) const { return polys_[index]; }
    PolynomialT<U> *data() noexcept { return polys_.data(); }
    const PolynomialT<U> *data() const noexcept { return polys_.data(); }

private:
    Preset preset_;
    std::optional<RNGSeed> seed_;
    std::vector<i8> coeffs_;
    std::vector<PolynomialT<U>> polys_;
};

// =========================================================================
// SwitchKeyT<U>
// =========================================================================

/**
 * @brief Key used for switching ciphertexts between secret keys.
 *
 * @tparam U Coefficient word type (u32 or u64, default u64).
 */
template <typename U = u64> class SwitchKeyT {
public:
    SwitchKeyT() = delete;
    explicit SwitchKeyT(
        Preset preset, const SwitchKeyKind type,
        const std::optional<Size> rot_idx = std::nullopt,
        const utils::NTTType ntt_type = utils::NTTType::NEGACYCLIC);

    Preset preset() const noexcept;
    void setType(const SwitchKeyKind type) noexcept;
    SwitchKeyKind type() const noexcept;
    void setRotIdx(Size rot_idx) noexcept;
    Size rotIdx() const noexcept;
    Size dnum() const noexcept;

    void
    addAx(const Size num_polyunit, std::optional<Size> size = std::nullopt,
          const utils::NTTType ntt_type = utils::NTTType::NONNTT,
          const utils::NTTRootType root_type = utils::getGlobalNTTRootType());
    void addAx(const PolynomialT<U> &poly);
    void
    addBx(const Size num_polyunit, std::optional<Size> size = std::nullopt,
          const utils::NTTType ntt_type = utils::NTTType::NONNTT,
          const utils::NTTRootType root_type = utils::getGlobalNTTRootType());
    void addBx(const PolynomialT<U> &poly);
    void setAxNTT(const utils::NTTType ntt_type,
                  const utils::NTTRootType root_type =
                      utils::getGlobalNTTRootType()) noexcept;
    void setBxNTT(const utils::NTTType ntt_type,
                  const utils::NTTRootType root_type =
                      utils::getGlobalNTTRootType()) noexcept;
    Size axSize() const noexcept;
    Size bxSize() const noexcept;
    std::vector<PolynomialT<U>> &getAx() noexcept;
    const std::vector<PolynomialT<U>> &getAx() const noexcept;
    std::vector<PolynomialT<U>> &getBx() noexcept;
    const std::vector<PolynomialT<U>> &getBx() const noexcept;
    PolynomialT<U> &ax(Size index = 0) noexcept;
    const PolynomialT<U> &ax(Size index = 0) const noexcept;
    PolynomialT<U> &bx(Size index = 0) noexcept;
    const PolynomialT<U> &bx(Size index = 0) const noexcept;

private:
    Preset preset_;
    SwitchKeyKind type_;
    std::optional<Size> rot_idx_;
    Size dnum_;
    std::vector<PolynomialT<U>> ax_;
    std::vector<PolynomialT<U>> bx_;
};

// =========================================================================
//  Explicit instantiation declarations and aliases
// =========================================================================

// Explicit instantiation declarations
#define DEB_DATASTRUCTURES                                                     \
    X(PolyUnit) X(Polynomial) X(Ciphertext) X(SecretKey) X(SwitchKey)

#ifdef DEB_U64
#define X(TYPE)                                                                \
    using TYPE = TYPE##T<u64>;                                                 \
    extern template class TYPE##T<u64>;
DEB_DATASTRUCTURES
#undef X
#endif

#ifdef DEB_U32
#define X(TYPE)                                                                \
    using TYPE##32 = TYPE##T<u32>;                                             \
    extern template class TYPE##T<u32>;
DEB_DATASTRUCTURES
#undef X
#endif

// =========================================================================
// Utility functions to get data pointers
// =========================================================================

template <typename U = u64>
inline U *getData(const CiphertextT<U> &cipher, const Size polyunit_idx,
                  const Size poly_idx) {
    if (poly_idx >= cipher.numPoly() ||
        polyunit_idx >= cipher[poly_idx].size()) {
        throw std::out_of_range("Index out of range in getData");
    }
    return cipher[poly_idx][polyunit_idx].data();
}

template <typename U = u64>
inline U *getData(const PolynomialT<U> &poly, const Size polyunit_idx) {
    if (polyunit_idx >= poly.size()) {
        throw std::out_of_range("Index out of range in getData");
    }
    return poly[polyunit_idx].data();
}

template <typename U = u64> inline U getData(const U *data, const Size idx) {
    return data[idx];
}

} // namespace deb
