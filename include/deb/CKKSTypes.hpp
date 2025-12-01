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

#include "Context.hpp"
#include "SeedGenerator.hpp"
#include "Types.hpp"

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
 * @brief Default complex type using @ref Real precision.
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
            data_.resize(getContext(preset)->get_num_slots());
        } else if constexpr (EncodeT == EncodingType::COEFF) {
            data_.resize(getContext(preset)->get_degree());
        }
    }
    /**
     * @brief Allocates storage based on a shared context.
     * @param context Shared context that exposes preset metadata.
     */
    explicit MessageBase(const Context &context) {
        if constexpr (EncodeT == EncodingType::SLOT) {
            data_.resize(context->get_num_slots());
        } else if constexpr (EncodeT == EncodingType::COEFF) {
            data_.resize(context->get_degree());
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
using CoeffMessage = CoeffMessageImpl<Real>;

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
    DECL_MESSAGE_TEMPLATE(EncodingType::COEFF, Real, prefix)

MESSAGE_TYPE_TEMPLATE(extern)

/**
 * @brief Represents a per-prime polynomial segment used inside ciphertexts or
 * keys.
 */
class PolyUnit {
public:
    PolyUnit() = delete;
    /**
     * @brief Initializes the unit for a preset at a specific modulus level.
     * @param preset Preset describes modulus chain metadata.
     * @param level Target modulus index.
     */
    explicit PolyUnit(const Preset preset, const Size level);
    /**
     * @brief Initializes the unit using a shared context.
     * @param context Shared context that exposes metadata.
     * @param level Target modulus index.
     */
    explicit PolyUnit(const Context &context, const Size level);
    /**
     * @brief Constructs a unit with explicit modulus and degree configuration.
     * @param prime Prime modulus value.
     * @param degree Number of coefficients.
     */
    explicit PolyUnit(u64 prime, Size degree);

    /**
     * @brief Creates a full copy of the unit including coefficient storage.
     */
    PolyUnit deepCopy() const;
    /**
     * @brief Updates the active modulus.
     * @param prime New prime modulus.
     */
    void setPrime(u64 prime) noexcept;
    /**
     * @brief Returns the current modulus.
     */
    u64 prime() const noexcept;
    /**
     * @brief Marks the coefficient representation as NTT or standard domain.
     * @param ntt_state True when data is in NTT domain.
     */
    void setNTT(bool ntt_state) noexcept;
    /**
     * @brief Returns true if the unit is in NTT domain.
     */
    bool isNTT() const noexcept;
    /**
     * @brief Number of coefficients available in this unit.
     */
    Size degree() const noexcept;
    /**
     * @brief Mutable coefficient accessor without bounds checks.
     * @param index Coefficient index.
     */
    u64 &operator[](Size index) noexcept;
    /**
     * @brief Const coefficient accessor without bounds checks.
     * @param index Coefficient index.
     */
    u64 operator[](Size index) const noexcept;
    /**
     * @brief Returns a mutable pointer to coefficient storage.
     */
    u64 *data() const noexcept;
    /**
     * @brief Sets an externally managed storage buffer.
     * @param new_data Pointer to caller-managed coefficients.
     * @param size Number of coefficients pointed to by @p new_data.
     */
    void setData(u64 *new_data, Size size);

private:
    u64 prime_;
    bool ntt_state_;
    std::shared_ptr<span<u64>> data_;
};

/**
 * @brief Collection of PolyUnit instances representing a multi-level
 * polynomial.
 */
class Polynomial {
public:
    Polynomial() = delete;
    /**
     * @brief Constructs a polynomial for a preset with optional full level
     * allocation.
     * @param preset Preset that describes modulus chain metadata.
     * @param full_level True to allocate every modulus level,
     * false to allocate only the default encryption level.
     */
    explicit Polynomial(const Preset preset, const bool full_level = false);
    /**
     * @brief Constructs with a shared context handle.
     * @param context Shared context that exposes metadata.
     * @param full_level True to allocate every modulus level,
     * false to allocate only the default encryption level.
     */
    explicit Polynomial(Context context, const bool full_level = false);
    /**
     * @brief Constructs with a custom number of PolyUnit entries.
     * @param context Shared context that exposes metadata.
     * @param custom_size Number of PolyUnit slots.
     */
    explicit Polynomial(Context context, const Size custom_size);
    /**
     * @brief Copies slices of another polynomial.
     * @param other Source polynomial.
     * @param others_idx Starting index within @p other to copy.
     * @param custom_size Number of PolyUnit entries to copy.
     */
    explicit Polynomial(const Polynomial &other, Size others_idx,
                        Size custom_size = 1);
    /**
     * @brief Produces a deep copy optionally limited to a prefix of units.
     * @param num_polyunit Optional number of units to copy.
     */
    Polynomial deepCopy(std::optional<Size> num_polyunit = std::nullopt) const;
    /**
     * @brief Marks every unit as NTT or standard domain.
     * @param ntt_state Desired transform state.
     */
    void setNTT(bool ntt_state) noexcept;
    /**
     * @brief Updates current level metadata.
     * @param preset Preset metadata.
     * @param level Target modulus index.
     */
    void setLevel(Preset preset, Size level);
    /**
     * @brief Current level index.
     */
    Size level() const noexcept;
    /**
     * @brief Adjusts the number of active PolyUnit entries.
     * @param preset Preset metadata.
     * @param size New number of PolyUnit entries.
     */
    void setSize(Preset preset, Size size);
    /**
     * @brief Current number of PolyUnit entries.
     */
    Size size() const noexcept;
    /**
     * @brief Mutable PolyUnit accessor.
     * @param index PolyUnit index.
     */
    PolyUnit &operator[](size_t index) noexcept;
    /**
     * @brief Read-only PolyUnit accessor.
     * @param index PolyUnit index.
     */
    const PolyUnit &operator[](size_t index) const noexcept;
    /**
     * @brief Mutable pointer to the first PolyUnit.
     */
    PolyUnit *data() noexcept;
    /**
     * @brief Const pointer to the first PolyUnit.
     */
    const PolyUnit *data() const noexcept;

private:
    std::vector<PolyUnit> data_;
};

/**
 * @brief Container for encrypted polynomials across modulus levels.
 */
class Ciphertext {
public:
    Ciphertext() = delete;
    /**
     * @brief Allocates ciphertext metadata for a preset with default level.
     */
    explicit Ciphertext(const Preset preset);
    /**
     * @brief Allocates ciphertext metadata using a shared context.
     */
    explicit Ciphertext(Context context);
    /**
     * @brief Allocates ciphertext with explicit level and number of
     * polynomials.
     * @param preset Preset that describes modulus chain metadata.
     * @param level Target modulus index.
     * @param num_poly Optional number of component polynomials.
     */
    explicit Ciphertext(const Preset preset, const Size level,
                        std::optional<Size> num_poly = std::nullopt);
    /**
     * @brief Context-based overload selecting level and size.
     * @param context Shared context that exposes metadata.
     * @param level Target modulus index.
     * @param num_poly Optional number of component polynomials.
     */
    explicit Ciphertext(Context context, const Size level,
                        std::optional<Size> num_poly = std::nullopt);
    /**
     * @brief Copies a subset of another ciphertext.
     * @param other Source ciphertext.
     * @param others_idx Index within @p other to copy from.
     */
    explicit Ciphertext(const Ciphertext &other, Size others_idx);

    /**
     * @brief Produces a deep copy optionally restricted to some PolyUnit
     * entries.
     * @param num_polyunit Optional number of PolyUnit entries per polynomial.
     */
    Ciphertext deepCopy(std::optional<Size> num_polyunit = std::nullopt) const;

    /**
     * @brief Returns associated preset metadata.
     */
    Preset preset() const noexcept;
    /**
     * @brief Changes encoding metadata between slot and coefficient domains.
     * @param encoding Desired encoding type.
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
     * @param ntt_state True when data is stored in NTT domain.
     */
    void setNTT(bool ntt_state);
    /**
     * @brief Updates level metadata.
     * @param level Target level index.
     */
    void setLevel(Size level);
    /**
     * @brief Current level index.
     */
    Size level() const noexcept;
    /**
     * @brief Resizes number of polynomials.
     * @param size Desired polynomial count.
     */
    void setNumPolyunit(Size size);
    /**
     * @brief Returns number of component polynomials.
     */
    Size numPoly() const noexcept;
    /**
     * @brief Mutable polynomial accessor.
     * @param index Polynomial index.
     */
    Polynomial &operator[](size_t index) noexcept;
    /**
     * @brief Const polynomial accessor.
     * @param index Polynomial index.
     */
    const Polynomial &operator[](size_t index) const noexcept;
    /**
     * @brief Mutable pointer to polynomial storage.
     */
    Polynomial *data() noexcept;
    /**
     * @brief Const pointer to polynomial storage.
     */
    const Polynomial *data() const noexcept;

private:
    Preset preset_;
    EncodingType encoding_;
    std::vector<Polynomial> polys_;
};

/**
 * @brief Holds secret key coefficients and polynomial decompositions.
 */
class SecretKey {
public:
    SecretKey() = delete;
    /**
     * @brief Deterministic constructor from preset and PRNG seed.
     * @param preset Preset that describes modulus chain metadata.
     * @param seed Seed used to regenerate coefficients on demand.
     */
    explicit SecretKey(Preset preset, const RNGSeed seed);
    /**
     * @brief Randomized constructor optionally using coefficient embedding.
     * @param preset Preset that describes modulus chain metadata.
     * @param embedding True to allocate polynomial components.
     */
    explicit SecretKey(Preset preset, bool embedding = true);

    /**
     * @brief Preset used to generate this key.
     */
    Preset preset() const noexcept;
    /**
     * @brief Checks whether a PRNG seed is stored.
     */
    bool hasSeed() const noexcept;
    /**
     * @brief Retrieves the stored seed.
     */
    RNGSeed getSeed() const noexcept;
    /**
     * @brief Sets the deterministic seed value.
     * @param seed New seed material.
     */
    void setSeed(const RNGSeed &seed) noexcept;
    /**
     * @brief Removes the stored seed to prevent future regenerations.
     */
    void flushSeed() noexcept;

    /**
     * @brief Number of raw coefficients currently allocated.
     */
    Size coeffsSize() const noexcept;
    /**
     * @brief Allocates coefficient storage according to the preset.
     */
    void allocCoeffs();
    /**
     * @brief Mutable coefficient accessor.
     * @param index Coefficient index.
     */
    i8 &coeff(Size index) noexcept;
    /**
     * @brief Const coefficient accessor.
     * @param index Coefficient index.
     */
    i8 coeff(Size index) const noexcept;
    /**
     * @brief Mutable pointer to coefficient array.
     */
    i8 *coeffs() noexcept;
    /**
     * @brief Const pointer to coefficient array.
     */
    const i8 *coeffs() const noexcept;

    /**
     * @brief Number of stored polynomial components.
     */
    Size numPoly() const noexcept;
    /**
     * @brief Allocates polynomial components.
     * @param num_polyunit Optional number of PolyUnit entries per polynomial.
     */
    void allocPolys(std::optional<Size> num_polyunit = std::nullopt);
    /**
     * @brief Mutable polynomial accessor.
     * @param index Polynomial index.
     */
    Polynomial &operator[](Size index);
    /**
     * @brief Const polynomial accessor.
     * @param index Polynomial index.
     */
    const Polynomial &operator[](Size index) const;
    /**
     * @brief Mutable pointer to polynomial array.
     */
    Polynomial *data() noexcept;
    /**
     * @brief Const pointer to polynomial array.
     */
    const Polynomial *data() const noexcept;

private:
    Preset preset_;
    std::optional<RNGSeed> seed_;
    std::vector<i8> coeffs_;
    std::vector<Polynomial> polys_;
};

/**
 * @brief Key used for switching ciphertexts between secret keys.
 */
class SwitchKey {
public:
    SwitchKey() = delete;
    /**
     * @brief Constructs a switching key for a preset and key kind.
     * @param preset Preset that describes modulus chain metadata.
     * @param type SwitchKeyKind (SWK_MULT, SWK_ROT, etc).
     * @param rot_idx Optional rotation index for rotation keys.
     */
    explicit SwitchKey(Preset preset, const SwitchKeyKind type,
                       const std::optional<Size> rot_idx = std::nullopt);
    /**
     * @brief Constructs a switching key from a context and key kind.
     * @param context Shared context that exposes metadata.
     * @param type SwitchKeyKind (SWK_MULT, SWK_ROT, etc).
     * @param rot_idx Optional rotation index.
     */
    explicit SwitchKey(const Context &context, const SwitchKeyKind type,
                       const std::optional<Size> rot_idx = std::nullopt);

    /**
     * @brief Returns the preset metadata for this key.
     */
    Preset preset() const noexcept;
    /**
     * @brief Sets the key type (SWK_MULT, SWK_ROT, etc).
     * @param type SwitchKeyKind value.
     */
    void setType(const SwitchKeyKind type) noexcept;
    /**
     * @brief Returns the key type.
     */
    SwitchKeyKind type() const noexcept;
    /**
     * @brief Sets the rotation index (for rotation keys).
     * @param rot_idx Rotation index value.
     */
    void setRotIdx(Size rot_idx) noexcept;
    /**
     * @brief Returns the rotation index (for rotation keys).
     */
    Size rotIdx() const noexcept;
    /**
     * @brief Returns the decomposition number (dnum).
     */
    Size dnum() const noexcept;
    /**
     * @brief Adds a polynomial to the Ax-part component.
     * @param num_polyunit Number of PolyUnit entries.
     * @param size Optional size of PolyUnit array.
     * @param ntt_state True if NTT domain.
     */
    void addAx(const Size num_polyunit, std::optional<Size> size = std::nullopt,
               const bool ntt_state = false);
    /**
     * @brief Adds a polynomial to the Ax-part component.
     * @param poly Polynomial to add.
     */
    void addAx(const Polynomial &poly);
    /**
     * @brief Adds a polynomial to the Bx-part component.
     * @param num_polyunit Number of PolyUnit entries.
     * @param size Optional size of PolyUnit array.
     * @param ntt_state True if NTT domain.
     */
    void addBx(const Size num_polyunit, std::optional<Size> size = std::nullopt,
               const bool ntt_state = false);
    /**
     * @brief Adds a polynomial to the Bx-part component.
     * @param poly Polynomial to add.
     */
    void addBx(const Polynomial &poly);
    /**
     * @brief Sets NTT state for all Ax-part polynomials.
     * @param ntt_state True if NTT domain.
     */
    void setAxNTT(bool ntt_state) noexcept;
    /**
     * @brief Sets NTT state for all Bx-part polynomials.
     * @param ntt_state True if NTT domain.
     */
    void setBxNTT(bool ntt_state) noexcept;
    /**
     * @brief Returns the number of Ax-part polynomials.
     */
    Size axSize() const noexcept;
    /**
     * @brief Returns the number of Bx-part polynomials.
     */
    Size bxSize() const noexcept;
    /**
     * @brief Mutable reference to Ax-part polynomial vector.
     */
    std::vector<Polynomial> &getAx() noexcept;
    /**
     * @brief Const reference to Ax-part polynomial vector.
     */
    const std::vector<Polynomial> &getAx() const noexcept;
    /**
     * @brief Mutable reference to Bx-part polynomial vector.
     */
    std::vector<Polynomial> &getBx() noexcept;
    /**
     * @brief Const reference to Bx-part polynomial vector.
     */
    const std::vector<Polynomial> &getBx() const noexcept;
    /**
     * @brief Mutable Ax-part polynomial accessor.
     * @param index Polynomial index.
     */
    Polynomial &ax(Size index = 0) noexcept;
    /**
     * @brief Const Ax-part polynomial accessor.
     * @param index Polynomial index.
     */
    const Polynomial &ax(Size index = 0) const noexcept;
    /**
     * @brief Mutable Bx-part polynomial accessor.
     * @param index Polynomial index.
     */
    Polynomial &bx(Size index = 0) noexcept;
    /**
     * @brief Const Bx-part polynomial accessor.
     * @param index Polynomial index.
     */
    const Polynomial &bx(Size index = 0) const noexcept;

private:
    Preset preset_;
    SwitchKeyKind type_;
    std::optional<Size> rot_idx_;
    Size dnum_;
    std::vector<Polynomial> ax_;
    std::vector<Polynomial> bx_;
};

// ---------------------------------------------------------------------
// Utility functions to get data pointers
// ---------------------------------------------------------------------
/**
 * @brief Returns a mutable pointer to the coefficient data for a given
 * ciphertext polynomial.
 * @param cipher Ciphertext object.
 * @param polyunit_idx Index of the PolyUnit within the polynomial.
 * @param poly_idx Index of the polynomial within the ciphertext (default 0).
 * @return Pointer to coefficient data.
 * @throws std::out_of_range if indices are invalid.
 */
inline u64 *getData(const Ciphertext &cipher, const Size polyunit_idx,
                    const Size poly_idx = 0) {
    if (poly_idx >= cipher.numPoly() ||
        polyunit_idx >= cipher[poly_idx].size()) {
        throw std::out_of_range("Index out of range in getData");
    }
    return cipher[poly_idx][polyunit_idx].data();
}

inline u64 *getData(const Polynomial &poly, const Size polyunit_idx = 0) {
    if (polyunit_idx >= poly.size()) {
        throw std::out_of_range("Index out of range in getData");
    }
    return poly[polyunit_idx].data();
}

inline u64 getData(const u64 *data, const Size idx = 0) { return data[idx]; }

} // namespace deb
