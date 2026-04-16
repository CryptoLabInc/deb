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

#include "CKKSTypes.hpp"

#include <cstdlib>
#if defined(_WIN32)
#include <malloc.h>
#endif

namespace deb {

#if DEB_ALINAS_LEN != 0
inline void *deb_aligned_alloc(size_t alignment, size_t size) {
#if defined(_WIN32)
    return _aligned_malloc(size, alignment);
#else
    return std::aligned_alloc(alignment, size);
#endif
}

inline void deb_aligned_free(void *ptr) {
#if defined(_WIN32)
    _aligned_free(ptr);
#else
    std::free(ptr);
#endif
}
#endif

//// ---------------------------------------------------------------------
//// Implementation of Message
//// ---------------------------------------------------------------------
template <EncodingType EncodeT, typename DataT>
MessageBase<EncodeT, DataT>::MessageBase(const Size size) : data_(size) {}
template <EncodingType EncodeT, typename DataT>
MessageBase<EncodeT, DataT>::MessageBase(const Size size, const DataT &init)
    : data_(size, init) {}
template <EncodingType EncodeT, typename DataT>
MessageBase<EncodeT, DataT>::MessageBase(const Size size, const DataT *array)
    : data_(array, array + size) {}
template <EncodingType EncodeT, typename DataT>
MessageBase<EncodeT, DataT>::MessageBase(std::vector<DataT> data)
    : data_(std::move(data)) {}
template <EncodingType EncodeT, typename DataT>
DataT &MessageBase<EncodeT, DataT>::operator[](Size index) noexcept {
    return data_[index];
}
template <EncodingType EncodeT, typename DataT>
DataT MessageBase<EncodeT, DataT>::operator[](Size index) const noexcept {
    return data_[index];
}
template <EncodingType EncodeT, typename DataT>
DataT *MessageBase<EncodeT, DataT>::data() noexcept {
    return data_.data();
}
template <EncodingType EncodeT, typename DataT>
const DataT *MessageBase<EncodeT, DataT>::data() const noexcept {
    return data_.data();
}
template <EncodingType EncodeT, typename DataT>
Size MessageBase<EncodeT, DataT>::size() const noexcept {
    return static_cast<Size>(data_.size());
}

MESSAGE_TYPE_TEMPLATE()

// ---------------------------------------------------------------------
// Implementation of PolyUnitT<U>
// ---------------------------------------------------------------------
template <typename U>
PolyUnitT<U>::PolyUnitT(const Preset preset, const Size level, const bool alloc)
    : prime_(static_cast<U>(get_primes(preset)[level])), ntt_state_(false),
      degree_(get_degree(preset)) {
    if (!alloc) {
        data_ptr_ = nullptr;
        degree_ = 0;
        return;
    }
#if DEB_ALINAS_LEN == 0
    data_ptr_ =
        std::shared_ptr<U[]>(new U[degree_], std::default_delete<U[]>());
#else
    auto *buf = static_cast<U *>(
        deb_aligned_alloc(DEB_ALINAS_LEN, sizeof(U) * degree_));
    data_ptr_ = std::shared_ptr<U[]>(buf, [](U *p) { deb_aligned_free(p); });
#endif
}

template <typename U>
PolyUnitT<U>::PolyUnitT(u64 prime, Size degree, const bool alloc)
    : prime_(static_cast<U>(prime)), ntt_state_(false), degree_(degree) {
    if (!alloc) {
        data_ptr_ = nullptr;
        degree_ = 0;
        return;
    }
#if DEB_ALINAS_LEN == 0
    data_ptr_ =
        std::shared_ptr<U[]>(new U[degree_], std::default_delete<U[]>());
#else
    auto *buf = static_cast<U *>(
        deb_aligned_alloc(DEB_ALINAS_LEN, sizeof(U) * degree_));
    data_ptr_ = std::shared_ptr<U[]>(buf, [](U *p) { deb_aligned_free(p); });
#endif
}

template <typename U> PolyUnitT<U> PolyUnitT<U>::deepCopy() const {
    const bool alloc = data_ptr_ != nullptr && degree_ != 0;
    PolyUnitT<U> copy(static_cast<u64>(prime_), degree_, alloc);
    if (alloc) {
        for (Size i = 0; i < degree_; ++i) {
            copy[i] = (*this)[i];
        }
    }
    copy.setNTT(ntt_state_);
    return copy;
}

template <typename U> void PolyUnitT<U>::setPrime(u64 prime) noexcept {
    prime_ = static_cast<U>(prime);
}

template <typename U> U PolyUnitT<U>::prime() const noexcept { return prime_; }

template <typename U> void PolyUnitT<U>::setNTT(bool ntt_state) noexcept {
    ntt_state_ = ntt_state;
}

template <typename U> bool PolyUnitT<U>::isNTT() const noexcept {
    return ntt_state_;
}

template <typename U> Size PolyUnitT<U>::degree() const noexcept {
    return degree_;
}

template <typename U> void PolyUnitT<U>::setData(U *new_data, Size size) {
    data_ptr_ = std::shared_ptr<U[]>(new_data, [](U *) {
        // do nothing, external data
    });
    degree_ = size;
}

// ---------------------------------------------------------------------
// Implementation of PolynomialT<U>
// ---------------------------------------------------------------------
template <typename U>
PolynomialT<U>::PolynomialT(const Preset preset, const bool full_level) {
    const Size degree = get_degree(preset);
    const Size num_poly =
        full_level ? get_num_p(preset) : get_encryption_level(preset) + 1;
#if DEB_ALINAS_LEN == 0
    dealloc_ptr_ = std::shared_ptr<U[]>(new U[num_poly * degree],
                                        std::default_delete<U[]>());
#else
    auto *buf = static_cast<U *>(
        deb_aligned_alloc(DEB_ALINAS_LEN, sizeof(U) * num_poly * degree));
    dealloc_ptr_ = std::shared_ptr<U[]>(buf, [](U *p) { deb_aligned_free(p); });
#endif
    for (Size l = 0; l < num_poly; ++l) {
        polyunits_.emplace_back(preset, l, false);
        polyunits_[l].setData(dealloc_ptr_.get() + l * degree, degree);
    }
}

template <typename U>
PolynomialT<U>::PolynomialT(const Preset preset, const Size custom_size) {
    const Size degree = get_degree(preset);
#if DEB_ALINAS_LEN == 0
    dealloc_ptr_ = std::shared_ptr<U[]>(new U[custom_size * degree],
                                        std::default_delete<U[]>());
#else
    auto *buf = static_cast<U *>(
        deb_aligned_alloc(DEB_ALINAS_LEN, sizeof(U) * custom_size * degree));
    dealloc_ptr_ = std::shared_ptr<U[]>(buf, [](U *p) { deb_aligned_free(p); });
#endif
    for (Size l = 0; l < custom_size; ++l) {
        polyunits_.emplace_back(preset, l, false);
        polyunits_[l].setData(dealloc_ptr_.get() + l * degree, degree);
    }
}

template <typename U>
PolynomialT<U>::PolynomialT(const PolynomialT<U> &other, Size others_idx,
                            Size custom_size)
    : polyunits_(&other.polyunits_[others_idx],
                 &other.polyunits_[others_idx] + custom_size),
      dealloc_ptr_(nullptr) {}

template <typename U>
PolynomialT<U>
PolynomialT<U>::deepCopy(std::optional<Size> num_polyunit) const {
    const auto num_polyunit_val = num_polyunit.value_or(this->size());
    deb_assert(
        num_polyunit_val <= this->size(),
        "[PolynomialT::deepCopy] Requested number of polyunits exceeds size.");
    PolynomialT<U> copy(*this, 0, 0);
    copy.polyunits_.clear();
    if (dealloc_ptr_ != nullptr) {
#if DEB_ALINAS_LEN == 0
        copy.dealloc_ptr_ = std::shared_ptr<U[]>(
            new U[num_polyunit_val * polyunits_[0].degree()],
            std::default_delete<U[]>());
#else
        auto *buf = static_cast<U *>(
            deb_aligned_alloc(DEB_ALINAS_LEN, sizeof(U) * num_polyunit_val *
                                                  polyunits_[0].degree()));
        copy.dealloc_ptr_ =
            std::shared_ptr<U[]>(buf, [](U *p) { deb_aligned_free(p); });
#endif
        for (Size i = 0; i < num_polyunit_val; ++i) {
            copy.polyunits_.emplace_back(polyunits_[i].prime(),
                                         polyunits_[i].degree(), true);
            copy.polyunits_[i].setNTT(polyunits_[i].isNTT());
            copy.polyunits_[i].setData(copy.dealloc_ptr_.get() +
                                           i * polyunits_[i].degree(),
                                       polyunits_[i].degree());
            for (Size j = 0; j < polyunits_[i].degree(); ++j) {
                copy.polyunits_[i][j] = polyunits_[i][j];
            }
        }
    } else {
        copy.dealloc_ptr_ = nullptr;
        for (Size i = 0; i < num_polyunit_val; ++i) {
            copy.polyunits_.push_back(polyunits_[i].deepCopy());
        }
    }
    return copy;
}

template <typename U> void PolynomialT<U>::setNTT(bool ntt_state) noexcept {
    for (auto &poly : polyunits_) {
        poly.setNTT(ntt_state);
    }
}

template <typename U> void PolynomialT<U>::setLevel(Preset preset, Size level) {
    setSize(preset, level + 1);
}

template <typename U> Size PolynomialT<U>::level() const noexcept {
    return static_cast<Size>(polyunits_.size()) - 1;
}

template <typename U> void PolynomialT<U>::setSize(Preset preset, Size size) {
    if (size <= this->size()) {
        polyunits_.erase(polyunits_.begin() + size, polyunits_.end());
    } else {
        const auto max_len = get_num_p(preset);
        for (Size l = this->size(); l < size; ++l) {
            polyunits_.emplace_back(get_primes(preset)[l % max_len],
                                    get_degree(preset));
        }
    }
}

template <typename U> Size PolynomialT<U>::size() const noexcept {
    return static_cast<Size>(polyunits_.size());
}

// ---------------------------------------------------------------------
// Implementation of CiphertextT<U>
// ---------------------------------------------------------------------
template <typename U>
CiphertextT<U>::CiphertextT(const Preset preset)
    : preset_(preset), encoding_(SLOT) {
    const Size num_polys = get_rank(preset) * get_num_secret(preset) + 1;
    for (Size i = 0; i < num_polys; ++i) {
        polys_.emplace_back(preset);
    }
}

template <typename U>
CiphertextT<U>::CiphertextT(const Preset preset, const Size level,
                            std::optional<Size> num_poly)
    : preset_(preset), encoding_(UNKNOWN) {
    const auto num_polys =
        num_poly.value_or(get_rank(preset) * get_num_secret(preset) + 1);
    for (Size i = 0; i < num_polys; ++i) {
        polys_.emplace_back(preset, level + 1);
    }
}

template <typename U>
CiphertextT<U>::CiphertextT(const CiphertextT<U> &other, Size others_idx)
    : preset_(other.preset_), encoding_(other.encoding_),
      polys_({other.polys_[others_idx]}) {}

template <typename U>
CiphertextT<U>
CiphertextT<U>::deepCopy(std::optional<Size> num_polyunit) const {
    CiphertextT<U> copy(*this);
    copy.polys_.clear();
    for (const auto &poly : polys_) {
        copy.polys_.emplace_back(poly.deepCopy(num_polyunit));
    }
    return copy;
}

template <typename U> Preset CiphertextT<U>::preset() const noexcept {
    return preset_;
}

template <typename U> void CiphertextT<U>::setEncoding(EncodingType encoding) {
    this->encoding_ = encoding;
}

template <typename U> EncodingType CiphertextT<U>::encoding() const noexcept {
    return encoding_;
}

template <typename U> bool CiphertextT<U>::isSlot() const noexcept {
    return encoding_ == SLOT;
}

template <typename U> bool CiphertextT<U>::isCoeff() const noexcept {
    return encoding_ == COEFF;
}

template <typename U> void CiphertextT<U>::setNTT(bool ntt_state) {
    for (auto &poly : polys_) {
        poly.setNTT(ntt_state);
    }
}

template <typename U> void CiphertextT<U>::setLevel(Size level) {
    std::for_each(polys_.begin(), polys_.end(),
                  [this, level](auto &poly) { poly.setLevel(preset_, level); });
}

template <typename U> Size CiphertextT<U>::level() const noexcept {
    if (polys_.empty()) {
        return 0;
    }
    return polys_[0].level();
}

template <typename U> void CiphertextT<U>::setNumPolyunit(Size size) {
    std::for_each(polys_.begin(), polys_.end(),
                  [this, size](auto &poly) { poly.setSize(preset_, size); });
}

template <typename U> Size CiphertextT<U>::numPoly() const noexcept {
    return static_cast<Size>(polys_.size());
}

// ---------------------------------------------------------------------
// Implementation of SecretKeyT<U>
// ---------------------------------------------------------------------
template <typename U>
SecretKeyT<U>::SecretKeyT(Preset preset, const RNGSeed seed)
    : preset_(preset), seed_(seed) {}

template <typename U>
SecretKeyT<U>::SecretKeyT(Preset preset, bool embedding) : preset_(preset) {
    coeffs_.resize(
        get_rank(preset) * get_num_secret(preset) * get_degree(preset), 0);
    if (embedding) {
        const Size num_poly = get_rank(preset) * get_num_secret(preset);
        for (Size i = 0; i < num_poly; ++i) {
            polys_.emplace_back(preset, true);
        }
    }
}

template <typename U>
SecretKeyT<U>::SecretKeyT(SecretKeyT<U> &&other) noexcept
    : preset_(other.preset_), seed_(std::move(other.seed_)),
      coeffs_(std::move(other.coeffs_)), polys_(std::move(other.polys_)) {
    other.zeroize();
}

template <typename U>
SecretKeyT<U> &SecretKeyT<U>::operator=(SecretKeyT<U> &&other) noexcept {
    if (this != &other) {
        zeroize();
        preset_ = other.preset_;
        seed_ = std::move(other.seed_);
        coeffs_ = std::move(other.coeffs_);
        polys_ = std::move(other.polys_);
        other.zeroize();
    }
    return *this;
}

template <typename U> SecretKeyT<U>::~SecretKeyT() noexcept { zeroize(); }

template <typename U> Preset SecretKeyT<U>::preset() const noexcept {
    return preset_;
}

template <typename U> bool SecretKeyT<U>::hasSeed() const noexcept {
    return seed_.has_value();
}

template <typename U> RNGSeed SecretKeyT<U>::getSeed() const noexcept {
    return seed_.value();
}

template <typename U>
void SecretKeyT<U>::setSeed(const RNGSeed &seed) noexcept {
    seed_.emplace(seed);
}

template <typename U> void SecretKeyT<U>::flushSeed() noexcept {
    seed_.reset();
}

template <typename U> Size SecretKeyT<U>::coeffsSize() const noexcept {
    return static_cast<Size>(coeffs_.size());
}

template <typename U> void SecretKeyT<U>::allocCoeffs() {
    coeffs_.clear();
    coeffs_.resize(
        get_rank(preset_) * get_num_secret(preset_) * get_degree(preset_), 0);
}

template <typename U> i8 &SecretKeyT<U>::coeff(Size index) noexcept {
    return coeffs_[index];
}

template <typename U> i8 SecretKeyT<U>::coeff(Size index) const noexcept {
    return coeffs_[index];
}

template <typename U> i8 *SecretKeyT<U>::coeffs() noexcept {
    return coeffs_.data();
}

template <typename U> const i8 *SecretKeyT<U>::coeffs() const noexcept {
    return coeffs_.data();
}

template <typename U> Size SecretKeyT<U>::numPoly() const noexcept {
    return static_cast<Size>(polys_.size());
}

template <typename U> void SecretKeyT<U>::zeroize() noexcept {
    if (!coeffs_.empty()) {
        deb_secure_zero(coeffs_.data(), coeffs_.size() * sizeof(i8));
    }
    if (seed_.has_value()) {
        deb_secure_zero(seed_->data(), seed_->size() * sizeof(u64));
        seed_.reset();
    }
    for (auto &poly : polys_) {
        for (Size i = 0; i < poly.size(); ++i) {
            deb_secure_zero(poly[i].data(), poly[i].degree() * sizeof(U));
        }
    }
}

template <typename U>
void SecretKeyT<U>::allocPolys(std::optional<Size> num_polyunit) {
    num_polyunit = num_polyunit.value_or(get_num_p(preset_));
    const Size num_poly = get_rank(preset_) * get_num_secret(preset_);
    polys_.clear();
    for (Size i = 0; i < num_poly; ++i) {
        polys_.emplace_back(preset_, num_polyunit.value());
    }
}

// ---------------------------------------------------------------------
// Implementation of SwitchKeyT<U>
// ---------------------------------------------------------------------
template <typename U>
SwitchKeyT<U>::SwitchKeyT(Preset preset, const SwitchKeyKind type,
                          const std::optional<Size> rot_idx)
    : preset_(preset), type_(type), rot_idx_(rot_idx),
      dnum_(get_gadget_rank(preset)) {
    if (type_ == SWK_MODPACK_SELF || type_ == SWK_GENERIC) {
        return;
    }
    const Size size = (type_ == SWK_ENC) ? 1 : dnum_;
    addAx(get_num_p(preset), size, true);
    addBx(get_num_p(preset), size * get_num_secret(preset), true);
}

template <typename U> Preset SwitchKeyT<U>::preset() const noexcept {
    return preset_;
}

template <typename U>
void SwitchKeyT<U>::setType(const SwitchKeyKind type) noexcept {
    type_ = type;
}

template <typename U> SwitchKeyKind SwitchKeyT<U>::type() const noexcept {
    return type_;
}

template <typename U> void SwitchKeyT<U>::setRotIdx(Size rot_idx) noexcept {
    rot_idx_.emplace(rot_idx);
}

template <typename U> Size SwitchKeyT<U>::rotIdx() const noexcept {
    if (rot_idx_)
        return rot_idx_.value();
    return static_cast<Size>(-1);
}

template <typename U> Size SwitchKeyT<U>::dnum() const noexcept {
    return dnum_;
}

template <typename U>
void SwitchKeyT<U>::addAx(const Size num_polyunit, std::optional<Size> size,
                          const bool ntt_state) {
    const auto num_poly = size.value_or(1);
    for (Size i = 0; i < num_poly; ++i) {
        ax_.emplace_back(preset_, num_polyunit);
    }
    setAxNTT(ntt_state);
}

template <typename U> void SwitchKeyT<U>::addAx(const PolynomialT<U> &poly) {
    ax_.push_back(poly);
}

template <typename U>
void SwitchKeyT<U>::addBx(const Size num_polyunit, std::optional<Size> size,
                          const bool ntt_state) {
    const auto num_poly = size.value_or(dnum_ * get_num_secret(preset_));
    for (Size i = 0; i < num_poly; ++i) {
        bx_.emplace_back(preset_, num_polyunit);
    }
    setBxNTT(ntt_state);
}

template <typename U> void SwitchKeyT<U>::addBx(const PolynomialT<U> &poly) {
    bx_.push_back(poly);
}

template <typename U> void SwitchKeyT<U>::setAxNTT(bool ntt_state) noexcept {
    for (auto &poly : ax_) {
        poly.setNTT(ntt_state);
    }
}

template <typename U> void SwitchKeyT<U>::setBxNTT(bool ntt_state) noexcept {
    for (auto &poly : bx_) {
        poly.setNTT(ntt_state);
    }
}

template <typename U> Size SwitchKeyT<U>::axSize() const noexcept {
    return static_cast<Size>(ax_.size());
}

template <typename U> Size SwitchKeyT<U>::bxSize() const noexcept {
    return static_cast<Size>(bx_.size());
}

template <typename U>
std::vector<PolynomialT<U>> &SwitchKeyT<U>::getAx() noexcept {
    return ax_;
}

template <typename U>
const std::vector<PolynomialT<U>> &SwitchKeyT<U>::getAx() const noexcept {
    return ax_;
}

template <typename U>
std::vector<PolynomialT<U>> &SwitchKeyT<U>::getBx() noexcept {
    return bx_;
}

template <typename U>
const std::vector<PolynomialT<U>> &SwitchKeyT<U>::getBx() const noexcept {
    return bx_;
}

template <typename U> PolynomialT<U> &SwitchKeyT<U>::ax(Size index) noexcept {
    return ax_[index];
}

template <typename U>
const PolynomialT<U> &SwitchKeyT<U>::ax(Size index) const noexcept {
    return ax_[index];
}

template <typename U> PolynomialT<U> &SwitchKeyT<U>::bx(Size index) noexcept {
    return bx_[index];
}

template <typename U>
const PolynomialT<U> &SwitchKeyT<U>::bx(Size index) const noexcept {
    return bx_[index];
}

// Explicit instantiations
#ifdef DEB_U64
#define X(TYPE) template class TYPE##T<u64>;
DEB_DATASTRUCTURES
#undef X
#endif

#ifdef DEB_U32
#define X(TYPE) template class TYPE##T<u32>;
DEB_DATASTRUCTURES
#undef X
#endif

} // namespace deb
