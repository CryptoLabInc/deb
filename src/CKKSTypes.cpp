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
namespace deb {

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
// Implementation of PolyUnit
// ---------------------------------------------------------------------
PolyUnit::PolyUnit(const Preset preset, const Size level, const bool alloc)
    : prime_(get_primes(preset)[level]), ntt_state_(false),
      degree_(get_degree(preset)) {
    if (!alloc) {
        data_ptr_ = nullptr;
        degree_ = 0;
        return;
    }
#if DEB_ALINAS_LEN == 0
    data_ptr_ =
        std::shared_ptr<u64[]>(new u64[degree_], std::default_delete<u64[]>());
#else
    auto *buf = static_cast<u64 *>(::operator new[](
        sizeof(u64) * degree_, std::align_val_t(DEB_ALINAS_LEN)));
    data_ptr_ = std::shared_ptr<u64[]>(buf, [](u64 *p) {
        ::operator delete[](p, std::align_val_t(DEB_ALINAS_LEN));
    });
#endif
}
PolyUnit::PolyUnit(u64 prime, Size degree, const bool alloc)
    : prime_(prime), ntt_state_(false), degree_(degree) {
    if (!alloc) {
        data_ptr_ = nullptr;
        degree_ = 0;
        return;
    }
#if DEB_ALINAS_LEN == 0
    data_ptr_ =
        std::shared_ptr<u64[]>(new u64[degree_], std::default_delete<u64[]>());
#else
    auto *buf = static_cast<u64 *>(::operator new[](
        sizeof(u64) * degree_, std::align_val_t(DEB_ALINAS_LEN)));
    data_ptr_ = std::shared_ptr<u64[]>(buf, [](u64 *p) {
        ::operator delete[](p, std::align_val_t(DEB_ALINAS_LEN));
    });
#endif
}

PolyUnit PolyUnit::deepCopy() const {
    const bool alloc = data_ptr_ != nullptr && degree_ != 0;
    PolyUnit copy(prime_, degree_, alloc);
    if (alloc) {
        for (Size i = 0; i < degree_; ++i) {
            copy[i] = (*this)[i];
        }
    }
    copy.setNTT(ntt_state_);
    return copy;
}

void PolyUnit::setPrime(u64 prime) noexcept { prime_ = prime; }
u64 PolyUnit::prime() const noexcept { return prime_; }
void PolyUnit::setNTT(bool ntt_state) noexcept { ntt_state_ = ntt_state; }
bool PolyUnit::isNTT() const noexcept { return ntt_state_; }
Size PolyUnit::degree() const noexcept { return degree_; }

void PolyUnit::setData(u64 *new_data, Size size) {
    data_ptr_ = std::shared_ptr<u64[]>(new_data, [](u64 *p) {
        // do nothing, external data
    });
    degree_ = size;
}

// ---------------------------------------------------------------------
// Implementation of Polynomial
// ---------------------------------------------------------------------
Polynomial::Polynomial(const Preset preset, const bool full_level) {
    const Size degree = get_degree(preset);
    const Size num_poly =
        full_level ? get_num_p(preset) : get_encryption_level(preset) + 1;
#if DEB_ALINAS_LEN == 0
    dealloc_ptr_ = std::shared_ptr<u64[]>(new u64[num_poly * degree],
                                          std::default_delete<u64[]>());
#else
    auto *buf = static_cast<u64 *>(
        std::aligned_alloc(DEB_ALINAS_LEN, sizeof(u64) * num_poly * degree));
    dealloc_ptr_ = std::shared_ptr<u64[]>(buf, [](u64 *p) { std::free(p); });
#endif
    for (Size l = 0; l < num_poly; ++l) {
        polyunits_.emplace_back(preset, l, false);
        polyunits_[l].setData(dealloc_ptr_.get() + l * degree, degree);
    }
}
Polynomial::Polynomial(const Preset preset, const Size custom_size) {
    const Size degree = get_degree(preset);
#if DEB_ALINAS_LEN == 0
    dealloc_ptr_ = std::shared_ptr<u64[]>(new u64[custom_size * degree],
                                          std::default_delete<u64[]>());
#else
    auto *buf = static_cast<u64 *>(
        std::aligned_alloc(DEB_ALINAS_LEN, sizeof(u64) * custom_size * degree));
    dealloc_ptr_ = std::shared_ptr<u64[]>(buf, [](u64 *p) { std::free(p); });
#endif
    for (Size l = 0; l < custom_size; ++l) {
        polyunits_.emplace_back(preset, l, false);
        polyunits_[l].setData(dealloc_ptr_.get() + l * degree, degree);
    }
}
Polynomial::Polynomial(const Polynomial &other, Size others_idx,
                       Size custom_size)
    : polyunits_(&other.polyunits_[others_idx],
                 &other.polyunits_[others_idx] + custom_size),
      dealloc_ptr_(nullptr) {}

Polynomial Polynomial::deepCopy(std::optional<Size> num_polyunit) const {
    const auto num_polyunit_val = num_polyunit.value_or(this->size());
    deb_assert(
        num_polyunit_val <= this->size(),
        "[Polynomial::deepCopy] Requested number of polyunits exceeds size.");
    Polynomial copy(*this, 0, 0);
    copy.polyunits_.clear();
    if (dealloc_ptr_ != nullptr) {
#if DEB_ALINAS_LEN == 0
        copy.dealloc_ptr_ = std::shared_ptr<u64[]>(
            new u64[num_polyunit_val * polyunits_[0].degree()],
            std::default_delete<u64[]>());
#else
        auto *buf = static_cast<u64 *>(::operator new[](
            sizeof(u64) * num_polyunit_val * polyunits_[0].degree(),
            std::align_val_t(DEB_ALINAS_LEN)));
        copy.dealloc_ptr_ = std::shared_ptr<u64[]>(buf, [buf](u64 *p) {
            ::operator delete[](buf, std::align_val_t(DEB_ALINAS_LEN));
        });
#endif
        for (Size i = 0; i < num_polyunit_val; ++i) {
            copy.polyunits_.emplace_back(polyunits_[i].prime(), 0, false);
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

void Polynomial::setNTT(bool ntt_state) noexcept {
    for (auto &poly : polyunits_) {
        poly.setNTT(ntt_state);
    }
}

void Polynomial::setLevel(Preset preset, Size level) {
    setSize(preset, level + 1);
}

Size Polynomial::level() const noexcept {
    return static_cast<Size>(polyunits_.size()) - 1;
}

void Polynomial::setSize(Preset preset, Size size) {
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

Size Polynomial::size() const noexcept {
    return static_cast<Size>(polyunits_.size());
}

// ---------------------------------------------------------------------
// Implementation of Ciphertext
// ---------------------------------------------------------------------
Ciphertext::Ciphertext(const Preset preset) : preset_(preset), encoding_(SLOT) {
    const Size num_polys = get_rank(preset) * get_num_secret(preset) + 1;
    for (Size i = 0; i < num_polys; ++i) {
        polys_.emplace_back(preset);
    }
}
Ciphertext::Ciphertext(const Preset preset, const Size level,
                       std::optional<Size> num_poly)
    : preset_(preset), encoding_(UNKNOWN) {
    const auto num_polys =
        num_poly.value_or(get_rank(preset) * get_num_secret(preset) + 1);
    for (Size i = 0; i < num_polys; ++i) {
        polys_.emplace_back(preset, level + 1);
    }
}
Ciphertext::Ciphertext(const Ciphertext &other, Size others_idx)
    : preset_(other.preset_), encoding_(other.encoding_),
      polys_({other.polys_[others_idx]}) {}

Ciphertext Ciphertext::deepCopy(std::optional<Size> num_polyunit) const {
    Ciphertext copy(*this);
    copy.polys_.clear();
    for (const auto &poly : polys_) {
        copy.polys_.emplace_back(poly.deepCopy(num_polyunit));
    }
    return copy;
}

Preset Ciphertext::preset() const noexcept { return preset_; }

void Ciphertext::setEncoding(EncodingType encoding) {
    this->encoding_ = encoding;
}
EncodingType Ciphertext::encoding() const noexcept { return encoding_; }
bool Ciphertext::isSlot() const noexcept { return encoding_ == SLOT; }
bool Ciphertext::isCoeff() const noexcept { return encoding_ == COEFF; }

void Ciphertext::setNTT(bool ntt_state) {
    for (auto &poly : polys_) {
        poly.setNTT(ntt_state);
    }
}

void Ciphertext::setLevel(Size level) {
    std::for_each(polys_.begin(), polys_.end(),
                  [this, level](auto &poly) { poly.setLevel(preset_, level); });
}
Size Ciphertext::level() const noexcept {
    if (polys_.empty()) {
        return 0;
    }
    return polys_[0].level();
}

void Ciphertext::setNumPolyunit(Size size) {
    std::for_each(polys_.begin(), polys_.end(),
                  [this, size](auto &poly) { poly.setSize(preset_, size); });
}
Size Ciphertext::numPoly() const noexcept {
    return static_cast<Size>(polys_.size());
}

// ---------------------------------------------------------------------
// Implementation of SecretKey
// ---------------------------------------------------------------------
SecretKey::SecretKey(Preset preset, const RNGSeed seed)
    : preset_(preset), seed_(seed) {}

SecretKey::SecretKey(Preset preset, bool embedding) : preset_(preset) {
    coeffs_.resize(
        get_rank(preset) * get_num_secret(preset) * get_degree(preset), 0);
    if (embedding) {
        const Size num_poly = get_rank(preset) * get_num_secret(preset);
        for (Size i = 0; i < num_poly; ++i) {
            polys_.emplace_back(preset, true);
        }
    }
}
SecretKey::SecretKey(SecretKey &&other) noexcept
    : preset_(other.preset_), seed_(std::move(other.seed_)),
      coeffs_(std::move(other.coeffs_)), polys_(std::move(other.polys_)) {
    other.zeroize();
}
SecretKey &SecretKey::operator=(SecretKey &&other) noexcept {
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
SecretKey::~SecretKey() noexcept { zeroize(); }
Preset SecretKey::preset() const noexcept { return preset_; }
bool SecretKey::hasSeed() const noexcept { return seed_.has_value(); }
RNGSeed SecretKey::getSeed() const noexcept { return seed_.value(); }
void SecretKey::setSeed(const RNGSeed &seed) noexcept { seed_.emplace(seed); }
void SecretKey::flushSeed() noexcept { seed_.reset(); }

Size SecretKey::coeffsSize() const noexcept {
    return static_cast<Size>(coeffs_.size());
}
void SecretKey::allocCoeffs() {
    coeffs_.clear();
    coeffs_.resize(
        get_rank(preset_) * get_num_secret(preset_) * get_degree(preset_), 0);
}
i8 &SecretKey::coeff(Size index) noexcept { return coeffs_[index]; }
i8 SecretKey::coeff(Size index) const noexcept { return coeffs_[index]; }
i8 *SecretKey::coeffs() noexcept { return coeffs_.data(); }
const i8 *SecretKey::coeffs() const noexcept { return coeffs_.data(); }
Size SecretKey::numPoly() const noexcept {
    return static_cast<Size>(polys_.size());
}
void SecretKey::zeroize() noexcept {
    if (!coeffs_.empty()) {
        deb_secure_zero(coeffs_.data(), coeffs_.size() * sizeof(i8));
    }
    if (seed_.has_value()) {
        deb_secure_zero(seed_->data(), seed_->size() * sizeof(u64));
        seed_.reset();
    }
    for (auto &poly : polys_) {
        for (Size i = 0; i < poly.size(); ++i) {
            deb_secure_zero(poly[i].data(), poly[i].degree() * sizeof(u64));
        }
    }
}

void SecretKey::allocPolys(std::optional<Size> num_polyunit) {
    num_polyunit = num_polyunit.value_or(get_num_p(preset_));
    const Size num_poly = get_rank(preset_) * get_num_secret(preset_);
    polys_.clear();
    for (Size i = 0; i < num_poly; ++i) {
        polys_.emplace_back(preset_, num_polyunit.value());
    }
}

// ---------------------------------------------------------------------
// Implementation of SwitchKey
// ---------------------------------------------------------------------
SwitchKey::SwitchKey(Preset preset, const SwitchKeyKind type,
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

Preset SwitchKey::preset() const noexcept { return preset_; }
void SwitchKey::setType(const SwitchKeyKind type) noexcept { type_ = type; }
SwitchKeyKind SwitchKey::type() const noexcept { return type_; }
void SwitchKey::setRotIdx(Size rot_idx) noexcept { rot_idx_.emplace(rot_idx); }
Size SwitchKey::rotIdx() const noexcept {
    if (rot_idx_)
        return rot_idx_.value();
    return static_cast<Size>(-1);
}
Size SwitchKey::dnum() const noexcept { return dnum_; }
void SwitchKey::addAx(const Size num_polyunit, std::optional<Size> size,
                      const bool ntt_state) {
    const auto num_poly = size.value_or(1);
    for (Size i = 0; i < num_poly; ++i) {
        ax_.emplace_back(preset_, num_polyunit);
    }
    setAxNTT(ntt_state);
}
void SwitchKey::addAx(const Polynomial &poly) { ax_.push_back(poly); }
void SwitchKey::addBx(const Size num_polyunit, std::optional<Size> size,
                      const bool ntt_state) {
    const auto num_poly = size.value_or(dnum_ * get_num_secret(preset_));
    for (Size i = 0; i < num_poly; ++i) {
        bx_.emplace_back(preset_, num_polyunit);
    }
    setBxNTT(ntt_state);
}
void SwitchKey::addBx(const Polynomial &poly) { bx_.push_back(poly); }
void SwitchKey::setAxNTT(bool ntt_state) noexcept {
    for (auto &poly : ax_) {
        poly.setNTT(ntt_state);
    }
}
void SwitchKey::setBxNTT(bool ntt_state) noexcept {
    for (auto &poly : bx_) {
        poly.setNTT(ntt_state);
    }
}
Size SwitchKey::axSize() const noexcept {
    return static_cast<Size>(ax_.size());
}
Size SwitchKey::bxSize() const noexcept {
    return static_cast<Size>(bx_.size());
}
std::vector<Polynomial> &SwitchKey::getAx() noexcept { return ax_; }
const std::vector<Polynomial> &SwitchKey::getAx() const noexcept { return ax_; }
std::vector<Polynomial> &SwitchKey::getBx() noexcept { return bx_; }
const std::vector<Polynomial> &SwitchKey::getBx() const noexcept { return bx_; }
Polynomial &SwitchKey::ax(Size index) noexcept { return ax_[index]; }
const Polynomial &SwitchKey::ax(Size index) const noexcept {
    return ax_[index];
}
Polynomial &SwitchKey::bx(Size index) noexcept { return bx_[index]; }
const Polynomial &SwitchKey::bx(Size index) const noexcept {
    return bx_[index];
}

} // namespace deb
