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

#include "CKKSTypes.hpp"

namespace deb {

// ---------------------------------------------------------------------
// Implementation of Message
// ---------------------------------------------------------------------
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
PolyUnit::PolyUnit(const Preset preset, const Size level)
    : PolyUnit(getContext(preset), level) {}

PolyUnit::PolyUnit(const Context &context, const Size level)
    : prime_(context->get_primes()[level]), ntt_state_(false) {
#if DEB_ALINAS_LEN == 0
    data_ = std::shared_ptr<span<u64>>(
        new span<u64>(new u64[context->get_degree()], context->get_degree()),
        [](span<u64> *p) {
            delete[] p->data();
            delete p;
        });
#else
    auto *buf = static_cast<u64 *>(::operator new[](
        sizeof(u64) * context->get_degree(), std::align_val_t(DEB_ALINAS_LEN)));
    data_ = std::shared_ptr<span<u64>>(
        new span<u64>(buf, context->get_degree()), [](span<u64> *p) {
            ::operator delete[](p->data(), std::align_val_t(DEB_ALINAS_LEN));
            delete p;
        });
#endif
}
PolyUnit::PolyUnit(u64 prime, Size degree) : prime_(prime), ntt_state_(false) {
#if DEB_ALINAS_LEN == 0
    data_ = std::shared_ptr<span<u64>>(new span<u64>(new u64[degree], degree),
                                       [](span<u64> *p) {
                                           delete[] p->data();
                                           delete p;
                                       });
#else
    auto *buf = static_cast<u64 *>(::operator new[](
        sizeof(u64) * degree, std::align_val_t(DEB_ALINAS_LEN)));
    data_ = std::shared_ptr<span<u64>>(
        new span<u64>(buf, degree), [](span<u64> *p) {
            ::operator delete[](p->data(), std::align_val_t(DEB_ALINAS_LEN));
            delete p;
        });
#endif
}

PolyUnit PolyUnit::deepCopy() const {
    PolyUnit copy(prime_, degree());
    for (Size i = 0; i < degree(); ++i) {
        copy[i] = (*this)[i];
    }
    copy.setNTT(ntt_state_);
    return copy;
}
void PolyUnit::setPrime(u64 prime) noexcept { prime_ = prime; }
u64 PolyUnit::prime() const noexcept { return prime_; }
void PolyUnit::setNTT(bool ntt_state) noexcept { ntt_state_ = ntt_state; }
bool PolyUnit::isNTT() const noexcept { return ntt_state_; }
Size PolyUnit::degree() const noexcept {
    return static_cast<Size>(data_->size());
}
u64 &PolyUnit::operator[](Size index) noexcept { return (*data_)[index]; }
u64 PolyUnit::operator[](Size index) const noexcept { return (*data_)[index]; }
u64 *PolyUnit::data() const noexcept { return data_->data(); }

void PolyUnit::setData(u64 *new_data, Size size) {
    data_ = std::shared_ptr<span<u64>>(new span<u64>(new_data, size),
                                       [](span<u64> *p) { delete p; });
}

// ---------------------------------------------------------------------
// Implementation of Polynomial
// ---------------------------------------------------------------------
Polynomial::Polynomial(const Preset preset, const bool full_level)
    : Polynomial(getContext(preset), full_level) {}
Polynomial::Polynomial(Context context, const bool full_level) {
    Size num_poly =
        full_level ? context->get_num_p() : context->get_encryption_level() + 1;
    for (Size l = 0; l < num_poly; ++l) {
        data_.emplace_back(context, l);
    }
}
Polynomial::Polynomial(Context context, const Size custom_size) {
    for (Size l = 0; l < custom_size; ++l) {
        data_.emplace_back(context, l);
    }
}
Polynomial::Polynomial(const Polynomial &other, Size others_idx,
                       Size custom_size)
    : data_(&other.data_[others_idx], &other.data_[others_idx] + custom_size) {}

Polynomial Polynomial::deepCopy(std::optional<Size> num_polyunit) const {
    const auto num_polyunit_val = num_polyunit.value_or(this->size());
    Polynomial copy(*this);
    copy.data_.clear();
    for (Size i = 0; i < num_polyunit_val; ++i) {
        copy.data_.push_back(data_[i].deepCopy());
    }
    return copy;
}

void Polynomial::setNTT(bool ntt_state) noexcept {
    for (auto &poly : data_) {
        poly.setNTT(ntt_state);
    }
}

void Polynomial::setLevel(Preset preset, Size level) {
    setSize(preset, level + 1);
}

Size Polynomial::level() const noexcept {
    return static_cast<Size>(data_.size()) - 1;
}

void Polynomial::setSize(Preset preset, Size size) {
    const auto context = getContext(preset);
    if (size <= this->size()) {
        data_.erase(data_.begin() + size, data_.end());
    } else {
        const auto max_len = context->get_num_p();
        for (Size l = this->size(); l < size; ++l) {
            data_.emplace_back(context->get_primes()[l % max_len],
                               context->get_degree());
        }
    }
}

Size Polynomial::size() const noexcept {
    return static_cast<Size>(data_.size());
}
PolyUnit &Polynomial::operator[](size_t index) noexcept { return data_[index]; }
const PolyUnit &Polynomial::operator[](size_t index) const noexcept {
    return data_[index];
}
PolyUnit *Polynomial::data() noexcept { return data_.data(); }
const PolyUnit *Polynomial::data() const noexcept { return data_.data(); }

// ---------------------------------------------------------------------
// Implementation of Ciphertext
// ---------------------------------------------------------------------
Ciphertext::Ciphertext(const Preset preset) : Ciphertext(getContext(preset)) {}
Ciphertext::Ciphertext(Context context)
    : preset_(context->get_preset()), encoding_(SLOT) {
    const Size num_polys = context->get_rank() * context->get_num_secret() + 1;
    for (Size i = 0; i < num_polys; ++i) {
        polys_.emplace_back(context);
    }
}
Ciphertext::Ciphertext(const Preset preset, const Size level,
                       std::optional<Size> num_poly)
    : Ciphertext(getContext(preset), level, num_poly) {}
Ciphertext::Ciphertext(Context context, const Size level,
                       std::optional<Size> num_poly)
    : preset_(context->get_preset()), encoding_(UNKNOWN) {
    const auto num_polys =
        num_poly.value_or(context->get_rank() * context->get_num_secret() + 1);
    for (Size i = 0; i < num_polys; ++i) {
        polys_.emplace_back(context, level + 1);
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

Polynomial &Ciphertext::operator[](size_t index) noexcept {
    return polys_[index];
}
const Polynomial &Ciphertext::operator[](size_t index) const noexcept {
    return polys_[index];
}
Polynomial *Ciphertext::data() noexcept { return polys_.data(); }
const Polynomial *Ciphertext::data() const noexcept { return polys_.data(); }

// ---------------------------------------------------------------------
// Implementation of SecretKey
// ---------------------------------------------------------------------
SecretKey::SecretKey(Preset preset, const RNGSeed seed)
    : preset_(preset), seed_(seed) {}

SecretKey::SecretKey(Preset preset, bool embedding) : preset_(preset) {
    Context context = getContext(preset);
    coeffs_.resize(context->get_rank() * context->get_num_secret() *
                       context->get_degree(),
                   0);
    if (embedding) {
        const Size num_poly = context->get_rank() * context->get_num_secret();
        for (Size i = 0; i < num_poly; ++i) {
            polys_.emplace_back(preset, true);
        }
    }
}

Preset SecretKey::preset() const noexcept { return preset_; }

bool SecretKey::hasSeed() const noexcept { return seed_.has_value(); }
RNGSeed SecretKey::getSeed() const noexcept { return seed_.value(); }
void SecretKey::setSeed(const RNGSeed &seed) noexcept { seed_.emplace(seed); }
void SecretKey::flushSeed() noexcept { seed_.reset(); }

Size SecretKey::coeffsSize() const noexcept {
    return static_cast<Size>(coeffs_.size());
}
void SecretKey::allocCoeffs() {
    auto context = getContext(preset_);
    coeffs_.clear();
    coeffs_.resize(context->get_rank() * context->get_num_secret() *
                       context->get_degree(),
                   0);
}
i8 &SecretKey::coeff(Size index) noexcept { return coeffs_[index]; }
i8 SecretKey::coeff(Size index) const noexcept { return coeffs_[index]; }
i8 *SecretKey::coeffs() noexcept { return coeffs_.data(); }
const i8 *SecretKey::coeffs() const noexcept { return coeffs_.data(); }
Size SecretKey::numPoly() const noexcept {
    return static_cast<Size>(polys_.size());
}
void SecretKey::allocPolys(std::optional<Size> num_polyunit) {
    const auto context = getContext(preset_);
    num_polyunit = num_polyunit.value_or(context->get_num_p());
    const Size num_poly = context->get_rank() * context->get_num_secret();
    polys_.clear();
    for (Size i = 0; i < num_poly; ++i) {
        polys_.emplace_back(context, num_polyunit.value());
    }
}
Polynomial &SecretKey::operator[](Size index) { return polys_[index]; }
const Polynomial &SecretKey::operator[](Size index) const {
    return polys_[index];
}
Polynomial *SecretKey::data() noexcept { return polys_.data(); }
const Polynomial *SecretKey::data() const noexcept { return polys_.data(); }

// SwitchKey Implementation
SwitchKey::SwitchKey(Preset preset, const SwitchKeyKind type,
                     const std::optional<Size> rot_idx)
    : SwitchKey(getContext(preset), type, rot_idx) {}
SwitchKey::SwitchKey(const Context &context, const SwitchKeyKind type,
                     const std::optional<Size> rot_idx)
    : preset_(context->get_preset()), type_(type), rot_idx_(rot_idx),
      dnum_(context->get_gadget_rank()) {
    switch (type_) {
    case SWK_ENC:
        addAx(context->get_num_p(), 1, true);
        addBx(context->get_num_p(), context->get_num_secret(), true);
        break;
    case SWK_MULT:
    case SWK_CONJ:
    case SWK_ROT:
    case SWK_AUTO:
    case SWK_MODPACK:
    case SWK_COMPOSE:
    case SWK_DECOMPOSE:
        addAx(context->get_num_p(), dnum_, true);
        addBx(context->get_num_p(), dnum_ * context->get_num_secret(), true);
        break;
    case SWK_MODPACK_SELF:
    case SWK_GENERIC:
    default:
        break;
    }
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
    const auto num_poly =
        size.value_or(dnum_ * getContext(preset_)->get_num_secret());
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
