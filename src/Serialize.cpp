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

#include "Serialize.hpp"
#include "utils/Basic.hpp"

#include <algorithm>
#include <string>

namespace deb {

namespace {

// --- Untrusted-input guards ------------------------------------------------
// A buffer reaching deserialize*() is attacker-controlled. The flatbuffers
// Verifier run by deserializeFromStream proves only that each vector lies
// inside the supplied bytes; it does not make an optional field present, and it
// does not force a vector's length to agree with a length the payload declares
// separately (Poly.size, Cipher.size, PolyUnit.degree, Coeff.size) or with the
// size implied by the preset. Every such field is therefore checked here before
// it is used to size a copy or to bound a loop.

[[noreturn]] void rejectBuffer(const char *what) {
    throw std::runtime_error(std::string("[deserialize] Malformed buffer: ") +
                             what);
}

// Rejects an absent (nullptr) flatbuffers vector field.
template <typename T> const T *requireField(const T *field, const char *what) {
    if (field == nullptr) {
        rejectBuffer(what);
    }
    return field;
}

// Rejects a vector whose real length disagrees with the length the payload
// declares, or with the length the preset implies.
void requireLength(size_t actual, size_t expected, const char *what) {
    if (actual != expected) {
        rejectBuffer(what);
    }
}

// Rejects a declared count above what the preset can possibly need. Checking a
// declared length only against another declared length is not enough: both come
// from the buffer, so they can agree with each other and still be absurd. Every
// count that ends up sizing an allocation or indexing a preset table is bounded
// here before it is used.
void requireMaxLength(size_t actual, size_t limit, const char *what) {
    if (actual > limit) {
        rejectBuffer(what);
    }
}

// Rejects a scalar that is not a valid enumerator. Unchecked casts of these
// bytes reach code that switches on them or uses them to pick a code path.
void requireEnumRange(int value, int min, int max, const char *what) {
    if (value < min || value > max) {
        rejectBuffer(what);
    }
}

// Rejects a preset byte that names no known preset. Without this the raw value
// flows into the preset accessors, which look it up in a global map and would
// otherwise silently substitute another preset's parameters.
Preset requirePreset(u8 raw) {
    const auto preset = static_cast<Preset>(raw);
    if (preset_map.find(preset) == preset_map.end()) {
        rejectBuffer("unknown preset");
    }
    return preset;
}

} // namespace

std::vector<deb_fb::Complex> toComplexVector(const Complex *data,
                                             const Size size) {
    std::vector<deb_fb::Complex> complex_vec(size);
    for (Size i = 0; i < size; ++i) {
        complex_vec[i] = {data[i].real(), data[i].imag()};
    }
    return complex_vec;
}

std::vector<Complex>
toDebComplexVector(const Vector<const deb_fb::Complex *> *data) {
    const Size size = data->size();
    std::vector<Complex> Complex_vec(size);
    for (Size i = 0; i < size; ++i) {
        Complex_vec[i] = {data->Get(i)->real(), data->Get(i)->imag()};
    }
    return Complex_vec;
}

std::vector<deb_fb::Complex32> toComplex32Vector(const ComplexT<float> *data,
                                                 const Size size) {
    std::vector<deb_fb::Complex32> complex_vec(size);
    for (Size i = 0; i < size; ++i) {
        complex_vec[i] = {data[i].real(), data[i].imag()};
    }
    return complex_vec;
}

std::vector<ComplexT<float>>
toDebComplex32Vector(const Vector<const deb_fb::Complex32 *> *data) {
    const Size size = data->size();
    std::vector<ComplexT<float>> Complex_vec(size);
    for (Size i = 0; i < size; ++i) {
        Complex_vec[i] = {data->Get(i)->real(), data->Get(i)->imag()};
    }
    return Complex_vec;
}

flatbuffers::Offset<deb_fb::Message>
serializeMessage(flatbuffers::FlatBufferBuilder &builder,
                 const Message &message) {
    auto complex_offset = builder.CreateVectorOfStructs(
        toComplexVector(message.data(), message.size()));
    return CreateMessage(builder, message.size(), complex_offset);
}

Message deserializeMessage(const deb_fb::Message *message) {
    const auto *data = requireField(message->data(), "Message.data");
    requireLength(data->size(), message->size(), "Message.data");
    return Message(toDebComplexVector(data));
}

flatbuffers::Offset<deb_fb::Message32>
serializeFMessage(flatbuffers::FlatBufferBuilder &builder,
                  const FMessage &message) {
    auto complex_offset = builder.CreateVectorOfStructs(
        toComplex32Vector(message.data(), message.size()));
    return CreateMessage32(builder, message.size(), complex_offset);
}

FMessage deserializeFMessage(const deb_fb::Message32 *message) {
    const auto *data = requireField(message->data(), "Message32.data");
    requireLength(data->size(), message->size(), "Message32.data");
    return FMessage(toDebComplex32Vector(data));
}

flatbuffers::Offset<deb_fb::Coeff>
serializeCoeff(flatbuffers::FlatBufferBuilder &builder,
               const CoeffMessage &coeff) {
    return deb_fb::CreateCoeff(
        builder, coeff.size(),
        builder.CreateVector(coeff.data(), coeff.size()));
}

CoeffMessage deserializeCoeff(const deb_fb::Coeff *coeff) {
    const auto *data = requireField(coeff->data(), "Coeff.data");
    requireLength(data->size(), coeff->size(), "Coeff.data");
    CoeffMessage coeff_t(coeff->size());
    std::memcpy(coeff_t.data(), data->data(), coeff_t.size() * sizeof(Real));
    return coeff_t;
}

flatbuffers::Offset<deb_fb::Coeff32>
serializeFCoeff(flatbuffers::FlatBufferBuilder &builder,
                const FCoeffMessage &coeff) {
    return deb_fb::CreateCoeff32(
        builder, coeff.size(),
        builder.CreateVector(coeff.data(), coeff.size()));
}

FCoeffMessage deserializeFCoeff(const deb_fb::Coeff32 *coeff) {
    const auto *data = requireField(coeff->data(), "Coeff32.data");
    requireLength(data->size(), coeff->size(), "Coeff32.data");
    FCoeffMessage coeff_t(coeff->size());
    std::memcpy(coeff_t.data(), data->data(), coeff_t.size() * sizeof(float));
    return coeff_t;
}

flatbuffers::Offset<deb_fb::PolyUnit>
serializePolyUnit(flatbuffers::FlatBufferBuilder &builder,
                  const PolyUnit &polyunit) {
    // encoding ntt type and root type into a single int
    int8_t ntt_info =
        static_cast<int8_t>(static_cast<int>(polyunit.getNTTType()) * 10 +
                            static_cast<int>(polyunit.getNTTRootType()));
    return deb_fb::CreatePolyUnit(
        builder, polyunit.prime(), polyunit.degree(), ntt_info,
        builder.CreateVector(polyunit.data(), polyunit.degree()));
}

PolyUnit deserializePolyUnit(const deb_fb::PolyUnit *polyunit,
                             std::optional<Preset> preset) {
    // Check the array before allocating: `degree` is a declared scalar, so an
    // unchecked one would both size a huge allocation and over-read the array.
    const auto *array = requireField(polyunit->array(), "PolyUnit.array");
    requireLength(array->size(), polyunit->degree(), "PolyUnit.array");
    // Agreeing with its own array is not enough. Everything downstream (the NTT
    // objects, the modular arithmetic, the encrypt/decrypt loops) is sized from
    // the PRESET degree, never from this field, so a self-consistent but short
    // unit becomes an undersized buffer that the first transform writes past.
    // The prime is bound to the preset for the same reason: it selects the
    // modulus the coefficients are reduced by.
    if (preset.has_value()) {
        requireLength(polyunit->degree(), get_degree(*preset),
                      "PolyUnit.degree does not match the preset");
        const u64 *primes = get_primes(*preset);
        const Size num_p = get_num_p(*preset);
        bool known_prime = false;
        for (Size i = 0; i < num_p && !known_prime; ++i) {
            known_prime = (primes[i] == polyunit->prime());
        }
        if (!known_prime) {
            rejectBuffer("PolyUnit.prime is not a prime of the preset");
        }
    }
    PolyUnit poly_t(polyunit->prime(), polyunit->degree());
    int ntt_info = polyunit->ntt_info();
    // encoding ntt type and root type into a single int
    poly_t.setNTT(static_cast<utils::NTTType>(ntt_info / 10),
                  static_cast<utils::NTTRootType>(ntt_info % 10));
    std::memcpy(poly_t.data(), array->data(), poly_t.degree() * sizeof(u64));
    return poly_t;
}

flatbuffers::Offset<deb_fb::Poly>
serializePoly(flatbuffers::FlatBufferBuilder &builder, const Polynomial &poly) {
    std::vector<flatbuffers::Offset<deb_fb::PolyUnit>> polys;
    polys.reserve(poly.size());
    for (Size i = 0; i < poly.size(); ++i) {
        polys.push_back(serializePolyUnit(builder, poly[i]));
    }
    return deb_fb::CreatePoly(builder, poly.size(),
                              builder.CreateVector(polys));
}

Polynomial deserializePoly(const Preset preset, const deb_fb::Poly *poly) {
    const auto *rnspolys = requireField(poly->rnspolys(), "Poly.rnspolys");
    requireLength(rnspolys->size(), poly->size(), "Poly.rnspolys");
    // Bound the limb count before constructing: PolynomialT walks the preset's
    // prime table once per limb, so an unbounded count reads past that table
    // (and grows the unit vector without limit) before any later guard runs.
    requireMaxLength(poly->size(), get_num_p(preset), "Poly.size");
    Polynomial poly_t(preset, poly->size());
    requireLength(rnspolys->size(), poly_t.size(), "Poly.rnspolys");
    for (Size i = 0; i < poly_t.size(); ++i) {
        poly_t[i] = deserializePolyUnit(
            requireField(rnspolys->Get(i), "Poly.rnspolys[]"), preset);
    }
    return poly_t;
}

flatbuffers::Offset<deb_fb::Cipher>
serializeCipher(flatbuffers::FlatBufferBuilder &builder,
                const Ciphertext &cipher) {
    std::vector<flatbuffers::Offset<deb_fb::Poly>> bigpolys;
    bigpolys.reserve(cipher.numPoly());
    for (Size i = 0; i < cipher.numPoly(); ++i) {
        // For a seed-only ciphertext the released 'a' part serializes as an
        // empty Poly (size 0); the seed below is what restores it.
        bigpolys.push_back(serializePoly(builder, cipher[i]));
    }
    auto bigpolys_offset = builder.CreateVector(bigpolys);

    RNGSeed seed{};
    const bool has_seed = cipher.hasSeed();
    if (has_seed) {
        seed = cipher.getSeed();
    }
    auto seed_offset = builder.CreateVector(has_seed ? seed.data() : nullptr,
                                            has_seed ? seed.size() : 0);

    return deb_fb::CreateCipher(builder, cipher.preset(), cipher.encoding(),
                                cipher.numPoly(), bigpolys_offset, seed_offset,
                                static_cast<uint8_t>(cipher.seedMode()));
}

Ciphertext deserializeCipher(const deb_fb::Cipher *cipher) {
    const auto preset = requirePreset(cipher->preset());
    const auto *bigpolys = requireField(cipher->bigpolys(), "Cipher.bigpolys");
    requireLength(bigpolys->size(), cipher->size(), "Cipher.bigpolys");
    if (bigpolys->size() == 0) {
        rejectBuffer("Cipher.bigpolys is empty");
    }
    const auto *first = requireField(bigpolys->Get(0), "Cipher.bigpolys[0]");
    // Bound BOTH declared counts against the preset before either sizes an
    // allocation. Checking them only against each other is not enough:
    // flatbuffers lets many vector entries alias one small table, so a tiny
    // buffer can declare an enormous component count.
    requireMaxLength(cipher->size(),
                     get_rank(preset) * get_num_secret(preset) + 1,
                     "Cipher.size");
    if (first->size() == 0) {
        rejectBuffer("Cipher.bigpolys[0] has no limbs");
    }
    requireMaxLength(first->size(), get_num_p(preset), "Cipher level");
    requireEnumRange(cipher->encoding(), UNKNOWN, REAL, "Cipher.encoding");
    // The ctor takes a level INDEX and allocates level+1 limbs, indexing the
    // preset prime table by limb; passing the limb count would read one past
    // it.
    Ciphertext cipher_t(preset, first->size() - 1, cipher->size());
    cipher_t.setEncoding(static_cast<EncodingType>(cipher->encoding()));
    requireLength(bigpolys->size(), cipher_t.numPoly(), "Cipher.bigpolys");
    for (Size i = 0; i < cipher_t.numPoly(); ++i) {
        const auto *poly = requireField(bigpolys->Get(i), "Cipher.bigpolys[]");
        // Components must agree on their limb count. The sole legitimate
        // exception is the released 'a' part of a seed-only ciphertext, which
        // serializes as an empty Poly and is regenerated from the seed.
        const bool released_ax =
            (i + 1 == cipher_t.numPoly()) && poly->size() == 0;
        if (!released_ax) {
            requireLength(poly->size(), first->size(), "Cipher.bigpolys[]");
        }
        cipher_t[i] = deserializePoly(preset, poly);
    }
    // Restore seed-only state (field absent for legacy buffers -> full cipher).
    if (cipher->seed() != nullptr && cipher->seed()->size() != 0) {
        RNGSeed seed{};
        requireLength(cipher->seed()->size(), seed.size(), "Cipher.seed");
        std::memcpy(seed.data(), cipher->seed()->data(), sizeof(RNGSeed));
        cipher_t.setSeed(seed);
        cipher_t.setSeedMode(static_cast<CipherSeedMode>(cipher->seed_mode()));
    }
    return cipher_t;
}

flatbuffers::Offset<deb_fb::Sk>
serializeSk(flatbuffers::FlatBufferBuilder &builder, const SecretKey &sk) {
    auto seed_offset =
        builder.CreateVector(sk.hasSeed() ? sk.getSeed().data() : nullptr,
                             sk.hasSeed() ? sk.getSeed().size() : 0);
    auto coeffs_offset = builder.CreateVector(sk.coeffs(), sk.coeffsSize());
    auto bigpolys_offsets = std::vector<flatbuffers::Offset<deb_fb::Poly>>();
    bigpolys_offsets.reserve(sk.numPoly());
    for (Size i = 0; i < sk.numPoly(); ++i) {
        bigpolys_offsets.push_back(serializePoly(builder, sk[i]));
    }
    auto bigpolys_vector = builder.CreateVector(bigpolys_offsets);
    return deb_fb::CreateSk(builder, sk.preset(), seed_offset, coeffs_offset,
                            bigpolys_vector);
}

SecretKey deserializeSk(const deb_fb::Sk *sk) {
    RNGSeed seed = {};
    SecretKey sk_t(requirePreset(sk->preset()), seed);
    sk_t.flushSeed();
    const auto *sk_seed = requireField(sk->seed(), "Sk.seed");
    if (sk_seed->size() != 0) {
        requireLength(sk_seed->size(), seed.size(), "Sk.seed");
        std::memcpy(seed.data(), sk_seed->data(), sizeof(RNGSeed));
        sk_t.setSeed(seed);
    }
    const auto *coeffs = requireField(sk->coeffs(), "Sk.coeffs");
    if (coeffs->size() != 0) {
        // The destination is sized from the preset alone, so the declared
        // length has to be checked against it: copying an attacker-chosen
        // number of coefficients into it is a heap overflow.
        sk_t.allocCoeffs();
        requireLength(coeffs->size(), sk_t.coeffsSize(), "Sk.coeffs");
        std::copy(coeffs->begin(), coeffs->end(), sk_t.coeffs());
    }
    const auto *bigpolys = requireField(sk->bigpolys(), "Sk.bigpolys");
    if (bigpolys->size() != 0) {
        const auto *first = requireField(
            requireField(bigpolys->Get(0), "Sk.bigpolys[0]")->rnspolys(),
            "Sk.bigpolys[0].rnspolys");
        if (first->size() == 0) {
            rejectBuffer("Sk.bigpolys[0] has no limbs");
        }
        requireMaxLength(first->size(), get_num_p(sk_t.preset()),
                         "Sk.bigpolys[0] level");
        sk_t.allocPolys(first->size());
        requireLength(bigpolys->size(), sk_t.numPoly(), "Sk.bigpolys");
        for (Size i = 0; i < sk_t.numPoly(); ++i) {
            sk_t[i] = deserializePoly(sk_t.preset(), bigpolys->Get(i));
        }
    }
    return sk_t;
}

flatbuffers::Offset<deb_fb::Swk>
serializeSwk(flatbuffers::FlatBufferBuilder &builder, const SwitchKey &swk) {
    std::vector<flatbuffers::Offset<deb_fb::Poly>> ax_offsets, bx_offsets;
    ax_offsets.reserve(swk.axSize());
    bx_offsets.reserve(swk.bxSize());
    for (Size i = 0; i < swk.axSize(); ++i) {
        ax_offsets.push_back(serializePoly(builder, swk.ax(i)));
    }
    for (Size i = 0; i < swk.bxSize(); ++i) {
        bx_offsets.push_back(serializePoly(builder, swk.bx(i)));
    }
    auto ax_vector = builder.CreateVector(ax_offsets);
    auto bx_vector = builder.CreateVector(bx_offsets);

    return deb_fb::CreateSwk(builder, swk.preset(), swk.type(), swk.rotIdx(),
                             swk.dnum(), ax_vector, bx_vector);
}

SwitchKey deserializeSwk(const deb_fb::Swk *swk) {
    const auto preset = requirePreset(swk->preset());
    const auto *ax = requireField(swk->ax(), "Swk.ax");
    const auto *bx = requireField(swk->bx(), "Swk.bx");
    requireEnumRange(swk->type(), SWK_GENERIC, SWK_MODPACK_SELF, "Swk.type");
    // A key's shape is fully determined by its kind and its dnum, so pin it
    // exactly rather than merely bounding it. Without this, a few KiB of
    // aliased flatbuffer offsets can declare an unbounded number of full-size
    // polynomials: each entry costs 4 bytes of input but one whole polynomial
    // of allocation.
    const auto kind = static_cast<SwitchKeyKind>(swk->type());
    const Size dnum = swk->dnum();
    // dnum is the number of ax polynomials. For a self mod-pack key it is the
    // pad_rank, a power of two that divides the degree; every other keyed kind
    // uses the preset's gadget rank.
    // A self mod-pack key's pad_rank is only bounded by the degree, which for a
    // large preset would still permit gigabytes of polynomials. Bound it by
    // what could actually have been WRITTEN instead: every ax and bx polynomial
    // must carry real coefficients, so a key needs at least ax_count * (1 +
    // num_secret) * num_p * degree * 8 bytes on the wire. A key that could
    // never fit in a serialized buffer cannot have come from serializeToStream,
    // so there is no reason to accept it -- and this is what stops a few KiB of
    // aliased offsets from declaring an unbounded key.
    const u64 bytes_per_ax = u64{1} + get_num_secret(preset);
    const u64 wire_bytes_per_ax =
        bytes_per_ax * get_num_p(preset) * get_degree(preset) * sizeof(u64);
    const Size max_ax_by_wire_size = static_cast<Size>(
        std::max<u64>(1, u64{DEB_MAX_SERIALIZED_SIZE} / wire_bytes_per_ax));

    if (kind == SWK_MODPACK_SELF) {
        if (!utils::isPowerOfTwo(dnum) || dnum > max_ax_by_wire_size) {
            rejectBuffer("Swk.dnum is not a valid pad_rank");
        }
    } else {
        requireMaxLength(dnum, get_gadget_rank(preset), "Swk.dnum");
    }
    if (kind == SWK_GENERIC) {
        // Built empty and filled by the caller, so only bound it.
        requireMaxLength(ax->size(), max_ax_by_wire_size, "Swk.ax");
    } else {
        // genEncKeyInplace asserts axSize()==1; every other kind asserts
        // axSize()==dnum().
        requireLength(ax->size(), (kind == SWK_ENC) ? Size{1} : dnum, "Swk.ax");
    }
    requireLength(bx->size(), ax->size() * get_num_secret(preset), "Swk.bx");
    SwitchKey swk_t(preset, static_cast<SwitchKeyKind>(swk->type()));
    swk_t.getAx().clear();
    for (Size i = 0; i < ax->size(); ++i) {
        Polynomial tmp = deserializePoly(preset, ax->Get(i));
        swk_t.addAx(tmp);
    }
    swk_t.getBx().clear();
    for (Size i = 0; i < bx->size(); ++i) {
        Polynomial tmp = deserializePoly(preset, bx->Get(i));
        swk_t.addBx(tmp);
    }
    swk_t.setDnum(dnum);
    if (swk->rot_idx() != static_cast<Size>(-1)) {
        swk_t.setRotIdx(swk->rot_idx());
    }
    return swk_t;
}
} // namespace deb
