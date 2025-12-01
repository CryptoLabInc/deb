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

#include "Serialize.hpp"
#include "Context.hpp"

namespace deb {

std::vector<deb_fb::Complex> toComplexVector(const Complex *data,
                                             const Size size) {
    std::vector<deb_fb::Complex> complex_vec;
    for (Size i = 0; i < size; ++i) {
        complex_vec.emplace_back(data[i].real(), data[i].imag());
    }
    return complex_vec;
}

std::vector<Complex>
toDebComplexVector(const Vector<const deb_fb::Complex *> *data) {
    const Size size = data->size();
    std::vector<Complex> Complex_vec;
    for (Size i = 0; i < size; ++i) {
        Complex_vec.emplace_back(data->Get(i)->real(), data->Get(i)->imag());
    }
    return Complex_vec;
}

std::vector<deb_fb::Complex32> toComplex32Vector(const ComplexT<float> *data,
                                                 const Size size) {
    std::vector<deb_fb::Complex32> complex_vec;
    for (Size i = 0; i < size; ++i) {
        complex_vec.emplace_back(static_cast<float>(data[i].real()),
                                 static_cast<float>(data[i].imag()));
    }
    return complex_vec;
}

std::vector<Complex>
toDebComplex32Vector(const Vector<const deb_fb::Complex32 *> *data) {
    const Size size = data->size();
    std::vector<Complex> Complex_vec;
    for (Size i = 0; i < size; ++i) {
        Complex_vec.emplace_back(static_cast<double>(data->Get(i)->real()),
                                 static_cast<double>(data->Get(i)->imag()));
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
    Message msg(message->size());
    memcpy(msg.data(), toDebComplexVector(message->data()).data(),
           message->size() * sizeof(Complex));
    return msg;
}

flatbuffers::Offset<deb_fb::Coeff>
serializeCoeff(flatbuffers::FlatBufferBuilder &builder,
               const CoeffMessage &coeff) {
    return deb_fb::CreateCoeff(
        builder, coeff.size(),
        builder.CreateVector(coeff.data(), coeff.size()));
}

CoeffMessage deserializeCoeff(const deb_fb::Coeff *coeff) {
    CoeffMessage coeff_t(coeff->size());
    std::memcpy(coeff_t.data(), coeff->data()->data(),
                coeff_t.size() * sizeof(Real));
    return coeff_t;
}

flatbuffers::Offset<deb_fb::PolyUnit>
serializePolyUnit(flatbuffers::FlatBufferBuilder &builder,
                  const PolyUnit &polyunit) {
    return deb_fb::CreatePolyUnit(
        builder, polyunit.prime(), polyunit.degree(), polyunit.isNTT(),
        builder.CreateVector(polyunit.data(), polyunit.degree()));
}

PolyUnit deserializePolyUnit(const deb_fb::PolyUnit *polyunit) {
    PolyUnit poly_t(polyunit->prime(), polyunit->degree());
    poly_t.setNTT(polyunit->ntt_state());
    std::memcpy(poly_t.data(), polyunit->array()->data(),
                poly_t.degree() * sizeof(u64));
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
    Polynomial poly_t(getContext(preset), poly->size());
    for (Size i = 0; i < poly_t.size(); ++i) {
        poly_t[i] = deserializePolyUnit(poly->rnspolys()->Get(i));
    }
    return poly_t;
}

flatbuffers::Offset<deb_fb::Cipher>
serializeCipher(flatbuffers::FlatBufferBuilder &builder,
                const Ciphertext &cipher) {
    std::vector<flatbuffers::Offset<deb_fb::Poly>> bigpolys;
    bigpolys.reserve(cipher.numPoly());
    for (Size i = 0; i < cipher.numPoly(); ++i) {
        bigpolys.push_back(serializePoly(builder, cipher[i]));
    }
    return deb_fb::CreateCipher(builder, cipher.preset(), cipher.encoding(),
                                cipher.numPoly(),
                                builder.CreateVector(bigpolys));
}

Ciphertext deserializeCipher(const deb_fb::Cipher *cipher) {
    auto preset = static_cast<Preset>(cipher->preset());
    Ciphertext cipher_t(getContext(preset), cipher->bigpolys()->Get(0)->size(),
                        cipher->size());
    cipher_t.setEncoding(static_cast<EncodingType>(cipher->encoding()));
    for (Size i = 0; i < cipher_t.numPoly(); ++i) {
        cipher_t[i] = deserializePoly(preset, cipher->bigpolys()->Get(i));
    }
    return cipher_t;
}

flatbuffers::Offset<deb_fb::Sk>
serializeSk(flatbuffers::FlatBufferBuilder &builder, const SecretKey &sk) {
    auto context = getContext(sk.preset());
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
    SecretKey sk_t(static_cast<Preset>(sk->preset()), seed);
    sk_t.flushSeed();
    if (sk->seeds()->size() != 0) {
        std::memcpy(seed.data(), sk->seeds()->data(), sizeof(RNGSeed));
        sk_t.setSeed(seed);
    }
    if (sk->coeffs()->size() != 0) {
        sk_t.allocCoeffs();
        std::copy(sk->coeffs()->begin(), sk->coeffs()->end(), sk_t.coeffs());
    }
    if (sk->bigpolys()->size() != 0) {
        sk_t.allocPolys(sk->bigpolys()->Get(0)->rnspolys()->size());
        for (Size i = 0; i < sk_t.numPoly(); ++i) {
            sk_t[i] = deserializePoly(sk_t.preset(), sk->bigpolys()->Get(i));
        }
    }
    return sk_t;
}

flatbuffers::Offset<deb_fb::Swk>
serializeSwk(flatbuffers::FlatBufferBuilder &builder, const SwitchKey &swk) {
    auto context = getContext(swk.preset());
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
    const auto preset = static_cast<Preset>(swk->preset());
    SwitchKey swk_t(getContext(preset),
                    static_cast<SwitchKeyKind>(swk->type()));
    swk_t.getAx().clear();
    for (Size i = 0; i < swk->ax()->size(); ++i) {
        Polynomial tmp = deserializePoly(preset, swk->ax()->Get(i));
        swk_t.addAx(tmp);
    }
    swk_t.getBx().clear();
    for (Size i = 0; i < swk->bx()->size(); ++i) {
        Polynomial tmp = deserializePoly(preset, swk->bx()->Get(i));
        swk_t.addBx(tmp);
    }
    if (swk->rot_idx() != static_cast<Size>(-1)) {
        swk_t.setRotIdx(swk->rot_idx());
    }
    return swk_t;
}
} // namespace deb
