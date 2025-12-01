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

#include "CKKSTypes.hpp"
#include "DebFBType.h"

#include <sstream>

namespace deb {

/**
 * @brief Convenience alias for FlatBuffers vector types.
 */
template <typename T> using Vector = flatbuffers::Vector<T>;

/**
 * @brief Converts a buffer of @ref Complex into a vector usable by FlatBuffers.
 * @param data Pointer to complex values.
 * @param size Number of elements to convert.
 * @return Vector of FlatBuffer-compatible complex values.
 */
std::vector<deb_fb::Complex> toComplexVector(const Complex *data,
                                             const Size size);
/**
 * @brief Converts FlatBuffers complex data back into @ref Complex values.
 * @param data FlatBuffers vector pointer.
 * @return Vector with decoded complex values.
 */
std::vector<Complex>
toDebComplexVector(const Vector<const deb_fb::Complex *> *data);

/**
 * @brief Converts single-precision complex data into FlatBuffers format.
 * @param data Pointer to complex32 values.
 * @param size Number of elements.
 * @return Vector of FlatBuffer-compatible complex32 values.
 */
std::vector<deb_fb::Complex32> toComplex32Vector(const ComplexT<float> *data,
                                                 const Size size);
/**
 * @brief Converts FlatBuffers complex32 data back into @ref Complex values.
 * @param data FlatBuffers vector pointer.
 * @return Vector with decoded complex values.
 */
std::vector<Complex>
toDebComplex32Vector(const Vector<const deb_fb::Complex32 *> *data);

/**
 * @brief Serializes a high-precision slot message into FlatBuffers format.
 * @param builder FlatBuffer builder used to allocate the payload.
 * @param message Plaintext message container.
 * @return Offset into the builder pointing to the serialized object.
 */
flatbuffers::Offset<deb_fb::Message>
serializeMessage(flatbuffers::FlatBufferBuilder &builder,
                 const Message &message);
/**
 * @brief Deserializes a FlatBuffers message into @ref Message.
 * @param message FlatBuffers object.
 * @return Plaintext message container.
 */
Message deserializeMessage(const deb_fb::Message *message);

/**
 * @brief Serializes coefficient-domain plaintexts.
 * @param builder FlatBuffer builder.
 * @param coeff Coefficient-domain message container.
 * @return Offset pointing to serialized coefficients.
 */
flatbuffers::Offset<deb_fb::Coeff>
serializeCoeff(flatbuffers::FlatBufferBuilder &builder,
               const CoeffMessage &coeff);

/**
 * @brief Deserializes coefficient-domain plaintexts.
 * @param coeff FlatBuffers coefficient object.
 * @return Coefficient-domain message container.
 */
CoeffMessage deserializeCoeff(const deb_fb::Coeff *coeff);

/**
 * @brief Serializes a poly unit into FlatBuffers form.
 * @param builder FlatBuffer builder.
 * @param polyunit PolyUnit to serialize.
 * @return Offset pointing to the serialized object.
 */
flatbuffers::Offset<deb_fb::PolyUnit>
serializePolyUnit(flatbuffers::FlatBufferBuilder &builder,
                  const PolyUnit &polyunit);

/**
 * @brief Deserializes a poly unit from FlatBuffers form.
 * @param polyunit FlatBuffers poly unit object.
 * @return PolyUnit populated from the serialized data.
 */
PolyUnit deserializePolyUnit(const deb_fb::PolyUnit *polyunit);

/**
 * @brief Serializes a polynomial object.
 * @param builder FlatBuffer builder.
 * @param poly Polynomial to serialize.
 * @return Offset pointing to the serialized object.
 */
flatbuffers::Offset<deb_fb::Poly>
serializePoly(flatbuffers::FlatBufferBuilder &builder, const Polynomial &poly);

/**
 * @brief Deserializes a polynomial using the provided preset.
 * @param preset Preset that defines polynomial dimensions.
 * @param poly FlatBuffers polynomial object.
 * @return Polynomial object populated from the serialized data.
 */
Polynomial deserializePoly(Preset preset, const deb_fb::Poly *poly);

/**
 * @brief Serializes a ciphertext to FlatBuffers format.
 * @param builder FlatBuffer builder.
 * @param cipher Ciphertext to serialize.
 * @return Offset pointing to the serialized ciphertext.
 */
flatbuffers::Offset<deb_fb::Cipher>
serializeCipher(flatbuffers::FlatBufferBuilder &builder,
                const Ciphertext &cipher);

/**
 * @brief Deserializes a ciphertext from FlatBuffers data.
 * @param cipher FlatBuffers ciphertext object.
 * @return Ciphertext instance.
 */
Ciphertext deserializeCipher(const deb_fb::Cipher *cipher);

/**
 * @brief Serializes a secret key.
 * @param builder FlatBuffer builder.
 * @param sk Secret key to serialize.
 * @return Offset pointing to the serialized secret key.
 */
flatbuffers::Offset<deb_fb::Sk>
serializeSk(flatbuffers::FlatBufferBuilder &builder, const SecretKey &sk);

/**
 * @brief Deserializes a secret key from FlatBuffers data.
 * @param sk FlatBuffers secret key object.
 * @return SecretKey instance.
 */
SecretKey deserializeSk(const deb_fb::Sk *sk);

/**
 * @brief Serializes a switching key.
 * @param builder FlatBuffer builder.
 * @param swk Switching key to serialize.
 * @return Offset pointing to the serialized switch key.
 */
flatbuffers::Offset<deb_fb::Swk>
serializeSwk(flatbuffers::FlatBufferBuilder &builder, const SwitchKey &swk);

/**
 * @brief Deserializes a switching key from FlatBuffers data.
 * @param swk FlatBuffers switch key object.
 * @return Switching key instance.
 */
SwitchKey deserializeSwk(const deb_fb::Swk *swk);

/**
 * @brief Appends a typed FlatBuffers offset into the union storage vectors.
 * @tparam T FlatBuffers union member type.
 * @param offset Offset produced by serialization.
 * @param type_vec Vector capturing union discriminators.
 * @param value_vec Vector capturing raw offsets.
 * @throws std::runtime_error When the type is unsupported.
 */
template <typename T>
void appendOffsetToVector(const flatbuffers::Offset<T> &offset,
                          std::vector<u8> &type_vec,
                          std::vector<flatbuffers::Offset<void>> &value_vec) {
    if constexpr (std::is_same_v<T, deb_fb::Swk>) {
        type_vec.push_back(deb_fb::DebUnion_Swk);
    } else if constexpr (std::is_same_v<T, deb_fb::Sk>) {
        type_vec.push_back(deb_fb::DebUnion_Sk);
    } else if constexpr (std::is_same_v<T, deb_fb::Cipher>) {
        type_vec.push_back(deb_fb::DebUnion_Cipher);
    } else if constexpr (std::is_same_v<T, deb_fb::Poly>) {
        type_vec.push_back(deb_fb::DebUnion_Poly);
    } else if constexpr (std::is_same_v<T, deb_fb::PolyUnit>) {
        type_vec.push_back(deb_fb::DebUnion_PolyUnit);
    } else if constexpr (std::is_same_v<T, deb_fb::Message>) {
        type_vec.push_back(deb_fb::DebUnion_Message);
    } else if constexpr (std::is_same_v<T, deb_fb::Coeff>) {
        type_vec.push_back(deb_fb::DebUnion_Coeff);
    } else {
        throw std::runtime_error(
            "[appendOffsetToVector] Unsupported type for serialization");
    }
    value_vec.push_back(flatbuffers::Offset<void>(offset.Union()));
}

/**
 * @brief Wraps a serialized object inside the Deb union container.
 * @tparam T FlatBuffers union member type.
 * @param builder FlatBuffer builder.
 * @param offset Member offset to wrap.
 * @return Offset pointing to the Deb union object.
 */
template <typename T>
flatbuffers::Offset<deb_fb::Deb> toDeb(flatbuffers::FlatBufferBuilder &builder,
                                       const flatbuffers::Offset<T> &offset) {
    std::vector<u8> type_vec;
    std::vector<flatbuffers::Offset<void>> value_vec;

    appendOffsetToVector(offset, type_vec, value_vec);

    return deb_fb::CreateDeb(builder, builder.CreateVector(type_vec),
                             builder.CreateVector(value_vec));
}

/**
 * @brief Serializes supported objects to a binary output stream.
 * @tparam T Supported object type (Ciphertext, SecretKey, etc.).
 * @param data Object to serialize.
 * @param os Output stream receiving the bytes.
 * @throws std::runtime_error If the object type is unsupported
 * or if serialization fails (e.g., output stream errors).
 */
template <typename T> void serializeToStream(const T &data, std::ostream &os) {
    flatbuffers::FlatBufferBuilder builder;
    if constexpr (std::is_same_v<T, SwitchKey>) {
        builder.Finish(toDeb(builder, serializeSwk(builder, data)));
    } else if constexpr (std::is_same_v<T, SecretKey>) {
        builder.Finish(toDeb(builder, serializeSk(builder, data)));
    } else if constexpr (std::is_same_v<T, Ciphertext>) {
        builder.Finish(toDeb(builder, serializeCipher(builder, data)));
    } else if constexpr (std::is_same_v<T, Polynomial>) {
        builder.Finish(toDeb(builder, serializePoly(builder, data)));
    } else if constexpr (std::is_same_v<T, PolyUnit>) {
        builder.Finish(toDeb(builder, serializePolyUnit(builder, data)));
    } else if constexpr (std::is_same_v<T, Message>) {
        builder.Finish(toDeb(builder, serializeMessage(builder, data)));
    } else if constexpr (std::is_same_v<T, CoeffMessage>) {
        builder.Finish(toDeb(builder, serializeCoeff(builder, data)));
    } else {
        throw std::runtime_error(
            "[serializeToStream] Unsupported type for serialization");
    }
    Size size = builder.GetSize();
    os.write(reinterpret_cast<const char *>(&size), sizeof(Size));
    os.write(reinterpret_cast<const char *>(builder.GetBufferPointer()),
             builder.GetSize());
}

/**
 * @brief Deserializes supported objects from a binary stream.
 * @tparam T Supported object type (Ciphertext, SecretKey, etc.).
 * @param is Input stream containing serialized bytes.
 * @param data Output object to populate.
 * @param preset Optional preset required for polynomials.
 * @throws std::runtime_error Need more info
 */
template <typename T>
void deserializeFromStream(std::istream &is, T &data,
                           std::optional<Preset> preset = std::nullopt) {
    Size size;
    is.read(reinterpret_cast<char *>(&size), sizeof(Size));
    deb_assert(size > 0,
               "[deserializeFromStream] Invalid size for deserialization");
    std::vector<char> buffer(size);
    is.read(buffer.data(), size);
    flatbuffers::Verifier verifier(
        reinterpret_cast<const uint8_t *>(buffer.data()), buffer.size());
    deb_assert(deb_fb::VerifyDebBuffer(verifier),
               "[deserializeFromStream] Invalid buffer for deserialization");
    const auto *deb = deb_fb::GetDeb(buffer.data());
    deb_assert(deb->list()->size() == 1,
               "[deserializeFromStream] Invalid Deb buffer: expected exactly "
               "one element");
    if constexpr (std::is_same_v<T, SwitchKey>) {
        data = deserializeSwk(deb->list()->GetAs<deb_fb::Swk>(0));
    } else if constexpr (std::is_same_v<T, SecretKey>) {
        data = deserializeSk(deb->list()->GetAs<deb_fb::Sk>(0));
    } else if constexpr (std::is_same_v<T, Ciphertext>) {
        data = deserializeCipher(deb->list()->GetAs<deb_fb::Cipher>(0));
    } else if constexpr (std::is_same_v<T, Polynomial>) {
        if (!preset.has_value()) {
            throw std::runtime_error("[deserializeFromStream] Preset must be "
                                     "provided for deserializing Polynomial");
        }
        data = deserializePoly(preset.value(),
                               deb->list()->GetAs<deb_fb::Poly>(0));
    } else if constexpr (std::is_same_v<T, PolyUnit>) {
        data = deserializePolyUnit(deb->list()->GetAs<deb_fb::PolyUnit>(0));
    } else if constexpr (std::is_same_v<T, Message>) {
        data = deserializeMessage(deb->list()->GetAs<deb_fb::Message>(0));
    } else if constexpr (std::is_same_v<T, CoeffMessage>) {
        data = deserializeCoeff(deb->list()->GetAs<deb_fb::Coeff>(0));
    } else {
        throw std::runtime_error(
            "[deserializeFromStream] Unsupported type for deserialization");
    }
}
} // namespace deb
