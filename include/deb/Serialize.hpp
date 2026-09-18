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

#include "CKKSTypes.hpp"
#include "DebFBType.h"

#include <sstream>
#include <string>

namespace deb {

/**
 * @brief Upper bound on the length prefix accepted by @ref
 * deserializeFromStream.
 *
 * The prefix is read from an untrusted stream and used directly to size the
 * read buffer, so it is bounded to keep a malformed or hostile header from
 * requesting an arbitrary allocation. The bound is exclusive: this value names
 * the smallest length that is rejected. 2 GiB is far above any real serialized
 * key or ciphertext, and @ref Size is 32-bit, so this is half the representable
 * range.
 */
constexpr Size DEB_MAX_SERIALIZED_SIZE = Size{1} << 31;

// FlatBuffers addresses a buffer with 32-bit signed offsets, so it cannot
// represent one at or above 2 GiB either. Keeping the two limits identical is
// what lets serializeToStream reject, up front, exactly the objects
// deserializeFromStream would refuse.
static_assert(DEB_MAX_SERIALIZED_SIZE - 1 <=
                  static_cast<Size>(FLATBUFFERS_MAX_BUFFER_SIZE),
              "DEB_MAX_SERIALIZED_SIZE must not exceed what FlatBuffers can "
              "represent");

namespace detail {

// Upper bounds on FlatBuffers' structural overhead. A PolyUnit table costs a
// vtable, a body (soffset, prime, degree, ntt_info, array offset), the array's
// length word and worst-case alignment padding -- measured at ~36 bytes, so
// these constants only ever over-estimate. Exactness is not the goal and would
// be fragile across a FlatBuffers bump; never under-counting is.
constexpr u64 FB_POLYUNIT_OVERHEAD = 64;
constexpr u64 FB_POLY_OVERHEAD = 48;
constexpr u64 FB_TABLE_OVERHEAD = 64;
/// Deb table, union type/value vectors, root offset, and the 4-byte length
/// prefix serializeToStream writes ahead of the buffer.
constexpr u64 FB_ENVELOPE_OVERHEAD = 128;
/// One slot in a vector of offsets.
constexpr u64 FB_OFFSET = 4;
/// A `[uint64]` seed vector: length word, payload, worst-case padding.
constexpr u64 FB_SEED_VECTOR = 16 + 8 * u64{DEB_U64_SEED_SIZE};
constexpr u64 FB_EMPTY_VECTOR = 8;

inline u64 boundPolyUnit(const PolyUnit &unit) {
    // degree() is 0 for a released unit, which is exactly what
    // serializePolyUnit writes, so emptiness needs no special case.
    return u64{8} * unit.degree() + FB_POLYUNIT_OVERHEAD;
}

inline u64 boundPoly(const Polynomial &poly) {
    u64 bytes = FB_POLY_OVERHEAD;
    // Units within one Polynomial can have different degrees (a sliced or
    // partially-copied polynomial does), so sum them rather than multiplying by
    // any preset-derived limb count.
    for (Size i = 0; i < poly.size(); ++i) {
        bytes += boundPolyUnit(poly[i]) + FB_OFFSET;
    }
    return bytes;
}

} // namespace detail

/**
 * @brief Upper bound, in bytes, on what @ref serializeToStream writes for
 * @p data, including the length prefix.
 *
 * Computed from the object's own shape in 64-bit arithmetic, so it stays exact
 * for sizes that a serialized buffer could never represent. A seed-only
 * ciphertext needs no special case: @ref CiphertextT::flushAx leaves the
 * released @c a part as a zero-size polynomial, which the sum below skips.
 */
inline u64 serializedSizeUpperBound(const Ciphertext &cipher) {
    u64 bytes = detail::FB_TABLE_OVERHEAD + detail::FB_ENVELOPE_OVERHEAD;
    for (Size i = 0; i < cipher.numPoly(); ++i) {
        bytes += detail::boundPoly(cipher[i]) + detail::FB_OFFSET;
    }
    bytes +=
        cipher.hasSeed() ? detail::FB_SEED_VECTOR : detail::FB_EMPTY_VECTOR;
    return bytes;
}

/** @copydoc serializedSizeUpperBound(const Ciphertext &) */
inline u64 serializedSizeUpperBound(const SwitchKey &swk) {
    u64 bytes = detail::FB_TABLE_OVERHEAD + detail::FB_ENVELOPE_OVERHEAD;
    for (Size i = 0; i < swk.axSize(); ++i) {
        bytes += detail::boundPoly(swk.ax(i)) + detail::FB_OFFSET;
    }
    // bxSize() is not always axSize(): addBx() can append dnum*num_secret
    // polynomials in a single call.
    for (Size i = 0; i < swk.bxSize(); ++i) {
        bytes += detail::boundPoly(swk.bx(i)) + detail::FB_OFFSET;
    }
    return bytes;
}

/** @copydoc serializedSizeUpperBound(const Ciphertext &) */
inline u64 serializedSizeUpperBound(const SecretKey &sk) {
    u64 bytes = detail::FB_TABLE_OVERHEAD + detail::FB_ENVELOPE_OVERHEAD;
    // The coefficients and the embedded polynomials are independently optional.
    bytes += u64{sk.coeffsSize()} + detail::FB_EMPTY_VECTOR;
    for (Size i = 0; i < sk.numPoly(); ++i) {
        bytes += detail::boundPoly(sk[i]) + detail::FB_OFFSET;
    }
    bytes += sk.hasSeed() ? detail::FB_SEED_VECTOR : detail::FB_EMPTY_VECTOR;
    return bytes;
}

/** @copydoc serializedSizeUpperBound(const Ciphertext &) */
inline u64 serializedSizeUpperBound(const Polynomial &poly) {
    return detail::FB_ENVELOPE_OVERHEAD + detail::boundPoly(poly);
}

/** @copydoc serializedSizeUpperBound(const Ciphertext &) */
inline u64 serializedSizeUpperBound(const PolyUnit &unit) {
    return detail::FB_ENVELOPE_OVERHEAD + detail::boundPolyUnit(unit);
}

/** @copydoc serializedSizeUpperBound(const Ciphertext &) */
inline u64 serializedSizeUpperBound(const Message &msg) {
    return detail::FB_ENVELOPE_OVERHEAD + detail::FB_TABLE_OVERHEAD +
           u64{2 * sizeof(Real)} * msg.size();
}

/** @copydoc serializedSizeUpperBound(const Ciphertext &) */
inline u64 serializedSizeUpperBound(const FMessage &msg) {
    return detail::FB_ENVELOPE_OVERHEAD + detail::FB_TABLE_OVERHEAD +
           u64{2 * sizeof(float)} * msg.size();
}

/** @copydoc serializedSizeUpperBound(const Ciphertext &) */
inline u64 serializedSizeUpperBound(const CoeffMessage &coeff) {
    return detail::FB_ENVELOPE_OVERHEAD + detail::FB_TABLE_OVERHEAD +
           u64{sizeof(Real)} * coeff.size();
}

/** @copydoc serializedSizeUpperBound(const Ciphertext &) */
inline u64 serializedSizeUpperBound(const FCoeffMessage &coeff) {
    return detail::FB_ENVELOPE_OVERHEAD + detail::FB_TABLE_OVERHEAD +
           u64{sizeof(float)} * coeff.size();
}

/**
 * @brief Convenience alias for FlatBuffers vector types.
 */
template <typename T> using Vector = flatbuffers::Vector<T>;

/**
 * @brief The union tag a serialized @p T carries, or @c DebUnion_NONE for a
 * type that is not serializable.
 *
 * Used to reject type confusion: @c GetAs<T>() is an unchecked reinterpret, so
 * without comparing the stored tag a buffer holding one type and read back as
 * another turns scalar payload bytes into table and vector offsets.
 */
template <typename T> constexpr deb_fb::DebUnion debUnionTag() {
    if constexpr (std::is_same_v<T, SwitchKey>) {
        return deb_fb::DebUnion_Swk;
    } else if constexpr (std::is_same_v<T, SecretKey>) {
        return deb_fb::DebUnion_Sk;
    } else if constexpr (std::is_same_v<T, Ciphertext>) {
        return deb_fb::DebUnion_Cipher;
    } else if constexpr (std::is_same_v<T, Polynomial>) {
        return deb_fb::DebUnion_Poly;
    } else if constexpr (std::is_same_v<T, PolyUnit>) {
        return deb_fb::DebUnion_PolyUnit;
    } else if constexpr (std::is_same_v<T, Message>) {
        return deb_fb::DebUnion_Message;
    } else if constexpr (std::is_same_v<T, FMessage>) {
        return deb_fb::DebUnion_Message32;
    } else if constexpr (std::is_same_v<T, CoeffMessage>) {
        return deb_fb::DebUnion_Coeff;
    } else if constexpr (std::is_same_v<T, FCoeffMessage>) {
        return deb_fb::DebUnion_Coeff32;
    } else {
        return deb_fb::DebUnion_NONE;
    }
}

/**
 * @brief Converts a double-precision complex into FlatBuffers format.
 * @param data Pointer to double-precision complex values.
 * @param size Number of elements in @p data.
 * @return Vector of FlatBuffer-compatible complex values.
 */
std::vector<deb_fb::Complex> toComplexVector(const Complex *data,
                                             const Size size);
/**
 * @brief Converts FlatBuffers double-precision complex data back into @ref
 * Complex values.
 * @param data FlatBuffers double-precision complex vector pointer.
 * @return Vector with decoded complex values.
 */
std::vector<Complex>
toDebComplexVector(const Vector<const deb_fb::Complex *> *data);

/**
 * @brief Converts single-precision complex into FlatBuffers format.
 * @param data Pointer to single-precision complex values.
 * @param size Number of elements in @p data.
 * @return Vector of FlatBuffer-compatible complex values.
 */
std::vector<deb_fb::Complex32> toComplex32Vector(const ComplexT<float> *data,
                                                 const Size size);
/**
 * @brief Converts FlatBuffers single-precision complex data back into @ref
 * ComplexT<float> values.
 * @param data FlatBuffers single-precision complex vector pointer.
 * @return Vector with decoded complex values.
 */
std::vector<ComplexT<float>>
toDebComplex32Vector(const Vector<const deb_fb::Complex32 *> *data);

/**
 * @brief Serializes a double-precision slot message into FlatBuffers format.
 * @param builder FlatBuffer builder.
 * @param message Double-precision deb message object.
 * @return Offset into the builder pointing to the serialized object.
 */
flatbuffers::Offset<deb_fb::Message>
serializeMessage(flatbuffers::FlatBufferBuilder &builder,
                 const Message &message);
/**
 * @brief Deserializes a FlatBuffers double-precision message into @ref Message.
 * @param message FlatBuffers double-precision message object.
 * @return Deserialized deb format message.
 */
Message deserializeMessage(const deb_fb::Message *message);

/**
 * @brief Serializes a single-precision slot message into FlatBuffers format.
 * @param builder FlatBuffer builder.
 * @param message Single-precision message object.
 * @return Offset into the builder pointing to the serialized object.
 */
flatbuffers::Offset<deb_fb::Message32>
serializeFMessage(flatbuffers::FlatBufferBuilder &builder,
                  const FMessage &message);

/**
 * @brief Deserializes a FlatBuffers single-precision message into @ref
 * FMessage.
 * @param message FlatBuffers single-precision message object.
 * @return Deserialized deb format message.
 */
FMessage deserializeFMessage(const deb_fb::Message32 *message);

/**
 * @brief Serializes a double-precision coefficient message into FlatBuffers
 * format.
 * @param builder FlatBuffer builder.
 * @param coeff Double-precision coefficient message object.
 * @return Offset pointing to serialized coefficients.
 */
flatbuffers::Offset<deb_fb::Coeff>
serializeCoeff(flatbuffers::FlatBufferBuilder &builder,
               const CoeffMessage &coeff);

/**
 * @brief Deserializes a FlatBuffers double-precision coefficient message into
 * @ref CoeffMessage.
 * @param coeff FlatBuffers double-precision coefficient object.
 * @return Deserialized deb format coefficient message.
 */
CoeffMessage deserializeCoeff(const deb_fb::Coeff *coeff);

/**
 * @brief Serializes a single-precision coefficient message into FlatBuffers
 * format.
 * @param builder FlatBuffer builder.
 * @param coeff Single-precision coefficient message object.
 * @return Offset pointing to serialized coefficients.
 */
flatbuffers::Offset<deb_fb::Coeff32>
serializeFCoeff(flatbuffers::FlatBufferBuilder &builder,
                const FCoeffMessage &coeff);

/**
 * @brief Deserializes a FlatBuffers single-precision coefficient message into
 * @ref FCoeffMessage.
 * @param coeff FlatBuffers single-precision coefficient object.
 * @return Deserialized deb format coefficient message.
 */
FCoeffMessage deserializeFCoeff(const deb_fb::Coeff32 *coeff);

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
PolyUnit deserializePolyUnit(const deb_fb::PolyUnit *polyunit,
                             std::optional<Preset> preset = std::nullopt);

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
    } else if constexpr (std::is_same_v<T, deb_fb::Message32>) {
        type_vec.push_back(deb_fb::DebUnion_Message32);
    } else if constexpr (std::is_same_v<T, deb_fb::Coeff>) {
        type_vec.push_back(deb_fb::DebUnion_Coeff);
    } else if constexpr (std::is_same_v<T, deb_fb::Coeff32>) {
        type_vec.push_back(deb_fb::DebUnion_Coeff32);
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
 * @throws std::runtime_error If the object type is unsupported, if the object
 * is too large to fit in one buffer (see @ref serializedSizeUpperBound and
 * @ref DEB_MAX_SERIALIZED_SIZE), or if writing to @p os fails.
 */
template <typename T> void serializeToStream(const T &data, std::ostream &os) {
    // Reject an oversized object BEFORE building it. FlatBuffers' only size
    // guard is a FLATBUFFERS_ASSERT, i.e. plain assert(), which this library's
    // release builds compile out; past 4 GiB its internal 32-bit size counter
    // simply wraps. builder.GetSize() is that same uint32, so a check after
    // Finish() would be reading a number modulo 2^32 -- and a wrapped value can
    // land back inside the accepted range, turning a loud failure into a
    // silently truncated buffer. The bound below is the only reliable check,
    // and it also costs nothing: an object too large to represent is rejected
    // without allocating it.
    const u64 size_bound = serializedSizeUpperBound(data);
    if (size_bound >= static_cast<u64>(DEB_MAX_SERIALIZED_SIZE)) {
        throw std::runtime_error(
            "[serializeToStream] Object is too large to serialize: it needs "
            "about " +
            std::to_string(size_bound) +
            " bytes, and a single buffer cannot reach " +
            std::to_string(static_cast<u64>(DEB_MAX_SERIALIZED_SIZE)) +
            " bytes. Split it, or use a smaller parameter (for a self mod-pack "
            "key, a smaller pad_rank).");
    }

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
    } else if constexpr (std::is_same_v<T, FMessage>) {
        builder.Finish(toDeb(builder, serializeFMessage(builder, data)));
    } else if constexpr (std::is_same_v<T, CoeffMessage>) {
        builder.Finish(toDeb(builder, serializeCoeff(builder, data)));
    } else if constexpr (std::is_same_v<T, FCoeffMessage>) {
        builder.Finish(toDeb(builder, serializeFCoeff(builder, data)));
    } else {
        throw std::runtime_error(
            "[serializeToStream] Unsupported type for serialization");
    }
    Size size = builder.GetSize();
    // Second line of defence, using the reader's exact predicate so the two
    // cannot disagree. This is only sound because the bound above already ruled
    // out a wrapped size; on its own it would be meaningless.
    if (size == 0 || size >= DEB_MAX_SERIALIZED_SIZE) {
        throw std::runtime_error(
            "[serializeToStream] Serialized buffer has an unusable size");
    }
    os.write(reinterpret_cast<const char *>(&size), sizeof(Size));
    os.write(reinterpret_cast<const char *>(builder.GetBufferPointer()),
             builder.GetSize());
    // A failed first write makes the second a silent no-op, and failbit/badbit
    // are sticky, so one check covers both. Note this reports a write error,
    // not durability: a buffered stream may only fail later, at flush or close.
    if (!os) {
        throw std::runtime_error(
            "[serializeToStream] Failed to write to the output stream");
    }
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
    // Validation of an untrusted buffer is a security boundary, not a
    // "resource check": these checks throw unconditionally rather than through
    // deb_assert, which compiles to nothing when DEB_RUNTIME_RESOURCE_CHECK is
    // off and would leave the parser reading unverified bytes.
    Size size = 0;
    if (!is.read(reinterpret_cast<char *>(&size), sizeof(Size))) {
        throw std::runtime_error(
            "[deserializeFromStream] Could not read the buffer length");
    }
    if (size == 0 || size >= DEB_MAX_SERIALIZED_SIZE) {
        throw std::runtime_error(
            "[deserializeFromStream] Invalid size for deserialization");
    }
    std::vector<char> buffer(size);
    if (!is.read(buffer.data(), static_cast<std::streamsize>(size))) {
        throw std::runtime_error(
            "[deserializeFromStream] Truncated serialized buffer");
    }
    flatbuffers::Verifier verifier(
        reinterpret_cast<const uint8_t *>(buffer.data()), buffer.size());
    if (!deb_fb::VerifyDebBuffer(verifier)) {
        throw std::runtime_error(
            "[deserializeFromStream] Invalid buffer for deserialization");
    }
    const auto *deb = deb_fb::GetDeb(buffer.data());
    if (deb == nullptr || deb->list() == nullptr || deb->list()->size() != 1) {
        throw std::runtime_error(
            "[deserializeFromStream] Invalid Deb buffer: expected exactly "
            "one element");
    }
    // GetAs<T>() below is an unchecked reinterpret, so the stored union tag
    // must be confirmed to match the requested type first.
    constexpr deb_fb::DebUnion expected_tag = debUnionTag<T>();
    if (deb->list_type() == nullptr || deb->list_type()->size() != 1 ||
        deb->list_type()->Get(0) != expected_tag) {
        throw std::runtime_error(
            "[deserializeFromStream] Serialized object is not of the "
            "requested type");
    }
    if constexpr (std::is_same_v<T, SwitchKey>) {
        data = deserializeSwk(deb->list()->GetAs<deb_fb::Swk>(0));
    } else if constexpr (std::is_same_v<T, SecretKey>) {
        data = std::move(deserializeSk(deb->list()->GetAs<deb_fb::Sk>(0)));
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
        if (!preset.has_value()) {
            throw std::runtime_error("[deserializeFromStream] Preset must be "
                                     "provided for deserializing PolyUnit");
        }
        data = deserializePolyUnit(deb->list()->GetAs<deb_fb::PolyUnit>(0),
                                   preset);
    } else if constexpr (std::is_same_v<T, Message>) {
        data = deserializeMessage(deb->list()->GetAs<deb_fb::Message>(0));
    } else if constexpr (std::is_same_v<T, FMessage>) {
        data = deserializeFMessage(deb->list()->GetAs<deb_fb::Message32>(0));
    } else if constexpr (std::is_same_v<T, CoeffMessage>) {
        data = deserializeCoeff(deb->list()->GetAs<deb_fb::Coeff>(0));
    } else if constexpr (std::is_same_v<T, FCoeffMessage>) {
        data = deserializeFCoeff(deb->list()->GetAs<deb_fb::Coeff32>(0));
    } else {
        throw std::runtime_error(
            "[deserializeFromStream] Unsupported type for deserialization");
    }
}
} // namespace deb
