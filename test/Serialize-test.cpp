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

#include "DebParam.hpp"
#include "Serialize.hpp"
#include "TestBase.hpp"

#include <gtest/gtest.h>

using namespace deb;

class Serialize : public DebTestBase {
public:
    void compareCipher(const Ciphertext &cipher1, const Ciphertext &cipher2) {
        ASSERT_EQ(cipher1.preset(), cipher2.preset());
        ASSERT_EQ(cipher1.numPoly(), cipher2.numPoly());
        ASSERT_EQ(cipher1.encoding(), cipher2.encoding());
        for (Size i = 0; i < cipher1.numPoly(); ++i) {
            comparePoly(cipher1[i], cipher2[i]);
        }
    }
};

TEST_P(Serialize, MessageSerializationTest) {
    Message msg = gen_random_message<MSGS>()[0];
    std::ostringstream os;
    serializeToStream(msg, os);
    std::istringstream is(os.str());
    Message deserialized_msg(0);
    deserializeFromStream(is, deserialized_msg);

    EXPECT_EQ(msg.size(), deserialized_msg.size());
    for (Size i = 0; i < msg.size(); ++i) {
        ASSERT_EQ(msg[i].real(), deserialized_msg[i].real());
        ASSERT_EQ(msg[i].imag(), deserialized_msg[i].imag());
    }
}

TEST_P(Serialize, FMessageSerializationTest) {
    FMessage msg = gen_random_message<FMSGS>()[0];
    std::ostringstream os;
    serializeToStream(msg, os);
    std::istringstream is(os.str());
    FMessage deserialized_msg(0);
    deserializeFromStream(is, deserialized_msg);

    EXPECT_EQ(msg.size(), deserialized_msg.size());
    compareArray(msg.data(), deserialized_msg.data(), msg.size());
}

TEST_P(Serialize, CoeffSerializationTest) {
    CoeffMessage coeff = gen_random_coeff<COEFFS>()[0];
    std::ostringstream os;
    serializeToStream(coeff, os);
    std::istringstream is(os.str());
    CoeffMessage deserialized_coeff(0);
    deserializeFromStream(is, deserialized_coeff);

    EXPECT_EQ(coeff.size(), deserialized_coeff.size());
    compareArray(coeff.data(), deserialized_coeff.data(), coeff.size());
}

TEST_P(Serialize, FCoeffSerializationTest) {
    FCoeffMessage coeff = gen_random_coeff<FCOEFFS>()[0];
    std::ostringstream os;
    serializeToStream(coeff, os);
    std::istringstream is(os.str());
    FCoeffMessage deserialized_coeff(0);
    deserializeFromStream(is, deserialized_coeff);

    EXPECT_EQ(coeff.size(), deserialized_coeff.size());
    compareArray(coeff.data(), deserialized_coeff.data(), coeff.size());
}

TEST_P(Serialize, PolyUnitSerializationTest) {
    const auto prime = get_primes(preset)[0];
    PolyUnit poly(prime, degree);
    for (Size i = 0; i < degree; ++i) {
        poly[i] = static_cast<u64>(dist(gen) * static_cast<double>(prime));
    }

    std::ostringstream os;
    serializeToStream(poly, os);
    std::istringstream is(os.str());
    PolyUnit deserialized_poly(prime, 0);
    // A bare PolyUnit carries its own degree and prime, so a preset is required
    // to bind them -- as it already is for Polynomial.
    deserializeFromStream(is, deserialized_poly, preset);

    comparePolyUnit(poly, deserialized_poly);

    // Without the preset there is nothing to validate the declared degree
    // against, so the call is refused rather than trusting the buffer.
    std::istringstream is_nopreset(os.str());
    PolyUnit out(prime, 0);
    EXPECT_THROW(deserializeFromStream(is_nopreset, out), std::runtime_error);
}

TEST_P(Serialize, PolySerializationTest) {
    Polynomial bigpoly(preset);
    const auto *const primes = get_primes(preset);
    for (Size i = 0; i < bigpoly.size(); ++i) {
        for (Size j = 0; j < degree; ++j) {
            bigpoly[i][j] =
                static_cast<u64>(dist(gen) * static_cast<double>(primes[i]));
        }
    }

    std::ostringstream os;
    serializeToStream(bigpoly, os);
    std::istringstream is(os.str());
    Polynomial deserialized_bigpoly(preset, static_cast<Size>(0));
    deserializeFromStream(is, deserialized_bigpoly, preset);

    comparePoly(bigpoly, deserialized_bigpoly);
}

TEST_P(Serialize, CipherSerializationTest) {
    Ciphertext ctxt(preset, get_encryption_level(preset),
                    get_num_secret(preset));
    for (Size i = 0; i < ctxt.numPoly(); ++i) {
        for (Size j = 0; j < ctxt[i].size(); ++j) {
            for (Size k = 0; k < degree; ++k) {
                // Fill with random values
                ctxt[i][j][k] = static_cast<u64>(
                    dist(gen) * static_cast<double>(ctxt[i][j].prime()));
            }
        }
    }

    std::ostringstream os;
    serializeToStream(ctxt, os);
    std::istringstream is(os.str());
    Ciphertext deserialized_ctxt(preset, 0, 1);
    deserializeFromStream(is, deserialized_ctxt);

    compareCipher(ctxt, deserialized_ctxt);
}

TEST_P(Serialize, SecretKeySerializationTest) {
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    std::ostringstream os;
    serializeToStream(sk, os);
    std::istringstream is(os.str());
    SecretKey deserialized_sk(preset);
    deserializeFromStream(is, deserialized_sk);

    EXPECT_EQ(sk.preset(), deserialized_sk.preset());
    EXPECT_EQ(sk.numPoly(), deserialized_sk.numPoly());
    compareArray(sk.coeffs(), deserialized_sk.coeffs(), sk.coeffsSize());
    for (Size i = 0; i < sk.numPoly(); ++i) {
        comparePoly(sk[i], deserialized_sk[i]);
    }
}

TEST_P(Serialize, SwkSerializationTest) {
    const SwitchKeyKind kind = SWK_ROT;
    SwitchKey swk(preset, kind, dist_u64(gen) % ((degree >> 1) - 1) + 1);

    for (Size i = 0; i < swk.axSize(); ++i) {
        for (Size j = 0; j < swk.ax(i).size(); ++j) {
            for (Size d = 0; d < degree; ++d) {
                swk.ax(i)[j][d] = dist_u64(gen);
                swk.bx(i)[j][d] = dist_u64(gen);
            }
        }
    }

    std::ostringstream os;
    serializeToStream(swk, os);
    std::istringstream is(os.str());
    SwitchKey deserialized_swk(preset, kind);
    deserializeFromStream(is, deserialized_swk);

    EXPECT_EQ(swk.preset(), deserialized_swk.preset());
    EXPECT_EQ(swk.type(), deserialized_swk.type());
    EXPECT_EQ(swk.rotIdx(), deserialized_swk.rotIdx());
    EXPECT_EQ(swk.dnum(), deserialized_swk.dnum());
    EXPECT_EQ(swk.axSize(), deserialized_swk.axSize());
    EXPECT_EQ(swk.bxSize(), deserialized_swk.bxSize());
    for (Size i = 0; i < swk.axSize(); ++i) {
        comparePoly(swk.ax(i), deserialized_swk.ax(i));
    }
    for (Size i = 0; i < swk.bxSize(); ++i) {
        comparePoly(swk.bx(i), deserialized_swk.bx(i));
    }
}

TEST_P(Serialize, EndecryptionSerializationTest) {

    MSGS msg = gen_random_message<MSGS>();
    msg = scale_message(msg, 0);
    MSGS decrypted_msg = gen_empty_message<MSGS>();

    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    Ciphertext ctxt(preset);
    encryptor.encrypt(msg, sk, ctxt);

    std::ostringstream os;
    serializeToStream(ctxt, os);
    serializeToStream(sk, os);

    std::istringstream is(os.str());
    Ciphertext deserialized_ctxt(preset);
    deserializeFromStream(is, deserialized_ctxt);
    SecretKey deserialized_sk(preset);
    deserializeFromStream(is, deserialized_sk);

    decryptor.decrypt(ctxt, sk, msg);
    decryptor.decrypt(deserialized_ctxt, deserialized_sk, decrypted_msg);
    compareCipher(ctxt, deserialized_ctxt);
    EXPECT_EQ(sk.preset(), deserialized_sk.preset());
    EXPECT_EQ(sk.numPoly(), deserialized_sk.numPoly());
    compareArray(sk.getSeed().data(), deserialized_sk.getSeed().data(),
                 sk.getSeed().size());
    compareArray(sk.coeffs(), deserialized_sk.coeffs(), sk.coeffsSize());
    for (Size i = 0; i < sk.numPoly(); ++i) {
        comparePoly(sk[i], deserialized_sk[i]);
    }
    compare_msg(msg, decrypted_msg, scale_error(sk_err, 0));
}

TEST_P(Serialize, EndecryptionWithEncKeySerializationTest) {
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    KeyGenerator keygen(preset);
    SwitchKey swk = keygen.genEncKey(sk);
    std::ostringstream os;
    serializeToStream(swk, os);
    std::istringstream is(os.str());
    SwitchKey deserialized_swk(preset, SWK_ENC);
    deserializeFromStream(is, deserialized_swk);

    MSGS msg = gen_random_message<MSGS>();
    msg = scale_message(msg, 0);
    MSGS decrypted_msg = gen_empty_message<MSGS>();

    Ciphertext ctxt(preset);
    encryptor.encrypt(msg, deserialized_swk, ctxt);
    decryptor.decrypt(ctxt, sk, decrypted_msg);
    compare_msg(msg, decrypted_msg, scale_error(enc_err, 0));
}

TEST_P(Serialize, MinimalSecretKeySerializationTest) {
    const RNGSeed seed = SeedGenerator::Gen();
    SecretKey sk(preset, seed);

    std::ostringstream os;
    serializeToStream(sk, os);
    EXPECT_LE(os.str().size(), degree);

    std::istringstream is(os.str());
    SecretKey deserialized_sk(preset, false);
    deserializeFromStream(is, deserialized_sk);

    sk.allocCoeffs();
    SecretKeyGenerator::GenCoeffInplace(preset, sk.coeffs(), sk.getSeed());
    os = std::ostringstream();
    serializeToStream(sk, os);
    EXPECT_LE(os.str().size(), degree + sk.coeffsSize());

    EXPECT_EQ(sk.preset(), deserialized_sk.preset());
    EXPECT_EQ(deserialized_sk.coeffsSize(), 0);
    EXPECT_EQ(deserialized_sk.numPoly(), 0);
    compareArray(seed.data(), deserialized_sk.getSeed().data(), seed.size());

    completeSecretKey(sk);
    completeSecretKey(deserialized_sk);
    for (Size i = 0; i < sk.numPoly(); ++i) {
        comparePoly(sk[i], deserialized_sk[i]);
    }
}

TEST_P(Serialize, SeedOnlyCipherSerializationTest) {
    MSGS msg = gen_random_message<MSGS>();
    msg = scale_message(msg, 0);
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);

    // Full ciphertext for a size baseline.
    Ciphertext full(preset);
    encryptor.encrypt(msg, sk, full);
    std::ostringstream os_full;
    serializeToStream(full, os_full);

    // Seed-only ciphertext: the 'a' polynomial is dropped, only the seed kept.
    Ciphertext ctxt(preset);
    encryptor.encrypt(msg, sk, ctxt, EncryptOptions().SeedOnlyA(true));
    ASSERT_TRUE(ctxt.hasSeed());
    ASSERT_TRUE(ctxt.isAxFlushed());

    std::ostringstream os;
    serializeToStream(ctxt, os);
    EXPECT_LT(os.str().size(), os_full.str().size());

    std::istringstream is(os.str());
    Ciphertext deserialized(preset);
    deserializeFromStream(is, deserialized);

    EXPECT_TRUE(deserialized.hasSeed());
    EXPECT_TRUE(deserialized.isAxFlushed());
    EXPECT_EQ(static_cast<int>(deserialized.seedMode()),
              static_cast<int>(CipherSeedMode::UNIFORM));
    compareArray(ctxt.getSeed().data(), deserialized.getSeed().data(),
                 ctxt.getSeed().size());

    // The deserialized seed-only ciphertext decrypts correctly (auto-expand).
    MSGS dec = gen_empty_message<MSGS>();
    decryptor.decrypt(deserialized, sk, dec);
    compare_msg(msg, dec, scale_error(sk_err, 0));
}

// Deserialization consumes untrusted bytes, so every malformed shape must be
// rejected with an exception rather than parsed. These checks are
// unconditional: they must hold regardless of DEB_RUNTIME_RESOURCE_CHECK,
// which previously gated the flatbuffers verifier call and compiled it out
// entirely when off.
TEST_P(Serialize, MalformedBufferIsRejected) {
    // A valid buffer to corrupt, and a sanity check that it round-trips.
    MSGS msg = gen_random_message<MSGS>();
    msg = scale_message(msg, 0);
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    Ciphertext ctxt(preset);
    encryptor.encrypt(msg, sk, ctxt);
    std::ostringstream os;
    serializeToStream(ctxt, os);
    const std::string good = os.str();
    {
        std::istringstream is(good);
        Ciphertext out(preset);
        EXPECT_NO_THROW(deserializeFromStream(is, out));
    }
    ASSERT_GT(good.size(), sizeof(Size));

    const auto with_prefix = [](Size n, const std::string &payload) {
        std::string s(reinterpret_cast<const char *>(&n), sizeof(Size));
        s += payload;
        return s;
    };
    const std::string body = good.substr(sizeof(Size));

    // Empty stream: the length prefix itself cannot be read.
    {
        std::istringstream is(std::string{});
        Ciphertext out(preset);
        EXPECT_THROW(deserializeFromStream(is, out), std::runtime_error);
    }
    // Zero-length payload.
    {
        std::istringstream is(with_prefix(0, std::string{}));
        Ciphertext out(preset);
        EXPECT_THROW(deserializeFromStream(is, out), std::runtime_error);
    }
    // Length prefix at or beyond the bound: must be refused by the bound
    // itself, before any allocation is attempted. The payload is left tiny on
    // purpose -- if the bound were removed, this would try to allocate 2 GiB
    // rather than fail the check, so the case genuinely covers the bound.
    {
        std::istringstream is(with_prefix(DEB_MAX_SERIALIZED_SIZE, body));
        Ciphertext out(preset);
        EXPECT_THROW(deserializeFromStream(is, out), std::runtime_error);
    }
    {
        std::istringstream is(
            with_prefix(DEB_MAX_SERIALIZED_SIZE + 1, std::string{}));
        Ciphertext out(preset);
        EXPECT_THROW(deserializeFromStream(is, out), std::runtime_error);
    }
    // Length prefix longer than the bytes actually present (truncated stream).
    {
        std::istringstream is(
            with_prefix(static_cast<Size>(body.size()), body.substr(0, 8)));
        Ciphertext out(preset);
        EXPECT_THROW(deserializeFromStream(is, out), std::runtime_error);
    }
    // Structurally invalid payload of a plausible length: caught by the
    // flatbuffers verifier.
    {
        std::string garbage(body.size(), '\xA5');
        std::istringstream is(
            with_prefix(static_cast<Size>(garbage.size()), garbage));
        Ciphertext out(preset);
        EXPECT_THROW(deserializeFromStream(is, out), std::runtime_error);
    }
    // Truncated-but-well-prefixed payload: the declared length matches the
    // bytes supplied, so only the verifier can reject it.
    {
        const std::string half = body.substr(0, body.size() / 2);
        std::istringstream is(
            with_prefix(static_cast<Size>(half.size()), half));
        Ciphertext out(preset);
        EXPECT_THROW(deserializeFromStream(is, out), std::runtime_error);
    }
}

// A secret key blob is parsed with the destination sized from the preset alone,
// so the declared coefficient count must be checked against it. Round-tripping
// the library's own output must keep working.
TEST_P(Serialize, SecretKeyRoundTripKeepsCoeffs) {
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    sk.allocCoeffs();
    SecretKeyGenerator::GenCoeffInplace(preset, sk.coeffs(), sk.getSeed());
    ASSERT_GT(sk.coeffsSize(), 0u);

    std::ostringstream os;
    serializeToStream(sk, os);
    std::istringstream is(os.str());
    SecretKey out(preset, false);
    ASSERT_NO_THROW(deserializeFromStream(is, out));
    EXPECT_EQ(out.coeffsSize(), sk.coeffsSize());
    compareArray(sk.coeffs(), out.coeffs(), sk.coeffsSize());
}

// A self mod-pack key is sized by its pad_rank rather than the preset's gadget
// rank. That rank is carried as the key's dnum, which is what lets
// deserialization pin the key's shape exactly instead of merely bounding it.
TEST_P(Serialize, ModPackSelfKeySerializationTest) {
    if (num_secret != 1) {
        GTEST_SKIP()
            << "MODPACK_SELF key generation is only for single secret.";
    }
    KeyGenerator keygen(preset);
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    // Kept small on purpose: a self mod-pack key holds pad_rank*(1+num_secret)
    // full polynomials, so a large pad_rank runs into the serialized-size
    // ceiling rather than testing the shape validation. It must also differ
    // from the gadget rank, which varies with the parameter set -- otherwise a
    // dnum that silently fell back to the gadget rank would still look right.
    Size pad_rank = 2;
    while (pad_rank == get_gadget_rank(preset)) {
        pad_rank *= 2;
    }
    if (pad_rank > degree) {
        GTEST_SKIP() << "pad_rank must not exceed the degree.";
    }

    SwitchKey modkey = keygen.genModPackKeyBundle(pad_rank, sk);
    ASSERT_EQ(modkey.axSize(), pad_rank);
    ASSERT_EQ(modkey.bxSize(), pad_rank * num_secret);
    // The generator records pad_rank as dnum, keeping axSize()==dnum() true for
    // this kind as it already is for every other one.
    ASSERT_EQ(modkey.dnum(), pad_rank);
    ASSERT_NE(pad_rank, get_gadget_rank(preset))
        << "pad_rank must differ from the gadget rank for this test to prove "
           "that dnum really carries pad_rank";

    std::ostringstream os;
    serializeToStream(modkey, os);
    std::istringstream is(os.str());
    SwitchKey back(preset, SwitchKeyKind::SWK_MODPACK_SELF);
    ASSERT_NO_THROW(deserializeFromStream(is, back));

    EXPECT_EQ(back.type(), modkey.type());
    EXPECT_EQ(back.dnum(), pad_rank);
    EXPECT_EQ(back.axSize(), pad_rank);
    EXPECT_EQ(back.bxSize(), pad_rank * num_secret);
    for (Size i = 0; i < modkey.axSize(); ++i) {
        comparePoly(modkey.ax(i), back.ax(i));
    }
    for (Size i = 0; i < modkey.bxSize(); ++i) {
        comparePoly(modkey.bx(i), back.bx(i));
    }
}

// serializeToStream refuses an object too large for one buffer, using this
// bound. FlatBuffers' internal size counter is a uint32 whose only guard is an
// assert that release builds compile out, so the bound has to be computed from
// the object BEFORE building -- and it must never under-count, or the guard
// lets through exactly the buffers it exists to stop.
TEST_P(Serialize, SerializedSizeUpperBoundNeverUnderCounts) {
    const auto check = [](const char *what, const auto &obj) {
        std::ostringstream os;
        serializeToStream(obj, os);
        const u64 actual = os.str().size();
        const u64 bound = serializedSizeUpperBound(obj);
        EXPECT_GE(bound, actual) << what << ": bound under-counts";
        // Loose enough to survive a FlatBuffers bump, tight enough that the
        // bound still means something.
        EXPECT_LT(bound, actual * 2) << what << ": bound is uselessly loose";
    };

    Message msg = gen_random_message<MSGS>()[0];
    check("Message", msg);
    check("CoeffMessage", gen_random_coeff<COEFFS>()[0]);
    check("FMessage", gen_random_message<FMSGS>()[0]);
    check("FCoeffMessage", gen_random_coeff<FCOEFFS>()[0]);

    Polynomial poly(preset);
    check("Polynomial", poly);
    check("PolyUnit", poly[0]);

    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    check("SecretKey", sk);

    MSGS msgs = gen_random_message<MSGS>();
    msgs = scale_message(msgs, 0);
    Ciphertext ctxt(preset);
    encryptor.encrypt(msgs, sk, ctxt);
    check("Ciphertext", ctxt);

    // A seed-only ciphertext releases its 'a' part, so the bound must follow
    // the real per-polynomial shapes rather than any preset-derived limb count.
    Ciphertext seed_only(preset);
    encryptor.encrypt(msgs, sk, seed_only, EncryptOptions().SeedOnlyA(true));
    check("Ciphertext seed-only", seed_only);

    KeyGenerator keygen(preset);
    check("SwitchKey enc", keygen.genEncKey(sk));
    check("SwitchKey mult", keygen.genMultKey(sk));
}

// A write failure must not pass silently: a failed first write makes the second
// a no-op, so without a check a truncated record is indistinguishable from a
// complete one.
TEST_P(Serialize, SerializeReportsStreamFailure) {
    Message msg = gen_random_message<MSGS>()[0];
    std::ostringstream os;
    os.setstate(std::ios::badbit);
    EXPECT_THROW(serializeToStream(msg, os), std::runtime_error);
}

#define X(PRESET) Preset::PRESET_##PRESET,
const std::vector<Preset> all_presets = {PRESET_LIST
#undef X
};
INSTANTIATE_TEST_SUITE_P(Serialize, Serialize, testing::ValuesIn(all_presets));
