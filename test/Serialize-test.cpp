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

#include "DebParam.hpp"
#include "Serialize.hpp"
#include "TestBase.hpp"

#include <gtest/gtest.h>

using namespace deb;

class Serialize : public DebTestBase {
public:
    template <typename T>
    void compareArray(const T *arr1, const T *arr2, const Size size) {
        for (Size i = 0; i < size; ++i) {
            ASSERT_EQ(arr1[i], arr2[i]);
        }
    }

    void comparePoly(const PolyUnit &poly1, const PolyUnit &poly2) {
        ASSERT_EQ(poly1.prime(), poly2.prime());
        ASSERT_EQ(poly1.degree(), poly2.degree());
        ASSERT_EQ(poly1.isNTT(), poly2.isNTT());
        compareArray(poly1.data(), poly2.data(), poly1.degree());
    }

    void compareBigPoly(const Polynomial &bigpoly1,
                        const Polynomial &bigpoly2) {
        ASSERT_EQ(bigpoly1.size(), bigpoly2.size());
        for (Size i = 0; i < bigpoly1.size(); ++i) {
            comparePoly(bigpoly1[i], bigpoly2[i]);
        }
    }

    void compareCipher(const Ciphertext &cipher1, const Ciphertext &cipher2) {
        ASSERT_EQ(cipher1.numPoly(), cipher2.numPoly());
        ASSERT_EQ(cipher1.encoding(), cipher2.encoding());
        for (Size i = 0; i < cipher1.numPoly(); ++i) {
            compareBigPoly(cipher1[i], cipher2[i]);
        }
    }
};

TEST_P(Serialize, MessageSerializationTest) {
    Message msg = gen_random_message()[0];
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

TEST_P(Serialize, CoeffSerializationTest) {
    CoeffMessage coeff = gen_random_coeff()[0];
    std::ostringstream os;
    serializeToStream(coeff, os);
    std::istringstream is(os.str());
    CoeffMessage deserialized_coeff(0);
    deserializeFromStream(is, deserialized_coeff);

    EXPECT_EQ(coeff.size(), deserialized_coeff.size());
    compareArray(coeff.data(), deserialized_coeff.data(), coeff.size());
}

TEST_P(Serialize, PolySerializationTest) {
    const auto prime = context->get_primes()[0];
    PolyUnit poly(prime, degree);
    for (Size i = 0; i < degree; ++i) {
        poly[i] = static_cast<u64>(dist(gen) * static_cast<double>(prime));
    }

    std::ostringstream os;
    serializeToStream(poly, os);
    std::istringstream is(os.str());
    PolyUnit deserialized_poly(prime, 0);
    deserializeFromStream(is, deserialized_poly);

    comparePoly(poly, deserialized_poly);
}

TEST_P(Serialize, BigPolySerializationTest) {
    Polynomial bigpoly(context);
    const auto *const primes = context->get_primes();
    for (Size i = 0; i < bigpoly.size(); ++i) {
        for (Size j = 0; j < degree; ++j) {
            bigpoly[i][j] =
                static_cast<u64>(dist(gen) * static_cast<double>(primes[i]));
        }
    }

    std::ostringstream os;
    serializeToStream(bigpoly, os);
    std::istringstream is(os.str());
    Polynomial deserialized_bigpoly(context, static_cast<Size>(0));
    deserializeFromStream(is, deserialized_bigpoly, preset);

    compareBigPoly(bigpoly, deserialized_bigpoly);
}

TEST_P(Serialize, CipherSerializationTest) {
    Ciphertext ctxt(context, context->get_encryption_level(),
                    context->get_num_secret());
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
    Ciphertext deserialized_ctxt(context, 0, 1);
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
        compareBigPoly(sk[i], deserialized_sk[i]);
    }
}

TEST_P(Serialize, SwkSerializationTest) {
    const SwitchKeyKind kind = SWK_ROT;
    SwitchKey swk(context, kind, dist_u64(gen) % ((degree >> 1) - 1) + 1);

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
    SwitchKey deserialized_swk(context, kind);
    deserializeFromStream(is, deserialized_swk);

    EXPECT_EQ(swk.preset(), deserialized_swk.preset());
    EXPECT_EQ(swk.type(), deserialized_swk.type());
    EXPECT_EQ(swk.rotIdx(), deserialized_swk.rotIdx());
    EXPECT_EQ(swk.dnum(), deserialized_swk.dnum());
    EXPECT_EQ(swk.axSize(), deserialized_swk.axSize());
    EXPECT_EQ(swk.bxSize(), deserialized_swk.bxSize());
    for (Size i = 0; i < swk.axSize(); ++i) {
        compareBigPoly(swk.ax(i), deserialized_swk.ax(i));
    }
    for (Size i = 0; i < swk.bxSize(); ++i) {
        compareBigPoly(swk.bx(i), deserialized_swk.bx(i));
    }
}

TEST_P(Serialize, EndecryptionSerializationTest) {

    MSGS msg = gen_random_message();
    msg = scale_message(msg, 0);
    MSGS decrypted_msg = gen_empty_message();

    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    Ciphertext ctxt(context);
    encryptor.encrypt(msg, sk, ctxt);

    std::ostringstream os;
    serializeToStream(ctxt, os);
    serializeToStream(sk, os);

    std::istringstream is(os.str());
    Ciphertext deserialized_ctxt(context);
    deserializeFromStream(is, deserialized_ctxt);
    SecretKey deserialized_sk(preset);
    deserializeFromStream(is, deserialized_sk);

    decryptor.decrypt(deserialized_ctxt, deserialized_sk, decrypted_msg);
    compare_msg(msg, decrypted_msg, scale_error(sk_err, 0));
}

TEST_P(Serialize, EndecryptionWithEncKeySerializationTest) {
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    KeyGenerator keygen(preset);
    SwitchKey swk = keygen.genEncKey(sk);
    std::ostringstream os;
    serializeToStream(swk, os);
    std::istringstream is(os.str());
    SwitchKey deserialized_swk(context, SWK_ENC);
    deserializeFromStream(is, deserialized_swk);

    MSGS msg = gen_random_message();
    msg = scale_message(msg, 0);
    MSGS decrypted_msg = gen_empty_message();

    Ciphertext ctxt(context);
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
        compareBigPoly(sk[i], deserialized_sk[i]);
    }
}

#define X(PRESET) Preset::PRESET_##PRESET,
const std::vector<Preset> all_presets = {PRESET_LIST
#undef X
};
INSTANTIATE_TEST_SUITE_P(Serialize, Serialize, testing::ValuesIn(all_presets));
