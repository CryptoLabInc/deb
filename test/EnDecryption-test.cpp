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
#include "TestBase.hpp"
#include "utils/FFT.hpp"
#include "utils/OmpUtils.hpp"

using namespace deb;

class EnDecrypt : public DebTestBase {};

TEST_P(EnDecrypt, EncryptWithEmptySecretKey) {
    MSGS msg = gen_random_message<MSGS>();

    SecretKey sk(preset, SeedGenerator::Gen());
    Ciphertext ctxt(preset);
    DEB_TEST_EXPECT(encryptor.encrypt(msg, sk, ctxt));
}
TEST_P(EnDecrypt, DecryptWithEmptySecretKey) {
    utils::setOmpThreadLimit(1);
    MSGS msg = gen_random_message<MSGS>();
    SecretKey sk =
        SecretKeyGenerator::GenSecretKey(preset, SeedGenerator::Gen());
    Ciphertext ctxt(preset);
    encryptor.encrypt(msg, sk, ctxt);
    sk.allocPolys(0);

    DEB_TEST_EXPECT(decryptor.decrypt(ctxt, sk, msg));
    utils::unsetOmpThreadLimit();
}

TEST_P(EnDecrypt, EncryptAndDecryptWithSecretKey) {
    MSGS msg = gen_random_message<MSGS>();

    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    MSGS decrypted_msg = gen_empty_message<MSGS>();

    for (Size l = 0; l < get_num_p(preset); ++l) {
        Ciphertext ctxt(preset, l);
        MSGS scaled_msg = scale_message(msg, l);
        encryptor.encrypt(scaled_msg, sk, ctxt, EncryptOptions().Level(l));
        decryptor.decrypt(ctxt, sk, decrypted_msg);

        compare_msg(scaled_msg, decrypted_msg, scale_error(sk_err, l));
    }
}

TEST_P(EnDecrypt, EncryptAndDecryptFloatWithSecretKey) {
    FMSGS msg = gen_random_message<FMSGS>();

    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    FMSGS decrypted_msg = gen_empty_message<FMSGS>();

    for (Size l = 0; l < std::min(2U, get_num_p(preset)); ++l) {
        Ciphertext ctxt(preset, l);
        encryptor.encrypt(msg, sk, ctxt, EncryptOptions().Level(l));
        decryptor.decrypt(ctxt, sk, decrypted_msg);

        compare_msg(msg, decrypted_msg, scale_error(sk_err_f, l));
    }
}

TEST_P(EnDecrypt, EncryptAndDecryptWithEncKey) {
    MSGS msg = gen_random_message<MSGS>();

    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    KeyGenerator keygen(preset);
    SwitchKey enckey = keygen.genEncKey(sk);
    MSGS decrypted_msg = gen_empty_message<MSGS>();

    for (Size l = 0; l < get_num_p(preset); ++l) {
        Ciphertext ctxt(preset, l);
        MSGS scaled_msg = scale_message(msg, l);
        encryptor.encrypt(scaled_msg, enckey, ctxt, EncryptOptions().Level(l));
        decryptor.decrypt(ctxt, sk, decrypted_msg);

        compare_msg(scaled_msg, decrypted_msg, scale_error(enc_err, l));
    }
}

TEST_P(EnDecrypt, EncryptAndDecryptFloatWithEncKey) {
    FMSGS msg = gen_random_message<FMSGS>();

    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    KeyGenerator keygen(preset);
    SwitchKey enckey = keygen.genEncKey(sk);
    FMSGS decrypted_msg = gen_empty_message<FMSGS>();

    for (Size l = 0; l < std::min(2U, get_num_p(preset)); ++l) {
        Ciphertext ctxt(preset, l);
        encryptor.encrypt(msg, enckey, ctxt, EncryptOptions().Level(l));
        decryptor.decrypt(ctxt, sk, decrypted_msg);

        compare_msg(msg, decrypted_msg, scale_error(enc_err_f, l));
    }
}

TEST_P(EnDecrypt, ScaleEncryptAndDecryptWithSecretKey) {

    MSGS msg = gen_random_message<MSGS>();
    const int max_scale_bit =
        static_cast<int>(utils::bitWidth(get_primes(preset)[0]) - 2);
    const double min_scale_bit = static_cast<int>(30 + log_error);
    const double scale_bit =
        min_scale_bit + abs(dist(gen)) * (max_scale_bit - min_scale_bit);
    const double scale = std::pow(2.0, scale_bit);
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);

    MSGS decrypted_msg = gen_empty_message<MSGS>();

    for (Size l = 0; l < get_num_p(preset); ++l) {
        Ciphertext ctxt(preset, l);
        encryptor.encrypt(msg, sk, ctxt,
                          EncryptOptions().Level(l).Scale(scale));
        decryptor.decrypt(ctxt, sk, decrypted_msg, scale);
        compare_msg(msg, decrypted_msg, scale_error(sk_err, l));
    }
}

TEST_P(EnDecrypt, ScaleEncryptAndDecryptWithEncKey) {

    MSGS msg = gen_random_message<MSGS>();

    const int max_scale_bit =
        static_cast<int>(utils::bitWidth(get_primes(preset)[0]) - 2);
    const double min_scale_bit = static_cast<int>(30 + log_error);
    const double scale_bit =
        min_scale_bit + abs(dist(gen)) * (max_scale_bit - min_scale_bit);
    const double scale = std::pow(2.0, scale_bit);
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    SwitchKey enckey = KeyGenerator(preset).genEncKey(sk);

    MSGS decrypted_msg = gen_empty_message<MSGS>();

    for (Size l = 0; l < get_num_p(preset); ++l) {
        Ciphertext ctxt(preset, l);
        encryptor.encrypt(msg, enckey, ctxt,
                          EncryptOptions().Level(l).Scale(scale));
        decryptor.decrypt(ctxt, sk, decrypted_msg, scale);
        compare_msg(msg, decrypted_msg, scale_error(enc_err, l));
    }
}

TEST_P(EnDecrypt, EncryptAndDecryptCoeffWithSecretKey) {

    COEFFS coeff = gen_random_coeff<COEFFS>();
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);

    COEFFS decrypted_coeff = gen_empty_coeff<COEFFS>();

    for (Size l = 0; l < get_num_p(preset); ++l) {
        Ciphertext ctxt(preset, l);
        COEFFS scaled_coeff = scale_coeff(coeff, l);
        encryptor.encrypt(scaled_coeff, sk, ctxt, EncryptOptions().Level(l));
        decryptor.decrypt(ctxt, sk, decrypted_coeff);
        compare_coeff(scaled_coeff, decrypted_coeff, scale_error(sk_err, l));
    }
}

TEST_P(EnDecrypt, EncryptAndDecryptFloatCoeffWithSecretKey) {

    FCOEFFS coeff = gen_random_coeff<FCOEFFS>();
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);

    FCOEFFS decrypted_coeff = gen_empty_coeff<FCOEFFS>();

    for (Size l = 0; l < std::min(2U, get_num_p(preset)); ++l) {
        Ciphertext ctxt(preset, l);
        encryptor.encrypt(coeff, sk, ctxt, EncryptOptions().Level(l));
        decryptor.decrypt(ctxt, sk, decrypted_coeff);
        compare_coeff(coeff, decrypted_coeff, scale_error(sk_err_f, l));
    }
}

TEST_P(EnDecrypt, EncryptAndDecryptCoeffWithEncKey) {

    COEFFS coeff = gen_random_coeff<COEFFS>();
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    KeyGenerator keygen(preset);
    SwitchKey enckey = keygen.genEncKey(sk);

    COEFFS decrypted_coeff = gen_empty_coeff<COEFFS>();

    for (Size l = 0; l < get_num_p(preset); ++l) {
        Ciphertext ctxt(preset, l);
        COEFFS scaled_coeff = scale_coeff(coeff, l);
        encryptor.encrypt(scaled_coeff, enckey, ctxt,
                          EncryptOptions().Level(l));
        decryptor.decrypt(ctxt, sk, decrypted_coeff);
        compare_coeff(scaled_coeff, decrypted_coeff, scale_error(enc_err, l));
    }
}

TEST_P(EnDecrypt, EncryptAndDecryptFloatCoeffWithEncKey) {

    FCOEFFS coeff = gen_random_coeff<FCOEFFS>();
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    KeyGenerator keygen(preset);
    SwitchKey enckey = keygen.genEncKey(sk);

    FCOEFFS decrypted_coeff = gen_empty_coeff<FCOEFFS>();

    for (Size l = 0; l < std::min(2U, get_num_p(preset)); ++l) {
        Ciphertext ctxt(preset, l);
        encryptor.encrypt(coeff, enckey, ctxt, EncryptOptions().Level(l));
        decryptor.decrypt(ctxt, sk, decrypted_coeff);
        compare_coeff(coeff, decrypted_coeff, scale_error(enc_err_f, l));
    }
}

TEST_P(EnDecrypt, ScaleEncryptAndDecryptCoeffWithSecretKey) {

    COEFFS coeff = gen_random_coeff<COEFFS>();

    const int max_scale_bit =
        static_cast<int>(utils::bitWidth(get_primes(preset)[0]) - 2);
    const double min_scale_bit = static_cast<int>(30 + log_error);
    const double scale_bit =
        min_scale_bit + abs(dist(gen)) * (max_scale_bit - min_scale_bit);
    const double scale = std::pow(2.0, scale_bit);
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);

    COEFFS decrypted_coeff = gen_empty_coeff<COEFFS>();

    for (Size l = 0; l < get_num_p(preset); ++l) {
        Ciphertext ctxt(preset, l);
        encryptor.encrypt(coeff, sk, ctxt,
                          EncryptOptions().Level(l).Scale(scale));
        decryptor.decrypt(ctxt, sk, decrypted_coeff, scale);
        compare_coeff(coeff, decrypted_coeff, scale_error(sk_err, l));
    }
}

TEST_P(EnDecrypt, ScaleEncryptAndDecryptCoeffWithEncKey) {

    COEFFS coeff = gen_random_coeff<COEFFS>();

    const int max_scale_bit =
        static_cast<int>(utils::bitWidth(get_primes(preset)[0]) - 2);
    const double min_scale_bit = static_cast<int>(30 + log_error);
    const double scale_bit =
        min_scale_bit + abs(dist(gen)) * (max_scale_bit - min_scale_bit);
    const double scale = std::pow(2.0, scale_bit);
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    SwitchKey enckey = KeyGenerator(preset).genEncKey(sk);

    COEFFS decrypted_coeff = gen_empty_coeff<COEFFS>();

    for (Size l = 0; l < get_num_p(preset); ++l) {
        Ciphertext ctxt(preset, l);
        encryptor.encrypt(coeff, enckey, ctxt,
                          EncryptOptions().Level(l).Scale(scale));
        decryptor.decrypt(ctxt, sk, decrypted_coeff, scale);
        compare_coeff(coeff, decrypted_coeff, scale_error(enc_err, l));
    }
}

/*---------------------------------------------------
    Seed-only 'a' Tests
---------------------------------------------------*/
// Secret-key seed-only encryption: 'a' is released after encryption and the
// decryptor transparently regenerates it from the stored seed.
TEST_P(EnDecrypt, SeedOnlyEncryptAndDecryptWithSecretKey) {
    MSGS msg = gen_random_message<MSGS>();
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    MSGS decrypted_msg = gen_empty_message<MSGS>();

    for (Size l = 0; l < get_num_p(preset); ++l) {
        Ciphertext ctxt(preset, l);
        MSGS scaled_msg = scale_message(msg, l);
        encryptor.encrypt(scaled_msg, sk, ctxt,
                          EncryptOptions().Level(l).SeedOnlyA(true));
        EXPECT_TRUE(ctxt.hasSeed());
        EXPECT_TRUE(ctxt.isAxFlushed());
        EXPECT_EQ(static_cast<int>(ctxt.seedMode()),
                  static_cast<int>(CipherSeedMode::UNIFORM));
        decryptor.decrypt(ctxt, sk, decrypted_msg); // auto-expands 'a'
        compare_msg(scaled_msg, decrypted_msg, scale_error(sk_err, l));
    }
}

// Same fixed a_seed + error_seed must yield byte-identical ciphertexts, and the
// regenerated 'a' from both the free function and the Encryptor member overload
// must agree.
TEST_P(EnDecrypt, SeedOnlyDeterministicRegeneration) {
    MSGS msg = gen_random_message<MSGS>();
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    RNGSeed a_seed = SeedGenerator::Gen();
    RNGSeed e_seed = SeedGenerator::Gen();
    auto opt = EncryptOptions().ASeed(a_seed).ErrorSeed(e_seed).SeedOnlyA(true);

    Ciphertext c1(preset), c2(preset);
    encryptor.encrypt(msg, sk, c1, opt);
    encryptor.encrypt(msg, sk, c2, opt);

    ASSERT_TRUE(c1.isAxFlushed());
    ASSERT_TRUE(c2.isAxFlushed());
    EXPECT_TRUE(c1.getSeed() == a_seed); // stored seed is the supplied one

    completeCiphertext(c1);           // free function (UNIFORM)
    encryptor.completeCiphertext(c2); // member overload (delegates)
    ASSERT_FALSE(c1.isAxFlushed());
    ASSERT_FALSE(c2.isAxFlushed());
    ASSERT_EQ(c1.numPoly(), c2.numPoly());
    for (Size p = 0; p < c1.numPoly(); ++p) {
        comparePoly(c1[p], c2[p]); // b parts and regenerated a part identical
    }
}

// Public-key seed-only encryption: 'a' = v*ax + e cannot be regenerated without
// the encryption key, so the decryptor must refuse and
// completeCiphertext(enckey) is required first.
TEST_P(EnDecrypt, SeedOnlyEncryptAndDecryptWithEncKey) {
    MSGS msg = gen_random_message<MSGS>();
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    SwitchKey enckey = KeyGenerator(preset).genEncKey(sk);
    MSGS decrypted_msg = gen_empty_message<MSGS>();

    for (Size l = 0; l < get_num_p(preset); ++l) {
        Ciphertext ctxt(preset, l);
        MSGS scaled_msg = scale_message(msg, l);
        encryptor.encrypt(scaled_msg, enckey, ctxt,
                          EncryptOptions().Level(l).SeedOnlyA(true));
        EXPECT_TRUE(ctxt.hasSeed());
        EXPECT_TRUE(ctxt.isAxFlushed());
        EXPECT_EQ(static_cast<int>(ctxt.seedMode()),
                  static_cast<int>(CipherSeedMode::PUBLICKEY));

        MSGS tmp = gen_empty_message<MSGS>();
        EXPECT_THROW(decryptor.decrypt(ctxt, sk, tmp), std::runtime_error);

        encryptor.completeCiphertext(ctxt, enckey);
        EXPECT_FALSE(ctxt.isAxFlushed());
        decryptor.decrypt(ctxt, sk, decrypted_msg);
        compare_msg(scaled_msg, decrypted_msg, scale_error(enc_err, l));
    }
}

// Public-key path is deterministic from (a_seed, error_seed, enckey).
TEST_P(EnDecrypt, SeedOnlyEncKeyDeterministicRegeneration) {
    MSGS msg = gen_random_message<MSGS>();
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    SwitchKey enckey = KeyGenerator(preset).genEncKey(sk);
    RNGSeed a_seed = SeedGenerator::Gen();
    RNGSeed e_seed = SeedGenerator::Gen();
    auto opt = EncryptOptions().ASeed(a_seed).ErrorSeed(e_seed).SeedOnlyA(true);

    Ciphertext c1(preset), c2(preset);
    encryptor.encrypt(msg, enckey, c1, opt);
    encryptor.encrypt(msg, enckey, c2, opt);
    encryptor.completeCiphertext(c1, enckey);
    encryptor.completeCiphertext(c2, enckey);

    ASSERT_EQ(c1.numPoly(), c2.numPoly());
    for (Size p = 0; p < c1.numPoly(); ++p) {
        comparePoly(c1[p], c2[p]);
    }
}

// Seed-only with ntt_out == false: the stored 'b' is in the coefficient domain
// and the regenerated 'a' must follow it.
TEST_P(EnDecrypt, SeedOnlyNttOutFalseWithSecretKey) {
    MSGS msg = gen_random_message<MSGS>();
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    MSGS decrypted_msg = gen_empty_message<MSGS>();

    for (Size l = 0; l < get_num_p(preset); ++l) {
        Ciphertext ctxt(preset, l);
        MSGS scaled_msg = scale_message(msg, l);
        encryptor.encrypt(
            scaled_msg, sk, ctxt,
            EncryptOptions().Level(l).NTTOut(false).SeedOnlyA(true));
        EXPECT_TRUE(ctxt.isAxFlushed());
        EXPECT_FALSE(ctxt[0][0].isNTT()); // 'b' is in coefficient domain

        // Auto-expand decrypt works (the decryptor handles mixed domains).
        decryptor.decrypt(ctxt, sk, decrypted_msg);
        compare_msg(scaled_msg, decrypted_msg, scale_error(sk_err, l));

        // Explicit completion regenerates 'a' in the same (coefficient) domain.
        completeCiphertext(ctxt);
        ASSERT_FALSE(ctxt.isAxFlushed());
        EXPECT_EQ(ctxt[ctxt.numPoly() - 1][0].isNTT(), ctxt[0][0].isNTT());
    }
}

TEST_P(EnDecrypt, SeedOnlyNttOutFalseWithEncKey) {
    MSGS msg = gen_random_message<MSGS>();
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    SwitchKey enckey = KeyGenerator(preset).genEncKey(sk);
    MSGS decrypted_msg = gen_empty_message<MSGS>();

    for (Size l = 0; l < get_num_p(preset); ++l) {
        Ciphertext ctxt(preset, l);
        MSGS scaled_msg = scale_message(msg, l);
        encryptor.encrypt(
            scaled_msg, enckey, ctxt,
            EncryptOptions().Level(l).NTTOut(false).SeedOnlyA(true));
        EXPECT_FALSE(ctxt[0][0].isNTT());

        MSGS tmp = gen_empty_message<MSGS>();
        EXPECT_THROW(decryptor.decrypt(ctxt, sk, tmp), std::runtime_error);

        encryptor.completeCiphertext(ctxt, enckey);
        ASSERT_FALSE(ctxt.isAxFlushed());
        EXPECT_EQ(ctxt[ctxt.numPoly() - 1][0].isNTT(), ctxt[0][0].isNTT());
        decryptor.decrypt(ctxt, sk, decrypted_msg);
        compare_msg(scaled_msg, decrypted_msg, scale_error(enc_err, l));
    }
}

/*---------------------------------------------------
    Real Encryption Tests
---------------------------------------------------*/
class RealEnDecrypt : public DebTestBase {
public:
    RealEnDecrypt() {
        for (auto &p : Presets) {
            if (get_preset_name(p) == "FGbD12L0") {
                preset = p;
                break;
            }
        }
        if (get_preset_name(preset) == "FGbD12L0") {
            encryptor = Encryptor(preset);
            decryptor = Decryptor(preset);
            num_slots = get_num_slots(preset);
            degree = get_degree(preset);
            num_secret = get_num_secret(preset);
        }
    }
    void SetUp() override {
        if (get_preset_name(preset) != "FGbD12L0") {
            GTEST_SKIP()
                << "No suitable preset found for real encryption tests.";
        }
    }
};

TEST_P(RealEnDecrypt, EncryptAndDecryptWithSecretKey) {
    MSGS msg = gen_empty_real_message<MSGS>();
    for (Size s = 0; s < num_secret; ++s) {
        for (Size j = 0; j < degree; ++j) {
            msg[s][j].real(dist(gen));
            msg[s][j].imag(0.0);
        }
    }
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset, std::nullopt,
                                                    utils::NTTType::CYCLIC);
    MSGS decrypted_msg = gen_empty_real_message<MSGS>();

    for (Size l = 0; l < get_num_p(preset); ++l) {
        Ciphertext ctxt(preset, l);
        MSGS scaled_msg = scale_complex_message(msg, l);
        encryptor.encrypt(scaled_msg, sk, ctxt,
                          EncryptOptions().Level(l).RealEncrypt(true));
        decryptor.decrypt(ctxt, sk, decrypted_msg);
        compare_heaan_msg(scaled_msg, decrypted_msg, scale_error(sk_err, l));
    }
}

TEST_P(RealEnDecrypt, EncryptAndDecryptFloatWithSecretKey) {
    FMSGS msg = gen_empty_real_message<FMSGS>();
    for (Size s = 0; s < num_secret; ++s) {
        for (Size j = 0; j < degree; ++j) {
            msg[s][j].real(static_cast<float>(dist(gen)));
            msg[s][j].imag(0.0f);
        }
    }
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset, std::nullopt,
                                                    utils::NTTType::CYCLIC);
    FMSGS decrypted_msg = gen_empty_real_message<FMSGS>();

    for (Size l = 0; l < get_num_p(preset); ++l) {
        Ciphertext ctxt(preset, l);
        FMSGS scaled_msg = scale_complex_message(msg, l);
        encryptor.encrypt(scaled_msg, sk, ctxt,
                          EncryptOptions().Level(l).RealEncrypt(true));
        decryptor.decrypt(ctxt, sk, decrypted_msg);
        compare_heaan_msg(scaled_msg, decrypted_msg, scale_error(sk_err_f, l));
    }
}

TEST_P(RealEnDecrypt, EncryptAndDecryptWithEncKey) {
    MSGS msg = gen_empty_real_message<MSGS>();
    for (Size s = 0; s < num_secret; ++s) {
        for (Size j = 0; j < degree; ++j) {
            msg[s][j].real(dist(gen));
            msg[s][j].imag(0.0);
        }
    }
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset, std::nullopt,
                                                    utils::NTTType::CYCLIC);
    KeyGenerator keygen(preset);
    SwitchKey enckey = keygen.genEncKey(sk);
    MSGS decrypted_msg = gen_empty_real_message<MSGS>();

    for (Size l = 0; l < get_num_p(preset); ++l) {
        Ciphertext ctxt(preset, l);
        MSGS scaled_msg = scale_complex_message(msg, l);
        encryptor.encrypt(scaled_msg, enckey, ctxt,
                          EncryptOptions().Level(l).RealEncrypt(true));
        decryptor.decrypt(ctxt, sk, decrypted_msg);
        compare_heaan_msg(scaled_msg, decrypted_msg, scale_error(enc_err, l));
    }
}

TEST_P(RealEnDecrypt, EncryptAndDecryptFloatWithEncKey) {
    FMSGS msg = gen_empty_real_message<FMSGS>();
    for (Size s = 0; s < num_secret; ++s) {
        for (Size j = 0; j < degree; ++j) {
            msg[s][j].real(static_cast<float>(dist(gen)));
            msg[s][j].imag(0.0f);
        }
    }
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset, std::nullopt,
                                                    utils::NTTType::CYCLIC);
    KeyGenerator keygen(preset);
    SwitchKey enckey = keygen.genEncKey(sk);

    FMSGS decrypted_msg = gen_empty_real_message<FMSGS>();

    for (Size l = 0; l < get_num_p(preset); ++l) {
        Ciphertext ctxt(preset, l);
        FMSGS scaled_msg = scale_complex_message(msg, l);
        encryptor.encrypt(scaled_msg, enckey, ctxt,
                          EncryptOptions().Level(l).RealEncrypt(true));
        decryptor.decrypt(ctxt, sk, decrypted_msg);
        compare_heaan_msg(scaled_msg, decrypted_msg, scale_error(enc_err_f, l));
    }
}

TEST_P(RealEnDecrypt, EncryptAndDecryptCoeffWithSecretKey) {
    COEFFS coeff = gen_random_coeff<COEFFS>();
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset, std::nullopt,
                                                    utils::NTTType::CYCLIC);
    COEFFS decrypted_coeff = gen_empty_coeff<COEFFS>();

    for (Size l = 0; l < get_num_p(preset); ++l) {
        Ciphertext ctxt(preset, l);
        COEFFS scaled_coeff = scale_coeff(coeff, l);
        encryptor.encrypt(scaled_coeff, sk, ctxt,
                          EncryptOptions().Level(l).RealEncrypt(true));
        decryptor.decrypt(ctxt, sk, decrypted_coeff);
        compare_coeff(scaled_coeff, decrypted_coeff, scale_error(sk_err_f, l));
    }
}

TEST_P(RealEnDecrypt, EncryptAndDecryptFloatCoeffWithSecretKey) {
    FCOEFFS coeff = gen_random_coeff<FCOEFFS>();
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset, std::nullopt,
                                                    utils::NTTType::CYCLIC);
    FCOEFFS decrypted_coeff = gen_empty_coeff<FCOEFFS>();

    for (Size l = 0; l < get_num_p(preset); ++l) {
        Ciphertext ctxt(preset, l);
        encryptor.encrypt(coeff, sk, ctxt,
                          EncryptOptions().Level(l).RealEncrypt(true));
        decryptor.decrypt(ctxt, sk, decrypted_coeff);
        compare_coeff(coeff, decrypted_coeff, scale_error(sk_err, l));
    }
}

TEST_P(RealEnDecrypt, EncryptAndDecryptCoeffWithEncKey) {
    COEFFS coeff = gen_random_coeff<COEFFS>();
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset, std::nullopt,
                                                    utils::NTTType::CYCLIC);
    KeyGenerator keygen(preset);
    SwitchKey enckey = keygen.genEncKey(sk);
    COEFFS decrypted_coeff = gen_empty_coeff<COEFFS>();

    for (Size l = 0; l < get_num_p(preset); ++l) {
        Ciphertext ctxt(preset, l);
        encryptor.encrypt(coeff, enckey, ctxt,
                          EncryptOptions().Level(l).RealEncrypt(true));
        decryptor.decrypt(ctxt, sk, decrypted_coeff);
        compare_coeff(coeff, decrypted_coeff, scale_error(enc_err_f, l));
    }
}

TEST_P(RealEnDecrypt, EncryptAndDecryptFloatCoeffWithEncKey) {
    FCOEFFS coeff = gen_random_coeff<FCOEFFS>();
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset, std::nullopt,
                                                    utils::NTTType::CYCLIC);
    KeyGenerator keygen(preset);
    SwitchKey enckey = keygen.genEncKey(sk);
    FCOEFFS decrypted_coeff = gen_empty_coeff<FCOEFFS>();

    for (Size l = 0; l < get_num_p(preset); ++l) {
        Ciphertext ctxt(preset, l);
        encryptor.encrypt(coeff, enckey, ctxt,
                          EncryptOptions().Level(l).RealEncrypt(true));
        decryptor.decrypt(ctxt, sk, decrypted_coeff);
        compare_coeff(coeff, decrypted_coeff, scale_error(enc_err_f, l));
    }
}

// Seed-only 'a' with real (CYCLIC NTT) encoding: regeneration must stamp the
// CYCLIC kind derived from encoding()==REAL.
TEST_P(RealEnDecrypt, SeedOnlyEncryptAndDecryptWithSecretKey) {
    MSGS msg = gen_empty_real_message<MSGS>();
    for (Size s = 0; s < num_secret; ++s) {
        for (Size j = 0; j < degree; ++j) {
            msg[s][j].real(dist(gen));
            msg[s][j].imag(0.0);
        }
    }
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset, std::nullopt,
                                                    utils::NTTType::CYCLIC);
    MSGS decrypted_msg = gen_empty_real_message<MSGS>();

    for (Size l = 0; l < get_num_p(preset); ++l) {
        Ciphertext ctxt(preset, l);
        MSGS scaled_msg = scale_complex_message(msg, l);
        encryptor.encrypt(
            scaled_msg, sk, ctxt,
            EncryptOptions().Level(l).RealEncrypt(true).SeedOnlyA(true));
        EXPECT_EQ(static_cast<int>(ctxt.seedMode()),
                  static_cast<int>(CipherSeedMode::UNIFORM));
        EXPECT_EQ(static_cast<int>(ctxt.encoding()), static_cast<int>(REAL));
        decryptor.decrypt(ctxt, sk, decrypted_msg); // auto-expands CYCLIC 'a'
        compare_heaan_msg(scaled_msg, decrypted_msg, scale_error(sk_err, l));
    }
}

#define X(PRESET) Preset::PRESET_##PRESET,
const std::vector<Preset> all_presets = {PRESET_LIST
#undef X
};
INSTANTIATE_TEST_SUITE_P(EnDecrypt, EnDecrypt, testing::ValuesIn(all_presets));

INSTANTIATE_TEST_SUITE_P(RealEnDecrypt, RealEnDecrypt,
                         testing::Values(static_cast<Preset>(0)));
