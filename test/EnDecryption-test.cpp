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
#include "TestBase.hpp"

using namespace deb;

class EnDecrypt : public DebTestBase {};

TEST_P(EnDecrypt, EncryptWithEmptySecretKey) {
    MSGS msg = gen_random_message();

    SecretKey sk(preset, SeedGenerator::Gen());
    Ciphertext ctxt(context);
    DEB_EXPECT(encryptor.encrypt(msg, sk, ctxt));
}
TEST_P(EnDecrypt, DecryptWithEmptySecretKey) {
    setOmpThreadLimit(1);
    MSGS msg = gen_random_message();
    SecretKey sk =
        SecretKeyGenerator::GenSecretKey(preset, SeedGenerator::Gen());
    Ciphertext ctxt(context);
    encryptor.encrypt(msg, sk, ctxt);
    sk.allocPolys(0);

    DEB_EXPECT(decryptor.decrypt(ctxt, sk, msg));
    unsetOmpThreadLimit();
}

TEST_P(EnDecrypt, EncryptAndDecryptWithSecretKey) {
    MSGS msg = gen_random_message();

    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    MSGS decrypted_msg = gen_empty_message();

    for (Size l = 0; l < context->get_num_p(); ++l) {
        Ciphertext ctxt(context, l);
        MSGS scaled_msg = scale_message(msg, l);
        encryptor.encrypt(scaled_msg, sk, ctxt, EncryptOptions().Level(l));
        decryptor.decrypt(ctxt, sk, decrypted_msg);

        compare_msg(scaled_msg, decrypted_msg, scale_error(sk_err, l));
    }
}

TEST_P(EnDecrypt, EncryptAndDecryptWithEncKey) {
    MSGS msg = gen_random_message();

    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    KeyGenerator keygen(preset);
    SwitchKey enckey = keygen.genEncKey(sk);
    MSGS decrypted_msg = gen_empty_message();

    for (Size l = 0; l < context->get_num_p(); ++l) {
        Ciphertext ctxt(context, l);
        MSGS scaled_msg = scale_message(msg, l);
        encryptor.encrypt(scaled_msg, enckey, ctxt, EncryptOptions().Level(l));
        decryptor.decrypt(ctxt, sk, decrypted_msg);

        compare_msg(scaled_msg, decrypted_msg, scale_error(enc_err, l));
    }
}

TEST_P(EnDecrypt, ScaleEncryptAndDecryptWithSecretKey) {

    MSGS msg = gen_random_message();
    const int max_scale_bit =
        static_cast<int>(utils::bitWidth(context->get_primes()[0]) - 2);
    const double min_scale_bit = static_cast<int>(30 + log_error);
    const double scale_bit =
        min_scale_bit + abs(dist(gen)) * (max_scale_bit - min_scale_bit);
    const double scale = std::pow(2.0, scale_bit);
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);

    MSGS decrypted_msg = gen_empty_message();

    for (Size l = 0; l < context->get_num_p(); ++l) {
        Ciphertext ctxt(context, l);
        encryptor.encrypt(msg, sk, ctxt,
                          EncryptOptions().Level(l).Scale(scale));
        decryptor.decrypt(ctxt, sk, decrypted_msg, scale);
        compare_msg(msg, decrypted_msg, scale_error(sk_err, l));
    }
}

TEST_P(EnDecrypt, ScaleEncryptAndDecryptWithEncKey) {

    MSGS msg = gen_random_message();

    const int max_scale_bit =
        static_cast<int>(utils::bitWidth(context->get_primes()[0]) - 2);
    const double min_scale_bit = static_cast<int>(30 + log_error);
    const double scale_bit =
        min_scale_bit + abs(dist(gen)) * (max_scale_bit - min_scale_bit);
    const double scale = std::pow(2.0, scale_bit);
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    SwitchKey enckey = KeyGenerator(preset).genEncKey(sk);

    MSGS decrypted_msg = gen_empty_message();

    for (Size l = 0; l < context->get_num_p(); ++l) {
        Ciphertext ctxt(context, l);
        encryptor.encrypt(msg, enckey, ctxt,
                          EncryptOptions().Level(l).Scale(scale));
        decryptor.decrypt(ctxt, sk, decrypted_msg, scale);
        compare_msg(msg, decrypted_msg, scale_error(enc_err, l));
    }
}

TEST_P(EnDecrypt, EncryptAndDecryptCoeffWithSecretKey) {

    COEFFS coeff = gen_random_coeff();
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);

    COEFFS decrypted_coeff = gen_empty_coeff();

    for (Size l = 0; l < context->get_num_p(); ++l) {
        Ciphertext ctxt(context, l);
        COEFFS scaled_coeff = scale_coeff(coeff, l);
        encryptor.encrypt(scaled_coeff, sk, ctxt, EncryptOptions().Level(l));
        decryptor.decrypt(ctxt, sk, decrypted_coeff);
        compare_coeff(scaled_coeff, decrypted_coeff, scale_error(sk_err, l));
    }
}

TEST_P(EnDecrypt, EncryptAndDecryptCoeffWithEncKey) {

    COEFFS coeff = gen_random_coeff();
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    KeyGenerator keygen(preset);
    SwitchKey enckey = keygen.genEncKey(sk);

    COEFFS decrypted_coeff = gen_empty_coeff();

    for (Size l = 0; l < context->get_num_p(); ++l) {
        Ciphertext ctxt(context, l);
        COEFFS scaled_coeff = scale_coeff(coeff, l);
        encryptor.encrypt(scaled_coeff, enckey, ctxt,
                          EncryptOptions().Level(l));
        decryptor.decrypt(ctxt, sk, decrypted_coeff);
        compare_coeff(scaled_coeff, decrypted_coeff, scale_error(enc_err, l));
    }
}

TEST_P(EnDecrypt, ScaleEncryptAndDecryptCoeffWithSecretKey) {

    COEFFS coeff = gen_random_coeff();

    const int max_scale_bit =
        static_cast<int>(utils::bitWidth(context->get_primes()[0]) - 2);
    const double min_scale_bit = static_cast<int>(30 + log_error);
    const double scale_bit =
        min_scale_bit + abs(dist(gen)) * (max_scale_bit - min_scale_bit);
    const double scale = std::pow(2.0, scale_bit);
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);

    COEFFS decrypted_coeff = gen_empty_coeff();

    for (Size l = 0; l < context->get_num_p(); ++l) {
        Ciphertext ctxt(context, l);
        encryptor.encrypt(coeff, sk, ctxt,
                          EncryptOptions().Level(l).Scale(scale));
        decryptor.decrypt(ctxt, sk, decrypted_coeff, scale);
        compare_coeff(coeff, decrypted_coeff, scale_error(sk_err, l));
    }
}

TEST_P(EnDecrypt, ScaleEncryptAndDecryptCoeffWithEncKey) {

    COEFFS coeff = gen_random_coeff();

    const int max_scale_bit =
        static_cast<int>(utils::bitWidth(context->get_primes()[0]) - 2);
    const double min_scale_bit = static_cast<int>(30 + log_error);
    const double scale_bit =
        min_scale_bit + abs(dist(gen)) * (max_scale_bit - min_scale_bit);
    const double scale = std::pow(2.0, scale_bit);
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    SwitchKey enckey = KeyGenerator(preset).genEncKey(sk);

    COEFFS decrypted_coeff = gen_empty_coeff();

    for (Size l = 0; l < context->get_num_p(); ++l) {
        Ciphertext ctxt(context, l);
        encryptor.encrypt(coeff, enckey, ctxt,
                          EncryptOptions().Level(l).Scale(scale));
        decryptor.decrypt(ctxt, sk, decrypted_coeff, scale);
        compare_coeff(coeff, decrypted_coeff, scale_error(enc_err, l));
    }
}

#define X(PRESET) Preset::PRESET_##PRESET,
const std::vector<Preset> all_presets = {PRESET_LIST
#undef X
};
INSTANTIATE_TEST_SUITE_P(EnDecrypt, EnDecrypt, testing::ValuesIn(all_presets));
