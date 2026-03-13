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
#include "KeyGenerator.hpp"
#include "TestBase.hpp"

using namespace deb;

class KeyGen : public DebTestBase {
public:
    const Size gadget_rank = get_gadget_rank(preset);
    const Size num_p = get_num_p(preset);

    KeyGenerator keygen{preset};
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
};

TEST_P(KeyGen, GenEncryptionKey) {
    SwitchKey enckey(preset, SwitchKeyKind::SWK_ENC);
    ASSERT_NO_THROW(enckey = keygen.genEncKey(sk));
    ASSERT_NO_THROW(keygen.genEncKeyInplace(enckey, sk));

    ASSERT_EQ(enckey.axSize(), 1);
    ASSERT_EQ(enckey.bxSize(), num_secret);
    ASSERT_EQ(enckey.ax().size(), num_p);
    ASSERT_EQ(enckey.bx().size(), num_p);
}

TEST_P(KeyGen, GenMultiplicationKey) {
    SwitchKey mulkey(preset, SwitchKeyKind::SWK_MULT);
    ASSERT_NO_THROW(mulkey = keygen.genMultKey(sk));
    ASSERT_NO_THROW(keygen.genMultKeyInplace(mulkey, sk));

    ASSERT_EQ(mulkey.axSize(), gadget_rank);
    ASSERT_EQ(mulkey.bxSize(), gadget_rank * num_secret);
    ASSERT_EQ(mulkey.ax().size(), num_p);
    ASSERT_EQ(mulkey.bx().size(), num_p);
}

TEST_P(KeyGen, GenConjugationKey) {
    SwitchKey conjkey(preset, SwitchKeyKind::SWK_CONJ);
    ASSERT_NO_THROW(conjkey = keygen.genConjKey(sk));
    ASSERT_NO_THROW(keygen.genConjKeyInplace(conjkey, sk));

    ASSERT_EQ(conjkey.axSize(), gadget_rank);
    ASSERT_EQ(conjkey.bxSize(), gadget_rank * num_secret);
    ASSERT_EQ(conjkey.ax().size(), num_p);
    ASSERT_EQ(conjkey.bx().size(), num_p);
}

TEST_P(KeyGen, GenRotationKeys) {
    const Size rot = dist_u64(gen) % (num_slots - 1) + 1;
    const RNGSeed seed = SeedGenerator::Gen();

    KeyGenerator keygen_same1(preset, seed);
    KeyGenerator keygen_same2(preset, seed);
    SwitchKey left_rotkey(preset, SwitchKeyKind::SWK_ROT, rot);
    ASSERT_NO_THROW(left_rotkey = keygen.genLeftRotKey(rot, sk));
    ASSERT_NO_THROW(keygen_same1.genLeftRotKeyInplace(rot, left_rotkey, sk));

    SwitchKey right_rotkey(preset, SwitchKeyKind::SWK_ROT, num_slots - rot);
    ASSERT_NO_THROW(right_rotkey = keygen.genRightRotKey(num_slots - rot, sk));
    ASSERT_NO_THROW(
        keygen_same2.genRightRotKeyInplace(num_slots - rot, right_rotkey, sk));
    ASSERT_EQ(left_rotkey.axSize(), gadget_rank);
    ASSERT_EQ(left_rotkey.bxSize(), gadget_rank * num_secret);
    ASSERT_EQ(left_rotkey.ax().size(), num_p);
    ASSERT_EQ(left_rotkey.bx().size(), num_p);

    ASSERT_EQ(right_rotkey.axSize(), gadget_rank);
    ASSERT_EQ(right_rotkey.bxSize(), gadget_rank * num_secret);
    ASSERT_EQ(right_rotkey.ax().size(), num_p);
    ASSERT_EQ(right_rotkey.bx().size(), num_p);

    for (Size i = 0; i < left_rotkey.axSize(); ++i) {
        comparePoly(left_rotkey.ax(i), right_rotkey.ax(i));
    }
    for (Size i = 0; i < left_rotkey.bxSize(); ++i) {
        comparePoly(left_rotkey.bx(i), right_rotkey.bx(i));
    }
}

TEST_P(KeyGen, GenAutomorphismKey) {
    const Size sig = dist_u64(gen) % (degree - 1) + 1;
    SwitchKey autokey(preset, SwitchKeyKind::SWK_AUTO);
    ASSERT_NO_THROW(autokey = keygen.genAutoKey(sig, sk));
    ASSERT_NO_THROW(keygen.genAutoKeyInplace(sig, autokey, sk));

    ASSERT_EQ(autokey.axSize(), gadget_rank);
    ASSERT_EQ(autokey.bxSize(), gadget_rank * num_secret);
    ASSERT_EQ(autokey.ax().size(), num_p);
    ASSERT_EQ(autokey.bx().size(), num_p);
}

TEST_P(KeyGen, GenModPackKey) {
    if (num_secret != 1) {
        GTEST_SKIP() << "MODPACK key generation is only for single secret.";
    }
    std::vector<SwitchKey> modkey;
    ASSERT_NO_THROW(modkey = keygen.genModPackKeyBundle(sk, sk));
    ASSERT_NO_THROW(keygen.genModPackKeyBundleInplace(sk, sk, modkey));
}

TEST_P(KeyGen, GenModPackKeySelf) {
    if (num_secret != 1) {
        GTEST_SKIP()
            << "MODPACK_SELF key generation is only for single secret.";
    }
    const Size pad_rank = 1U << (dist_u64(gen) % (get_log_degree(preset) / 2));
    SwitchKey modevikey(preset, SwitchKeyKind::SWK_MODPACK_SELF);
    ASSERT_NO_THROW(modevikey = keygen.genModPackKeyBundle(pad_rank, sk));
    ASSERT_NO_THROW(keygen.genModPackKeyBundleInplace(pad_rank, modevikey, sk));

    ASSERT_EQ(modevikey.axSize(), pad_rank);
    ASSERT_EQ(modevikey.bxSize(), pad_rank * num_secret);
    ASSERT_EQ(modevikey.ax().size(), num_p);
    ASSERT_EQ(modevikey.bx().size(), num_p);
}

#define X(PRESET) Preset::PRESET_##PRESET,
const std::vector<Preset> all_presets = {PRESET_LIST
#undef X
};
INSTANTIATE_TEST_SUITE_P(KeyGen, KeyGen, testing::ValuesIn(all_presets));
