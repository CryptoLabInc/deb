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
#include "KeyGenerator.hpp"
#include "TestBase.hpp"

using namespace deb;

class KeyGen : public DebTestBase {
public:
    SecretKey sk = SecretKeyGenerator::GenSecretKey(preset);
    KeyGenerator keygen{sk};

    void compareArray(const u64 *arr1, const u64 *arr2, const Size size) {
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
};

TEST_P(KeyGen, GenEncryptionKey) {
    SwitchKey enckey(context, SwitchKeyKind::SWK_ENC);
    ASSERT_NO_THROW(enckey = keygen.genEncKey());
    ASSERT_NO_THROW(keygen.genEncKeyInplace(enckey));

    ASSERT_EQ(enckey.axSize(), 1);
    ASSERT_EQ(enckey.bxSize(), context->get_num_secret());
    ASSERT_EQ(enckey.ax().size(), context->get_num_p());
    ASSERT_EQ(enckey.bx().size(), context->get_num_p());
}

TEST_P(KeyGen, GenMultiplicationKey) {
    SwitchKey mulkey(context, SwitchKeyKind::SWK_MULT);
    ASSERT_NO_THROW(mulkey = keygen.genMultKey());
    ASSERT_NO_THROW(keygen.genMultKeyInplace(mulkey));

    ASSERT_EQ(mulkey.axSize(), context->get_gadget_rank());
    ASSERT_EQ(mulkey.bxSize(),
              context->get_gadget_rank() * context->get_num_secret());
    ASSERT_EQ(mulkey.ax().size(), context->get_num_p());
    ASSERT_EQ(mulkey.bx().size(), context->get_num_p());
}

TEST_P(KeyGen, GenConjugationKey) {
    SwitchKey conjkey(context, SwitchKeyKind::SWK_CONJ);
    ASSERT_NO_THROW(conjkey = keygen.genConjKey());
    ASSERT_NO_THROW(keygen.genConjKeyInplace(conjkey));

    ASSERT_EQ(conjkey.axSize(), context->get_gadget_rank());
    ASSERT_EQ(conjkey.bxSize(),
              context->get_gadget_rank() * context->get_num_secret());
    ASSERT_EQ(conjkey.ax().size(), context->get_num_p());
    ASSERT_EQ(conjkey.bx().size(), context->get_num_p());
}

TEST_P(KeyGen, GenRotationKeys) {
    const Size num_slots = context->get_num_slots();
    const Size rot = rand() % (num_slots - 1) + 1;
    const RNGSeed seed = SeedGenerator::Gen();

    KeyGenerator keygen_same1(sk, seed);
    KeyGenerator keygen_same2(sk, seed);
    SwitchKey left_rotkey(context, SwitchKeyKind::SWK_ROT, rot);
    ASSERT_NO_THROW(left_rotkey = keygen.genLeftRotKey(rot));
    ASSERT_NO_THROW(keygen_same1.genLeftRotKeyInplace(rot, left_rotkey));

    SwitchKey right_rotkey(context, SwitchKeyKind::SWK_ROT, num_slots - rot);
    ASSERT_NO_THROW(right_rotkey = keygen.genRightRotKey(num_slots - rot));
    ASSERT_NO_THROW(
        keygen_same2.genRightRotKeyInplace(num_slots - rot, right_rotkey));
    ASSERT_EQ(left_rotkey.axSize(), context->get_gadget_rank());
    ASSERT_EQ(left_rotkey.bxSize(),
              context->get_gadget_rank() * context->get_num_secret());
    ASSERT_EQ(left_rotkey.ax().size(), context->get_num_p());
    ASSERT_EQ(left_rotkey.bx().size(), context->get_num_p());

    ASSERT_EQ(right_rotkey.axSize(), context->get_gadget_rank());
    ASSERT_EQ(right_rotkey.bxSize(),
              context->get_gadget_rank() * context->get_num_secret());
    ASSERT_EQ(right_rotkey.ax().size(), context->get_num_p());
    ASSERT_EQ(right_rotkey.bx().size(), context->get_num_p());

    for (Size i = 0; i < left_rotkey.axSize(); ++i) {
        compareBigPoly(left_rotkey.ax(i), right_rotkey.ax(i));
    }
    for (Size i = 0; i < left_rotkey.bxSize(); ++i) {
        compareBigPoly(left_rotkey.bx(i), right_rotkey.bx(i));
    }
}

TEST_P(KeyGen, GenAutomorphismKey) {
    const Size sig = rand() % (degree - 1) + 1;
    SwitchKey autokey(context, SwitchKeyKind::SWK_AUTO);
    ASSERT_NO_THROW(autokey = keygen.genAutoKey(sig));
    ASSERT_NO_THROW(keygen.genAutoKeyInplace(sig, autokey));

    ASSERT_EQ(autokey.axSize(), context->get_gadget_rank());
    ASSERT_EQ(autokey.bxSize(),
              context->get_gadget_rank() * context->get_num_secret());
    ASSERT_EQ(autokey.ax().size(), context->get_num_p());
    ASSERT_EQ(autokey.bx().size(), context->get_num_p());
}

TEST_P(KeyGen, GenModPackKey) {
    std::vector<SwitchKey> modkey;
    ASSERT_NO_THROW(modkey = keygen.genModPackKeyBundle(sk, sk));
    ASSERT_NO_THROW(keygen.genModPackKeyBundleInplace(sk, sk, modkey));
}

TEST_P(KeyGen, GenModPackKeySelf) {
    if (num_secret != 1) {
        GTEST_SKIP()
            << "MODPACK_SELF key generation is only for single secret.";
    }
    const Size pad_rank = 1U << (rand() % (context->get_log_degree() / 2));
    SwitchKey modevikey(context, SwitchKeyKind::SWK_MODPACK_SELF);
    ASSERT_NO_THROW(modevikey = keygen.genModPackKeyBundle(pad_rank));
    ASSERT_NO_THROW(keygen.genModPackKeyBundleInplace(pad_rank, modevikey));

    ASSERT_EQ(modevikey.axSize(), pad_rank);
    ASSERT_EQ(modevikey.bxSize(), pad_rank * context->get_num_secret());
    ASSERT_EQ(modevikey.ax().size(), context->get_num_p());
    ASSERT_EQ(modevikey.bx().size(), context->get_num_p());
}

#define X(PRESET) Preset::PRESET_##PRESET,
const std::vector<Preset> all_presets = {PRESET_LIST
#undef X
};
INSTANTIATE_TEST_SUITE_P(KeyGen, KeyGen, testing::ValuesIn(all_presets));
