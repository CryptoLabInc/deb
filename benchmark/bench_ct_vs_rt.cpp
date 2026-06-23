// Standalone A/B benchmark: compile-time-preset (templated) path vs
// runtime-preset path.  No google/benchmark dependency.
//
// CT = compile-time preset  -> compile-time-prime Barrett kernels.
// RT = runtime preset (PRESET_EMPTY) / runtime-prime Barrett kernels.
#include "Decryptor.hpp"
#include "Encryptor.hpp"
#include "KeyGenerator.hpp"
#include "SecretKeyGenerator.hpp"
#include "Types.hpp"
#include "utils/ModArith.hpp"
#include "utils/PresetTraits.hpp"

#include <chrono>
#include <cstdio>
#include <functional>
#include <random>
#include <vector>

using namespace deb;

static std::mt19937_64 gen{12345};
static std::uniform_real_distribution<double> dist{-1.0, 1.0};
static std::uniform_int_distribution<u64> dist_u64;

static Message gen_random_message(Size num_slots) {
    Message msg(num_slots);
    for (Size i = 0; i < msg.size(); ++i) {
        msg.data()[i].real(dist(gen));
        msg.data()[i].imag(dist(gen));
    }
    return msg;
}

template <typename F> static double time_us(int iters, F &&f) {
    for (int i = 0; i < 3; ++i) f(); // warmup
    auto t0 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iters; ++i) f();
    auto t1 = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double, std::micro>(t1 - t0).count() / iters;
}

static double best_of(int reps, std::function<double()> run) {
    double best = 1e300;
    for (int r = 0; r < reps; ++r) best = std::min(best, run());
    return best;
}

static void line(const char *name, double rt, double ct) {
    printf("%-34s  RT %10.2f us   CT %10.2f us   speedup %5.3fx\n", name, rt, ct,
           rt / ct);
}

// ---------------------------------------------------------------------------
// 1) Isolated Barrett multiply kernel: compile-time prime vs runtime prime,
//    SAME degree (65536).  Isolates exactly what constexpr primes buy.
// ---------------------------------------------------------------------------
template <Preset P> static void bench_mulpoly_kernel(const char *name) {
    using PS = PresetTraits<P, u64>;
    constexpr Size deg = PS::degree;
    const Size L = PS::encryption_level + 1; // active polyunits

    std::vector<utils::ModArith<deg, u64>> ma;
    for (Size i = 0; i < L; ++i)
        ma.emplace_back(deg, PS::primes[i]);

    PolynomialT<u64> a(P, true), b(P, true), r(P, true);
    a.setNTT(utils::NTTType::NEGACYCLIC);
    b.setNTT(utils::NTTType::NEGACYCLIC);
    for (Size i = 0; i < L; ++i)
        for (Size j = 0; j < deg; ++j) {
            a[i][j] = dist_u64(gen) % PS::primes[i];
            b[i][j] = dist_u64(gen) % PS::primes[i];
        }

    // Correctness: CT kernel must match the runtime kernel bit-for-bit.
    PolynomialT<u64> r_rt(P, true), r_ct(P, true);
    r_rt.setNTT(utils::NTTType::NEGACYCLIC);
    r_ct.setNTT(utils::NTTType::NEGACYCLIC);
    utils::mulPoly(ma, a, b, r_rt, L);
    mulPolyP<P>(ma, a, b, r_ct, L);
    bool eq = true;
    for (Size i = 0; i < L && eq; ++i)
        for (Size j = 0; j < deg; ++j)
            if (r_rt[i][j] != r_ct[i][j]) { eq = false; break; }
    if (!eq) printf("  [%s] CT != RT  <-- CORRECTNESS FAILURE\n", name);

    const int iters = 50;
    double rt = best_of(7, [&] {
        return time_us(iters, [&] { utils::mulPoly(ma, a, b, r, L); });
    });
    double ct = best_of(7, [&] {
        return time_us(iters, [&] { mulPolyP<P>(ma, a, b, r, L); });
    });
    line(name, rt, ct);
}

// ---------------------------------------------------------------------------
// 2) End-to-end templated object vs runtime object.
// ---------------------------------------------------------------------------
template <Preset P> static void bench_encrypt(const char *name, int iters) {
    const Size ns = get_num_secret(P);
    std::vector<Message> msg_v;
    for (Size i = 0; i < ns; ++i)
        msg_v.push_back(gen_random_message(get_num_slots(P)));
    SecretKey sk = SecretKeyGenerator::GenSecretKey(P);

    EncryptorT<P> enc_ct;
    Ciphertext ctxt_ct(P);
    double ct = best_of(5, [&] {
        return time_us(iters, [&] { enc_ct.encrypt(msg_v, sk, ctxt_ct); });
    });
    EncryptorT<PRESET_EMPTY> enc_rt(P);
    Ciphertext ctxt_rt(P);
    double rt = best_of(5, [&] {
        return time_us(iters, [&] { enc_rt.encrypt(msg_v, sk, ctxt_rt); });
    });
    line(name, rt, ct);
}

template <Preset P> static void bench_decrypt(const char *name, int iters) {
    const Size ns = get_num_secret(P);
    std::vector<Message> msg_v;
    for (Size i = 0; i < ns; ++i)
        msg_v.push_back(gen_random_message(get_num_slots(P)));
    SecretKey sk = SecretKeyGenerator::GenSecretKey(P);
    EncryptorT<PRESET_EMPTY> enc(P);
    Ciphertext ctxt(P);
    enc.encrypt(msg_v, sk, ctxt);

    DecryptorT<P> dec_ct;
    double ct = best_of(5, [&] {
        return time_us(iters, [&] { dec_ct.decrypt(ctxt, sk, msg_v.data()); });
    });
    DecryptorT<PRESET_EMPTY> dec_rt(P);
    double rt = best_of(5, [&] {
        return time_us(iters, [&] { dec_rt.decrypt(ctxt, sk, msg_v.data()); });
    });
    line(name, rt, ct);
}

template <Preset P> static void bench_multkey(const char *name, int iters) {
    SecretKey sk = SecretKeyGenerator::GenSecretKey(P);
    KeyGeneratorT<P> kg_ct;
    double ct = best_of(5, [&] {
        return time_us(iters, [&] { auto k = kg_ct.genMultKey(sk); (void)k; });
    });
    KeyGeneratorT<PRESET_EMPTY> kg_rt(P);
    double rt = best_of(5, [&] {
        return time_us(iters, [&] { auto k = kg_rt.genMultKey(sk); (void)k; });
    });
    line(name, rt, ct);
}

template <Preset P> static void check_roundtrip(const char *name) {
    const Size ns = get_num_secret(P);
    std::vector<Message> in;
    for (Size i = 0; i < ns; ++i) in.push_back(gen_random_message(get_num_slots(P)));
    std::vector<Message> out = in;
    SecretKey sk = SecretKeyGenerator::GenSecretKey(P);
    EncryptorT<P> enc;
    Ciphertext ctxt(P);
    enc.encrypt(in, sk, ctxt);
    DecryptorT<P> dec;
    dec.decrypt(ctxt, sk, out.data());
    double max_err = 0;
    for (Size s = 0; s < ns; ++s)
        for (Size i = 0; i < out[s].size(); ++i) {
            max_err = std::max(max_err, std::abs(out[s][i].real() - in[s][i].real()));
            max_err = std::max(max_err, std::abs(out[s][i].imag() - in[s][i].imag()));
        }
    printf("  [%s templated roundtrip] max abs err = %.3e  %s\n", name, max_err,
           max_err < 1e-5 ? "OK" : "<-- FAILURE");
}

int main() {
    printf("=== Correctness (templated encrypt -> templated decrypt) ===\n");
    check_roundtrip<PRESET_FGb>("FGb");
    check_roundtrip<PRESET_FGbD12L0>("FGbD12L0");
    check_roundtrip<PRESET_FGbMS>("FGbMS");

    printf("\n=== Barrett mulPoly kernel (same degree; isolates constexpr "
           "prime) ===\n");
    bench_mulpoly_kernel<PRESET_FGb>("mulPoly FGb (deg 65536, 13 primes)");
    bench_mulpoly_kernel<PRESET_FGbD12L0>("mulPoly FGbD12L0 (deg 4096)");

    printf("\n=== genMultKey (Barrett-heavy keygen) ===\n");
    bench_multkey<PRESET_FGb>("genMultKey FGb", 30);

    printf("\n=== Decryption ===\n");
    bench_decrypt<PRESET_FGb>("decrypt FGb (deg 65536)", 80);
    bench_decrypt<PRESET_FGbD12L0>("decrypt FGbD12L0 (deg 4096)", 800);

    printf("\n=== Encryption (RNG-dominated; shown for completeness) ===\n");
    bench_encrypt<PRESET_FGb>("encrypt FGb (deg 65536)", 20);
    return 0;
}
