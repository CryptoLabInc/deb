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

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

#include "json.hpp" // nlohmann/json (https://github.com/nlohmann/json)
using json = nlohmann::json;

static inline uint64_t bitWidth(uint64_t op) {
    uint64_t n = 64;
    uint64_t tmp = op >> 32;
    if (tmp != 0) {
        n = n - 32;
        op = tmp;
    }
    tmp = op >> 16;
    if (tmp != 0) {
        n = n - 16;
        op = tmp;
    }
    tmp = op >> 8;
    if (tmp != 0) {
        n = n - 8;
        op = tmp;
    }
    tmp = op >> 4;
    if (tmp != 0) {
        n = n - 4;
        op = tmp;
    }
    tmp = op >> 2;
    if (tmp != 0) {
        n = n - 2;
        op = tmp;
    }
    tmp = op >> 1;
    if (tmp != 0)
        return 62 - n;

    return UINT64_C(0);
}

static uint32_t get_u32(const json &j, const char *key, bool &has,
                        uint32_t def) {
    if (j.contains(key)) {
        has = true;
        return j.at(key).get<uint32_t>();
    }
    has = false;
    return def;
}
static std::string get_str(const json &j, const char *key, bool &has,
                           const std::string &def = {}) {
    if (j.contains(key)) {
        has = true;
        return j.at(key).get<std::string>();
    }
    has = false;
    return def;
}
struct CustomP {
    std::string NAME;
    uint32_t LOG_DEGREE;
    uint32_t LOG_BP_SIZE;
    uint32_t LOG_QP_SIZE;
    uint32_t LOG_TP_SIZE;

    uint32_t CHAIN_LENGTH = 1;
    uint32_t RANK = 1;
    uint32_t NUM_SECRET = 1;
    uint32_t GADGET_RANK = 1;
    uint32_t HWT = 0;
    std::vector<double> SCALE_FACTORS;
};

struct PresetP {
    // direct as read from JSON (optional)
    std::string NAME;
    std::string PARENT; // optional
    bool has_PARENT = false;

    uint32_t LOG_DEGREE = 0;
    bool has_LOG_DEGREE = false;
    uint32_t NUM_BASE = 1;
    bool has_NUM_BASE = false;
    uint32_t NUM_QP = 0;
    bool has_NUM_QP = false;
    uint32_t NUM_TP = 0;
    bool has_NUM_TP = false;
    uint32_t ENC_LEVEL = 0;
    bool has_ENC_LEVEL = false;
    uint32_t HWT = 0;
    bool has_HWT = false;

    uint32_t RANK = 1;
    bool has_RANK = false;
    uint32_t NUM_SECRET = 1;
    bool has_NUM_SECRET = false;
    uint32_t GADGET_RANK = 1;
    bool has_GADGET_RANK = false;

    std::vector<uint64_t> PRIMES;
    bool has_PRIMES = false;
    std::vector<double> SCALE_FACTORS;
    bool has_SCALE_FACTORS = false;
};

using RawPreset = std::variant<CustomP, PresetP>;

struct FinalPreset {
    // fully-resolved (after inheritance)
    std::string NAME;
    std::string PARENT; // may be empty (== self or none)
    uint32_t LOG_DEGREE = 0;
    uint32_t NUM_BASE = 1;
    uint32_t NUM_QP = 0;
    uint32_t NUM_TP = 0;
    uint32_t ENC_LEVEL = 0;
    uint32_t HWT = 0;
    uint32_t RANK = 1;
    uint32_t NUM_SECRET = 1;
    uint32_t GADGET_RANK = 1;
    std::vector<uint64_t> PRIMES;
    // precomputed values
    std::vector<double> SCALE_FACTORS;
    // FOR FFT
    std::vector<uint64_t> POWER_OF_FIVE;
    std::vector<uint64_t> ROOTS;
    std::vector<uint64_t> ROOTS_INV;
    std::vector<uint64_t> ROOTS_COMPLEX;
    // FOR NTT
    std::vector<uint64_t> DEGREE_INV;
    std::vector<uint64_t> DEGREE_INV_BARRETT;
    std::vector<uint64_t> DEGREE_INV_W;
    std::vector<uint64_t> DEGREE_INV_W_BARRETT;
    std::vector<std::vector<uint64_t>> NTT_PSI;
    std::vector<std::vector<uint64_t>> NTT_PSI_INV;
    std::vector<std::vector<uint64_t>> NTT_PSI_SHOUP;
    std::vector<std::vector<uint64_t>> NTT_PSI_INV_SHOUP;
    // FOR KEYGEN
    std::vector<uint64_t> P_MOP;
    std::vector<uint64_t> HAT_Q_MOD;
    std::vector<uint64_t> HAT_Q_INV_MOD;
    // FOR ModuloArithmetic
    std::vector<uint64_t> BARRETT_RATIO;
    std::vector<uint64_t> BARRETT_EXPT;
};

static CustomP parse_custom_preset(const json &j) {
    CustomP p;
    bool has;
    p.NAME = j.at("NAME").get<std::string>();
    p.LOG_DEGREE = j.at("LOG_DEGREE").get<uint32_t>();
    p.LOG_BP_SIZE = j.at("LOG_BP_SIZE").get<uint32_t>();
    p.LOG_QP_SIZE = j.at("LOG_QP_SIZE").get<uint32_t>();
    p.LOG_TP_SIZE = j.at("LOG_TP_SIZE").get<uint32_t>();
    p.CHAIN_LENGTH = get_u32(j, "CHAIN_LENGTH", has, p.CHAIN_LENGTH);
    p.RANK = get_u32(j, "RANK", has, p.RANK);
    p.GADGET_RANK = get_u32(j, "GADGET_RANK", has, p.GADGET_RANK);
    p.NUM_SECRET = get_u32(j, "NUM_SECRET", has, p.NUM_SECRET);
    p.HWT = get_u32(j, "HWT", has, (1 << (p.LOG_DEGREE)) * p.RANK * 2 / 3);
    if (j.contains("SCALE_FACTORS")) {
        for (const auto &v : j.at("SCALE_FACTORS")) {
            p.SCALE_FACTORS.push_back(v.get<double>());
        }
    }

    if (j.contains("RANK")) {
        p.RANK = j.at("RANK").get<uint32_t>();
    }
    if (j.contains("NUM_SECRET")) {
        p.NUM_SECRET = j.at("NUM_SECRET").get<uint32_t>();
    }
    return p;
}

static PresetP parse_raw_preset(const json &j) {
    PresetP r;
    r.NAME = j.at("NAME").get<std::string>();
    r.PARENT = get_str(j, "PARENT", r.has_PARENT);
    r.LOG_DEGREE = get_u32(j, "LOG_DEGREE", r.has_LOG_DEGREE, r.LOG_DEGREE);
    r.NUM_BASE = get_u32(j, "NUM_BASE", r.has_NUM_BASE, r.NUM_BASE);
    r.NUM_QP = get_u32(j, "NUM_QP", r.has_NUM_QP, r.NUM_QP);
    r.NUM_TP = get_u32(j, "NUM_TP", r.has_NUM_TP, r.NUM_TP);
    r.ENC_LEVEL = get_u32(j, "ENC_LEVEL", r.has_ENC_LEVEL, r.ENC_LEVEL);
    r.RANK = get_u32(j, "RANK", r.has_RANK, r.RANK);
    r.HWT =
        get_u32(j, "HWT", r.has_HWT, (1 << (r.LOG_DEGREE)) * r.RANK * 2 / 3);
    r.NUM_SECRET = get_u32(j, "NUM_SECRET", r.has_NUM_SECRET, r.NUM_SECRET);
    r.GADGET_RANK = get_u32(j, "GADGET_RANK", r.has_GADGET_RANK, r.GADGET_RANK);

    if (j.contains("PRIMES")) {
        r.has_PRIMES = true;
        for (const auto &v : j.at("PRIMES")) {
            // accept number (assumed fits uint64)
            r.PRIMES.push_back(v.get<uint64_t>());
        }
    } else if (r.PARENT.empty()) {
        throw std::runtime_error(
            "Preset " + r.NAME +
            " must specify PRIMES when PARENT is not given");
    }
    if (j.contains("SCALE_FACTORS")) {
        r.has_SCALE_FACTORS = true;
        for (const auto &v : j.at("SCALE_FACTORS")) {
            r.SCALE_FACTORS.push_back(v.get<double>());
        }
    }
    return r;
}

bool isPrime(const uint64_t n) {
    if (n == 2 || n == 3 || n == 5 || n == 7)
        return true;
    if (n % 2 == 0 || n % 3 == 0 || n % 5 == 0 || n % 7 == 0)
        return false;
    if (n < 121)
        return (n > 1);

    int expo = 0;
    uint64_t oddpart = n - 1;
    while ((oddpart & UINT64_C(1)) == UINT64_C(0)) {
        expo++;
        oddpart >>= UINT64_C(1);
    }

    static const std::array<uint64_t, 7> SINCLAIR_BASE{
        UINT64_C(2),         UINT64_C(325),    UINT64_C(9375),
        UINT64_C(28178),     UINT64_C(450775), UINT64_C(9780504),
        UINT64_C(1795265022)};

    auto mulModSimple = [](uint64_t a, uint64_t b, uint64_t mod) {
        uint64_t a_hi = a >> 32;
        uint64_t a_lo = a & UINT32_MAX;
        uint64_t b_hi = b >> 32;
        uint64_t b_lo = b & UINT32_MAX;

        uint64_t cross = ((a_hi * b_lo) % mod + (a_lo * b_hi) % mod) % mod;
        uint64_t lo = (a_lo * b_lo) % mod;
        uint64_t hi = (a_hi * b_hi) % mod;
        // Now, combine the terms: hi * 2^64, cross * 2^32, lo
        for (std::size_t i = 0; i < 64; ++i) {
            if (hi * 2 < hi) // if overflow
                hi = (2 * hi - mod) % mod;
            else
                hi = (2 * hi) % mod;
        }
        uint64_t cross_term = cross;
        for (std::size_t i = 0; i < 32; ++i) {
            if (cross_term * 2 < cross_term) // if overflow
                cross_term = (2 * cross_term - mod) % mod;
            else
                cross_term = (2 * cross_term) % mod;
        }
        uint64_t result = hi;
        if (result + cross_term < result)
            result = (result + cross_term - mod) % mod;
        else
            result = (result + cross_term) % mod;
        if (result + lo < result)
            return (result + lo - mod) % mod;
        else
            return (result + lo) % mod;
    };
    auto powModSimple = [mulModSimple](uint64_t base, uint64_t expo,
                                       uint64_t mod) {
        uint64_t res = UINT64_C(1);
        while (expo > 0) {
            if (expo & 1) // if odd
                res = mulModSimple(res, base, mod);
            base = mulModSimple(base, base, mod);
            expo >>= 1;
        }
        return res;
    };
    auto is_strong_probable_prime_of_base = [=](uint64_t base) {
        uint64_t x = powModSimple(base, oddpart, n);
        if (x == UINT64_C(1) || x == n - 1)
            return true;
        for (int i = 0; i < expo - 1; ++i) {
            x = mulModSimple(x, x, n);
            if (x == n - 1)
                return true;
        }
        return false;
    };

    return std::all_of(SINCLAIR_BASE.begin(), SINCLAIR_BASE.end(),
                       is_strong_probable_prime_of_base);
}

void seekPrimes(const uint64_t center, const uint64_t gap, uint64_t number,
                std::vector<uint64_t> &out) {

    uint64_t base = center + 1;
    uint64_t multiplier = 1;
    uint64_t p;

    while (true) {
        p = base - multiplier * gap;
        if (isPrime(p)) {
            out.push_back(p);
            number--;
        }

        if (number == 0)
            break;

        multiplier++;
    }
}
std::vector<uint64_t> computePrimes(uint32_t log_degree, uint32_t log_bp_size,
                                    uint32_t log_qp_size, uint32_t log_tp_size,
                                    uint32_t chain_length,
                                    uint32_t gadget_rank) {
    std::vector<uint64_t> primes;
    uint64_t degree = UINT64_C(1) << log_degree;
    uint64_t bpsize = UINT64_C(1) << log_bp_size;
    uint64_t qpsize = UINT64_C(1) << log_qp_size;
    uint64_t tpsize = UINT64_C(1) << log_tp_size;
    uint64_t num_tp = (chain_length + gadget_rank - 1) / gadget_rank;
    if (log_bp_size != log_qp_size) {
        seekPrimes(bpsize, 2 * degree, 1, primes);
        seekPrimes(qpsize, 2 * degree, chain_length - 1, primes);
        std::vector<uint64_t> tprimes;
        seekPrimes(tpsize, 2 * degree, num_tp + 1, tprimes);
        for (auto it = tprimes.begin() + 1; it != tprimes.end(); ++it) {
            primes.push_back(*it);
        }
    } else {
        if (log_bp_size != log_tp_size) {
            seekPrimes(qpsize, 2 * degree, chain_length, primes);
            seekPrimes(tpsize, 2 * degree, num_tp, primes);
        }
        if (log_bp_size == log_tp_size) {
            seekPrimes(tpsize, 2 * degree, chain_length + num_tp, primes);
            std::reverse(primes.begin(), primes.end());
        }
    }
    return primes;
}

// Resolve inheritance with DFS + memoization
static FinalPreset
resolve_one(const std::string &name,
            const std::unordered_map<std::string, RawPreset> &raw,
            std::unordered_map<std::string, FinalPreset> &memo,
            std::unordered_set<std::string> &visiting) {
    if (memo.count(name))
        return memo[name];
    if (!raw.count(name))
        throw std::runtime_error("Unknown preset name: " + name);

    if (visiting.count(name))
        throw std::runtime_error("Cyclic PARENT detected at: " + name);
    visiting.insert(name);

    const RawPreset &pr = raw.at(name);
    FinalPreset out;

    auto pick_u32 = [](bool has, uint32_t v, uint32_t basev) {
        return has ? v : basev;
    };
    auto pick_str = [](bool has, const std::string &v,
                       const std::string &basev) { return has ? v : basev; };

    if (std::holds_alternative<CustomP>(pr)) {
        CustomP cr = std::get<CustomP>(pr);
        if (cr.LOG_DEGREE < 6 || cr.LOG_DEGREE > 20)
            throw std::runtime_error("[resolve_one] Invalid log_degree");
        if (cr.CHAIN_LENGTH > 50)
            throw std::runtime_error("[resolve_one] Invalid chain_length");
        if (cr.RANK != 1)
            throw std::runtime_error("[resolve_one] custom parameter with rank "
                                     "> 1 is not supported.");
        if (cr.LOG_BP_SIZE >= 62 || cr.LOG_QP_SIZE >= 62 ||
            cr.LOG_TP_SIZE >= 62)
            throw std::runtime_error("[resolve_one] Invalid log prime size");
        if (cr.LOG_QP_SIZE < 36)
            throw std::runtime_error("[resolve_one] Quantize primes should be "
                                     "greater than or equal to 36 bit");
        if (cr.LOG_BP_SIZE +
                cr.LOG_QP_SIZE *
                    ((cr.CHAIN_LENGTH + cr.GADGET_RANK - 1) / cr.GADGET_RANK -
                     1) >
            cr.LOG_TP_SIZE * (cr.CHAIN_LENGTH + cr.GADGET_RANK - 1) /
                cr.GADGET_RANK)
            throw std::runtime_error(
                "[resolve_one] log_tpsize should be greater "
                "than log_qpsize + (log_bpsize - log_qpsize)/numTP");
        out.NAME = cr.NAME;
        out.PARENT = cr.NAME;
        out.LOG_DEGREE = cr.LOG_DEGREE;
        out.NUM_BASE = 1;
        out.NUM_QP = cr.CHAIN_LENGTH - out.NUM_BASE;
        out.NUM_TP = (cr.CHAIN_LENGTH + cr.GADGET_RANK - 1) / cr.GADGET_RANK;
        out.ENC_LEVEL = cr.CHAIN_LENGTH - 1;
        out.RANK = cr.RANK;
        out.NUM_SECRET = cr.NUM_SECRET;
        out.GADGET_RANK = cr.GADGET_RANK;
        const uint32_t degree = 1u << out.LOG_DEGREE;
        out.HWT = cr.HWT;

        out.PRIMES =
            computePrimes(cr.LOG_DEGREE, cr.LOG_BP_SIZE, cr.LOG_QP_SIZE,
                          cr.LOG_TP_SIZE, cr.CHAIN_LENGTH, cr.GADGET_RANK);
        if (!cr.SCALE_FACTORS.empty())
            out.SCALE_FACTORS = cr.SCALE_FACTORS;

    } else if (std::holds_alternative<PresetP>(pr)) {
        PresetP r = std::get<PresetP>(pr);
        // Base case: parent = self or not present -> no parent apply
        bool has_parent = r.has_PARENT && !r.PARENT.empty() && r.PARENT != name;
        FinalPreset base;
        if (has_parent) {
            base = resolve_one(r.PARENT, raw, memo, visiting);
        } else {
            // sensible defaults already in FinalPreset ctor
        }

        out.NAME = r.NAME; // Name must be unique
        out.PARENT =
            has_parent ? r.PARENT : (r.has_PARENT ? r.PARENT : base.PARENT);
        out.LOG_DEGREE =
            pick_u32(r.has_LOG_DEGREE, r.LOG_DEGREE, base.LOG_DEGREE);
        out.NUM_BASE = pick_u32(r.has_NUM_BASE, r.NUM_BASE, base.NUM_BASE);
        out.NUM_QP = pick_u32(r.has_NUM_QP, r.NUM_QP, base.NUM_QP);
        out.NUM_TP = pick_u32(r.has_NUM_TP, r.NUM_TP, base.NUM_TP);
        out.ENC_LEVEL = pick_u32(r.has_ENC_LEVEL, r.ENC_LEVEL, base.ENC_LEVEL);
        out.HWT = pick_u32(r.has_HWT, r.HWT, base.HWT);
        out.RANK = pick_u32(r.has_RANK, r.RANK, base.RANK);
        out.NUM_SECRET =
            pick_u32(r.has_NUM_SECRET, r.NUM_SECRET, base.NUM_SECRET);
        out.GADGET_RANK =
            pick_u32(r.has_GADGET_RANK, r.GADGET_RANK, base.GADGET_RANK);

        if (r.has_PRIMES)
            out.PRIMES = r.PRIMES;
        else
            out.PRIMES = base.PRIMES;

        if (r.has_SCALE_FACTORS)
            out.SCALE_FACTORS = r.SCALE_FACTORS;
        else if (!base.SCALE_FACTORS.empty() && !r.has_PRIMES)
            out.SCALE_FACTORS = base.SCALE_FACTORS;

    } else {
        throw std::runtime_error("Internal error: unknown RawPreset variant");
    }

    if (out.NUM_SECRET != 1 && out.RANK != 1) {
        throw std::runtime_error(
            "NUM_SECRET > 1 with RANK > 1 is not supported in preset: " + name);
    }
    if (out.SCALE_FACTORS.size() > out.NUM_BASE + out.NUM_QP + out.NUM_TP) {
        throw std::runtime_error("Too many SCALE_FACTORS in preset: " + name);
    }
    if (out.ENC_LEVEL > out.NUM_BASE + out.NUM_QP + out.NUM_TP - 1) {
        throw std::runtime_error(
            "ENC_LEVEL exceeds number of available levels in preset: " + name);
    }
    out.SCALE_FACTORS.resize(out.NUM_BASE + out.NUM_QP + out.NUM_TP, 0.0);

    visiting.erase(name);
    memo[name] = out;
    return memo[name];
}

static void write_header(const std::string &out_path,
                         const std::vector<FinalPreset> &finals) {
    std::ofstream os(out_path);
    if (!os)
        throw std::runtime_error("Failed to open output: " + out_path);

    os << "// Auto-generated by DebGenParam.cpp — DO NOT EDIT\n";
    os << "#pragma once\n\n";
    os << "#include <cstdint>\n";
    os << "#include <cinttypes>\n";
    os << "#include <vector>\n";
    os << "#include <string>\n";
    os << "#include <unordered_map>\n";
    os << "\n";
    os << "#include \"Types.hpp\"\n";
    os << "#define PRESET_LIST";
    for (const auto &final : finals) {
        os << " ";
        os << "X(" << final.NAME << ")";
    }
    os << "\nnamespace deb {\n\n";

    os << "enum Preset {\n";
    for (const auto &final : finals) {
        os << "\tPRESET_" << final.NAME << ",\n";
    }
    os << "\tPRESET_EMPTY\n";
    os << "};\n\n";

    auto emit_u64_vec = [&](const std::vector<uint64_t> &v) {
        std::ostringstream ss;
        ss << "{\n";
        for (size_t i = 0; i < v.size(); ++i) {
            ss << "\tUINT64_C(" << v[i] << "),  // " << i << "\n";
        }
        ss << "}";
        return ss.str();
    };
    auto emit_double_vec = [&](const std::vector<double> &v) {
        std::ostringstream ss;
        ss << std::setprecision(17);
        ss << "{\n";
        for (size_t i = 0; i < v.size(); ++i) {
            ss << "\t" << v[i] << ", // " << i << "\n";
        }
        ss << "}";
        return ss.str();
    };

    auto emit_constexpr_var = [&](const std::string &var_name,
                                  const std::string &val,
                                  const std::string &type = "Size") {
        std::ostringstream ss;
        ss << "inline static constexpr " << type << " " << var_name << " = "
           << val << ";\n";
        return ss.str();
    };
    FinalPreset empty_preset;
    empty_preset.NAME = empty_preset.PARENT = "EMPTY";
    std::vector<FinalPreset> finals_copy = finals;
    finals_copy.push_back(std::move(empty_preset));
    for (const auto &p : finals_copy) {
        os << "struct " << p.NAME << " { \n"
           << emit_constexpr_var("preset", "PRESET_" + p.NAME, "Preset")
           << emit_constexpr_var("parent", "PRESET_" + p.PARENT, "Preset")
           << emit_constexpr_var("preset_name", "\"" + p.NAME + "\"",
                                 "const char*")
           << emit_constexpr_var("rank", std::to_string(p.RANK))
           << emit_constexpr_var("num_secret", std::to_string(p.NUM_SECRET))
           << emit_constexpr_var("log_degree", std::to_string(p.LOG_DEGREE))
           << emit_constexpr_var("degree", std::to_string(1u << p.LOG_DEGREE))
           << emit_constexpr_var("num_slots",
                                 std::to_string((1u << p.LOG_DEGREE) / 2))
           << emit_constexpr_var("gadget_rank", std::to_string(p.GADGET_RANK))
           << emit_constexpr_var("num_base", std::to_string(p.NUM_BASE))
           << emit_constexpr_var("num_qp", std::to_string(p.NUM_QP))
           << emit_constexpr_var("num_tp", std::to_string(p.NUM_TP))
           << emit_constexpr_var(
                  "num_p", std::to_string(p.NUM_BASE + p.NUM_TP + p.NUM_QP))
           << emit_constexpr_var("encryption_level",
                                 std::to_string(p.ENC_LEVEL))
           << emit_constexpr_var("hamming_weight", std::to_string(p.HWT))
           << emit_constexpr_var("gaussian_error_stdev", "3.2", "Real")
           << emit_constexpr_var("primes[]", emit_u64_vec(p.PRIMES), "u64")
           << emit_constexpr_var("scale_factors[]",
                                 emit_double_vec(p.SCALE_FACTORS), "Real")
           << "};\n\n";
    }

    os << "} // namespace deb\n";
    os.close();
}
