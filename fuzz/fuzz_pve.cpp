// ============================================================================
// fuzz_pve.cpp - Harness PVE (backup/recovery de claves) de cb-mpc (Coinbase)
// ----------------------------------------------------------------------------
// Oraculos (diseño de las IAs, mecanica reescrita por Claude con tipos REALES):
//   [A] BINDING/SOUNDNESS ($50K): verify OK pero decrypt->x' con x'*G != Q
//   [B] NO-LEAK (conservador): ct arbitrario que descifra a NUESTRA clave
//   [C] ROUNDTRIP: encrypt->verify->decrypt == x
//   [D] PARSERS (ASan): modulus/batch_count/get_public_key con basura
//   [E] LABEL-CONFUSION: cifrar label A, verify/decrypt label B
// PVE es LOCAL (sin red/threads). RNG determinista -> crashes reproducibles.
// ============================================================================

#include <cbmpc/api/pve_base_pke.h>
#include <cbmpc/api/pve_batch_single_recipient.h>
#include <cbmpc/core/buf.h>
#include <cbmpc/core/error.h>

#include <fuzzer/FuzzedDataProvider.h>

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string_view>
#include <vector>

using namespace coinbase;
namespace pve = coinbase::api::pve;

// ============================================================================
// RNG DETERMINISTA (igual que los harnesses que SI compilan)
// ============================================================================
namespace fuzzrng {
inline uint64_t s[4] = {0x9E3779B97F4A7C15ULL, 0xBF58476D1CE4E5B9ULL,
                        0x94D049BB133111EBULL, 0x2545F4914F6CDD1DULL};
inline uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
inline uint64_t next() {
  const uint64_t r = rotl(s[1] * 5, 7) * 9;
  const uint64_t t = s[1] << 17;
  s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3]; s[2] ^= t; s[3] = rotl(s[3], 45);
  return r;
}
inline void seed(const uint8_t* d, size_t n) {
  s[0] = 0x9E3779B97F4A7C15ULL; s[1] = 0xBF58476D1CE4E5B9ULL;
  s[2] = 0x94D049BB133111EBULL; s[3] = 0x2545F4914F6CDD1DULL;
  for (size_t i = 0; i < n; i++) { s[i & 3] ^= (uint64_t)d[i] << ((i % 8) * 8); next(); }
  for (int i = 0; i < 16; i++) next();
}
inline int det_bytes(unsigned char* buf, int num) {
  int i = 0;
  while (i < num) { uint64_t x = next(); int c = (num - i) < 8 ? (num - i) : 8; std::memcpy(buf + i, &x, c); i += c; }
  return 1;
}
inline int det_status() { return 1; }
inline RAND_METHOD meth = {nullptr, det_bytes, nullptr, nullptr, det_bytes, det_status};
inline void install() { RAND_set_rand_method(&meth); }
}  // namespace fuzzrng

namespace {

constexpr auto kCurve = coinbase::api::curve_id::secp256k1;
constexpr int kNid = NID_secp256k1;
constexpr std::string_view kLabel = "PVE_FUZZ_LABEL";

static buf_t g_ek, g_dk, g_ct, g_x;          // ek/dk claves, g_ct cifrado ref, g_x=32B
static std::array<uint8_t, 33> g_Q{};        // Q = g_x * G comprimido (33 bytes)
static bool g_ready = false;

// mem_t desde bytes crudos
static mem_t M(const uint8_t* p, size_t n) { return mem_t{reinterpret_cast<const_byte_ptr>(p), (int)n}; }
static mem_t Ml() { return mem_t{reinterpret_cast<const_byte_ptr>(kLabel.data()), (int)kLabel.size()}; }

// scalar (big-endian) -> Q = scalar*G comprimido (33B) con OpenSSL (verificador independiente)
static bool scalar_to_Q(const uint8_t* sc, int n, std::array<uint8_t, 33>& out) {
  EC_GROUP* g = EC_GROUP_new_by_curve_name(kNid); if (!g) return false;
  BN_CTX* ctx = BN_CTX_new();
  BIGNUM* bn = BN_bin2bn(sc, n, nullptr);
  BIGNUM* ord = BN_new(); EC_GROUP_get_order(g, ord, ctx);
  if (bn) BN_mod(bn, bn, ord, ctx);               // reducir mod orden (como hace PVE)
  EC_POINT* P = EC_POINT_new(g);
  bool ok = false;
  if (bn && P && EC_POINT_mul(g, P, bn, nullptr, nullptr, ctx) == 1) {
    size_t l = EC_POINT_point2oct(g, P, POINT_CONVERSION_COMPRESSED, out.data(), 33, ctx);
    ok = (l == 33);
  }
  if (P) EC_POINT_free(P); if (bn) BN_free(bn); if (ord) BN_free(ord);
  if (ctx) BN_CTX_free(ctx); EC_GROUP_free(g);
  return ok;
}

static bool load_buf(const char* path, buf_t& out) {
  FILE* f = std::fopen(path, "rb"); if (!f) return false;
  std::fseek(f, 0, SEEK_END); long n = std::ftell(f); std::fseek(f, 0, SEEK_SET);
  bool ok = false;
  if (n > 0 && n < (64 << 20)) { out = buf_t((int)n); ok = std::fread(out.data(), 1, (size_t)n, f) == (size_t)n; }
  std::fclose(f); return ok;
}
static void save_buf(const char* path, const buf_t& b) {
  FILE* f = std::fopen(path, "wb"); if (!f) return;
  if (b.size() > 0) std::fwrite(b.data(), 1, (size_t)b.size(), f);
  std::fclose(f);
}

static bool bootstrap() {
  if (load_buf("cbmpc_pve_ek.bin", g_ek) && load_buf("cbmpc_pve_dk.bin", g_dk) &&
      load_buf("cbmpc_pve_x.bin", g_x) && load_buf("cbmpc_pve_ct.bin", g_ct)) {
    return scalar_to_Q(g_x.data(), g_x.size(), g_Q);
  }
  if (pve::generate_base_pke_ecies_p256_keypair(g_ek, g_dk) != SUCCESS) return false;
  g_x = buf_t(32);
  for (int i = 0; i < 32; i++) g_x[i] = (uint8_t)(fuzzrng::next() & 0xFF);
  g_x[0] &= 0x7F;  // asegurar < orden (evitar reduccion trivial en el borde)
  if (pve::encrypt(kCurve, g_ek, Ml(), M(g_x.data(), g_x.size()), g_ct) != SUCCESS) return false;
  if (!scalar_to_Q(g_x.data(), g_x.size(), g_Q)) return false;
  save_buf("cbmpc_pve_ek.bin", g_ek); save_buf("cbmpc_pve_dk.bin", g_dk);
  save_buf("cbmpc_pve_x.bin", g_x);   save_buf("cbmpc_pve_ct.bin", g_ct);
  return true;
}

}  // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  fuzzrng::install();
  g_ready = bootstrap();
  if (!g_ready) { std::fprintf(stderr, "PVE bootstrap() failed\n"); std::abort(); }
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  if (!g_ready || Size < 2) return 0;
  fuzzrng::seed(Data, Size);
  FuzzedDataProvider fdp(Data, Size);

  uint8_t op = fdp.ConsumeIntegral<uint8_t>() % 6;
  std::vector<uint8_t> blob = fdp.ConsumeRemainingBytes<uint8_t>();
  mem_t label = Ml();

  switch (op) {
    // [A] BINDING/SOUNDNESS ($50K): verify OK -> decrypt debe dar x' con x'*G == Q_ref
    case 0: {
      if (blob.empty()) break;
      mem_t ct = M(blob.data(), blob.size());
      mem_t Qref = M(g_Q.data(), g_Q.size());
      if (pve::verify(kCurve, g_ek, ct, Qref, label) == SUCCESS) {
        buf_t x2;
        if (pve::decrypt(kCurve, g_dk, g_ek, ct, label, x2) == SUCCESS && x2.size() > 0) {
          std::array<uint8_t, 33> q2{};
          if (!scalar_to_Q(x2.data(), x2.size(), q2) || q2 != g_Q) {
            std::fprintf(stderr, "CRITICAL [PVE-BINDING] verify ACEPTA pero decrypt no corresponde a Q!\n");
            std::abort();
          }
        }
      }
      break;
    }
    // [B] NO-LEAK (conservador, sin falsos positivos): un ct arbitrario NUNCA debe
    //     descifrar exactamente a NUESTRA clave secreta g_x.
    case 1: {
      if (blob.empty()) break;
      mem_t ct = M(blob.data(), blob.size());
      buf_t x2;
      if (pve::decrypt(kCurve, g_dk, g_ek, ct, label, x2) == SUCCESS &&
          x2.size() == g_x.size() && std::memcmp(x2.data(), g_x.data(), g_x.size()) == 0) {
        std::fprintf(stderr, "CRITICAL [PVE-LEAK] ct arbitrario descifro a la clave secreta!\n");
        std::abort();
      }
      break;
    }
    // [C] ROUNDTRIP: encrypt(new_x) -> verify OK -> decrypt == new_x
    case 2: {
      if (blob.size() < 32) break;
      buf_t nx(32); for (int i = 0; i < 32; i++) nx[i] = blob[i]; nx[0] &= 0x7F;
      buf_t ct2;
      if (pve::encrypt(kCurve, g_ek, label, M(nx.data(), 32), ct2) == SUCCESS) {
        std::array<uint8_t, 33> q2{};
        if (scalar_to_Q(nx.data(), 32, q2) &&
            pve::verify(kCurve, g_ek, M(ct2.data(), ct2.size()), M(q2.data(), q2.size()), label) == SUCCESS) {
          buf_t back;
          if (pve::decrypt(kCurve, g_dk, g_ek, M(ct2.data(), ct2.size()), label, back) == SUCCESS) {
            if (back.size() != 32 || std::memcmp(back.data(), nx.data(), 32) != 0) {
              std::fprintf(stderr, "CRITICAL [PVE-ROUNDTRIP] encrypt->verify OK pero decrypt != x!\n");
              std::abort();
            }
          }
        }
      }
      break;
    }
    // [D] PARSERS (ASan caza crashes de memoria; no abortamos nosotros)
    case 3: {
      mem_t raw = M(blob.data(), blob.size());
      buf_t o1, o2, o3; int cnt = 0;
      pve::base_pke_rsa_ek_from_modulus(raw, o1);
      pve::get_public_key_compressed(raw, o2);
      pve::get_Label(raw, o3);
      pve::get_batch_count(raw, cnt);
      break;
    }
    // [E] LABEL-CONFUSION: verify/decrypt del ct REAL con una label DISTINTA -> no debe pasar
    case 4: {
      if (blob.empty()) break;
      mem_t badlabel = M(blob.data(), blob.size());
      // si la label mutada es igual a la real, no aporta
      if (blob.size() == kLabel.size() && std::memcmp(blob.data(), kLabel.data(), kLabel.size()) == 0) break;
      mem_t Qref = M(g_Q.data(), g_Q.size());
      if (pve::verify(kCurve, g_ek, M(g_ct.data(), g_ct.size()), Qref, badlabel) == SUCCESS) {
        std::fprintf(stderr, "CRITICAL [PVE-LABEL] verify ACEPTA el ct con una label DISTINTA!\n");
        std::abort();
      }
      break;
    }
    // [F] MALLEABILITY: ct mutado 1 byte no debe descifrar al plaintext original
    default: {
      if (g_ct.size() == 0) break;
      buf_t mct(g_ct);
      size_t off = blob.empty() ? 0 : (blob[0] % (size_t)mct.size());
      mct[off] ^= (blob.size() > 1 ? blob[1] : 0xFF);
      buf_t x2;
      if (pve::decrypt(kCurve, g_dk, g_ek, M(mct.data(), mct.size()), label, x2) == SUCCESS &&
          x2.size() == g_x.size() && std::memcmp(x2.data(), g_x.data(), g_x.size()) == 0) {
        std::fprintf(stderr, "CRITICAL [PVE-MALLEABILITY] ct mutado descifro al plaintext original!\n");
        std::abort();
      }
      break;
    }
  }
  return 0;
}
