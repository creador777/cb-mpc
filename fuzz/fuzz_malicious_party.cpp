// ============================================================================
// fuzz_malicious_party.cpp — Harness DEFINITIVO v2 (4 objetivos de alto valor)
// ----------------------------------------------------------------------------
// Red-Team de cb-mpc (Coinbase). Modelo de amenaza alineado con BUG_BOUNTY.md:
//   * P1 = HONESTA, corre la lib SIN MODIFICAR, vía la API PÚBLICA.
//   * P2 = MALICIOSA: sus mensajes P2->P1 se mutan en tránsito (semántico +
//     inyección degenerada + reorden + serialización + ZK). Solo interactúa
//     por el límite del protocolo.
//
// v2 agrega 4 objetivos de alto valor ($15K–$1M):
//   [OBJ-1] Mutación quirúrgica de serialización (convert_len + code_type)
//   [OBJ-2] Inyección semántica de pruebas ZK falsas (challenge=0, response
//           fuera de rango, identity points, campo swaps)
//   [OBJ-3] Oráculo de nonce reforzado (high-s, R=infinity)
//   [OBJ-4] Expansión a ECDSA Multi-Party (#ifdef FUZZ_ECDSA_MP)
//
// Compilar con: bash fuzz/build_fuzz_malicious.sh   (ver ese script)
// ============================================================================

#include <cbmpc/api/ecdsa_2p.h>
#ifdef FUZZ_ECDSA_MP
#include <cbmpc/api/ecdsa_mp.h>
#include <cbmpc/core/access_structure.h>
#endif
#include <cbmpc/core/buf.h>
#include <cbmpc/core/error.h>
#include <cbmpc/core/job.h>

#include <fuzzer/FuzzedDataProvider.h>

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <string_view>
#include <thread>
#include <vector>

using namespace coinbase;
namespace e2 = coinbase::api::ecdsa_2p;
#ifdef FUZZ_ECDSA_MP
namespace emp = coinbase::api::ecdsa_mp;
#endif

// ============================================================================
// RNG DETERMINISTA sembrado desde el input del fuzzer.
// ============================================================================
namespace fuzzrng {
inline uint64_t s[4] = {0x9E3779B97F4A7C15ULL, 0xBF58476D1CE4E5B9ULL,
                        0x94D049BB133111EBULL, 0x2545F4914F6CDD1DULL};
inline uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
inline uint64_t next() {  // xoshiro256**
  const uint64_t r = rotl(s[1] * 5, 7) * 9;
  const uint64_t t = s[1] << 17;
  s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3]; s[2] ^= t; s[3] = rotl(s[3], 45);
  return r;
}
inline void seed(const uint8_t* d, size_t n) {
  s[0] = 0x9E3779B97F4A7C15ULL; s[1] = 0xBF58476D1CE4E5B9ULL;
  s[2] = 0x94D049BB133111EBULL; s[3] = 0x2545F4914F6CDD1DULL;
  for (size_t i = 0; i < n; i++) { s[i & 3] ^= (uint64_t)d[i] << ((i % 8) * 8); next(); }
  for (int i = 0; i < 16; i++) next();  // warm-up
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

constexpr std::chrono::seconds kRecvTimeout{8};
constexpr auto kCurve = coinbase::api::curve_id::secp256k1;
constexpr int kNid = NID_secp256k1;

// [OBJ-2/3] secp256k1 order n (big-endian, 32 bytes)
static constexpr uint8_t kSecp256k1Order[32] = {
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
  0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B, 0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};
// [OBJ-3] secp256k1 half-order n/2 (for BIP-62 low-s check)
static constexpr uint8_t kSecp256k1HalfOrder[32] = {
  0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D, 0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0
};
// [OBJ-1] MAX_CONVERT_LEN from converter_t (for boundary injection)
static constexpr uint32_t kMaxConvertLen = 64 * 1024 * 1024;  // 64 MiB

// ============================================================================
// splitmix64 (para CustomMutator / CrossOver)
// ============================================================================
struct splitmix64_t {
  uint64_t state;
  explicit splitmix64_t(uint64_t seed) : state(seed) {}
  uint64_t next() {
    state += 0x9e3779b97f4a7c15ULL;
    uint64_t z = state;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
  }
  uint64_t in_range(uint64_t lo, uint64_t hi) { return (lo >= hi) ? lo : lo + (next() % (hi - lo + 1)); }
};

// ============================================================================
// Oráculo OpenSSL: verifica firma DER bajo pubkey comprimida.
// ============================================================================
static bool ossl_verify(mem_t h32, const buf_t& pub_compressed, const buf_t& sig_der) {
  if (h32.size != 32 || pub_compressed.size() == 0 || sig_der.size() == 0) return false;
  EC_KEY* ec = EC_KEY_new_by_curve_name(kNid);
  if (!ec) return true;  // fallo del oráculo, no del target
  const unsigned char* pp = reinterpret_cast<const unsigned char*>(pub_compressed.data());
  if (!o2i_ECPublicKey(&ec, &pp, (long)pub_compressed.size())) { EC_KEY_free(ec); return false; }
  const unsigned char* sp = reinterpret_cast<const unsigned char*>(sig_der.data());
  ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &sp, (long)sig_der.size());
  if (!sig) { EC_KEY_free(ec); return false; }
  const BIGNUM *r = nullptr, *s = nullptr;
  ECDSA_SIG_get0(sig, &r, &s);
  bool ok_range = false;
  if (r && s && !BN_is_zero(r) && !BN_is_zero(s)) {
    BIGNUM* order = BN_new();
    if (order) {
      const EC_GROUP* g = EC_KEY_get0_group(ec);
      if (g && EC_GROUP_get_order(g, order, nullptr) == 1)
        ok_range = (BN_cmp(r, order) < 0) && (BN_cmp(s, order) < 0);
      BN_free(order);
    }
  }
  bool vr = false;
  if (ok_range) {
    const unsigned char* d = reinterpret_cast<const unsigned char*>(h32.data);
    vr = ECDSA_do_verify(d, (int)h32.size, sig, ec) == 1;
  }
  ECDSA_SIG_free(sig);
  EC_KEY_free(ec);
  return vr;
}

// r canónico de 32 bytes (padded).
static bool extract_r32(const buf_t& sig_der, std::array<uint8_t, 32>& r_out) {
  if (sig_der.size() == 0) return false;
  const unsigned char* sp = reinterpret_cast<const unsigned char*>(sig_der.data());
  ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &sp, (long)sig_der.size());
  if (!sig) return false;
  const BIGNUM *r = nullptr, *s = nullptr;
  ECDSA_SIG_get0(sig, &r, &s);
  bool ok = false;
  if (r && !BN_is_zero(r) && BN_num_bytes(r) <= 32) {
    r_out.fill(0);
    ok = BN_bn2binpad(r, r_out.data(), 32) == 32;
  }
  ECDSA_SIG_free(sig);
  return ok;
}

// ============================================================================
// [OBJ-3] Check s > order/2 (high-s → BIP-62 malleable signature, Medium tier)
// ============================================================================
static bool extract_s_is_high(const buf_t& sig_der) {
  if (sig_der.size() == 0) return false;
  const unsigned char* sp = reinterpret_cast<const unsigned char*>(sig_der.data());
  ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &sp, (long)sig_der.size());
  if (!sig) return false;
  const BIGNUM *r = nullptr, *s = nullptr;
  ECDSA_SIG_get0(sig, &r, &s);
  bool high = false;
  if (s && !BN_is_zero(s)) {
    BIGNUM* half = BN_bin2bn(kSecp256k1HalfOrder, 32, nullptr);
    if (half) {
      high = (BN_cmp(s, half) > 0);
      BN_free(half);
    }
  }
  ECDSA_SIG_free(sig);
  return high;
}

// ============================================================================
// Oráculo de reuso de nonce ($1M). Solo sobre firmas de la parte HONESTA.
// ============================================================================
class nonce_oracle_t {
 public:
  void check_and_record(const std::array<uint8_t, 32>& r, const std::array<uint8_t, 32>& h) {
    // El chequeo de r==0 vivia aca y era CODIGO MUERTO: extract_r32() descarta las
    // firmas con r==0 (BN_is_zero) y solo llama a esta funcion si devolvio true, asi
    // que nunca podia entrar con r en cero. Ahora se comprueba en sig_r_is_zero(),
    // ANTES de ossl_verify, que es donde el dato todavia existe.
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = map_.find(r);
    if (it == map_.end()) { if (map_.size() < kCap) map_.emplace(r, h); return; }
    if (it->second != h) {
      std::fprintf(stderr, "CRITICAL [NONCE-REUSE] mismo R para dos hashes distintos: clave privada extraíble\n");
      std::abort();
    }
  }
 private:
  static constexpr size_t kCap = 200000;  // ~12MB tope; evita OOM en corridas largas
  std::mutex mtx_;
  std::map<std::array<uint8_t, 32>, std::array<uint8_t, 32>> map_;
};

// r == 0 en una firma que cb-mpc dio por buena. Se mira ANTES de ossl_verify: si
// esperamos a OpenSSL, este rechaza r==0 por su cuenta y el caso nunca se ve.
// Que la libreria PRODUZCA una firma degenerada es el hallazgo, aunque un
// verificador externo despues la rechace.
static bool sig_r_is_zero(const buf_t& sig_der) {
  if (sig_der.size() == 0) return false;
  const unsigned char* sp = reinterpret_cast<const unsigned char*>(sig_der.data());
  ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &sp, (long)sig_der.size());
  if (!sig) return false;
  const BIGNUM *r = nullptr, *s = nullptr;
  ECDSA_SIG_get0(sig, &r, &s);
  bool zero = (r != nullptr) && BN_is_zero(r);
  ECDSA_SIG_free(sig);
  return zero;
}

// ============================================================================
// Oráculo de leak: el escalar privado NUNCA debe aparecer literal en el
// tráfico saliente de la parte honesta.
// ============================================================================
static bool contains_sub(const uint8_t* hay, size_t hn, const uint8_t* nee, size_t nn) {
  if (!hay || !nee || nn == 0 || hn < nn) return false;
  for (size_t i = 0; i + nn <= hn; ++i)
    if (std::memcmp(hay + i, nee, nn) == 0) return true;
  return false;
}
static void leak_oracle(const buf_t& honest_key, const std::vector<buf_t>& transcript, std::mutex& mtx) {
  buf_t pub_blob, priv;
  if (e2::detach_private_scalar(honest_key, pub_blob, priv) != SUCCESS) return;
  if (priv.size() < 16) return;
  std::lock_guard<std::mutex> lk(mtx);
  for (const auto& m : transcript)
    if (contains_sub(m.data(), (size_t)m.size(), priv.data(), (size_t)priv.size())) {
      std::fprintf(stderr, "CRITICAL [KEY-LEAK] el escalar privado apareció en el tráfico honesto\n");
      std::abort();
    }
}

// ============================================================================
// Red en memoria (bloqueante con timeout anti-deadlock).
// ============================================================================
struct channel_t { std::mutex m; std::condition_variable cv; std::deque<buf_t> q; };
struct network_t {
  explicit network_t(int parties) : n(parties), ch(parties, std::vector<std::shared_ptr<channel_t>>(parties)) {
    for (int a = 0; a < n; ++a) for (int b = 0; b < n; ++b) if (a != b) ch[a][b] = std::make_shared<channel_t>();
  }
  int n;
  std::vector<std::vector<std::shared_ptr<channel_t>>> ch;
  std::atomic<bool> aborted{false};
  void reset_abort() { aborted.store(false); }
  void abort_all() {
    aborted.store(true);
    for (auto& row : ch) for (auto& c : row) if (c) { std::lock_guard<std::mutex> lk(c->m); c->cv.notify_all(); }
  }
};

// Config de mutación derivada del input.
struct mut_cfg_t {
  bool enabled = false;
  bool enable_semantic = false;
  bool enable_reorder = false;
  uint8_t forced_mode = 0;         // 0=ninguno, 1=paillier-degenerate, 2=share-null
  uint8_t attack_focus = 0;        // [OBJ-1/2] 0=auto, 1=serialization, 2=zk, 3=legacy-semantic
  std::vector<uint8_t> entropy;
};

// ============================================================================
// Transporte HONESTO (P1): registra su tráfico saliente para el leak oracle.
// ============================================================================
class honest_transport_t final : public coinbase::api::data_transport_i {
 public:
  honest_transport_t(int self, std::shared_ptr<network_t> net, std::vector<buf_t>* tr, std::mutex* trm)
      : self_(self), net_(std::move(net)), tr_(tr), trm_(trm) {}
  error_t send(coinbase::api::party_idx_t rcv, mem_t msg) override {
    if (!net_ || rcv < 0 || rcv >= net_->n || rcv == self_) return E_BADARG;
    auto c = net_->ch[self_][rcv]; if (!c) return E_GENERAL;
    if (tr_ && trm_) { buf_t cp(msg); std::lock_guard<std::mutex> lk(*trm_); tr_->push_back(std::move(cp)); }
    { std::lock_guard<std::mutex> lk(c->m); c->q.emplace_back(msg); }
    c->cv.notify_one();
    return SUCCESS;
  }
  error_t receive(coinbase::api::party_idx_t snd, buf_t& msg) override {
    if (!net_ || snd < 0 || snd >= net_->n || snd == self_) return E_BADARG;
    auto c = net_->ch[snd][self_]; if (!c) return E_GENERAL;
    std::unique_lock<std::mutex> lk(c->m);
    c->cv.wait_for(lk, kRecvTimeout, [&] { return !c->q.empty() || net_->aborted.load(); });
    if (c->q.empty()) return E_GENERAL;
    msg = std::move(c->q.front()); c->q.pop_front();
    return SUCCESS;
  }
  error_t receive_all(const std::vector<coinbase::api::party_idx_t>& s, std::vector<buf_t>& m) override {
    m.clear(); m.resize(s.size());
    for (size_t i = 0; i < s.size(); ++i) if (error_t rv = receive(s[i], m[i])) return rv;
    return SUCCESS;
  }
 private:
  int self_; std::shared_ptr<network_t> net_; std::vector<buf_t>* tr_; std::mutex* trm_;
};

// ============================================================================
// Utilidades aritméticas big-endian de 32 bytes (para mutate_zk_proof_aggressive).
// ============================================================================
static int be_cmp_32(const uint8_t* a, const uint8_t* b) { return std::memcmp(a, b, 32); }
static bool is_zero_32(const uint8_t* a) {
  for (int i = 0; i < 32; ++i)
    if (a[i]) return false;
  return true;
}
// dst = a - b (big-endian 32 bytes; asume a >= b, sin underflow).
static void be_sub_32(uint8_t* dst, const uint8_t* a, const uint8_t* b) {
  int borrow = 0;
  for (int i = 31; i >= 0; --i) {
    int d = (int)a[i] - (int)b[i] - borrow;
    if (d < 0) { d += 256; borrow = 1; } else { borrow = 0; }
    dst[i] = (uint8_t)d;
  }
}

// ============================================================================
// Transporte MALICIOSO: muta P_mal->P_honesta. Incluye:
//   [OBJ-1] mutate_serialization_header (convert_len + code_type)
//   [OBJ-2] mutate_zk_proof (challenge=0, response OOR, identity points)
//   [orig]  mutate_semantically, force_paillier_degenerate, force_share_null
// ============================================================================
class malicious_transport_t final : public coinbase::api::data_transport_i {
 public:
  malicious_transport_t(int self, std::shared_ptr<network_t> net, mut_cfg_t cfg)
      : self_(self), net_(std::move(net)), cfg_(std::move(cfg)) {}

  error_t send(coinbase::api::party_idx_t rcv, mem_t msg) override {
    if (!net_ || rcv < 0 || rcv >= net_->n || rcv == self_) return E_BADARG;
    auto c = net_->ch[self_][rcv]; if (!c) return E_GENERAL;
    buf_t out(msg);
    // Solo mutar mensajes del malicioso (self_==1) hacia el honesto (rcv==0)
    if (cfg_.enabled && self_ == 1 && rcv == 0) {
      // Selección de mutación primaria (dirigida por attack_focus)
      switch (cfg_.attack_focus) {
        case 0: {  // Auto: entropía decide
          uint8_t pick = next_byte() % 8;
          if (pick < 3) mutate_serialization_header(out);       // [OBJ-1] 37.5%
          else if (pick < 5) { mutate_semantically(out); mutate_zk_proof_aggressive(out); }          // [orig]  25%
          else if (pick < 7) mutate_zk_proof(out);              // [OBJ-2] 25%
          break;  // pick==7: sin mutación primaria (12.5%)
        }
        case 1: mutate_serialization_header(out); break;        // [OBJ-1] forzado
        case 2: mutate_zk_proof(out); break;                    // [OBJ-2] forzado
        default: { if (cfg_.enable_semantic) { mutate_semantically(out); mutate_zk_proof_aggressive(out); } break; }  // legacy
      }
      // Mutaciones aditivas (pueden apilarse)
      if (cfg_.forced_mode == 1) force_paillier_degenerate(out);
      if (cfg_.forced_mode == 2) force_share_null(out);
    }
    // Reorden: retiene un mensaje y lo intercala después (ataque de estado).
    if (cfg_.enabled && cfg_.enable_reorder && self_ == 1 && rcv == 0 && next_bool()) {
      if (delayed_.empty()) { delayed_.push_back(std::move(out)); return SUCCESS; }
      std::lock_guard<std::mutex> lk(c->m);
      c->q.emplace_back(std::move(out));
      c->q.emplace_back(std::move(delayed_.front())); delayed_.pop_front();
      c->cv.notify_all();
      return SUCCESS;
    }
    { std::lock_guard<std::mutex> lk(c->m); c->q.emplace_back(std::move(out)); }
    c->cv.notify_one();
    return SUCCESS;
  }
  error_t receive(coinbase::api::party_idx_t snd, buf_t& msg) override {
    if (!net_ || snd < 0 || snd >= net_->n || snd == self_) return E_BADARG;
    flush_delayed();
    auto c = net_->ch[snd][self_]; if (!c) return E_GENERAL;
    std::unique_lock<std::mutex> lk(c->m);
    c->cv.wait_for(lk, kRecvTimeout, [&] { return !c->q.empty() || net_->aborted.load(); });
    if (c->q.empty()) return E_GENERAL;
    msg = std::move(c->q.front()); c->q.pop_front();
    return SUCCESS;
  }
  error_t receive_all(const std::vector<coinbase::api::party_idx_t>& s, std::vector<buf_t>& m) override {
    m.clear(); m.resize(s.size());
    for (size_t i = 0; i < s.size(); ++i) if (error_t rv = receive(s[i], m[i])) return rv;
    return SUCCESS;
  }

 private:
  struct cand_t { size_t off = 0, len = 0; uint32_t score = 0; };

  static uint32_t score_bigintish(const uint8_t* p, size_t n) {
    if (!p || n == 0) return 0;
    size_t zeros = 0, same = 0; uint8_t first = p[0], last = p[n - 1], seen[16] = {0}; size_t uniq = 0;
    for (size_t i = 0; i < n; ++i) {
      if (p[i] == 0) ++zeros; if (p[i] == first) ++same;
      uint8_t b = p[i] & 0x0F; if (!seen[b]) { seen[b] = 1; ++uniq; }
    }
    if (zeros == n || same == n) return 0;
    uint32_t s = 1; if (last != 0) s += 2; if (zeros < n) s += 2; s += (uint32_t)uniq;
    return s;
  }
  static void write_be_small(uint8_t* p, size_t n, uint32_t x) {
    if (!p || n == 0) return;
    std::memset(p, 0, n);
    for (size_t i = 0; i < 4 && i < n; ++i) p[n - 1 - i] = (uint8_t)((x >> (8 * i)) & 0xFF);
  }
  std::vector<cand_t> find_candidates(const buf_t& b) {
    std::vector<cand_t> cs; const size_t sz = b.size(); if (sz < 32) return cs;
    constexpr size_t lens[] = {32, 64, 128, 256};
    for (size_t len : lens) {
      if (sz < len) continue;
      const size_t stride = (len >= 128) ? 8 : 4;
      for (size_t off = 0; off + len <= sz; off += stride)
        if (uint32_t sc = score_bigintish(b.data() + off, len); sc >= 6) cs.push_back({off, len, sc});
    }
    if (cs.empty()) for (size_t len : lens) if (sz >= len) cs.push_back({0, len, 1});
    return cs;
  }
  cand_t pick(const buf_t& b, size_t min_len) {
    auto cs = find_candidates(b);
    cs.erase(std::remove_if(cs.begin(), cs.end(), [&](const cand_t& c) { return c.len < min_len; }), cs.end());
    if (cs.empty()) return {};
    std::sort(cs.begin(), cs.end(), [](const cand_t& a, const cand_t& b2) { return a.score > b2.score; });
    return cs[next_u32() % std::min<size_t>(cs.size(), 8)];
  }

  // --- Original semantic mutation ---
  void mutate_semantically(buf_t& b) {
    if (b.size() < 8 || !next_bool()) return;
    auto cs = find_candidates(b); if (cs.empty()) return;
    std::sort(cs.begin(), cs.end(), [](const cand_t& a, const cand_t& b2) { return a.score > b2.score; });
    const cand_t c = cs[next_u32() % std::min<size_t>(8, cs.size())];
    uint8_t* p = b.data() + c.off; const size_t n = c.len;
    switch (next_u32() % 5) {
      case 0: std::memset(p, 0, n); break;
      case 1: write_be_small(p, n, next_u32() % 16); break;
      case 2: for (size_t i = 0; i < n / 2; ++i) std::swap(p[i], p[n - 1 - i]); break;
      case 3: { size_t o = next_u32() % n, ml = std::min<size_t>(64, n - o), l = 1 + (next_u32() % ml);
                for (size_t i = 0; i < l; ++i) p[o + i] = (uint8_t)~p[o + i]; } break;
      case 4: { size_t o = next_u32() % n, ml = std::min<size_t>(64, n - o), l = 1 + (next_u32() % ml);
                std::memset(p + o, 0, l); } break;
    }
  }

  // ========================================================================
  // [OBJ-2-aggressive] Mutación ZK agresiva: zero-fill de challenges/responses
  // y puntos de curva comprimidos, más negación modular (mod n) del último
  // escalar de 32B. Ataca verificadores ZK (uc_dl_t, dh_t, pdl, ...).
  // ========================================================================
  void mutate_zk_proof_aggressive(buf_t& b) {
    const size_t sz = (size_t)b.size();
    if (sz < 64) return;
    uint8_t* data = b.data();
    std::vector<size_t> point33_offsets;
    std::vector<size_t> scalar32_offsets;

    if (point33_offsets.empty()) {
      for (size_t i = 0; i + 33 <= sz; ++i) {
        if (data[i] == 0x02 || data[i] == 0x03) {
          point33_offsets.push_back(i);
        }
      }
    }

    if (scalar32_offsets.empty()) {
      for (size_t i = 0; i + 32 <= sz; i += 32) {
        scalar32_offsets.push_back(i);
      }
    }

    if (!scalar32_offsets.empty()) {
      std::memset(data + scalar32_offsets[0], 0x00, 32);
    }

    if (scalar32_offsets.size() >= 2) {
      std::memset(data + scalar32_offsets[1], 0x00, 32);
    } else if (!scalar32_offsets.empty()) {
      size_t off = scalar32_offsets[0];
      if (off + 32 + 32 <= sz) {
        std::memset(data + off + 32, 0x00, 32);
      }
    }

    for (size_t k = 0; k < point33_offsets.size() && k < 2; ++k) {
      std::memset(data + point33_offsets[k], 0x00, 33);
    }

    if (!scalar32_offsets.empty()) {
      const size_t off = scalar32_offsets.back();
      uint8_t e[32];
      uint8_t t[32];
      uint8_t inv[32];
      std::memcpy(e, data + off, 32);
      std::memcpy(t, e, 32);
      if (be_cmp_32(t, kSecp256k1Order) >= 0) {
        uint8_t reduced[32];
        be_sub_32(reduced, t, kSecp256k1Order);
        std::memcpy(t, reduced, 32);
      }
      if (is_zero_32(t)) {
        std::memset(inv, 0x00, 32);
      } else {
        be_sub_32(inv, kSecp256k1Order, t);
      }
      std::memcpy(data + off, inv, 32);
    }
  }

  // ========================================================================
  // [OBJ-1] Mutación de cabecera de serialización (convert_len + code_type)
  // Ataca la capa de deserialización recién endurecida (MAX_CONVERT_LEN).
  // ========================================================================
  void mutate_serialization_header(buf_t& b) {
    if (b.size() < 12) return;
    switch (next_byte() % 7) {
      case 0: {  // Código de tipo inválido: 8 bytes aleatorios en offset 0
        for (int i = 0; i < 8 && i < (int)b.size(); ++i) b[i] = next_byte();
        break;
      }
      case 1: {  // convert_len = MAX_CONVERT_LEN exacto (4-byte encoding)
        // MAX=0x04000000: byte0 = 0x04|0xE0=0xE4, bytes 1-3 = 0x00
        if (b.size() >= 12) { b[8]=0xE4; b[9]=0x00; b[10]=0x00; b[11]=0x00; }
        break;
      }
      case 2: {  // convert_len = MAX_CONVERT_LEN + 1 (debe rechazarse)
        if (b.size() >= 12) { b[8]=0xE4; b[9]=0x00; b[10]=0x00; b[11]=0x01; }
        break;
      }
      case 3: {  // convert_len = 0 (campo vacío → potencial null-deref)
        if (b.size() >= 9) b[8] = 0x00;
        break;
      }
      case 4: {  // Máximo 4-byte convert_len (0x1FFFFFFF >> MAX, debe rechazarse)
        if (b.size() >= 12) { b[8]=0xFF; b[9]=0xFF; b[10]=0xFF; b[11]=0xFF; }
        break;
      }
      case 5: {  // 2-byte encoding en posición inesperada (confundir parser)
        size_t off = 8 + (next_byte() % std::min<size_t>(8, b.size() - 8));
        if (off < (size_t)b.size()) b[off] = 0x80 | (next_byte() & 0x3F);
        break;
      }
      case 6: {  // convert_len válido pero gigante: just under MAX
        // 0x03FFFFFF = MAX-1 → 0xE3, 0xFF, 0xFF, 0xFF
        if (b.size() >= 12) { b[8]=0xE3; b[9]=0xFF; b[10]=0xFF; b[11]=0xFF; }
        break;
      }
    }
  }

  // ========================================================================
  // [OBJ-2] Inyección semántica de pruebas ZK falsas
  // Ataca los verificadores ZK (uc_dl_t, dh_t, valid_paillier_t, pdl_t).
  // Un bug aquí es $50K–$1M (BitForge-class).
  // ========================================================================
  void mutate_zk_proof(buf_t& b) {
    if (b.size() < 64) return;
    auto cs = find_candidates(b); if (cs.empty()) return;
    std::sort(cs.begin(), cs.end(), [](const cand_t& a, const cand_t& b2) { return a.score > b2.score; });
    const cand_t c = cs[next_u32() % std::min<size_t>(4, cs.size())];
    uint8_t* p = b.data() + c.off; const size_t n = c.len;

    switch (next_u32() % 9) {
      case 0:  // Challenge e = 0 (trivializa ecuación z*G = R + e*Q → z*G = R)
        if (n >= 32) std::memset(p, 0, std::min<size_t>(32, n));
        break;
      case 1:  // Challenge e = 1 (simplifica: z*G = R + Q)
        if (n >= 32) { std::memset(p, 0, std::min<size_t>(32, n)); p[std::min<size_t>(31, n-1)] = 1; }
        break;
      case 2:  // Response z = 0
        { cand_t c2 = pick(b, 32);
          if (c2.len >= 32) std::memset(b.data() + c2.off, 0, std::min<size_t>(32, c2.len));
        } break;
      case 3:  // Response z = curve order (fuera de rango, overflow en mod)
        { cand_t c2 = pick(b, 32);
          if (c2.len >= 32) std::memcpy(b.data() + c2.off, kSecp256k1Order, 32);
        } break;
      case 4:  // Response z = order - 1 (edge case, máximo valor válido)
        { cand_t c2 = pick(b, 32);
          if (c2.len >= 32) {
            std::memcpy(b.data() + c2.off, kSecp256k1Order, 32);
            b.data()[c2.off + 31] -= 1;
          }
        } break;
      case 5:  // Negar campo: NOT bitwise (≈ negación modular aproximada)
        if (n >= 32) { for (size_t i = 0; i < std::min<size_t>(32, n); ++i) p[i] = ~p[i]; }
        break;
      case 6: {  // Identity point: SEC1 infinity (0x00 × 33 bytes)
        // Buscar un byte 0x02/0x03 (compressed point marker)
        size_t poff = find_point_offset(b);
        if (poff + 33 <= (size_t)b.size()) std::memset(b.data() + poff, 0, 33);
        break;
      }
      case 7: {  // Swap dos campos candidatos (confundir challenge/response)
        if (cs.size() >= 2 && cs[0].len == cs[1].len && cs[0].len <= 256) {
          size_t l = cs[0].len;
          std::vector<uint8_t> tmp(l);
          std::memcpy(tmp.data(), b.data() + cs[0].off, l);
          std::memmove(b.data() + cs[0].off, b.data() + cs[1].off, l);
          std::memcpy(b.data() + cs[1].off, tmp.data(), l);
        }
        break;
      }
      case 8: {  // Response z = 2 (constante chica → prueba trivialmente inválida,
                 // pero si pasa hay un bug serio de verificación)
        cand_t c2 = pick(b, 32);
        if (c2.len >= 32) write_be_small(b.data() + c2.off, std::min<size_t>(32, c2.len), 2);
        break;
      }
    }
  }

  // Helper: busca un byte 0x02 o 0x03 (SEC1 compressed point marker)
  size_t find_point_offset(const buf_t& b) {
    for (size_t i = 8; i + 33 <= (size_t)b.size(); i += 4) {
      if (b[i] == 0x02 || b[i] == 0x03) return i;
    }
    return std::min<size_t>(8, b.size() > 33 ? (size_t)(b.size()) - 33 : 0);
  }

  void force_paillier_degenerate(buf_t& b) { cand_t c = pick(b, 128); if (c.len) write_be_small(b.data() + c.off, c.len, 1); }
  void force_share_null(buf_t& b) { cand_t c = pick(b, 32); if (c.len) std::memset(b.data() + c.off, 0, std::min<size_t>(32, c.len)); }
  void flush_delayed() {
    if (self_ != 1 || delayed_.empty() || !net_) return;
    auto c = net_->ch[1][0]; if (!c) return;
    { std::lock_guard<std::mutex> lk(c->m);
      while (!delayed_.empty()) { c->q.emplace_back(std::move(delayed_.front())); delayed_.pop_front(); } }
    c->cv.notify_all();
  }
  uint8_t next_byte() {
    if (eidx_ < cfg_.entropy.size()) return cfg_.entropy[eidx_++];
    fb_ = fb_ * 1664525u + 1013904223u; return (uint8_t)((fb_ >> 16) & 0xFF);
  }
  uint32_t next_u32() { uint32_t x = 0; for (int i = 0; i < 4; ++i) x = (x << 8) | next_byte(); return x; }
  bool next_bool() { return (next_byte() & 1u) != 0; }

  int self_; std::shared_ptr<network_t> net_; mut_cfg_t cfg_;
  std::deque<buf_t> delayed_; size_t eidx_ = 0; uint32_t fb_ = 0xC0FEBABEu;
};

// ============================================================================
// Ejecuta un paso 2P en dos hilos.
// ============================================================================
template <typename F1, typename F2>
static void run_2pc(const std::shared_ptr<network_t>& net, F1&& f1, F2&& f2, error_t& rv1, error_t& rv2) {
  net->reset_abort();
  rv1 = E_GENERAL; rv2 = E_GENERAL;
  std::thread t1([&] { rv1 = f1(); if (rv1 != SUCCESS) net->abort_all(); });
  std::thread t2([&] { rv2 = f2(); if (rv2 != SUCCESS) net->abort_all(); });
  t1.join(); t2.join();
}

// ============================================================================
// [OBJ-4] Ejecuta un paso 3P en tres hilos (Multi-Party).
// ============================================================================
#ifdef FUZZ_ECDSA_MP
template <typename F1, typename F2, typename F3>
static void run_3pc(const std::shared_ptr<network_t>& net, F1&& f1, F2&& f2, F3&& f3,
                    error_t& rv1, error_t& rv2, error_t& rv3) {
  net->reset_abort();
  rv1 = rv2 = rv3 = E_GENERAL;
  std::thread t1([&] { rv1 = f1(); if (rv1 != SUCCESS) net->abort_all(); });
  std::thread t2([&] { rv2 = f2(); if (rv2 != SUCCESS) net->abort_all(); });
  std::thread t3([&] { rv3 = f3(); if (rv3 != SUCCESS) net->abort_all(); });
  t1.join(); t2.join(); t3.join();
}
#endif

// ============================================================================
// Estado global: clave de referencia (DKG LIMPIO una sola vez, persistida).
// ============================================================================
static buf_t g_key1, g_key2, g_pub;

// GLOBAL, no local a LLVMFuzzerTestOneInput. Estaba declarado dentro de la funcion,
// asi que el mapa nacia VACIO y moria en CADA ejecucion: solo podia detectar reuso de
// nonce entre las <=8 firmas de un mismo input, nunca a lo largo de la campana (millones
// de ejecuciones). El reuso de nonce en ECDSA permite EXTRAER la clave privada — es el
// oraculo de mas valor del harness y estaba castrado. El harness hermano de Schnorr ya
// lo tenia global ("global entre inputs"): el patron correcto existia y no se aplico aca.
// Lleva mutex y tope de memoria porque ahora vive toda la campana.
static nonce_oracle_t g_nonce;
static bool g_ready = false;

#ifdef FUZZ_ECDSA_MP
static buf_t g_mp_key[3];   // [OBJ-4] keys para P0, P1, P2
static buf_t g_mp_pub;
static bool g_mp_ready = false;
#endif

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
  if (load_buf("cbmpc_key1.bin", g_key1) && load_buf("cbmpc_key2.bin", g_key2) &&
      e2::get_public_key_compressed(g_key1, g_pub) == SUCCESS)
    return true;
  auto net = std::make_shared<network_t>(2);
  mut_cfg_t off;
  honest_transport_t t1(0, net, nullptr, nullptr);
  malicious_transport_t t2(1, net, off);
  constexpr std::string_view p1 = "P1", p2 = "P2";
  coinbase::api::job_2p_t j1{coinbase::api::party_2p_t::p1, p1, p2, t1};
  coinbase::api::job_2p_t j2{coinbase::api::party_2p_t::p2, p1, p2, t2};
  error_t r1, r2;
  run_2pc(net, [&] { return e2::dkg(j1, kCurve, g_key1); }, [&] { return e2::dkg(j2, kCurve, g_key2); }, r1, r2);
  if (r1 != SUCCESS || r2 != SUCCESS) {
    std::fprintf(stderr, "bootstrap DKG fallo rv1=%x rv2=%x\n", (unsigned)r1, (unsigned)r2);
    return false;
  }
  if (e2::get_public_key_compressed(g_key1, g_pub) != SUCCESS) return false;
  save_buf("cbmpc_key1.bin", g_key1);
  save_buf("cbmpc_key2.bin", g_key2);
  return true;
}

// ============================================================================
// [OBJ-4] Bootstrap Multi-Party (3 partes, DKG additive limpio)
// ============================================================================
#ifdef FUZZ_ECDSA_MP
static bool bootstrap_mp() {
  if (load_buf("cbmpc_mp_key0.bin", g_mp_key[0]) &&
      load_buf("cbmpc_mp_key1.bin", g_mp_key[1]) &&
      load_buf("cbmpc_mp_key2.bin", g_mp_key[2]) &&
      emp::get_public_key_compressed(g_mp_key[0], g_mp_pub) == SUCCESS)
    return true;

  auto net = std::make_shared<network_t>(3);
  honest_transport_t t0(0, net, nullptr, nullptr);
  honest_transport_t t1(1, net, nullptr, nullptr);
  honest_transport_t t2(2, net, nullptr, nullptr);

  static constexpr std::string_view names[] = {"P0", "P1", "P2"};
  std::vector<std::string_view> pnames(names, names + 3);

  coinbase::api::job_mp_t j0{0, pnames, t0};
  coinbase::api::job_mp_t j1{1, pnames, t1};
  coinbase::api::job_mp_t j2{2, pnames, t2};

  buf_t sid0, sid1, sid2;
  error_t r0, r1, r2;
  run_3pc(net,
    [&] { return emp::dkg_additive(j0, kCurve, g_mp_key[0], sid0); },
    [&] { return emp::dkg_additive(j1, kCurve, g_mp_key[1], sid1); },
    [&] { return emp::dkg_additive(j2, kCurve, g_mp_key[2], sid2); },
    r0, r1, r2);

  if (r0 != SUCCESS || r1 != SUCCESS || r2 != SUCCESS) {
    std::fprintf(stderr, "bootstrap_mp DKG fallo r0=%x r1=%x r2=%x\n",
                 (unsigned)r0, (unsigned)r1, (unsigned)r2);
    return false;
  }
  if (emp::get_public_key_compressed(g_mp_key[0], g_mp_pub) != SUCCESS) return false;

  save_buf("cbmpc_mp_key0.bin", g_mp_key[0]);
  save_buf("cbmpc_mp_key1.bin", g_mp_key[1]);
  save_buf("cbmpc_mp_key2.bin", g_mp_key[2]);
  return true;
}
#endif

}  // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  fuzzrng::install();
  g_ready = bootstrap();
  if (!g_ready) { std::fprintf(stderr, "bootstrap() failed\n"); std::abort(); }
#ifdef FUZZ_ECDSA_MP
  g_mp_ready = bootstrap_mp();
  if (!g_mp_ready) std::fprintf(stderr, "bootstrap_mp() failed, MP ops disabled\n");
#endif
  return 0;
}

// ============================================================================
// Cuerpo: sign/refresh ATACADOS contra la clave cacheada.
// Ops: 0=sign_2p, 1=refresh_2p, 2=sign_mp [OBJ-4], 3=refresh_mp [OBJ-4]
// ============================================================================
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  if (!g_ready || Size < 4) return 0;
  fuzzrng::seed(Data, Size);
  FuzzedDataProvider fdp(Data, Size);

  // --- config de mutación (deriva del input) ---
  const uint8_t flags = fdp.ConsumeIntegral<uint8_t>();
  mut_cfg_t cfg;
  cfg.enabled = true;
  cfg.enable_semantic = (flags & 0x01u);
  cfg.enable_reorder = (flags & 0x02u);
  if (flags & 0x08u) cfg.forced_mode = 1;
  if (flags & 0x10u) cfg.forced_mode = 2;
  cfg.attack_focus = (flags >> 5) & 0x03u;  // [OBJ-1/2] bits 5-6

  const int num_ops = fdp.ConsumeIntegralInRange<int>(1, 8);
  std::vector<uint8_t> ops(num_ops);
#ifdef FUZZ_ECDSA_MP
  for (auto& o : ops) o = fdp.ConsumeIntegralInRange<uint8_t>(0, 3);
#else
  for (auto& o : ops) o = fdp.ConsumeIntegralInRange<uint8_t>(0, 1);
#endif

  std::vector<std::array<uint8_t, 32>> hashes;
  for (uint8_t o : ops) if (o == 0
#ifdef FUZZ_ECDSA_MP
      || o == 2
#endif
  ) {
    std::array<uint8_t, 32> h{};
    auto v = fdp.ConsumeBytes<uint8_t>(32);
    for (size_t i = 0; i < v.size() && i < 32; ++i) h[i] = v[i];
    hashes.push_back(h);
  }

  cfg.entropy = fdp.ConsumeRemainingBytes<uint8_t>();

  auto net = std::make_shared<network_t>(2);
  std::vector<buf_t> transcript; std::mutex trmtx;
  honest_transport_t t_h(0, net, &transcript, &trmtx);
  malicious_transport_t t_m(1, net, cfg);
  constexpr std::string_view p1 = "P1", p2 = "P2";
  coinbase::api::job_2p_t j1{coinbase::api::party_2p_t::p1, p1, p2, t_h};
  coinbase::api::job_2p_t j2{coinbase::api::party_2p_t::p2, p1, p2, t_m};

  size_t hcur = 0;

  for (uint8_t op : ops) {
    if (op == 0) {  // ---------- SIGN 2P atacado ----------
      if (hcur >= hashes.size()) break;
      const std::array<uint8_t, 32>& h = hashes[hcur++];
      buf_t mh((int)32); for (int i = 0; i < 32; ++i) mh[i] = h[i];
      { std::lock_guard<std::mutex> lk(trmtx); transcript.clear(); }
      buf_t sid1, sid2, sig1, sig2; error_t r1, r2;
      run_2pc(net, [&] { return e2::sign(j1, g_key1, mh, sid1, sig1); },
              [&] { return e2::sign(j2, g_key2, mh, sid2, sig2); }, r1, r2);
      if (r1 == SUCCESS && sig1.size() > 0) {
        mem_t hv{mh.data(), mh.size()};
        if (sig_r_is_zero(sig1)) {
          std::fprintf(stderr, "CRITICAL [R-ZERO] 2P: SUCCESS con firma degenerada r=0\n");
          std::abort();
        }
        if (!ossl_verify(hv, g_pub, sig1)) {
          std::fprintf(stderr, "CRITICAL [SIGN-BREAK] P1 SUCCESS con firma que NO verifica bajo la clave real\n");
          std::abort();
        }
        std::array<uint8_t, 32> r{};
        if (extract_r32(sig1, r)) g_nonce.check_and_record(r, h);
        // [OBJ-3] Check high-s (BIP-62 malleability, Medium tier)
        if (extract_s_is_high(sig1)) {
          std::fprintf(stderr, "MEDIUM [HIGH-S] firma con s > order/2 (malleable, BIP-62)\n");
          // No abort: seguimos fuzzeando, pero logueamos para reporte
        }
        leak_oracle(g_key1, transcript, trmtx);
      }
    } else if (op == 1) {  // ---------- REFRESH 2P atacado ----------
      { std::lock_guard<std::mutex> lk(trmtx); transcript.clear(); }
      buf_t nk1, nk2; error_t r1, r2;
      run_2pc(net, [&] { return e2::refresh(j1, g_key1, nk1); },
              [&] { return e2::refresh(j2, g_key2, nk2); }, r1, r2);
      if (r1 == SUCCESS && nk1.size() > 0) {
        buf_t np;
        if (e2::get_public_key_compressed(nk1, np) == SUCCESS) {
          if (!(np == g_pub)) {
            std::fprintf(stderr, "CRITICAL [REFRESH-BREAK] refresh atacado cambió la clave pública de P1\n");
            std::abort();
          }
          leak_oracle(nk1, transcript, trmtx);
        }
      }
    }
    // ==================================================================
    // [OBJ-4] Multi-Party ops (solo si FUZZ_ECDSA_MP y bootstrap OK)
    // ==================================================================
#ifdef FUZZ_ECDSA_MP
    else if (op == 2 && g_mp_ready) {  // ---------- SIGN MP atacado ----------
      if (hcur >= hashes.size()) break;
      const std::array<uint8_t, 32>& h = hashes[hcur++];
      buf_t mh((int)32); for (int i = 0; i < 32; ++i) mh[i] = h[i];
      { std::lock_guard<std::mutex> lk(trmtx); transcript.clear(); }

      auto mp_net = std::make_shared<network_t>(3);
      honest_transport_t mp_t0(0, mp_net, &transcript, &trmtx);
      malicious_transport_t mp_t1(1, mp_net, cfg);  // P1 muta → P0
      honest_transport_t mp_t2(2, mp_net, nullptr, nullptr);

      static constexpr std::string_view mpn[] = {"P0", "P1", "P2"};
      std::vector<std::string_view> pnames(mpn, mpn + 3);
      coinbase::api::job_mp_t mj0{0, pnames, mp_t0};
      coinbase::api::job_mp_t mj1{1, pnames, mp_t1};
      coinbase::api::job_mp_t mj2{2, pnames, mp_t2};

      buf_t msig0, msig1, msig2;
      error_t mr0, mr1, mr2;
      run_3pc(mp_net,
        [&] { return emp::sign_additive(mj0, g_mp_key[0], mh, 0, msig0); },
        [&] { return emp::sign_additive(mj1, g_mp_key[1], mh, 0, msig1); },
        [&] { return emp::sign_additive(mj2, g_mp_key[2], mh, 0, msig2); },
        mr0, mr1, mr2);

      // Oráculo: P0 SUCCESS + firma → DEBE verificar bajo g_mp_pub
      if (mr0 == SUCCESS && msig0.size() > 0) {
        mem_t hv{mh.data(), mh.size()};
        if (sig_r_is_zero(msig0)) {
          std::fprintf(stderr, "CRITICAL [R-ZERO] MP: SUCCESS con firma degenerada r=0\n");
          std::abort();
        }
        if (!ossl_verify(hv, g_mp_pub, msig0)) {
          std::fprintf(stderr, "CRITICAL [MP-SIGN-BREAK] firma MP no verifica bajo clave real\n");
          std::abort();
        }
        std::array<uint8_t, 32> r{};
        if (extract_r32(msig0, r)) g_nonce.check_and_record(r, h);
        if (extract_s_is_high(msig0)) {
          std::fprintf(stderr, "MEDIUM [MP-HIGH-S] firma MP con s > order/2\n");
        }
        leak_oracle(g_mp_key[0], transcript, trmtx);
      }
    } else if (op == 3 && g_mp_ready) {  // ---------- REFRESH MP atacado ----------
      { std::lock_guard<std::mutex> lk(trmtx); transcript.clear(); }

      auto mp_net = std::make_shared<network_t>(3);
      honest_transport_t mp_t0(0, mp_net, &transcript, &trmtx);
      malicious_transport_t mp_t1(1, mp_net, cfg);
      honest_transport_t mp_t2(2, mp_net, nullptr, nullptr);

      static constexpr std::string_view mpn[] = {"P0", "P1", "P2"};
      std::vector<std::string_view> pnames(mpn, mpn + 3);
      coinbase::api::job_mp_t mj0{0, pnames, mp_t0};
      coinbase::api::job_mp_t mj1{1, pnames, mp_t1};
      coinbase::api::job_mp_t mj2{2, pnames, mp_t2};

      buf_t sid0, sid1, sid2;
      buf_t nk0, nk1, nk2;
      error_t mr0, mr1, mr2;
      run_3pc(mp_net,
        [&] { return emp::refresh_additive(mj0, sid0, g_mp_key[0], nk0); },
        [&] { return emp::refresh_additive(mj1, sid1, g_mp_key[1], nk1); },
        [&] { return emp::refresh_additive(mj2, sid2, g_mp_key[2], nk2); },
        mr0, mr1, mr2);

      if (mr0 == SUCCESS && nk0.size() > 0) {
        buf_t np;
        if (emp::get_public_key_compressed(nk0, np) == SUCCESS) {
          if (!(np == g_mp_pub)) {
            std::fprintf(stderr, "CRITICAL [MP-REFRESH-BREAK] refresh MP cambió la clave pública\n");
            std::abort();
          }
          leak_oracle(nk0, transcript, trmtx);
        }
      }
    }
#endif  // FUZZ_ECDSA_MP
  }
  return 0;
}

// ============================================================================
// Structure-Aware Custom Mutator for cb-mpc converter_t serialized inputs.
// ----------------------------------------------------------------------------
// Walks the input as a converter_t stream: keeps the first 8 bytes (uint64_t
// type-code, i.e. convert_code_type) and every convert_len prefix untouched,
// and injects semantically poisonous values into payload fields (zero
// scalars, all-0xff, secp256k1 order/prime, invalid compressed points, etc.).
// The total size and all length prefixes are preserved so the library's
// converter_t parser accepts the message and advances into the deep
// cryptographic logic instead of bailing out with "Converter error".
// ============================================================================
namespace {

// Max value encodable by the 4-byte branch of converter_t::convert_len().
// (kMaxConvertLen = 64 MiB, the library's rejection threshold, and
// kSecp256k1Order are already defined earlier in this TU and are reused here
// to avoid duplicate definitions in the merged anonymous namespace.)
constexpr uint32_t kConvertLenMaxEncoding = 0x1FFFFFFF;

struct Field {
  size_t prefix_off;   // start of convert_len prefix in Data
  int prefix_len;      // 1..4
  uint32_t len;        // payload length
  size_t payload_off;  // start of payload in Data
};

// Decode the cb-mpc variable-length prefix used by converter_t::convert_len().
// Format (big-endian length stored in the trailing bytes):
//   0xxxxxxx               -> 1 byte,  len <= 0x7f
//   10xxxxxx + byte        -> 2 bytes, len <= 0x3fff
//   110xxxxx + 2 bytes     -> 3 bytes, len <= 0x1fffff
//   1110xxxx + 3 bytes     -> 4 bytes, len <= 0x1fffffff
// Returns false if the prefix is incomplete or invalid.
bool ReadConvertLen(const uint8_t* data, size_t size, size_t off,
                    uint32_t& out_len, int& out_prefix_len) {
  if (off >= size) return false;
  const uint8_t b = data[off];
  if ((b & 0x80) == 0) {
    out_len = b;
    out_prefix_len = 1;
    return out_len <= kConvertLenMaxEncoding;
  }
  if ((b & 0x40) == 0) {
    if (off + 2 > size) return false;
    out_len = (static_cast<uint32_t>(b & 0x3f) << 8) | data[off + 1];
    out_prefix_len = 2;
    return out_len <= kConvertLenMaxEncoding;
  }
  if ((b & 0x20) == 0) {
    if (off + 3 > size) return false;
    out_len = (static_cast<uint32_t>(b & 0x1f) << 16) |
              (static_cast<uint32_t>(data[off + 1]) << 8) |
              static_cast<uint32_t>(data[off + 2]);
    out_prefix_len = 3;
    return out_len <= kConvertLenMaxEncoding;
  }
  if (off + 4 > size) return false;
  out_len = (static_cast<uint32_t>(b & 0x1f) << 24) |
            (static_cast<uint32_t>(data[off + 1]) << 16) |
            (static_cast<uint32_t>(data[off + 2]) << 8) |
            static_cast<uint32_t>(data[off + 3]);
  out_prefix_len = 4;
  return out_len <= kConvertLenMaxEncoding;
}

// secp256k1 field prime p (big-endian, 32 bytes).
static const uint8_t kSecp256k1P[32] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f};

enum PoisonAction {
  POISON_ZERO_FILL = 0,
  POISON_ALL_FF,
  POISON_SECP256K1_ORDER,
  POISON_SECP256K1_P,
  POISON_COMPRESSED_INVALID,
  POISON_ONE,
  POISON_FLIP_HIGH_BIT,
  POISON_COUNT
};

// Overwrite a field's payload with a semantically poisonous pattern.
// The convert_len prefix is left untouched, so it remains valid.
void InjectPoison(uint8_t* Data, const Field& f, int action) {
  if (f.len == 0) return;
  uint8_t* p = Data + f.payload_off;
  switch (action) {
    case POISON_ZERO_FILL:
      std::memset(p, 0x00, f.len);
      break;
    case POISON_ALL_FF:
      std::memset(p, 0xff, f.len);
      break;
    case POISON_SECP256K1_ORDER:
      if (f.len == 32) {
        std::memcpy(p, kSecp256k1Order, 32);
      } else {
        std::memset(p, 0x00, f.len);
        p[f.len - 1] = 0x01;
      }
      break;
    case POISON_SECP256K1_P:
      if (f.len == 32) {
        std::memcpy(p, kSecp256k1P, 32);
      } else {
        std::memset(p, 0xff, f.len);
      }
      break;
    case POISON_COMPRESSED_INVALID:
      // A valid compressed point starts with 0x02/0x03; 0x00 is invalid.
      if (f.len == 33) {
        std::memset(p, 0x00, 33);
      } else {
        std::memset(p, 0x00, f.len);
        if (f.len > 0) p[0] = 0x00;
      }
      break;
    case POISON_ONE:
      std::memset(p, 0x00, f.len);
      p[f.len - 1] = 0x01;
      break;
    case POISON_FLIP_HIGH_BIT:
      for (uint32_t i = 0; i < f.len; ++i) {
        p[i] ^= 0x80;
      }
      break;
    default:
      break;
  }
}

}  // namespace

// Structure-aware custom mutator for cb-mpc converter_t serialized inputs.
//   * Keeps the first 8 bytes (uint64_t type-code) untouched.
//   * Parses every convert_len prefix and never modifies it.
//   * Uses FuzzedDataProvider to pick which fields to poison and how.
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* Data, size_t Size, size_t MaxSize, unsigned int Seed) {
  (void)Seed;
  if (Size < 8 || MaxSize < 8) return Size;
  if (Size > MaxSize) Size = MaxSize;

  // Snapshot used only to drive FuzzedDataProvider decisions.
  // The actual mutation happens in-place on Data.
  std::vector<uint8_t> snapshot(Data, Data + Size);
  FuzzedDataProvider fdp(snapshot.data() + 8, snapshot.size() - 8);

  // Parse fields after the 8-byte type code.
  // Each field is: [convert_len prefix (1..4 bytes)] [payload]
  std::vector<Field> fields;
  size_t off = 8;
  while (off < Size) {
    uint32_t len = 0;
    int prefix_len = 0;
    if (!ReadConvertLen(Data, Size, off, len, prefix_len)) break;
    if (len > kConvertLenMaxEncoding) break;
    if (off + static_cast<size_t>(prefix_len) > Size) break;
    if (off + static_cast<size_t>(prefix_len) + len > Size) break;
    Field f;
    f.prefix_off = off;
    f.prefix_len = prefix_len;
    f.len = len;
    f.payload_off = off + prefix_len;
    fields.push_back(f);
    off += prefix_len + len;
  }

  if (fields.empty()) return Size;

  // Decide how many fields to poison (1..min(3, fields.size())).
  const int max_mutations = static_cast<int>(std::min<size_t>(3, fields.size()));
  const int mutations = fdp.ConsumeIntegralInRange<int>(1, max_mutations);

  for (int i = 0; i < mutations; ++i) {
    const int idx = fdp.ConsumeIntegralInRange<int>(0, static_cast<int>(fields.size()) - 1);
    const int action = fdp.ConsumeIntegralInRange<int>(0, POISON_COUNT - 1);
    InjectPoison(Data, fields[idx], action);
  }

  return Size;
}

// ============================================================================
// CustomCrossOver: combina dos entradas del corpus en frontera de 32B.
// ============================================================================
extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t* D1, size_t S1, const uint8_t* D2, size_t S2,
                                            uint8_t* Out, size_t MaxOut, unsigned int Seed) {
  if (MaxOut == 0) return 0;
  splitmix64_t rng(Seed);
  size_t t1 = std::min(S1, MaxOut);
  if (t1 >= 32) t1 = (size_t)rng.in_range(0, t1 / 32) * 32;
  if (t1 > S1) t1 = S1;
  if (t1 > MaxOut) t1 = MaxOut;
  size_t rem = MaxOut - t1;
  size_t t2 = std::min(S2, rem);
  if (t1) std::memcpy(Out, D1, t1);
  if (t2) std::memcpy(Out + t1, D2, t2);
  return t1 + t2;
}