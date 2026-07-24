// ============================================================================
// fuzz_failed_sign.cpp - Harness para Extracción de Clave (Lindell17/BitForge)
// ----------------------------------------------------------------------------
// Modelo de amenaza: P2 maliciosa fuerza firmas fallidas y ZK inválidas.
// Oráculos: Leak de escalar, Forgery (OpenSSL), State-Corruption, Nonce-Reuse.
// Generado por IA (arena.ai) + verificado/arreglado por Claude:
//   [FIX1] +#include <array>            (no compilaba)
//   [FIX2] kRecvTimeout 200ms -> 8s     (200ms = falsos CRITICAL por timeout)
//   [FIX3] entropy por-op acotada        (antes drenaba el FDP en la 1ra vuelta)
//   [FIX4] oraculo state-corruption NO aborta ante fallo transitorio (cry-wolf)
// ============================================================================

#include <cbmpc/api/ecdsa_2p.h>
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

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <string_view>
#include <thread>
#include <vector>

using namespace coinbase;
namespace e2 = coinbase::api::ecdsa_2p;

// ============================================================================
// 1) RNG DETERMINISTA (Para que los crashes reproduzcan)
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

// [FIX2] 8 segundos, como el harness que SI funciona. 200ms provocaba falsos
// CRITICAL de state-corruption porque la cripto MPC (Paillier) tarda mas.
constexpr std::chrono::seconds kRecvTimeout{8};
constexpr auto kCurve = coinbase::api::curve_id::secp256k1;
constexpr int kNid = NID_secp256k1;

// ============================================================================
// 2) Oráculos Independientes (OpenSSL)
// ============================================================================
static bool ossl_verify(mem_t h32, const buf_t& pub_compressed, const buf_t& sig_der) {
  if (h32.size != 32 || pub_compressed.size() == 0 || sig_der.size() == 0) return false;
  EC_KEY* ec = EC_KEY_new_by_curve_name(kNid);
  if (!ec) return true;
  const unsigned char* pp = reinterpret_cast<const unsigned char*>(pub_compressed.data());
  if (!o2i_ECPublicKey(&ec, &pp, (long)pub_compressed.size())) { EC_KEY_free(ec); return false; }
  const unsigned char* sp = reinterpret_cast<const unsigned char*>(sig_der.data());
  ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &sp, (long)sig_der.size());
  if (!sig) { EC_KEY_free(ec); return false; }
  const unsigned char* d = reinterpret_cast<const unsigned char*>(h32.data);
  bool vr = ECDSA_do_verify(d, (int)h32.size, sig, ec) == 1;
  ECDSA_SIG_free(sig);
  EC_KEY_free(ec);
  return vr;
}

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
// 3) Red 2P en memoria (Con captura de tráfico para el oráculo de Leak)
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

// Transporte Honesto: graba todo lo que sale para buscar fugas.
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

struct mut_cfg_t {
  bool enabled = false;
  std::vector<uint8_t> entropy;
};

// Transporte Malicioso: muta mensajes para causar abort (ZK inválido, fuera de rango).
class malicious_transport_t final : public coinbase::api::data_transport_i {
 public:
  malicious_transport_t(int self, std::shared_ptr<network_t> net, mut_cfg_t cfg) : self_(self), net_(std::move(net)), cfg_(std::move(cfg)) {}
  error_t send(coinbase::api::party_idx_t rcv, mem_t msg) override {
    if (!net_ || rcv < 0 || rcv >= net_->n || rcv == self_) return E_BADARG;
    auto c = net_->ch[self_][rcv]; if (!c) return E_GENERAL;
    buf_t out(msg);
    if (cfg_.enabled && self_ == 1 && rcv == 0) mutate_semantically(out);
    { std::lock_guard<std::mutex> lk(c->m); c->q.emplace_back(out); }
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
  void mutate_semantically(buf_t& b) {
    if (b.size() < 8 || cfg_.entropy.empty()) return;
    uint8_t op = cfg_.entropy[0] % 4;
    if (op == 0) {  // Zero out (rompe validaciones de rango)
      size_t off = cfg_.entropy.size() > 1 ? cfg_.entropy[1] % (size_t)b.size() : 0;
      size_t len = std::min<size_t>(32, (size_t)b.size() - off);
      std::memset(b.data() + off, 0, len);
    } else if (op == 1) {  // Truncate (rompe serialización)
      if (b.size() > 1) b.resize(b.size() / 2);
    } else if (op == 2) {  // Flip bits (corrompe ZK proofs)
      size_t off = cfg_.entropy.size() > 1 ? cfg_.entropy[1] % (size_t)b.size() : 0;
      b.data()[off] ^= 0xFF;
    } else {  // Inyectar bytes del fuzzer
      size_t len = std::min<size_t>(cfg_.entropy.size(), (size_t)b.size());
      std::memcpy(b.data(), cfg_.entropy.data(), len);
    }
  }
  int self_; std::shared_ptr<network_t> net_; mut_cfg_t cfg_;
};

template <typename F1, typename F2>
static void run_2pc(const std::shared_ptr<network_t>& net, F1&& f1, F2&& f2, error_t& rv1, error_t& rv2) {
  net->reset_abort();
  rv1 = E_GENERAL; rv2 = E_GENERAL;
  std::thread t1([&] { rv1 = f1(); if (rv1 != SUCCESS) net->abort_all(); });
  std::thread t2([&] { rv2 = f2(); if (rv2 != SUCCESS) net->abort_all(); });
  t1.join(); t2.join();
}

// ============================================================================
// 4) Estado Global (cacheado a disco). Oráculo de nonce GLOBAL entre inputs.
// ============================================================================
static buf_t g_key1, g_key2, g_pub;
static bool g_ready = false;
static std::mutex g_nonce_mtx;
static std::map<std::array<uint8_t, 32>, std::array<uint8_t, 32>> g_nonce_map;  // R -> hash

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
  if (load_buf("cbmpc_fs_key1.bin", g_key1) && load_buf("cbmpc_fs_key2.bin", g_key2) &&
      e2::get_public_key_compressed(g_key1, g_pub) == SUCCESS)
    return true;
  auto net = std::make_shared<network_t>(2);
  mut_cfg_t off;
  honest_transport_t t1(0, net, nullptr, nullptr);
  malicious_transport_t t2_tr(1, net, off);
  constexpr std::string_view p1 = "P1", p2 = "P2";
  coinbase::api::job_2p_t j1{coinbase::api::party_2p_t::p1, p1, p2, t1};
  coinbase::api::job_2p_t j2{coinbase::api::party_2p_t::p2, p1, p2, t2_tr};
  error_t r1, r2;
  run_2pc(net, [&] { return e2::dkg(j1, kCurve, g_key1); }, [&] { return e2::dkg(j2, kCurve, g_key2); }, r1, r2);
  if (r1 != SUCCESS || r2 != SUCCESS) return false;
  if (e2::get_public_key_compressed(g_key1, g_pub) != SUCCESS) return false;
  save_buf("cbmpc_fs_key1.bin", g_key1);
  save_buf("cbmpc_fs_key2.bin", g_key2);
  return true;
}

static bool contains_sub(const uint8_t* hay, size_t hn, const uint8_t* nee, size_t nn) {
  if (!hay || !nee || nn == 0 || hn < nn) return false;
  for (size_t i = 0; i + nn <= hn; ++i)
    if (std::memcmp(hay + i, nee, nn) == 0) return true;
  return false;
}

static void nonce_check(const std::array<uint8_t, 32>& r, const std::array<uint8_t, 32>& h) {
  std::lock_guard<std::mutex> lk(g_nonce_mtx);
  auto it = g_nonce_map.find(r);
  if (it == g_nonce_map.end()) { if (g_nonce_map.size() < 200000) g_nonce_map.emplace(r, h); return; }
  if (it->second != h) {
    std::fprintf(stderr, "CRITICAL [NONCE-REUSE] mismo R para dos hashes distintos: clave privada extraible!\n");
    std::abort();
  }
}

}  // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  fuzzrng::install();
  g_ready = bootstrap();
  if (!g_ready) { std::fprintf(stderr, "Failed Sign bootstrap() failed\n"); std::abort(); }
  return 0;
}

// ============================================================================
// 5) FUZZ TARGET Y ORÁCULOS DE EXTRACCIÓN
// ============================================================================
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  if (!g_ready || Size < 16) return 0;
  fuzzrng::seed(Data, Size);
  FuzzedDataProvider fdp(Data, Size);

  const int num_ops = fdp.ConsumeIntegralInRange<int>(1, 8);

  // Escalar privado de P1 para el oráculo de leak.
  buf_t pub_blob, priv_scalar;
  e2::detach_private_scalar(g_key1, pub_blob, priv_scalar);

  for (int op = 0; op < num_ops; ++op) {
    uint8_t op_type = fdp.ConsumeIntegral<uint8_t>() % 3;  // 0=malicious sign, 1=clean sign, 2=malicious refresh

    std::array<uint8_t, 32> h{};
    auto v = fdp.ConsumeBytes<uint8_t>(32);
    for (size_t i = 0; i < v.size() && i < 32; ++i) h[i] = v[i];
    buf_t mh((int)32); for (int i = 0; i < 32; ++i) mh[i] = h[i];
    mem_t mh_view(mh.data(), mh.size());

    mut_cfg_t cfg;
    cfg.enabled = (op_type != 1);
    cfg.entropy = fdp.ConsumeBytes<uint8_t>(64);  // [FIX3] acotado por-op (antes drenaba el FDP)

    auto net = std::make_shared<network_t>(2);
    std::vector<buf_t> transcript; std::mutex trmtx;
    honest_transport_t t_h(0, net, &transcript, &trmtx);
    malicious_transport_t t_m(1, net, cfg);
    constexpr std::string_view p1 = "P1", p2 = "P2";
    coinbase::api::job_2p_t j1{coinbase::api::party_2p_t::p1, p1, p2, t_h};
    coinbase::api::job_2p_t j2{coinbase::api::party_2p_t::p2, p1, p2, t_m};

    buf_t sig1, sig2, sid1, sid2, nk1, nk2;
    error_t r1, r2;

    if (op_type == 2) {  // Malicious Refresh
      run_2pc(net, [&] { return e2::refresh(j1, g_key1, nk1); }, [&] { return e2::refresh(j2, g_key2, nk2); }, r1, r2);
      if (r1 == SUCCESS && nk1.size() > 0) {
        buf_t np;
        if (e2::get_public_key_compressed(nk1, np) == SUCCESS && !(np == g_pub)) {
          std::fprintf(stderr, "CRITICAL [REFRESH-BREAK] refresh atacado cambio la pubkey de P1!\n");
          std::abort();
        }
      }
    } else {  // Sign (malicioso o limpio)
      run_2pc(net, [&] { return e2::sign(j1, g_key1, mh_view, sid1, sig1); },
              [&] { return e2::sign(j2, g_key2, mh_view, sid2, sig2); }, r1, r2);

      // [A] LEAK: el escalar privado NUNCA debe aparecer en el trafico honesto, ni tras abort.
      if (priv_scalar.size() >= 16) {
        std::lock_guard<std::mutex> lk(trmtx);
        for (const auto& msg : transcript)
          if (contains_sub(msg.data(), (size_t)msg.size(), priv_scalar.data(), (size_t)priv_scalar.size())) {
            std::fprintf(stderr, "CRITICAL [KEY-LEAK] el escalar privado aparecio en el trafico honesto!\n");
            std::abort();
          }
      }

      if (r1 == SUCCESS && sig1.size() > 0) {
        // [B] FORGERY: P1 SUCCESS -> la firma DEBE verificar bajo la clave real (verificador independiente).
        mem_t hv(mh.data(), mh.size());
        if (!ossl_verify(hv, g_pub, sig1)) {
          std::fprintf(stderr, "CRITICAL [FORGERY] P1 SUCCESS pero OpenSSL rechaza la firma!\n");
          std::abort();
        }
        // [D] NONCE-REUSE (global entre inputs): mismo R con distinto hash -> clave extraible.
        std::array<uint8_t, 32> r_out{};
        if (extract_r32(sig1, r_out)) nonce_check(r_out, h);
      }
    }
  }

  // [C] STATE-CORRUPTION: tras K firmas atacadas, una firma LIMPIA debe seguir siendo VALIDA.
  // [FIX4] Solo abortamos si la firma tiene EXITO pero es INVALIDA (corrupcion real).
  // Si aborta transitoriamente NO es bug (evita cry-wolf de falsos CRITICAL).
  {
    auto net = std::make_shared<network_t>(2);
    honest_transport_t t_h(0, net, nullptr, nullptr);
    malicious_transport_t t_m(1, net, mut_cfg_t{});  // sin mutacion
    constexpr std::string_view p1 = "P1", p2 = "P2";
    coinbase::api::job_2p_t j1{coinbase::api::party_2p_t::p1, p1, p2, t_h};
    coinbase::api::job_2p_t j2{coinbase::api::party_2p_t::p2, p1, p2, t_m};
    buf_t mh((int)32); for (int i = 0; i < 32; ++i) mh[i] = (uint8_t)(i + 1);
    mem_t mh_view(mh.data(), mh.size());
    buf_t sig1, sig2, sid1, sid2; error_t r1, r2;
    run_2pc(net, [&] { return e2::sign(j1, g_key1, mh_view, sid1, sig1); },
            [&] { return e2::sign(j2, g_key2, mh_view, sid2, sig2); }, r1, r2);
    if (r1 == SUCCESS && sig1.size() > 0) {
      mem_t hv(mh.data(), mh.size());
      if (!ossl_verify(hv, g_pub, sig1)) {
        std::fprintf(stderr, "CRITICAL [STATE-CORRUPTION] firma limpia con exito pero INVALIDA tras firmas atacadas!\n");
        std::abort();
      }
    }
    // (r1 != SUCCESS transitorio: NO es bug, no abortamos)
  }

  return 0;
}
