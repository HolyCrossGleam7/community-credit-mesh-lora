#include "device_keys.h"

#include <LittleFS.h>
#include <Arduino.h>
#include <vector>

#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>

static const char* PRIV_PATH = "/keys/privkey.der";
static const char* PUB_PATH  = "/keys/pubkey.der";

static uint8_t g_fp8[8] = {0};
static uint8_t g_pub65[65] = {0};

static bool sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
  return mbedtls_sha256_ret(data, len, out, 0 /*is224*/) == 0;
}

static bool ensureKeysDir() {
  if (LittleFS.exists("/keys")) return true;
  return LittleFS.mkdir("/keys");
}

static bool readFile(const char* path, std::vector<uint8_t>& out) {
  File f = LittleFS.open(path, "r");
  if (!f) return false;
  out.resize(f.size());
  if (out.size() > 0) {
    size_t n = f.read(out.data(), out.size());
    f.close();
    return n == out.size();
  }
  f.close();
  return true;
}

static bool writeFile(const char* path, const uint8_t* data, size_t len) {
  File f = LittleFS.open(path, "w");
  if (!f) return false;
  size_t n = f.write(data, len);
  f.close();
  return n == len;
}

static bool pkToPub65(mbedtls_pk_context& pk, uint8_t out65[65]) {
  if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECKEY)) return false;
  mbedtls_ecp_keypair* ec = mbedtls_pk_ec(pk);

  // Ensure uncompressed point format: 65 bytes for P-256
  size_t olen = 0;
  int rc = mbedtls_ecp_point_write_binary(&ec->grp, &ec->Q,
                                         MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &olen, out65, 65);
  return (rc == 0 && olen == 65);
}

static void fp8FromPub65(const uint8_t pub65[65]) {
  uint8_t h[32];
  if (!sha256(pub65, 65, h)) {
    memset(g_fp8, 0, sizeof(g_fp8));
    return;
  }
  memcpy(g_fp8, h, 8);
}

static String bytesToHex(const uint8_t* b, size_t n) {
  const char* hex = "0123456789abcdef";
  String out;
  out.reserve(n * 2);
  for (size_t i = 0; i < n; i++) {
    out += hex[(b[i] >> 4) & 0xF];
    out += hex[(b[i] >> 0) & 0xF];
  }
  return out;
}

bool keysInit() {
  if (!LittleFS.begin(true)) return false;
  if (!ensureKeysDir()) return false;

  // Load if exists
  if (LittleFS.exists(PUB_PATH) && LittleFS.exists(PRIV_PATH)) {
    std::vector<uint8_t> pubDer;
    std::vector<uint8_t> privDer;
    if (!readFile(PUB_PATH, pubDer)) return false;
    if (!readFile(PRIV_PATH, privDer)) return false;
    if (pubDer.empty() || privDer.empty()) return false;

    // Parse private key so we can compute pub65 reliably from the actual keypair
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int rc = mbedtls_pk_parse_key(&pk, privDer.data(), privDer.size(), nullptr, 0);
    if (rc != 0) {
      mbedtls_pk_free(&pk);
      return false;
    }

    if (!pkToPub65(pk, g_pub65)) {
      mbedtls_pk_free(&pk);
      return false;
    }
    fp8FromPub65(g_pub65);
    mbedtls_pk_free(&pk);
    return true;
  }

  // Generate new P-256 keypair
  mbedtls_pk_context pk;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_pk_init(&pk);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  const char* pers = "ccm-lora-keygen";
  int rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char*)pers, strlen(pers));
  if (rc != 0) goto fail;

  rc = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
  if (rc != 0) goto fail;

  rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pk),
                           mbedtls_ctr_drbg_random, &ctr_drbg);
  if (rc != 0) goto fail;

  // Export private key (DER)
  uint8_t privBuf[1200];
  memset(privBuf, 0, sizeof(privBuf));
  int privLen = mbedtls_pk_write_key_der(&pk, privBuf, sizeof(privBuf));
  if (privLen <= 0) goto fail;

  // Export public key (DER)
  uint8_t pubBuf[800];
  memset(pubBuf, 0, sizeof(pubBuf));
  int pubLen = mbedtls_pk_write_pubkey_der(&pk, pubBuf, sizeof(pubBuf));
  if (pubLen <= 0) goto fail;

  const uint8_t* privDer = privBuf + (sizeof(privBuf) - privLen);
  const uint8_t* pubDer  = pubBuf  + (sizeof(pubBuf)  - pubLen);

  if (!writeFile(PRIV_PATH, privDer, privLen)) goto fail;
  if (!writeFile(PUB_PATH,  pubDer,  pubLen)) goto fail;

  if (!pkToPub65(pk, g_pub65)) goto fail;
  fp8FromPub65(g_pub65);

  mbedtls_pk_free(&pk);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return true;

fail:
  mbedtls_pk_free(&pk);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return false;
}

const uint8_t* keysFp8() { return g_fp8; }
String keysFp8Hex() { return bytesToHex(g_fp8, 8); }

const uint8_t* keysPub65() { return g_pub65; }
String keysPub65Hex() { return bytesToHex(g_pub65, 65); }

bool keysSignSha256(const uint8_t* msg, size_t msgLen, uint8_t* sigDerOut, size_t sigDerMax, size_t& sigDerLenOut) {
  sigDerLenOut = 0;
  if (!LittleFS.begin(true)) return false;

  std::vector<uint8_t> privDer;
  if (!readFile(PRIV_PATH, privDer)) return false;
  if (privDer.empty()) return false;

  uint8_t h[32];
  if (!sha256(msg, msgLen, h)) return false;

  mbedtls_pk_context pk;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_pk_init(&pk);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  const char* pers = "ccm-lora-sign";
  int rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char*)pers, strlen(pers));
  if (rc != 0) goto fail;

  rc = mbedtls_pk_parse_key(&pk, privDer.data(), privDer.size(), nullptr, 0);
  if (rc != 0) goto fail;

  // mbedtls_pk_sign writes DER signature
  size_t sigLen = 0;
  rc = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, h, 0,
                       sigDerOut, sigDerMax, &sigLen,
                       mbedtls_ctr_drbg_random, &ctr_drbg);
  if (rc != 0) goto fail;

  sigDerLenOut = sigLen;

  mbedtls_pk_free(&pk);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return true;

fail:
  mbedtls_pk_free(&pk);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return false;
}
