#include "device_keys.h"

#include <LittleFS.h>
#include <Arduino.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>

static const char* PRIV_PATH = "/keys/privkey.der";
static const char* PUB_PATH  = "/keys/pubkey.der";

static uint8_t g_fp8[8] = {0};

static bool sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
  // mbedtls_sha256_ret exists in ESP32 Arduino builds
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

static void fp8FromPub(const uint8_t* pubDer, size_t pubDerLen) {
  uint8_t h[32];
  if (!sha256(pubDer, pubDerLen, h)) {
    memset(g_fp8, 0, sizeof(g_fp8));
    return;
  }
  memcpy(g_fp8, h, 8);
}

bool keysInit() {
  // trustInit() already calls LittleFS.begin(); but it’s OK if we call begin again.
  if (!LittleFS.begin(true)) return false;
  if (!ensureKeysDir()) return false;

  // If pubkey exists, load and compute fp8
  if (LittleFS.exists(PUB_PATH) && LittleFS.exists(PRIV_PATH)) {
    std::vector<uint8_t> pub;
    if (!readFile(PUB_PATH, pub)) return false;
    if (pub.size() == 0) return false;
    fp8FromPub(pub.data(), pub.size());
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

  // mbedtls writes at end of buffer
  const uint8_t* privDer = privBuf + (sizeof(privBuf) - privLen);
  const uint8_t* pubDer  = pubBuf  + (sizeof(pubBuf)  - pubLen);

  if (!writeFile(PRIV_PATH, privDer, privLen)) goto fail;
  if (!writeFile(PUB_PATH,  pubDer,  pubLen)) goto fail;

  fp8FromPub(pubDer, pubLen);

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

const uint8_t* keysFp8() {
  return g_fp8;
}

String keysFp8Hex() {
  const char* hex = "0123456789abcdef";
  String out;
  out.reserve(16);
  for (int i = 0; i < 8; i++) {
    out += hex[(g_fp8[i] >> 4) & 0xF];
    out += hex[(g_fp8[i] >> 0) & 0xF];
  }
  return out;
}
