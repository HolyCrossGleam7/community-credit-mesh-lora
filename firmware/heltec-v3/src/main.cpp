#include <Arduino.h>
#include <vector>
#include "config.h"
#include "protocol.h"
#include "trust_store.h"
#include "device_keys.h"

// Heltec library
#include "heltec.h"

#include "cold_wallet.cpp"

// Add these helper functions near the top of main.cpp (after includes), before setup():

static bool readU32BE(const std::vector<uint8_t>& b, size_t off, uint32_t& out) {
  if (off + 4 > b.size()) return false;
  out = ((uint32_t)b[off] << 24) | ((uint32_t)b[off + 1] << 16) | ((uint32_t)b[off + 2] << 8) | ((uint32_t)b[off + 3]);
  return true;
}

static bool readI32BE(const std::vector<uint8_t>& b, size_t off, int32_t& out) {
  uint32_t u = 0;
  if (!readU32BE(b, off, u)) return false;
  out = (int32_t)u;
  return true;
}

struct RxTxParsed {
  uint8_t ver;
  uint8_t type;
  uint8_t flags;
  String sender;
  String receiver;
  int32_t amountMinor;
  uint32_t nonce;
  uint8_t fp8[8];
  uint8_t sigLen;
  size_t sigOff;
  uint8_t pubLen;
  uint8_t pub65[65];
};

static bool parseTxPacket(const std::vector<uint8_t>& buf, RxTxParsed& out) {
  // Must have at least header bytes: ver,type,flags,senderLen,receiverLen
  if (buf.size() < 5) return false;

  out.ver = buf[0];
  out.type = buf[1];
  out.flags = buf[2];
  uint8_t senderLen = buf[3];
  uint8_t receiverLen = buf[4];

  if (out.ver != PROTO_VERSION) return false;
  if (out.type != MSG_TX) return false;
  if (senderLen > 20 || receiverLen > 20) return false;

  size_t off = 5;
  if (off + senderLen + receiverLen > buf.size()) return false;

  out.sender = "";
  out.receiver = "";
  for (uint8_t i = 0; i < senderLen; i++) out.sender += (char)buf[off + i];
  off += senderLen;
  for (uint8_t i = 0; i < receiverLen; i++) out.receiver += (char)buf[off + i];
  off += receiverLen;

  // amountMinor (int32) + nonce (uint32) + fp8 (8 bytes) + sigLen (1 byte)
  if (off + 4 + 4 + 8 + 1 > buf.size()) return false;

  if (!readI32BE(buf, off, out.amountMinor)) return false;
  off += 4;

  if (!readU32BE(buf, off, out.nonce)) return false;
  off += 4;

  for (int i = 0; i < 8; i++) out.fp8[i] = buf[off + i];
  off += 8;

  // pubkey length + pubkey bytes
  out.pubLen = buf[off];
  off += 1;
  if (out.pubLen != 65) return false;
  if (off + 65 > buf.size()) return false;
  for (int i = 0; i < 65; i++) out.pub65[i] = buf[off + i];
  off += 65;

  // signature length + signature bytes
  out.sigLen = buf[off];
  off += 1;
  if (off + out.sigLen > buf.size()) return false;

  out.sigOff = off;
  return true;
}

#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>
#include <mbedtls/sha256.h>

// Verify DER ECDSA signature using a 65-byte uncompressed P-256 pubkey.
// pub65 must be: 0x04 || X(32) || Y(32)
static bool verifyTxSigPub65(const std::vector<uint8_t>& canonical,
                             const uint8_t pub65[65],
                             const uint8_t* sigDer,
                             size_t sigDerLen) {
  if (canonical.empty()) return false;
  if (sigDerLen == 0) return false;
  if (pub65[0] != 0x04) return false;

  // Hash canonical bytes
  uint8_t h[32];
  if (mbedtls_sha256_ret(canonical.data(), canonical.size(), h, 0 /*is224*/) != 0) {
    return false;
  }

  // Build an mbedTLS public key from pub65
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  int rc = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
  if (rc != 0) {
    mbedtls_pk_free(&pk);
    return false;
  }

  mbedtls_ecp_keypair* ec = mbedtls_pk_ec(pk);
  rc = mbedtls_ecp_group_load(&ec->grp, MBEDTLS_ECP_DP_SECP256R1);
  if (rc != 0) {
    mbedtls_pk_free(&pk);
    return false;
  }

  // Parse point from binary
  rc = mbedtls_ecp_point_read_binary(&ec->grp, &ec->Q, pub65, 65);
  if (rc != 0) {
    mbedtls_pk_free(&pk);
    return false;
  }

  // Verify DER signature over SHA256 hash
  rc = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, h, 0, sigDer, sigDerLen);

  mbedtls_pk_free(&pk);
  return rc == 0;
}

static void printFp8(const uint8_t fp8[8]) {
  for (int i=0;i<8;i++) {
    if (fp8[i] < 16) Serial.print("0");
    Serial.print(fp8[i], HEX);
  }
}

std::vector<uint8_t> buildCanonical(const TxFields& tx) {
  uint8_t flags = 0;
  std::vector<uint8_t> out;
  auto senderB = tx.sender;
  auto receiverB = tx.receiver;

  if (senderB.length() > 20) senderB = senderB.substring(0, 20);
  if (receiverB.length() > 20) receiverB = receiverB.substring(0, 20);

  out.push_back(PROTO_VERSION);
  out.push_back(MSG_TX);
  out.push_back(flags);
  out.push_back((uint8_t)senderB.length());
  out.push_back((uint8_t)receiverB.length());

  for (size_t i=0;i<senderB.length();i++) out.push_back((uint8_t)senderB[i]);
  for (size_t i=0;i<receiverB.length();i++) out.push_back((uint8_t)receiverB[i]);

  // amountMinor (int32 BE)
  int32_t a = tx.amountMinor;
  out.push_back((a >> 24) & 0xFF);
  out.push_back((a >> 16) & 0xFF);
  out.push_back((a >> 8) & 0xFF);
  out.push_back((a) & 0xFF);

  // nonce (uint32 BE)
  uint32_t n = tx.nonce;
  out.push_back((n >> 24) & 0xFF);
  out.push_back((n >> 16) & 0xFF);
  out.push_back((n >> 8) & 0xFF);
  out.push_back((n) & 0xFF);

  // fp8
  for (int i=0;i<8;i++) out.push_back(tx.fp8[i]);

  return out;
}

// NOTE: This starter does NOT yet implement real ECDSA signing/verification.
// It sets signatureLen=0 and focuses on the repo skeleton + packet layout.
// Next step is to add ECDSA P-256 signing with mbedTLS and persist trust store.

static void sendTx(const String& sender, const String& receiver, int32_t amountMinor) {
  TxFields tx;
  tx.sender = sender;
  tx.receiver = receiver;
  tx.amountMinor = amountMinor;
  tx.nonce = esp_random();

  // Placeholder fingerprint for now (TODO: derive from stable device fp8)
   const uint8_t* fp = keysFp8();
  for (int i = 0; i < 8; i++) tx.fp8[i] = fp[i];
  
  auto canonical = buildCanonical(tx);

  std::vector<uint8_t> packet = canonical;
    auto canonical = buildCanonical(tx);

  std::vector<uint8_t> packet = canonical;

  // Append pubkey (65 bytes)
  packet.push_back(65);
  const uint8_t* pub = keysPub65();
  for (int i = 0; i < 65; i++) packet.push_back(pub[i]);

  // Append DER signature over canonical bytes
  uint8_t sigDer[80];
  size_t sigLen = 0;
  if (!keysSignSha256(canonical.data(), canonical.size(), sigDer, sizeof(sigDer), sigLen) || sigLen == 0 || sigLen > 255) {
    Serial.println("ERROR: signing failed; not sending");
    return;
  }
  packet.push_back((uint8_t)sigLen);
  for (size_t i = 0; i < sigLen; i++) packet.push_back(sigDer[i]);

  Heltec.LoRa.beginPacket();
  Heltec.LoRa.write(packet.data(), packet.size());
  Heltec.LoRa.endPacket();

  Serial.print("Sent TX ");
  Serial.print(sender);
  Serial.print(" -> ");
  Serial.print(receiver);
  Serial.print(" amountMinor=");
  Serial.print(amountMinor);
  Serial.print(" fp8=");
  printFp8(tx.fp8);
  Serial.println();
}

static void sendColdWalletOp(const String& sender, uint8_t subtype,
                             const String& itemName, uint16_t quantity,
                             int32_t creditValueMinor) {
  uint32_t nonce = esp_random();
  const uint8_t* fp = keysFp8();

  String senderTrunc = sender;
  String itemTrunc   = itemName;
  if (senderTrunc.length() > 20) senderTrunc = senderTrunc.substring(0, 20);
  if (itemTrunc.length()   > 20) itemTrunc   = itemTrunc.substring(0, 20);

  // Build canonical bytes for signing
  std::vector<uint8_t> canonical;
  canonical.push_back(PROTO_VERSION);
  canonical.push_back(MSG_COLD_WALLET_OP);
  canonical.push_back(subtype); // flags = subtype
  canonical.push_back((uint8_t)senderTrunc.length());
  for (size_t i = 0; i < senderTrunc.length(); i++) canonical.push_back((uint8_t)senderTrunc[i]);
  canonical.push_back(subtype); // subtype field in body
  canonical.push_back((uint8_t)itemTrunc.length());
  for (size_t i = 0; i < itemTrunc.length(); i++) canonical.push_back((uint8_t)itemTrunc[i]);
  // quantity (uint16 BE)
  canonical.push_back((quantity >> 8) & 0xFF);
  canonical.push_back(quantity & 0xFF);
  // creditValueMinor (int32 BE)
  canonical.push_back((creditValueMinor >> 24) & 0xFF);
  canonical.push_back((creditValueMinor >> 16) & 0xFF);
  canonical.push_back((creditValueMinor >>  8) & 0xFF);
  canonical.push_back( creditValueMinor        & 0xFF);
  // nonce (uint32 BE)
  canonical.push_back((nonce >> 24) & 0xFF);
  canonical.push_back((nonce >> 16) & 0xFF);
  canonical.push_back((nonce >>  8) & 0xFF);
  canonical.push_back( nonce        & 0xFF);
  // fp8
  for (int i = 0; i < 8; i++) canonical.push_back(fp[i]);

  std::vector<uint8_t> packet = canonical;

  // Append pubkey (65 bytes)
  packet.push_back(65);
  const uint8_t* pub = keysPub65();
  for (int i = 0; i < 65; i++) packet.push_back(pub[i]);

  // Sign and append DER signature
  uint8_t sigDer[80];
  size_t sigLen = 0;
  if (!keysSignSha256(canonical.data(), canonical.size(), sigDer, sizeof(sigDer), sigLen) || sigLen == 0 || sigLen > 255) {
    Serial.println("ERROR: signing failed; not sending");
    return;
  }
  packet.push_back((uint8_t)sigLen);
  for (size_t i = 0; i < sigLen; i++) packet.push_back(sigDer[i]);

  Heltec.LoRa.beginPacket();
  Heltec.LoRa.write(packet.data(), packet.size());
  Heltec.LoRa.endPacket();

  Serial.print("[COLD] Sent COLD_WALLET_OP subtype=0x0");
  Serial.print(subtype, HEX);
  Serial.print(" sender=");
  Serial.print(sender);
  Serial.print(" item=");
  Serial.print(itemName);
  Serial.print(" qty=");
  Serial.print(quantity);
  Serial.print(" creditValueMinor=");
  Serial.println(creditValueMinor);
}

static void handleSerial() {
  if (!Serial.available()) return;

  String line = Serial.readStringUntil('\n');
  line.trim();
  if (line.length() == 0) return;

  // ---- SEND ----
  if (line.startsWith("send ")) {
    // send alice bob 1234
    int p1 = line.indexOf(' ');
    int p2 = line.indexOf(' ', p1 + 1);
    int p3 = line.indexOf(' ', p2 + 1);
    if (p1 < 0 || p2 < 0 || p3 < 0) {
      Serial.println("Usage: send <sender> <receiver> <amountMinor>");
      return;
    }
    String sender = line.substring(p1 + 1, p2);
    String receiver = line.substring(p2 + 1, p3);
    int32_t amount = line.substring(p3 + 1).toInt();
    sendTx(sender, receiver, amount);
    return;
  }

  // ---- TRUST: LIST ----
  if (line == "trust list") {
    Serial.print(trustListHuman());
    return;
  }

  // ---- TRUST: RESET ALL ----
  if (line == "trust reset-all") {
    if (trustResetAll()) Serial.println("Trust cleared.");
    else Serial.println("ERROR: trust reset-all failed");
    return;
  }

  // ---- TRUST: RESET ONE ----
  if (line.startsWith("trust reset ")) {
    String who = line.substring(String("trust reset ").length());
    who.trim();

    if (who.length() == 0) {
      Serial.println("Usage: trust reset <sender>");
      return;
    }

    if (trustReset(who)) {
      Serial.print("Trust reset for ");
      Serial.println(who);
    } else {
      Serial.println("ERROR: trust reset failed (filesystem/write error)");
    }
    return;
  }

  // ---- FREEZE ----
  // Usage: FREEZE:item_name:quantity:credits_spent
  if (line.startsWith("FREEZE:")) {
    String rest = line.substring(7);
    int c1 = rest.indexOf(':');
    int c2 = rest.indexOf(':', c1 + 1);
    if (c1 < 0 || c2 < 0) {
      Serial.println("Usage: FREEZE:item_name:quantity:credits_spent");
      return;
    }
    String itemName   = rest.substring(0, c1);
    uint16_t quantity = (uint16_t)rest.substring(c1 + 1, c2).toInt();
    int32_t credits   = (int32_t)rest.substring(c2 + 1).toInt();
    String deviceId   = keysFp8Hex();
    if (coldWalletFreeze(deviceId.c_str(), itemName.c_str(), quantity, credits)) {
      Serial.print("[COLD] Frozen ");
      Serial.print(quantity);
      Serial.print("x ");
      Serial.print(itemName);
      Serial.print(" (");
      Serial.print(credits);
      Serial.println(" credits spent)");
      sendColdWalletOp(deviceId, COLD_SUBTYPE_FREEZE, itemName, quantity, credits);
    } else {
      Serial.println("[COLD] ERROR: freeze failed");
    }
    return;
  }

  // ---- THAW ----
  // Usage: THAW:item_name:quantity:price_per_unit
  if (line.startsWith("THAW:")) {
    String rest = line.substring(5);
    int c1 = rest.indexOf(':');
    int c2 = rest.indexOf(':', c1 + 1);
    if (c1 < 0 || c2 < 0) {
      Serial.println("Usage: THAW:item_name:quantity:price_per_unit");
      return;
    }
    String itemName         = rest.substring(0, c1);
    uint16_t quantity       = (uint16_t)rest.substring(c1 + 1, c2).toInt();
    int32_t pricePerUnit    = (int32_t)rest.substring(c2 + 1).toInt();
    String deviceId         = keysFp8Hex();
    if (coldWalletThaw(deviceId.c_str(), itemName.c_str(), quantity, pricePerUnit)) {
      int32_t creditsReceived = (int32_t)((int64_t)quantity * pricePerUnit);
      Serial.print("[COLD] Thawed ");
      Serial.print(quantity);
      Serial.print("x ");
      Serial.print(itemName);
      Serial.print(" @ ");
      Serial.print(pricePerUnit);
      Serial.print("/unit = ");
      Serial.print(creditsReceived);
      Serial.println(" credits");
      sendColdWalletOp(deviceId, COLD_SUBTYPE_THAW, itemName, quantity, pricePerUnit);
    } else {
      Serial.println("[COLD] ERROR: thaw failed (insufficient items or item not found)");
    }
    return;
  }

  // ---- COLDWALLET ----
  if (line.startsWith("COLDWALLET")) {
    char buf[COLD_WALLET_BUF_SIZE];
    String deviceId = keysFp8Hex();
    coldWalletGetAll(deviceId.c_str(), buf, sizeof(buf));
    Serial.print("[COLD] Items: ");
    Serial.println(buf);
    return;
  }

  // ---- HELP ----
  Serial.println("Commands:");
  Serial.println("  send <sender> <receiver> <amountMinor>");
  Serial.println("  FREEZE:item_name:quantity:credits_spent");
  Serial.println("  THAW:item_name:quantity:price_per_unit");
  Serial.println("  COLDWALLET");
  Serial.println("  trust list");
  Serial.println("  trust reset <sender>");
  Serial.println("  trust reset-all");
}


void setup() {
  Serial.begin(115200);
  delay(300);

  Heltec.begin(true /*display*/, true /*LoRa*/, true /*Serial*/, true /*PABOOST*/, LORA_FREQUENCY_HZ);
  Heltec.LoRa.setSpreadingFactor(9);
  Heltec.LoRa.setSignalBandwidth(125E3);
  Heltec.LoRa.setCodingRate4(5);

  Serial.print("LoRa frequency Hz: ");
  Serial.println(LORA_FREQUENCY_HZ);
  Serial.println("Ready. Type: send alice bob 1234");
    if (!trustInit()) {
    Serial.println("ERROR: LittleFS trustInit failed");
  } else {
    Serial.println("LittleFS trust store ready");
  }
    if (!keysInit()) {
    Serial.println("ERROR: keysInit failed");
  } else {
    Serial.print("Device fp8=");
    Serial.println(keysFp8Hex());
  }
  coldWalletInit();
  Serial.println("[COLD] Cold wallet initialized");
}

void loop() {
  handleSerial();

  int packetSize = Heltec.LoRa.parsePacket();
  if (packetSize) {
    std::vector<uint8_t> buf(packetSize);
    for (int i = 0; i < packetSize; i++) buf[i] = (uint8_t)Heltec.LoRa.read();

    Serial.print("RX bytes=");
    Serial.println(packetSize);

    // Check for COLD_WALLET_OP (type 0x03) before TX parsing
    if (buf.size() >= 5 && buf[0] == PROTO_VERSION && buf[1] == MSG_COLD_WALLET_OP) {
      uint8_t subtype   = buf[2]; // flags byte holds subtype
      uint8_t senderLen = buf[3];
      if (senderLen <= 20 && (size_t)(5 + senderLen) <= buf.size()) {
        String rxSender = "";
        for (uint8_t i = 0; i < senderLen; i++) rxSender += (char)buf[5 + i];
        size_t off = 5 + senderLen;
        // subtype byte in body
        if (off + 1 <= buf.size()) {
          off += 1; // skip body subtype (same as flags)
        }
        // itemNameLen + itemName
        if (off + 1 <= buf.size()) {
          uint8_t itemNameLen = buf[off++];
          if (itemNameLen <= 20 && off + itemNameLen <= buf.size()) {
            String rxItem = "";
            for (uint8_t i = 0; i < itemNameLen; i++) rxItem += (char)buf[off + i];
            off += itemNameLen;
            // quantity (uint16 BE)
            uint16_t rxQty = 0;
            if (off + 2 <= buf.size()) {
              rxQty = ((uint16_t)buf[off] << 8) | buf[off + 1];
              off += 2;
            }
            // creditValueMinor (int32 BE)
            int32_t rxCredit = 0;
            if (off + 4 <= buf.size()) {
              readI32BE(buf, off, rxCredit);
              off += 4;
            }
            // nonce (uint32 BE)
            uint32_t rxNonce = 0;
            if (off + 4 <= buf.size()) {
              readU32BE(buf, off, rxNonce);
              off += 4;
            }
            // fp8 (8 bytes) + pubLen + pub65 + sigLen + sig
            uint8_t rxFp8[8] = {};
            uint8_t rxPub65[65] = {};
            uint8_t rxSigLen = 0;
            size_t  rxSigOff = 0;
            bool rxHasSig = false;
            if (off + 8 + 1 + 65 + 1 <= buf.size()) {
              for (int i = 0; i < 8; i++) rxFp8[i] = buf[off + i];
              off += 8;
              uint8_t rxPubLen = buf[off++];
              if (rxPubLen == 65 && off + 65 + 1 <= buf.size()) {
                for (int i = 0; i < 65; i++) rxPub65[i] = buf[off + i];
                off += 65;
                rxSigLen = buf[off++];
                if (off + rxSigLen <= buf.size()) {
                  rxSigOff = off;
                  rxHasSig = true;
                }
              }
            }
            // Verify signature
            if (rxHasSig) {
              // Rebuild canonical bytes (must match sendColdWalletOp canonical construction)
              std::vector<uint8_t> coldCanonical;
              coldCanonical.push_back(PROTO_VERSION);
              coldCanonical.push_back(MSG_COLD_WALLET_OP);
              coldCanonical.push_back(subtype);
              coldCanonical.push_back((uint8_t)rxSender.length());
              for (size_t i = 0; i < (size_t)rxSender.length(); i++) coldCanonical.push_back((uint8_t)rxSender[i]);
              coldCanonical.push_back(subtype);
              coldCanonical.push_back((uint8_t)rxItem.length());
              for (size_t i = 0; i < (size_t)rxItem.length(); i++) coldCanonical.push_back((uint8_t)rxItem[i]);
              coldCanonical.push_back((rxQty >> 8) & 0xFF);
              coldCanonical.push_back(rxQty & 0xFF);
              coldCanonical.push_back((rxCredit >> 24) & 0xFF);
              coldCanonical.push_back((rxCredit >> 16) & 0xFF);
              coldCanonical.push_back((rxCredit >>  8) & 0xFF);
              coldCanonical.push_back( rxCredit        & 0xFF);
              coldCanonical.push_back((rxNonce >> 24) & 0xFF);
              coldCanonical.push_back((rxNonce >> 16) & 0xFF);
              coldCanonical.push_back((rxNonce >>  8) & 0xFF);
              coldCanonical.push_back( rxNonce        & 0xFF);
              for (int i = 0; i < 8; i++) coldCanonical.push_back(rxFp8[i]);

              if (!verifyTxSigPub65(coldCanonical, rxPub65, buf.data() + rxSigOff, rxSigLen)) {
                Serial.print("[COLD-RX] SIG BAD sender=");
                Serial.println(rxSender);
                return;
              }
            } else {
              Serial.println("[COLD-RX] missing signature; dropping");
              return;
            }
            if (subtype == COLD_SUBTYPE_FREEZE) {
              Serial.print("[COLD-RX] ");
              Serial.print(rxSender);
              Serial.print(" froze ");
              Serial.print(rxQty);
              Serial.print("x ");
              Serial.print(rxItem);
              Serial.print(" (");
              Serial.print(rxCredit);
              Serial.println(" credits spent)");
              coldWalletFreeze(rxSender.c_str(), rxItem.c_str(), rxQty, rxCredit);
            } else if (subtype == COLD_SUBTYPE_THAW) {
              Serial.print("[COLD-RX] ");
              Serial.print(rxSender);
              Serial.print(" thawed ");
              Serial.print(rxQty);
              Serial.print("x ");
              Serial.print(rxItem);
              Serial.print(" @ ");
              Serial.print(rxCredit);
              Serial.println("/unit (manual price)");
              coldWalletThaw(rxSender.c_str(), rxItem.c_str(), rxQty, rxCredit);
            } else {
              Serial.println("[COLD-RX] Unknown subtype");
            }
          }
        }
      }
      return;
    }

    RxTxParsed p;
    if (!parseTxPacket(buf, p)) {
      Serial.println("RX: parse failed (not a valid TX packet)");
      return;
    }

    // Pin or block based on senderId+fp8
    uint8_t pinnedFp8[8];
    bool hasPinned = trustLookupFp8(p.sender, pinnedFp8);

    if (!hasPinned) {
      if (trustPinFp8(p.sender, p.fp8)) {
        Serial.print("TRUST PINNED sender=");
        Serial.print(p.sender);
        Serial.print(" fp8=");
        Serial.println(fp8ToHex(p.fp8));
      } else {
        Serial.println("ERROR: failed to pin trust (filesystem/write error)");
      }
    } else if (!fp8Equal(pinnedFp8, p.fp8)) {
      Serial.print("TRUST BLOCKED sender=");
      Serial.print(p.sender);
      Serial.print(" pinned=");
      Serial.print(fp8ToHex(pinnedFp8));
      Serial.print(" got=");
      Serial.println(fp8ToHex(p.fp8));
      return; // BLOCK: do not process further
    } else {
      Serial.print("TRUST OK sender=");
      Serial.print(p.sender);
      Serial.print(" fp8=");
      Serial.println(fp8ToHex(p.fp8));
    }

        // ---- SIGNATURE VERIFY ----
    // Rebuild canonical bytes from parsed fields (must match what sender signed)
    TxFields txv;
    txv.sender = p.sender;
    txv.receiver = p.receiver;
    txv.amountMinor = p.amountMinor;
    txv.nonce = p.nonce;
    for (int i = 0; i < 8; i++) txv.fp8[i] = p.fp8[i];

    std::vector<uint8_t> canonical = buildCanonical(txv);

    const uint8_t* sigPtr = buf.data() + p.sigOff;
    size_t sigLen = p.sigLen;

    if (!verifyTxSigPub65(canonical, p.pub65, sigPtr, sigLen)) {
      Serial.print("SIG BAD sender=");
      Serial.println(p.sender);
      return; // BLOCK
    } else {
      Serial.print("SIG OK sender=");
      Serial.println(p.sender);
    }

    // If we reach here, trust passed (or was newly pinned)
    Serial.print("TX ");
    Serial.print(p.sender);
    Serial.print(" -> ");
    Serial.print(p.receiver);
    Serial.print(" amountMinor=");
    Serial.print(p.amountMinor);
    Serial.print(" nonce=");
    Serial.println(p.nonce);

    // Signature verification will go here later
  }
}
