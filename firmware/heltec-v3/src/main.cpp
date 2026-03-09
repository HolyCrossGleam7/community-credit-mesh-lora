#include <Arduino.h>

#include "config.h"
#include "protocol.h"
#include "trust_store.h"

// Heltec library
#include "heltec.h"

// Simple pinned trust store in RAM for now (manual starter).
// Next step: persist to NVS/LittleFS.
#include "trust_store.h"

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

  // Placeholder fingerprint for now (TODO: derive from real public key)
  for (int i=0;i<8;i++) tx.fp8[i] = (uint8_t)(esp_random() & 0xFF);

  auto canonical = buildCanonical(tx);

  std::vector<uint8_t> packet = canonical;
  packet.push_back(0); // signatureLen = 0

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

  // ---- HELP ----
  Serial.println("Commands:");
  Serial.println("  send <sender> <receiver> <amountMinor>");
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
}

void loop() {
  handleSerial();

  int packetSize = Heltec.LoRa.parsePacket();
  if (packetSize) {
    std::vector<uint8_t> buf(packetSize);
    for (int i=0;i<packetSize;i++) buf[i] = (uint8_t)Heltec.LoRa.read();

    Serial.print("RX bytes=");
    Serial.println(packetSize);

    // Minimal decode: show first few bytes
    if (buf.size() >= 5) {
      uint8_t ver = buf[0];
      uint8_t type = buf[1];
      Serial.print("ver=");
      Serial.print(ver);
      Serial.print(" type=");
      Serial.println(type);
    }
  }
}
