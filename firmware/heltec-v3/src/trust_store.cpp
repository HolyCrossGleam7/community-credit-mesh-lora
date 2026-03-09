#include "trust_store.h"

#include <LittleFS.h>
#include <ArduinoJson.h>

static const char* TRUST_PATH = "/trust.json";

String fp8ToHex(const uint8_t fp8[8]) {
  const char* hex = "0123456789abcdef";
  String out;
  out.reserve(16);
  for (int i = 0; i < 8; i++) {
    out += hex[(fp8[i] >> 4) & 0xF];
    out += hex[(fp8[i] >> 0) & 0xF];
  }
  return out;
}

static bool hexToFp8(const String& hexStr, uint8_t out[8]) {
  if (hexStr.length() != 16) return false;
  auto toNibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
  };
  for (int i = 0; i < 8; i++) {
    int hi = toNibble(hexStr[2*i]);
    int lo = toNibble(hexStr[2*i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
}

bool fp8Equal(const uint8_t a[8], const uint8_t b[8]) {
  for (int i = 0; i < 8; i++) if (a[i] != b[i]) return false;
  return true;
}

static JsonDocument readTrustDoc() {
  JsonDocument doc;
  if (!LittleFS.exists(TRUST_PATH)) {
    doc["version"] = 1;
    doc["pinned"] = JsonObject();
    return doc;
  }

  File f = LittleFS.open(TRUST_PATH, "r");
  if (!f) {
    doc["version"] = 1;
    doc["pinned"] = JsonObject();
    return doc;
  }

  DeserializationError err = deserializeJson(doc, f);
  f.close();

  if (err) {
    // Corrupt file: start fresh
    doc.clear();
    doc["version"] = 1;
    doc["pinned"] = JsonObject();
  }

  if (!doc["pinned"].is<JsonObject>()) {
    doc["pinned"] = JsonObject();
  }
  if (!doc["version"].is<int>()) {
    doc["version"] = 1;
  }
  return doc;
}

static bool writeTrustDoc(const JsonDocument& doc) {
  File f = LittleFS.open(TRUST_PATH, "w");
  if (!f) return false;
  if (serializeJson(doc, f) == 0) {
    f.close();
    return false;
  }
  f.close();
  return true;
}

bool trustInit() {
  if (!LittleFS.begin(true /* formatOnFail */)) {
    return false;
  }
  // Ensure file exists
  JsonDocument doc = readTrustDoc();
  return writeTrustDoc(doc);
}

bool trustLookupFp8(const String& senderId, uint8_t outFp8[8]) {
  JsonDocument doc = readTrustDoc();
  JsonObject pinned = doc["pinned"].as<JsonObject>();
  if (!pinned.containsKey(senderId)) return false;

  String hexStr = pinned[senderId].as<String>();
  return hexToFp8(hexStr, outFp8);
}

bool trustPinFp8(const String& senderId, const uint8_t fp8[8]) {
  JsonDocument doc = readTrustDoc();
  JsonObject pinned = doc["pinned"].as<JsonObject>();
  pinned[senderId] = fp8ToHex(fp8);
  return writeTrustDoc(doc);
}

bool trustReset(const String& senderId) {
  JsonDocument doc = readTrustDoc();
  JsonObject pinned = doc["pinned"].as<JsonObject>();
  if (pinned.containsKey(senderId)) {
    pinned.remove(senderId);
    return writeTrustDoc(doc);
  }
  return true;
}

bool trustResetAll() {
  JsonDocument doc;
  doc["version"] = 1;
  doc["pinned"] = JsonObject();
  return writeTrustDoc(doc);
}

String trustListHuman() {
  JsonDocument doc = readTrustDoc();
  JsonObject pinned = doc["pinned"].as<JsonObject>();

  String out;
  out.reserve(256);
  out += "Pinned identities:\n";
  if (pinned.size() == 0) {
    out += "  (none)\n";
    return out;
  }

  for (JsonPair kv : pinned) {
    out += "  ";
    out += kv.key().c_str();
    out += " => ";
    out += kv.value().as<String>();
    out += "\n";
  }
  return out;
}
