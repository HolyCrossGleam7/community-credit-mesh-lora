#pragma once
#include <Arduino.h>

// Load/generate keypair in LittleFS. Must be called once in setup().
bool keysInit();

// Fingerprint = SHA256(pubkey65) first 8 bytes.
const uint8_t* keysFp8();
String keysFp8Hex();

// 65-byte uncompressed public key: 0x04 || X(32) || Y(32)
const uint8_t* keysPub65();
String keysPub65Hex();

// Sign message bytes with device private key (ECDSA P-256, SHA-256).
// Output is DER-encoded ECDSA signature (variable length, usually ~70-72 bytes).
bool keysSignSha256(const uint8_t* msg, size_t msgLen, uint8_t* sigDerOut, size_t sigDerMax, size_t& sigDerLenOut);
