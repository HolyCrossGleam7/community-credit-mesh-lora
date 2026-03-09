#pragma once
#include <Arduino.h>

// Initializes LittleFS key material.
// - If keys exist: load them
// - If missing: generate and store them
bool keysInit();

// Returns pointer to internal fp8 (8 bytes). Valid after keysInit().
const uint8_t* keysFp8();

// Returns a printable fp8 hex string.
String keysFp8Hex();
