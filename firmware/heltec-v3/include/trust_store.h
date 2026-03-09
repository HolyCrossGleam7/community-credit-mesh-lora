#pragma once
#include <Arduino.h>

bool trustInit();

bool trustLookupFp8(const String& senderId, uint8_t outFp8[8]);
bool trustPinFp8(const String& senderId, const uint8_t fp8[8]);     // create/update
bool trustReset(const String& senderId);                            // remove sender
bool trustResetAll();

String trustListHuman();                                            // pretty print
String fp8ToHex(const uint8_t fp8[8]);
bool fp8Equal(const uint8_t a[8], const uint8_t b[8]);
