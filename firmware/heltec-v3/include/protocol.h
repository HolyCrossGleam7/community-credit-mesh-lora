#pragma once
#include <Arduino.h>
#include <vector>

static const uint8_t PROTO_VERSION = 0x01;
static const uint8_t MSG_TX = 0x01;
static const uint8_t MSG_COLD_WALLET_OP = 0x03;

static const uint8_t COLD_SUBTYPE_FREEZE = 0x01;
static const uint8_t COLD_SUBTYPE_THAW   = 0x02;

struct TxFields {
  String sender;
  String receiver;
  int32_t amountMinor;
  uint32_t nonce;
  uint8_t fp8[8];
};

std::vector<uint8_t> buildCanonical(const TxFields& tx);
