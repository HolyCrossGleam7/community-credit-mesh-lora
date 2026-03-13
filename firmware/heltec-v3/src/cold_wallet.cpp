// cold_wallet.cpp — Cold Wallet storage for ESP32
// Stores items in /cold_wallet.json on LittleFS
// Format: {"wallets": {"userId": {"itemName": quantity, ...}}, "history": [...]}

#include <Arduino.h>
#include <LittleFS.h>
#include <ArduinoJson.h>

#define COLD_WALLET_FILE "/cold_wallet.json"
#define MAX_HISTORY 50
#define COLD_WALLET_BUF_SIZE 512

static JsonDocument coldDoc;
static bool coldLoaded = false;

void coldWalletSave() {
    File f = LittleFS.open(COLD_WALLET_FILE, "w");
    if (!f) return;
    serializeJson(coldDoc, f);
    f.close();
}

void coldWalletInit() {
    if (coldLoaded) return;
    // LittleFS is already mounted by trust_store; mount only if needed
    if (!LittleFS.begin(false)) {
        LittleFS.begin(true); // format on failure
    }
    if (LittleFS.exists(COLD_WALLET_FILE)) {
        File f = LittleFS.open(COLD_WALLET_FILE, "r");
        if (f) {
            DeserializationError err = deserializeJson(coldDoc, f);
            f.close();
            if (err) {
                coldDoc.clear();
            }
        }
    }
    if (!coldDoc["wallets"].is<JsonObject>()) {
        coldDoc["wallets"].to<JsonObject>();
    }
    if (!coldDoc["history"].is<JsonArray>()) {
        coldDoc["history"].to<JsonArray>();
    }
    coldLoaded = true;
}

bool coldWalletFreeze(const char* userId, const char* itemName, uint16_t quantity, int32_t creditsSpent) {
    if (!coldLoaded) coldWalletInit();

    JsonObject wallets = coldDoc["wallets"].as<JsonObject>();
    if (!wallets[userId].is<JsonObject>()) {
        wallets[userId].to<JsonObject>();
    }
    JsonObject userWallet = wallets[userId].as<JsonObject>();
    uint16_t current = userWallet[itemName].is<JsonVariant>() ? (uint16_t)userWallet[itemName].as<int>() : 0;
    userWallet[itemName] = current + quantity;

    // Record history (cap at MAX_HISTORY)
    JsonArray history = coldDoc["history"].as<JsonArray>();
    while ((int)history.size() >= MAX_HISTORY) {
        history.remove(0);
    }
    JsonObject entry = history.add<JsonObject>();
    entry["type"]          = "freeze";
    entry["user"]          = userId;
    entry["item"]          = itemName;
    entry["quantity"]      = quantity;
    entry["credits_spent"] = creditsSpent;
    entry["timestamp"]     = (uint32_t)millis(); // uptime ms; overflows ~49 days

    coldWalletSave();
    return true;
}

bool coldWalletThaw(const char* userId, const char* itemName, uint16_t quantity, int32_t pricePerUnitMinor) {
    if (!coldLoaded) coldWalletInit();

    JsonObject wallets = coldDoc["wallets"].as<JsonObject>();
    if (!wallets[userId].is<JsonObject>()) return false;
    JsonObject userWallet = wallets[userId].as<JsonObject>();
    if (!userWallet[itemName].is<JsonVariant>()) return false;

    uint16_t current = (uint16_t)userWallet[itemName].as<int>();
    if (current < quantity) return false;

    if (current - quantity == 0) {
        userWallet.remove(itemName);
    } else {
        userWallet[itemName] = current - quantity;
    }

    int32_t creditsReceived = (int32_t)((int64_t)quantity * pricePerUnitMinor);

    // Record history (cap at MAX_HISTORY)
    JsonArray history = coldDoc["history"].as<JsonArray>();
    while ((int)history.size() >= MAX_HISTORY) {
        history.remove(0);
    }
    JsonObject entry = history.add<JsonObject>();
    entry["type"]           = "thaw";
    entry["user"]           = userId;
    entry["item"]           = itemName;
    entry["quantity"]       = quantity;
    entry["price_per_unit"] = pricePerUnitMinor;
    entry["credits_received"] = creditsReceived;
    entry["timestamp"]      = (uint32_t)millis(); // uptime ms; overflows ~49 days

    coldWalletSave();
    return true;
}

void coldWalletGetAll(const char* userId, char* outBuf, size_t bufLen) {
    if (!coldLoaded) coldWalletInit();

    JsonObject wallets = coldDoc["wallets"].as<JsonObject>();
    if (!wallets[userId].is<JsonObject>()) {
        snprintf(outBuf, bufLen, "{}");
        return;
    }
    serializeJson(wallets[userId], outBuf, bufLen);
}

uint16_t coldWalletGetItemQty(const char* userId, const char* itemName) {
    if (!coldLoaded) coldWalletInit();

    JsonObject wallets = coldDoc["wallets"].as<JsonObject>();
    if (!wallets[userId].is<JsonObject>()) return 0;
    JsonObject userWallet = wallets[userId].as<JsonObject>();
    if (!userWallet[itemName].is<JsonVariant>()) return 0;
    return (uint16_t)userWallet[itemName].as<int>();
}
