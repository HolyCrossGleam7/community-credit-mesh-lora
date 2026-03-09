# community-credit-mesh-lora

Send **signed** Community Credit Mesh transactions over **LoRa P2P** using **Heltec WiFi LoRa 32 V3 (ESP32 + SX1262)**.

## What this repo is
- **Offline** peer-to-peer LoRa messaging (not LoRaWAN)
- Compact transaction packets
- Device “Digital ID” keys used to **sign** transactions
- **Strict identity pinning (TOFU)**:
  - First time you see `senderId`, you pin their public key fingerprint
  - If the fingerprint changes later, the message is **blocked**
  - You can **reset trust** manually via Serial

## Hardware
- Heltec WiFi LoRa 32 **V3** (SX1262)

## Regions (compile-time)
In `firmware/heltec-v3/include/config.h` choose one:
- `REGION_US915` (default)
- `REGION_EU868`

> A US build cannot talk to an EU build (different legal frequencies), but the same code supports both.

## Build / Flash (PlatformIO)
1. Install VS Code + PlatformIO
2. Open `firmware/heltec-v3/`
3. Build + Upload

## Docs
- Protocol: `protocol/packet_format.md`
- First test with two boards: `docs/first_test.md`

## Security model (simple)
- Packets are signed so others can’t forge “Alice paid Bob”
- Identity is pinned by `senderId` to prevent impersonation
- “Reset trust” is available because users may reinstall / change devices
