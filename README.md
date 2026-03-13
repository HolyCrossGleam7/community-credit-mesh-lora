# community-credit-mesh-lora

Send **signed** Community Credit Mesh transactions over **LoRa P2P** using **Heltec WiFi LoRa 32 V3 (ESP32 + SX1262)**.

## What this repo is
- **Offline** peer-to-peer LoRa messaging (not LoRaWAN)
- Compact transaction packets
- Device "Digital ID" keys used to **sign** transactions
- **Strict identity pinning (TOFU)**:
  - First time you see `senderId`, you pin their public key fingerprint
  - If the fingerprint changes later, the message is **blocked**
  - You can **reset trust** manually via Serial
- **Cold Wallet** — freeze credits into items, thaw back at a user-set price, broadcast over LoRa

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

## 🧊 Cold Wallet

The Cold Wallet stores items locally on the ESP32 (LittleFS) and broadcasts freeze/thaw operations over LoRa as packet type `0x03` (`COLD_WALLET_OP`).

### Freeze (Credits → Items)
- Serial command: `FREEZE:item_name:quantity:credits_spent`
- Stores **item name + quantity** only — no price saved
- Broadcasts a `COLD_WALLET_OP` packet (subtype `0x01`) over LoRa

### Thaw (Items → Credits)
- Serial command: `THAW:item_name:quantity:price_per_unit`
- **User manually sets the price per unit** — never automatic
- Credits received = quantity × user-set price
- Broadcasts a `COLD_WALLET_OP` packet (subtype `0x02`) over LoRa

### View Cold Wallet
- Serial command: `COLDWALLET`
- Shows all items in cold storage as JSON

### Why no stored price?
In a mutual credit community, the value of goods changes over time. The Cold Wallet deliberately does NOT store prices — **the user decides what their items are worth when they thaw them**.

## Serial Commands

| Command | Description |
|---------|-------------|
| `TX:receiver:amount` | Send a signed credit transaction over LoRa |
| `BALANCE` | Show current device balance |
| `ID` | Show device ID and public key fingerprint |
| `FREEZE:item:qty:credits` | Freeze credits into items (cold wallet) |
| `THAW:item:qty:price` | Thaw items back to credits at manual price |
| `COLDWALLET` | Show all items in cold storage |
| `trust reset <senderId>` | Reset pinned key for a sender |

## Packet Types

| Type | Name | Description |
|------|------|-------------|
| `0x01` | `TX` | Signed credit transaction |
| `0x02` | `ACK` | Acknowledgement |
| `0x03` | `COLD_WALLET_OP` | Cold wallet freeze/thaw broadcast |

## Docs
- Protocol: `protocol/packet_format.md`
- First test with two boards: `docs/first_test.md`

## Security model (simple)
- Packets are signed so others can't forge "Alice paid Bob"
- Identity is pinned by `senderId` to prevent impersonation
- "Reset trust" is available because users may reinstall / change devices

## 📚 Related Projects

- **[Community Credit Mesh Desktop](https://github.com/HolyCrossGleam7/community-credit-mesh)** — Python desktop application (PyQt6)
- **[Community Credit Mesh PWA](https://github.com/HolyCrossGleam7/community-credit-mesh-pwa)** — Progressive Web App (mobile/browser)
- **Live PWA:** https://HolyCrossGleam7.github.io/community-credit-mesh-pwa/
- All three apps work independently and peer-to-peer

## 📄 License

GNU General Public License v3 (GPLv3)

See [LICENSE](LICENSE) for details.
