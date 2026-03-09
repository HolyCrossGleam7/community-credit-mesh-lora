# Packet Format (CCM-LoRa v1)

Goal: keep packets small enough for LoRa, while still supporting signing + anti-replay.

## Overview
We use a compact **binary** packet:

### Header
- `version` (1 byte) = `0x01`
- `type` (1 byte)
  - `0x01` = TX (transaction)
  - `0x02` = ACK (optional future)
- `flags` (1 byte) (reserved)
- `senderIdLen` (1 byte) (max 20)
- `receiverIdLen` (1 byte) (max 20)

### Body (TX)
- `senderId` (N bytes, UTF-8)
- `receiverId` (M bytes, UTF-8)
- `amountMinor` (int32, big-endian)  
  Example: 1234 = 12.34 credits (you decide the decimal display in UI)
- `nonce` (uint32, big-endian)  
  A random number per message (anti-replay helper)
- `pubKeyFingerprint` (8 bytes)  
  First 8 bytes of SHA-256(publicKeyBytes)
- `signatureLen` (1 byte)
- `signature` (variable)

### Public key handling
To verify, a receiver must know the sender’s public key. We include **fingerprint** in the packet and use a pinned mapping:
- If senderId not seen: accept + pin fingerprint (TOFU)
- If seen and fingerprint mismatches: **BLOCK**
- Reset trust removes the pin.

## Canonical bytes to sign
For TX packets, sign this exact byte sequence:

`version|type|flags|senderIdLen|receiverIdLen|senderId|receiverId|amountMinor|nonce|pubKeyFingerprint`

Signature algorithm:
- ECDSA P-256 with SHA-256

## Replay protection
Device keeps a small cache per senderId of recently seen nonces.
- If same senderId+nonce repeats: reject.
