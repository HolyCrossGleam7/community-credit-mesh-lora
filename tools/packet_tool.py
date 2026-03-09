"""
Simple dev tool (host-side) to inspect packet encoding rules.

This is not a full emulator; it's a reference for:
- canonical bytes
- field layout
"""

import struct
import hashlib
import os

VERSION = 1
TYPE_TX = 1

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def fingerprint8(pubkey_bytes: bytes) -> bytes:
    return sha256(pubkey_bytes)[:8]

def build_canonical(sender: str, receiver: str, amount_minor: int, nonce: int, fp8: bytes) -> bytes:
    sender_b = sender.encode("utf-8")[:20]
    receiver_b = receiver.encode("utf-8")[:20]
    flags = 0
    header = struct.pack(">BBBBB", VERSION, TYPE_TX, flags, len(sender_b), len(receiver_b))
    body = sender_b + receiver_b + struct.pack(">iI", amount_minor, nonce) + fp8
    return header + body

def build_packet(sender, receiver, amount_minor, nonce, pubkey_bytes, signature_bytes):
    fp8 = fingerprint8(pubkey_bytes)
    canonical = build_canonical(sender, receiver, amount_minor, nonce, fp8)
    sig = signature_bytes
    if len(sig) > 255:
        raise ValueError("signature too long")
    return canonical + struct.pack(">B", len(sig)) + sig

if __name__ == "__main__":
    sender = "alice"
    receiver = "bob"
    amount_minor = 1234
    nonce = int.from_bytes(os.urandom(4), "big")
    pubkey = b"example_pubkey_bytes"
    sig = b"example_signature"

    pkt = build_packet(sender, receiver, amount_minor, nonce, pubkey, sig)
    print("nonce:", nonce)
    print("packet hex:", pkt.hex())
