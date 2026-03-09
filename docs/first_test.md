# First Test (2 boards)

## What you need
- 2x Heltec WiFi LoRa 32 V3
- USB cables
- VS Code + PlatformIO

## Step 1: Flash both boards
Open `firmware/heltec-v3/` in PlatformIO and upload to each board.

## Step 2: Open Serial Monitor
Baud: 115200

You should see:
- region frequency
- device key fingerprint

## Step 3: Send a test transaction
In serial monitor, type:
send alice bob 1234

That means: Alice pays Bob 12.34 (minor units = 1234).

On the receiver:
- It should print received packet
- It should verify signature
- It should pin Alice’s identity (first time)

## Step 4: Test strict blocking
Reset trust store on one device (so it generates a new identity) and send again.
Receiver should BLOCK due to fingerprint mismatch.

## Step 5: Reset trust
On receiver serial, type:
trust reset alice

Then send again. It should accept and re-pin.
