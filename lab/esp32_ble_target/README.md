# ESP32 BLE lab target ("C3i-Lab-Lock")

A deliberately weak BLE smart-lock for exercising the Bluetooth modules against
real radio traffic. Flash it only onto a board you own and keep it in the lab.

> Status: the sketch has not been compiled or flashed in this repository's CI.
> It uses only the BLE library bundled with the Arduino-ESP32 core.

## Flash it

1. Install the Arduino IDE, then *Boards Manager → esp32 by Espressif*.
2. Open `esp32_ble_target.ino`, pick your board (e.g. *ESP32 Dev Module*) and
   port, and upload. If the IDE reports the sketch is too big, choose
   *Tools → Partition Scheme → Huge APP*.
3. Open the serial monitor at 115200 baud. It prints the board's Bluetooth
   address: `[lab] C3i-Lab-Lock advertising, address AA:BB:...`.

If your board's LED is not on GPIO 2, change `LED_PIN` at the top of the sketch.

## Test it with the testbed

Add the board's address to an engagement's authorized targets, then run the
Bluetooth modules in this order (all passive):

| Module | Expected result |
|---|---|
| `scan` | `C3i-Lab-Lock` listed with an RSSI and `address_type: public` |
| `profile` | Named device; "exposes services without a pairing requirement" |
| `le_security` | Fixed public address (trackable); services exposed while unpaired |
| `gatt_firmware` | Manufacturer `C3i Lab`, model `LAB-LOCK-1`, firmware `1.0.3` |
| `gatt_enum` | 3 services from the sketch plus the generic ones; findings below |

`gatt_enum` should classify the three lab characteristics differently:

| Characteristic | Sketch behaviour | Expected classification |
|---|---|---|
| `c3100001…` lock control | write, no security | **open write** (high finding) |
| `c3100002…` config | read, no security | **open read**, value `ssid=C3i-Lab;psk=labpassword` |
| `c3100003…` admin token | read/write need an encrypted link | **protected** - the read is rejected on an unpaired link |

The third row is the important check. BlueZ reports only a remote
characteristic's *properties*, so the token looks like a plain `read` until the
read is attempted and refused. If the testbed lists it under open reads, the
classifier has regressed.

## Confirm the open write by hand

`gatt_enum` never writes. To see the weakness, write one byte from any BLE
client you control (nRF Connect on a phone, or `bluetoothctl` → `gatt.select-attribute`
→ `gatt.write 0x01`). The LED turns on and the serial monitor prints
`lock control written without authentication -> UNLOCKED`, with no pairing.
