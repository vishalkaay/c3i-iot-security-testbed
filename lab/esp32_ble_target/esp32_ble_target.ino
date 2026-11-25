/*
 * C3i lab BLE target - a DELIBERATELY WEAK "smart lock" for testing the
 * Bluetooth modules of the C3i IoT testbed. Flash it only onto a board you own
 * and keep it in the lab: everything below is intentionally insecure.
 *
 * Board:    any ESP32 (classic, C3, S3) with the Arduino-ESP32 core.
 * Library:  the BLE library bundled with the core (no extra install).
 *
 * What it exposes                               What the testbed should report
 * --------------------------------------------  ------------------------------
 * Name "C3i-Lab-Lock", fixed public address     scan/profile: named device;
 *                                               le_security: public address
 * Device Information Service (0x180A)           gatt_firmware: vendor/model/
 *   firmware "1.0.3", model "LAB-LOCK-1"          firmware revision
 * Battery Service (0x180F), level = 87          gatt_enum: open read, value 0x57
 * Lab service c3100000-...
 *   c3100001  lock control   write, no security gatt_enum: open WRITE (high)
 *   c3100002  config         read,  no security gatt_enum: open read exposing a
 *                                                 fake Wi-Fi passphrase
 *   c3100003  admin token    read/write, needs   gatt_enum: PROTECTED (read is
 *                            an encrypted link     rejected on an unpaired link)
 *
 * The on-board LED follows the lock state, so an unauthenticated write is
 * visible: write 0x01 to c3100001 = "unlock" (LED on), 0x00 = "lock".
 */
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>

#define LED_PIN 2  // on-board LED on most ESP32 dev kits; change if yours differs

#define LAB_SERVICE_UUID "c3100000-1d0c-4b5e-9a6f-0c3110070001"
#define LOCK_CHAR_UUID   "c3100001-1d0c-4b5e-9a6f-0c3110070001"
#define CONFIG_CHAR_UUID "c3100002-1d0c-4b5e-9a6f-0c3110070001"
#define TOKEN_CHAR_UUID  "c3100003-1d0c-4b5e-9a6f-0c3110070001"

static BLECharacteristic *lockChar = nullptr;

class LockCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *c) override {
    // No pairing, no encryption, no application-level check: the weakness.
    if (c->getLength() < 1) return;
    bool unlocked = c->getData()[0] != 0;
    digitalWrite(LED_PIN, unlocked ? HIGH : LOW);
    Serial.printf("[lab] lock control written without authentication -> %s\n",
                  unlocked ? "UNLOCKED" : "locked");
  }
};

class ServerCallbacks : public BLEServerCallbacks {
  void onConnect(BLEServer *) override { Serial.println("[lab] central connected"); }
  void onDisconnect(BLEServer *) override {
    Serial.println("[lab] central disconnected; advertising again");
    BLEDevice::startAdvertising();
  }
};

static void addReadOnly(BLEService *svc, uint16_t uuid, const char *value) {
  BLECharacteristic *c =
      svc->createCharacteristic(BLEUUID(uuid), BLECharacteristic::PROPERTY_READ);
  c->setValue(value);
}

void setup() {
  Serial.begin(115200);
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);

  BLEDevice::init("C3i-Lab-Lock");
  BLEServer *server = BLEDevice::createServer();
  server->setCallbacks(new ServerCallbacks());

  // --- Device Information Service: gives gatt_firmware something to read ---
  BLEService *dis = server->createService(BLEUUID((uint16_t)0x180A), 20);
  addReadOnly(dis, 0x2A29, "C3i Lab");      // manufacturer name
  addReadOnly(dis, 0x2A24, "LAB-LOCK-1");   // model number
  addReadOnly(dis, 0x2A25, "LAB000001");    // serial number
  addReadOnly(dis, 0x2A26, "1.0.3");        // firmware revision
  addReadOnly(dis, 0x2A27, "rev-A");        // hardware revision
  addReadOnly(dis, 0x2A28, "lab-sdk-0.9");  // software revision
  dis->start();

  // --- Battery Service: a benign open read ---
  BLEService *battery = server->createService(BLEUUID((uint16_t)0x180F));
  BLECharacteristic *level = battery->createCharacteristic(
      BLEUUID((uint16_t)0x2A19), BLECharacteristic::PROPERTY_READ);
  uint8_t percent = 87;
  level->setValue(&percent, 1);
  battery->start();

  // --- Lab service: one open write, one leaky read, one protected value ---
  BLEService *lab = server->createService(LAB_SERVICE_UUID, 20);

  lockChar = lab->createCharacteristic(
      LOCK_CHAR_UUID,
      BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_WRITE_NR);
  lockChar->setCallbacks(new LockCallbacks());

  BLECharacteristic *config =
      lab->createCharacteristic(CONFIG_CHAR_UUID, BLECharacteristic::PROPERTY_READ);
  config->setValue("ssid=C3i-Lab;psk=labpassword");  // fake secret, lab only

  BLECharacteristic *token = lab->createCharacteristic(
      TOKEN_CHAR_UUID,
      BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_WRITE);
  token->setAccessPermissions(ESP_GATT_PERM_READ_ENCRYPTED | ESP_GATT_PERM_WRITE_ENCRYPTED);
  token->setValue("admin-token-lab-only");
  lab->start();

  BLEAdvertising *adv = BLEDevice::getAdvertising();
  adv->addServiceUUID(LAB_SERVICE_UUID);
  adv->addServiceUUID(BLEUUID((uint16_t)0x180A));
  adv->setScanResponse(true);
  BLEDevice::startAdvertising();

  Serial.print("[lab] C3i-Lab-Lock advertising, address ");
  Serial.println(BLEDevice::getAddress().toString().c_str());
}

void loop() { delay(1000); }
