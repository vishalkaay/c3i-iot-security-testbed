#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Raspberry Pi 5 provisioning for the hardware testbed rig.
# Enables UART + SPI, installs the toolchain, and prepares the GPIO groups.
# Run as root (or via sudo) ON THE PI:  sudo bash deploy/provision-pi.sh
# ---------------------------------------------------------------------------
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root: sudo bash deploy/provision-pi.sh"
  exit 1
fi

echo "==> Installing system packages"
apt-get update
apt-get install -y --no-install-recommends \
    python3-venv python3-pip git build-essential \
    bluez bluez-tools \
    nmap tcpdump tshark openssl \
    mosquitto-clients \
    binutils file binwalk flashrom squashfs-tools \
    i2c-tools sigrok-cli usbutils \
    aircrack-ng iw wireless-tools \
    libgpiod2 gpiod python3-libgpiod

echo "==> Enabling UART, SPI and I2C interfaces"
# Use raspi-config non-interactively when available.
if command -v raspi-config >/dev/null 2>&1; then
  raspi-config nonint do_serial 2 || true     # enable UART, disable login shell on it
  raspi-config nonint do_spi 0 || true        # enable SPI
  raspi-config nonint do_i2c 0 || true        # enable I2C
  echo "    UART + SPI + I2C enabled (reboot required)."
else
  echo "    raspi-config not found - enable UART/SPI manually via raspi-config or /boot/firmware/config.txt"
fi

echo "==> Ensuring serial console does not hold the GPIO UART"
systemctl disable --now serial-getty@ttyAMA0.service 2>/dev/null || true
systemctl disable --now serial-getty@ttyS0.service 2>/dev/null || true

echo "==> Adding the invoking user to hardware groups"
TARGET_USER="${SUDO_USER:-pi}"
usermod -aG gpio,dialout,plugdev,bluetooth,i2c,spi "$TARGET_USER" || true
  echo "    Added '$TARGET_USER' to gpio/dialout/plugdev/bluetooth/i2c/spi groups."

cat <<'EOF'

==================================================================
 Raspberry Pi 5 provisioning complete.

   Next:
     1) Reboot to apply UART/SPI + group changes:
            sudo reboot
     2) Wire the testbed per docs/HARDWARE_SETUP.md:
            - UART  TX/RX on BCM14/15 (pins 8/10)
            - Relay/optocoupler power on the configured BCM pins
            - SPI flash clip on SPI0 (BCM 8/9/10/11)
     3) Install the testbed:
            bash deploy/install.sh
     4) Verify the rig:
            cd backend && ../.venv/bin/python -m app.cli doctor
     (only interfaces that are actually connected/enabled should report OK)
==================================================================
EOF
