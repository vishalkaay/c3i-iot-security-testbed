#!/usr/bin/env bash
# Software 802.11 lab for the radio-layer modules (wireless_survey, capture,
# deauth_test). Uses the kernel's mac80211_hwsim driver: three virtual radios,
# no RF is transmitted and your real Wi-Fi card is left alone.
#
#   sudo lab/wifi_hwsim_lab.sh up       # weak WPA2 AP (no PMF, WPS on) + open AP
#   sudo lab/wifi_hwsim_lab.sh status
#   sudo lab/wifi_hwsim_lab.sh down
#
# Needs: hostapd, iw.  (Arch: pacman -S hostapd iw · Debian: apt install hostapd iw)
# The backend must run on this same machine, as root or with CAP_NET_ADMIN,
# to perform an active scan on the spare radio.
set -euo pipefail

STATE=/run/c3i-hwsim
cmd=${1:-status}

[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }

sim_ifaces() {
    for dev in /sys/class/net/*; do
        [[ "$(basename "$(readlink -f "$dev/device/driver" 2>/dev/null)")" == mac80211_hwsim ]] \
            && basename "$dev"
    done | sort
}

case "$cmd" in
up)
    command -v hostapd >/dev/null || { echo "hostapd is not installed"; exit 1; }
    lsmod | grep -q '^mac80211_hwsim' || modprobe mac80211_hwsim radios=3
    sleep 1
    mapfile -t IF < <(sim_ifaces)
    [[ ${#IF[@]} -ge 3 ]] || { echo "expected 3 virtual radios, found ${#IF[@]}"; exit 1; }
    mkdir -p "$STATE"
    # Keep NetworkManager from grabbing the virtual radios.
    if command -v nmcli >/dev/null; then
        for i in "${IF[@]}"; do nmcli device set "$i" managed no 2>/dev/null || true; done
    fi
    cat >"$STATE/ap-weak.conf" <<EOF
interface=${IF[0]}
driver=nl80211
ssid=C3i-Lab-Weak
hw_mode=g
channel=6
wpa=3
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
wpa_passphrase=labpassword
ieee80211w=0
wps_state=2
eap_server=1
EOF
    cat >"$STATE/ap-open.conf" <<EOF
interface=${IF[1]}
driver=nl80211
ssid=C3i-Lab-Open
hw_mode=g
channel=11
EOF
    hostapd -B -P "$STATE/ap-weak.pid" "$STATE/ap-weak.conf" >/dev/null
    hostapd -B -P "$STATE/ap-open.pid" "$STATE/ap-open.conf" >/dev/null
    ip link set "${IF[2]}" up
    echo "Lab is up."
    echo "  weak AP : C3i-Lab-Weak on ${IF[0]} (WPA/WPA2 mixed, TKIP, WPS, no 802.11w)"
    echo "  open AP : C3i-Lab-Open on ${IF[1]}"
    echo "  scanner : ${IF[2]}   <- use this as 'interface' in wireless_survey"
    ;;
down)
    for pid in "$STATE"/*.pid; do
        [[ -f "$pid" ]] && kill "$(cat "$pid")" 2>/dev/null || true
    done
    sleep 1
    rm -rf "$STATE"
    modprobe -r mac80211_hwsim 2>/dev/null || true
    echo "Lab is down."
    ;;
status)
    mapfile -t IF < <(sim_ifaces)
    if [[ ${#IF[@]} -eq 0 ]]; then echo "No virtual radios loaded."; exit 0; fi
    echo "Virtual radios: ${IF[*]}"
    pgrep -a hostapd || echo "hostapd is not running"
    ;;
*)
    echo "usage: $0 up|down|status"; exit 2 ;;
esac
