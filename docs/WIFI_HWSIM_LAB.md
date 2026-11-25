# No-RF Wi-Fi lab (`mac80211_hwsim` + hostapd)

The loopback target in [`TESTING_LAB.md`](TESTING_LAB.md) is an **IP-service
simulator**: it exercises `discovery`, `portscan`, `tls_audit`,
`default_credentials` and `mqtt_audit` without any radio. It cannot validate the
radio-layer modules — `wireless_survey`, monitor-mode capture, channel
switching or `deauth_test` — because those need an 802.11 interface.

This recipe builds a **software 802.11 lab** with the Linux kernel's
`mac80211_hwsim` driver, so those modules have a deterministic target with **no
transmitter and no RF**. Everything lives inside one Linux box (ideally a VM or a
throwaway host); the virtual radios never touch real spectrum.

> **Scope.** This is a lab-construction note, not a module. The testbed does not
> provision the kernel lab for you. Build it on a host you own. Even simulated,
> treat `deauth_test` as invasive and keep it behind a signed Rules of Engagement.

## 1. What `mac80211_hwsim` gives you

Loading the module creates N fully virtual Wi-Fi radios that speak the real
`mac80211` stack. You get genuine `wlanX` interfaces that `iw`, `hostapd`,
`wpa_supplicant`, `tcpdump` and `aircrack-ng` treat like hardware — including
monitor mode and management frames — but the "air" is a kernel medium, not a
physical antenna.

## 2. One-time host setup

```bash
sudo apt install hostapd wpasupplicant iw tcpdump aircrack-ng
# radios appear as wlan0, wlan1, ...  (2 is enough: one AP, one client)
sudo modprobe mac80211_hwsim radios=3
iw dev            # confirm wlan0/1/2 exist
```

To start clean later: `sudo modprobe -r mac80211_hwsim` and re-load.

## 3. Stand up a simulated access point (wlan0)

Create `/tmp/hwsim-ap.conf`:

```ini
interface=wlan0
driver=nl80211
ssid=C3i-Lab-AP
hw_mode=g
channel=6
# Deliberately weak posture for the lab:
wmm_enabled=0
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=labpassword
# ieee80211w=0  -> no 802.11w/PMF, so deauth protection is OFF (what deauth_test looks for)
ieee80211w=0
```

```bash
sudo rfkill unblock all
sudo hostapd /tmp/hwsim-ap.conf      # keep this terminal running
```

For a **WPS-exposed** or **open** variant (to see `wireless_survey` flag it),
add `wps_state=2` / `eap_server=1`, or set `wpa=0` with no passphrase.

## 4. Associate a client (wlan1) so there is a station to observe

Create `/tmp/hwsim-cli.conf`:

```ini
network={
    ssid="C3i-Lab-AP"
    psk="labpassword"
}
```

```bash
sudo wpa_supplicant -i wlan1 -c /tmp/hwsim-cli.conf      # keep running
sudo dhclient wlan1   # optional: give the client an IP
```

`iw dev wlan0 station dump` on the AP side now lists the associated client — a
real target for a deauth test.

## 5. Point the testbed at it

The backend reads the interface on the **backend host**, so run the backend on
this same machine/VM. Then:

| Module | Parameters | Expected observation |
|---|---|---|
| `wireless_survey` | `interface=wlan2` (an unused radio) | Sees `C3i-Lab-AP` on channel 6, encryption WPA2, WPS/open flagged if configured |
| `traffic_capture` | `interface=wlan1`, `seconds=5` | Captures frames; encryption verified on the associated link |
| `deauth_test` (invasive) | `interface=wlan0`/monitor, target = client MAC, `frames<=20` | Client briefly deauthenticates and re-associates; **missing 802.11w** reported because `ieee80211w=0` |

Put the AP/client MACs (or the lab subnet) in the engagement's authorized
targets and sign the Rules of Engagement before the invasive `deauth_test`, exactly
as you would for real hardware.

## 6. Monitor-mode capture (optional, matches the hardware path)

```bash
sudo iw dev wlan2 interface add mon0 type monitor
sudo ip link set mon0 up
sudo tcpdump -i mon0 -w /tmp/hwsim.pcap    # or let traffic_capture drive it
```

## 7. Limits of the simulation

- **No real RF.** Signal strength, multipath, interference and range are not
  modelled. `wireless_survey` RSSI values are synthetic — do not benchmark
  distance or coverage here.
- **Driver-specific quirks differ.** Real adapters vary in monitor-mode and
  injection support; validate the actual adapter you will deploy with.
- **PMF/802.11w behaviour** is whatever you configured in `hostapd.conf`; it
  proves the module's *logic*, not a specific vendor AP.
- Teardown: stop `hostapd`/`wpa_supplicant`, then
  `sudo modprobe -r mac80211_hwsim`.

## 8. Why this is the recommended Wi-Fi lab

It is the only no-cost, no-RF way to exercise the full radio path
(survey → capture → deauth → re-association) deterministically and repeatably,
in CI or on a laptop, without broadcasting on real spectrum or risking a
neighbour's network. For final sign-off, still validate against a real isolated
AP and the Wi-Fi adapter you intend to ship with.
