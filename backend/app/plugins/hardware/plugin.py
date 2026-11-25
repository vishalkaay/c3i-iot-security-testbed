"""Hardware auditing testbed plugin (Raspberry Pi 5).

Implements the automated hardware auditing testbed from the C3i Hub paper
*Automated Hardware Auditing Testbed for UART and SPI based IoT Devices*
(IOTSMS 2023): power-based fault injection, UART console interaction
(boot-log capture, console detection, bootloader breakout), SPI flash
extraction, and a static-analysis hand-off.

  hardware_info     -> rig diagnostics (GPIO backend, serial, capabilities)
  detect_baud       -> automatic UART baud-rate discovery
  capture_bootlog   -> power-cycle + capture + inline boot-log analysis
  uart_console      -> console/login detection + optional bootloader breakout
  serial_exec       -> execute one bounded command on the UART shell
  filesystem_dump   -> stream a flash partition off the DUT over UART (dd|base64);
                       all_partitions=True dumps EVERY /proc/mtd partition (complete)
  rootfs_archive    -> tar the LIVE mounted filesystem over UART or netcat (overlay/
                       tmpfs included) -- the running-device acquisition path
  host_block_acquire-> read-only image of a USB/SD device attached to THIS host
  adb_acquire       -> tar a filesystem off an Android-based device via adb exec-out
  power_control     -> manual relay/optocoupler switching + power cycle
  spi_identify      -> read-only SPI flash identity + write-protection state
  i2c_scan          -> I2C bus scan / bounded EEPROM-style dump
  logic_capture     -> passive logic-analyzer capture + UART/SPI/I2C decode
  spi_dump          -> (INVASIVE, gated) SPI flash read-out
  voltage_glitch    -> (INVASIVE, gated) bounded voltage fault injection

On a non-Pi host the rig operations use a mock backend and say so explicitly.
"""

from __future__ import annotations

import json
import re
import time
from typing import Literal

from pydantic import BaseModel, Field

from app.core.authorization import Safety
from app.plugins.base import (
    BasePlugin,
    EvidenceDraft,
    FindingDraft,
    ModuleResult,
    PluginContext,
    module,
)
from app.plugins.capabilities import (
    CAP_ADB,
    CAP_FLASHROM,
    CAP_GPIO,
    CAP_I2C,
    CAP_I2C_TOOLS,
    CAP_LINUX,
    CAP_LSBLK,
    CAP_PI,
    CAP_SERIAL,
    CAP_SIGROK,
    CAP_SPI,
    describe_all,
)
from app.services.bootlog import analyse_bootlog
from app.services.vuln import vuln_intel

from . import support


class BaudParams(BaseModel):
    candidates: list[int] = Field(
        default_factory=lambda: list(support.DEFAULT_BAUDS),
        description="Baud rates to try",
    )
    read_seconds: float = Field(default=3.0, ge=1.0, le=15.0)
    power_cycles: int = Field(default=1, ge=0, le=3)
    mode: str = Field(default="optocoupler",
                      description="optocoupler | relay. 'octocoupler' is a deprecated alias for optocoupler.")


class BootlogParams(BaseModel):
    baud: int = Field(default=115200, ge=300, le=2000000)
    read_seconds: float = Field(default=20.0, ge=5.0, le=120.0)
    power_cycle: bool = Field(default=True)
    mode: str = Field(default="optocoupler",
                      description="optocoupler | relay. 'octocoupler' is a deprecated alias for optocoupler.")


class ConsoleParams(BaseModel):
    baud: int = Field(default=115200, ge=300, le=2000000)
    listen_seconds: float = Field(default=6.0, ge=2.0, le=30.0)
    attempt_bootloader_breakout: bool = Field(default=True)
    mode: str = Field(default="optocoupler",
                      description="optocoupler | relay. 'octocoupler' is a deprecated alias for optocoupler.")


class PowerParams(BaseModel):
    action: str = Field(default="cycle", description="on | off | cycle")
    mode: str = Field(default="optocoupler",
                      description="optocoupler | relay. 'octocoupler' is a deprecated alias for optocoupler.")
    off_seconds: float = Field(default=1.0, ge=0.1, le=10.0)


class SpiParams(BaseModel):
    chip: str | None = Field(default=None, description="Optional flashrom chip name")
    programmer: str | None = Field(
        default=None,
        description="flashrom programmer: linux_spi (Pi spidev, default) | ch341a_spi | ft2232_spi")


class I2cParams(BaseModel):
    action: Literal["scan", "dump"] = Field(
        default="scan", description="scan the bus, or dump 256 bytes from one address")
    bus: int = Field(default=1, ge=0, le=255, description="I2C bus number, e.g. 1 on a Pi")
    address: int = Field(default=0x50, ge=0x03, le=0x77,
                         description="7-bit address for dump (0x03-0x77)")


class LogicParams(BaseModel):
    driver: str = Field(default="fx2lafw", max_length=64,
                        description="sigrok driver, e.g. fx2lafw, saleae-logic16, demo")
    channels: str = Field(default="D0,D1,D2,D3", max_length=128,
                          description="Comma-separated capture channels, e.g. D0,D1")
    protocol: Literal["uart", "spi", "i2c"] = Field(
        default="uart", description="Protocol decoder to run")
    sample_rate: int = Field(default=1_000_000, ge=1_000, le=100_000_000,
                             description="Sample rate in Hz; use >=10x the signal rate")
    duration_s: float = Field(default=5.0, ge=0.2, le=60.0)
    baudrate: int = Field(default=115200, ge=300, le=4_000_000)
    rx: str = Field(default="D0", max_length=16)
    tx: str | None = Field(default=None, max_length=16)
    scl: str = Field(default="D0", max_length=16)
    sda: str = Field(default="D1", max_length=16)
    clk: str = Field(default="D0", max_length=16)
    mosi: str = Field(default="D1", max_length=16)
    miso: str = Field(default="D2", max_length=16)
    cs: str = Field(default="D3", max_length=16)


class ShellParams(BaseModel):
    port: str | None = Field(default=None, description="Serial device (auto-resolved if omitted)")
    baud: int = Field(default=115200, ge=300, le=2000000)
    username: str | None = Field(default=None, max_length=64)
    password: str | None = Field(default=None, max_length=64,
                                 description="Empty string = blank password (common on cameras)")


class SerialExecParams(ShellParams):
    command: str = Field(min_length=1, max_length=200,
                         description="Single shell command to execute on the console")
    timeout_s: float = Field(default=30, ge=5, le=300)


class FileSystemDumpParams(ShellParams):
    partition: str | None = Field(
        default=None, description="Substring of the /proc/mtd name, e.g. 'rootfs'")
    device: str | None = Field(
        default=None, max_length=64,
        pattern=r"^/dev/(?:mtd(?:block)?\d+|mmcblk\d+(?:p\d+)?|sd[a-z](?:\d+)?)$",
        description="Explicit node, e.g. /dev/mtd5 or /dev/mmcblk0p2 (overrides partition)")
    expected_size: int | None = Field(default=None, ge=1, le=268435456,
                                      description="Required byte size for nodes absent from /proc/mtd")
    list_only: bool = Field(default=False, description="Only report the partition map")
    all_partitions: bool = Field(
        default=False,
        description="Complete acquisition: dump EVERY /proc/mtd partition (one image "
                    "each) instead of a single one. Overrides partition/device.")
    timeout_s: float = Field(default=900, ge=30, le=7200)


class RootfsArchiveParams(ShellParams):
    paths: list[str] = Field(
        default=["/etc", "/bin", "/sbin", "/usr", "/lib", "/www", "/var", "/root", "/home"],
        description="Absolute paths to archive from the LIVE filesystem. Avoid /proc /sys /dev.")
    exclude: list[str] = Field(
        default_factory=lambda: ["/proc", "/sys", "/dev", "/tmp"],  # noqa: S108 - tar exclude, not a temp path
        description="tar --exclude patterns.")
    compression: Literal["gzip", "none"] = Field(default="gzip")
    transport: Literal["serial", "netcat"] = Field(
        default="serial",
        description="serial = base64 over UART (slow, always works). netcat = DUT pushes "
                    "tar over TCP to this host (fast; needs the DUT to have an IP + nc).")
    host_ip: str | None = Field(
        default=None, max_length=45,
        description="This host's IP as seen by the DUT (netcat transport only).")
    host_port: int = Field(default=4444, ge=1, le=65535,
                           description="TCP port this host listens on (netcat transport).")
    max_bytes: int = Field(default=64 * 1024 * 1024, ge=4096, le=256 * 1024 * 1024,
                           description="Hard ceiling on the archive size.")
    timeout_s: float = Field(default=1800, ge=30, le=7200)


class HostBlockParams(BaseModel):
    device: str = Field(
        pattern=r"^/dev/(?:sd[a-z]\d*|mmcblk\d+(?:p\d+)?)$",
        description="Block node on THIS host, e.g. /dev/sdb or /dev/mmcblk0 "
                    "(USB mass-storage / SD reader). Run `list_only` first to see candidates.")
    confirm: str = Field(
        default="",
        description="Retype the exact device path to authorize imaging (safety interlock).")
    list_only: bool = Field(default=False, description="Only inventory host block devices.")
    max_bytes: int = Field(default=0, ge=0, le=64 * 1024 * 1024 * 1024,
                           description="0 = whole device; otherwise cap the image size (bytes).")
    use_ddrescue: bool = Field(default=False,
                               description="Use ddrescue (resilient to read errors) instead of dd.")
    timeout_s: int = Field(default=3600, ge=30, le=14400)


class AdbParams(BaseModel):
    serial: str | None = Field(default=None, max_length=128,
                               description="adb device serial (omit if exactly one is attached).")
    paths: list[str] = Field(
        default=["/system", "/vendor", "/data/local"],
        description="Absolute paths to tar off the Android device via adb exec-out.")
    list_only: bool = Field(default=False, description="Only list attached adb devices.")
    timeout_s: int = Field(default=1800, ge=30, le=7200)


class GlitchParams(BaseModel):
    pin: int | None = Field(default=None, ge=1, le=27,
                            description="BCM pin for the pulse train (overrides VOLTAGE_GLITCH_PIN)")
    on_us: int = Field(default=5000, ge=50, le=500000, description="Pulse ON width (µs)")
    off_us: int = Field(default=5000, ge=50, le=500000, description="Pulse OFF width (µs)")
    duration_s: float = Field(default=2.0, ge=0.1, le=120.0)
    mode: str = Field(default="optocoupler",
                      description="optocoupler | relay. 'octocoupler' is a deprecated alias for optocoupler.")


class HardwarePlugin(BasePlugin):
    name = "hardware"
    domain = "hardware"
    title = "Hardware Testbed (UART / SPI / I2C / Logic)"
    description = (
        "Automated hardware auditing: UART baud discovery and console interaction, "
        "boot-log capture, SPI/I2C acquisition, passive logic decoding, power control, "
        "bounded fault injection, and firmware hand-off."
    )

    # ------------------------------------------------------------------ #
    @module(
        name="hardware_info",
        title="Rig diagnostics",
        safety=Safety.PASSIVE,
        tags=["status"],
    )
    def hardware_info(self, ctx: PluginContext, _: BaseModel) -> ModuleResult:
        """Report the hardware rig state so operators know what is live vs mocked."""
        gpio, backend = support.get_gpio()
        ports = support.list_serial_ports()
        serial_available = bool(ports)
        probes = support.usb_debug_probes()
        i2c_buses = support.bus_nodes("/dev/i2c-*")
        spi_buses = support.bus_nodes("/dev/spidev*")
        readiness = {
            "uart": serial_available,
            "gpio_automation": backend != "mock",
            "spi": support.has_tool("flashrom") and bool(spi_buses or probes),
            "i2c": support.has_tool("i2cdetect") and bool(i2c_buses),
            "logic_decode": support.has_tool("sigrok-cli"),
        }
        data = {
            "gpio_backend": backend,
            "gpio_is_mock": backend == "mock",
            "serial_ports": ports,
            "uart_port": support.resolve_serial_port(),
            "debug_probes": probes,
            "storage_devices": support.storage_devices(),
            "i2c_buses": i2c_buses,
            "spi_buses": spi_buses,
            "logic_analyzer_available": support.has_tool("sigrok-cli"),
            "readiness": readiness,
            "capabilities": describe_all([
                CAP_PI, CAP_GPIO, CAP_SERIAL, CAP_SPI, CAP_I2C, CAP_I2C_TOOLS,
                CAP_SIGROK, CAP_FLASHROM,
            ]),
            "ready_for_physical_tests": any(readiness.values()),
        }
        note = ""
        if backend == "mock" and serial_available:
            note = ("UART/USB hardware is available, but GPIO power/glitch actions are mock "
                    "no-ops. A Raspberry Pi is only required for GPIO automation.")
        elif backend == "mock":
            note = ("No live UART/GPIO rig detected. Firmware and network workflows still work; "
                    "connect USB probes or use a Raspberry Pi for physical tests.")
        elif not serial_available:
            note = ("GPIO is live but no serial port is detected; connect USB-TTL or enable "
                    "the Pi UART for console workflows.")
        return ModuleResult(data=data, summary=note or "At least one physical interface is ready.")

    # ------------------------------------------------------------------ #
    @module(
        name="spi_identify",
        title="Identify SPI flash (read-only)",
        safety=Safety.ACTIVE,
        params_model=SpiParams,
        capabilities=[CAP_FLASHROM],
        tags=["spi", "recon"],
    )
    def spi_identify(self, ctx: PluginContext, params: SpiParams) -> ModuleResult:
        """Read JEDEC identity, capacity and write-protection state without writing."""
        ctx.progress(20, "probing SPI flash identity")
        result = support.spi_identify(chip=params.chip, programmer=params.programmer)
        if not result.get("ok"):
            return ModuleResult(data=result,
                                summary=f"SPI identify failed: {result.get('error', 'flashrom error')}")
        ctx.progress(80, "recording identity and write-protection state")
        wp = result.get("write_protection") or {}
        findings: list[FindingDraft] = []
        if wp.get("supported") and wp.get("mode") == "disabled":
            findings.append(FindingDraft(
                title="SPI flash write protection is disabled",
                category="spi-write-protection",
                severity="medium",
                description="The attached SPI NOR flash reports no active write protection. "
                            "An attacker with physical access can reprogram or replace the "
                            "firmware unless integrity is enforced elsewhere (secure boot).",
                remediation="Enable the flash status-register block protection, verify secure "
                            "boot/root-of-trust, and use tamper-evident packaging.",
                evidence=json.dumps(wp, indent=2)[:1200],
                extra={"chip": result.get("chip"), "vendor": result.get("vendor")},
            ))
        ev = ctx.save_evidence(EvidenceDraft(
            kind="spi-identity", filename=f"spi_identity_{int(time.time())}.json",
            content=json.dumps(result, indent=2).encode(),
            note="read-only flashrom identity + write-protection state",
        ))
        wp_text = wp.get("mode", "unknown")
        return ModuleResult(
            data=result, findings=findings, evidence=[ev],
            summary=f"{result.get('vendor') or 'unknown vendor'} "
                    f"{result.get('chip') or 'unknown chip'}, "
                    f"{result.get('size_human') or 'unknown size'}; write protection: {wp_text}.",
        )

    # ------------------------------------------------------------------ #
    @module(
        name="i2c_scan",
        title="Scan / read I2C bus",
        safety=Safety.ACTIVE,
        params_model=I2cParams,
        capabilities=[CAP_I2C, CAP_I2C_TOOLS],
        tags=["i2c", "recon"],
    )
    def i2c_scan(self, ctx: PluginContext, params: I2cParams) -> ModuleResult:
        """Enumerate I2C addresses or read a bounded dump from one address.

        Use this for board bring-up, EEPROM/SPD discovery and sensor inventory.
        A bus scan is not proof of a vulnerability; the result records what
        responded so the operator can decide what to probe next.
        """
        if params.action == "dump":
            ctx.progress(30, f"reading I2C bus {params.bus} address 0x{params.address:02x}")
            result = support.i2c_dump(params.bus, params.address)
            if not result.get("ok"):
                return ModuleResult(data=result,
                                    summary=f"I2C dump failed: {result.get('error')}")
            findings: list[FindingDraft] = []
            if not result.get("responded"):
                findings.append(FindingDraft(
                    title=f"No I2C response at 0x{params.address:02x} on bus {params.bus}",
                    category="i2c-recon",
                    severity="info",
                    description="i2cdump returned only XX bytes. Check the address, wiring, "
                                "pull-ups and whether the device is powered.",
                    evidence=result.get("raw", "")[:800],
                ))
            ev = ctx.save_evidence(EvidenceDraft(
                kind="i2c-dump", filename=f"i2c_{params.bus}_{params.address:02x}_{int(time.time())}.txt",
                content=(result.get("raw") or "").encode(),
                note=f"I2C dump bus {params.bus} address 0x{params.address:02x}",
            ))
            return ModuleResult(
                data=result, findings=findings, evidence=[ev],
                summary=f"I2C bus {params.bus} address 0x{params.address:02x}: "
                        f"{'responded' if result.get('responded') else 'no response'}.",
            )

        ctx.progress(30, f"scanning I2C bus {params.bus}")
        result = support.i2c_scan(params.bus)
        if not result.get("ok"):
            return ModuleResult(data=result,
                                summary=f"I2C scan failed: {result.get('error')}")
        devices = result.get("devices") or []
        findings = []
        if devices:
            findings.append(FindingDraft(
                title=f"I2C bus {params.bus} exposes {len(devices)} device(s)",
                category="i2c-recon",
                severity="info",
                description="I2C addresses responded to a read-byte scan. This is an "
                            "inventory result, not a vulnerability; inspect EEPROMs and "
                            "debug/control devices for sensitive data or writable state.",
                evidence=", ".join(d["address"] for d in devices),
                extra={"bus": params.bus, "addresses": [d["address"] for d in devices]},
            ))
        eeproms = [d["address"] for d in devices if 0x50 <= int(d["address"], 16) <= 0x57]
        if eeproms:
            findings.append(FindingDraft(
                title=f"I2C EEPROM/SPD candidate(s) detected on bus {params.bus}",
                category="i2c-eeprom",
                severity="low",
                description="Addresses 0x50-0x57 commonly hold EEPROM/SPD data. Such parts "
                            "may contain serial numbers, calibration data, credentials or "
                            "writable configuration; confirm with a read-only dump.",
                remediation="Protect sensitive EEPROM contents, enforce write protection, "
                            "and do not store secrets in plaintext on accessible buses.",
                evidence=", ".join(eeproms),
                extra={"bus": params.bus, "addresses": eeproms},
            ))
        ev = ctx.save_evidence(EvidenceDraft(
            kind="i2c-scan", filename=f"i2c_scan_{params.bus}_{int(time.time())}.txt",
            content=(result.get("raw") or "").encode(),
            note=f"I2C bus scan on bus {params.bus}",
        ))
        return ModuleResult(
            data=result, findings=findings, evidence=[ev],
            summary=f"I2C bus {params.bus}: {len(devices)} device(s) responded.",
        )

    # ------------------------------------------------------------------ #
    @module(
        name="logic_capture",
        title="Decode a logic-analyzer capture",
        safety=Safety.ACTIVE,
        params_model=LogicParams,
        capabilities=[CAP_SIGROK],
        tags=["logic-analyzer", "uart", "spi", "i2c"],
    )
    def logic_capture(self, ctx: PluginContext, params: LogicParams) -> ModuleResult:
        """Passively capture and decode UART/SPI/I2C with sigrok-cli.

        This is the bridge between a $10 logic analyzer and the testbed: it
        captures a bounded trace, decodes the selected protocol, and stores the
        decoded transcript as evidence. It never drives the target's bus.
        """
        if params.protocol == "uart":
            options = {"baudrate": str(params.baudrate), "rx": params.rx}
            if params.tx:
                options["tx"] = params.tx
        elif params.protocol == "i2c":
            options = {"scl": params.scl, "sda": params.sda}
        else:
            options = {"clk": params.clk, "mosi": params.mosi,
                       "miso": params.miso, "cs": params.cs}
        ctx.progress(20, f"capturing {params.protocol} for {params.duration_s:g}s")
        result = support.logic_capture(
            driver=params.driver, channels=params.channels, protocol=params.protocol,
            sample_rate=params.sample_rate, duration_s=params.duration_s,
            decoder_options=options,
        )
        if not result.get("ok"):
            return ModuleResult(data=result,
                                summary=f"Logic capture failed: {result.get('error')}")
        ctx.progress(85, "saving decoded transcript")
        ev = ctx.save_evidence(EvidenceDraft(
            kind="logic-capture",
            filename=f"logic_{params.protocol}_{int(time.time())}.txt",
            content=(f"argv: {' '.join(result.get('argv', []))}\n\n"
                     f"{result.get('decoded', '')}").encode()[:2_000_000],
            note=f"{params.protocol} logic capture on {params.driver} ({params.channels})",
        ))
        findings: list[FindingDraft] = []
        if result.get("line_count", 0) == 0:
            findings.append(FindingDraft(
                title=f"No {params.protocol} frames decoded from logic capture",
                category="logic-capture",
                severity="info",
                description="The capture completed but produced no decoded annotations. "
                            "Check channel mapping, common ground, logic voltage, sample "
                            "rate (>=10x signal rate), baud rate and decoder options.",
                evidence=result.get("decoded", "")[:800],
                extra={"protocol": params.protocol, "channels": params.channels},
            ))
        return ModuleResult(
            data=result, findings=findings, evidence=[ev],
            summary=f"{params.protocol} capture: {result.get('line_count', 0)} decoded "
                    f"line(s) over {params.duration_s:g}s.",
        )

    # ------------------------------------------------------------------ #
    @module(
        name="detect_baud",
        title="Auto-detect UART baud rate",
        safety=Safety.ACTIVE,
        params_model=BaudParams,
        capabilities=[CAP_SERIAL, CAP_GPIO],
        tags=["uart"],
    )
    def detect_baud(self, ctx: PluginContext, params: BaudParams) -> ModuleResult:
        """Try candidate baud rates, scoring captured output for boot-log quality."""
        port = support.resolve_serial_port()
        if not port:
            return ModuleResult(data={"error": "no serial port"},
                                summary="No serial port available for baud detection.")

        power = support.PowerController(mode=params.mode)
        results: list[support.BaudCandidate] = []
        total = len(params.candidates)
        for i, baud in enumerate(params.candidates):
            ctx.progress(int(10 + 80 * i / max(1, total)), f"trying {baud} baud")
            buf = b""
            # Open the port *before* any power cycle so early boot output
            # (bootloader banner) is not lost between open and read.
            with support.open_serial(port, baud) as handle:
                if params.power_cycles:
                    for _ in range(params.power_cycles):
                        if not power.is_mock():
                            power.cycle(off_seconds=0.8)
                        buf += support.read_serial_from(
                            handle, params.read_seconds, cancel_cb=ctx.cancelled
                        )
                else:
                    buf += support.read_serial_from(
                        handle, params.read_seconds, cancel_cb=ctx.cancelled
                    )
            results.append(
                support.BaudCandidate(
                    baud=baud, score=support.score_output(buf), bytes_read=len(buf),
                    sample=buf.decode("latin-1", errors="replace"),
                )
            )
        results.sort(key=lambda c: c.score, reverse=True)
        best = results[0] if results else None
        ctx.progress(95, f"best candidate: {best.baud if best else 'n/a'}")

        findings: list[FindingDraft] = []
        if best and best.score > 0:
            findings.append(
                FindingDraft(
                    title=f"UART console active at {best.baud} baud",
                    category="uart-console",
                    severity="medium",
                    description="A readable UART console was detected. An exposed console can "
                                "lead to boot-log leakage, credential brute-force, and "
                                "bootloader breakout.",
                    remediation="Disable the UART console in production or gate it with a unique "
                                "password and disabled bootloader prompt.",
                    evidence=best.sample[:1500],
                    extra={"baud": best.baud, "score": best.score},
                )
            )
        elif power.is_mock():
            findings.append(
                FindingDraft(
                    title="Baud detection ran on a mock rig (no real signal)",
                    category="rig-status",
                    severity="info",
                    description="No physical UART was present; results are not meaningful.",
                )
            )
        return ModuleResult(
            data={"port": port, "best_baud": best.baud if best else None,
                  "candidates": [c.to_dict() for c in results],
                  "mock": power.is_mock()},
            findings=findings,
            summary=f"Best baud {best.baud} (score {best.score:.2f})" if best else "no candidates",
        )

    # ------------------------------------------------------------------ #
    @module(
        name="capture_bootlog",
        title="Capture & analyse boot log",
        safety=Safety.ACTIVE,
        params_model=BootlogParams,
        capabilities=[CAP_SERIAL],
        tags=["uart", "bootlog"],
    )
    def capture_bootlog(self, ctx: PluginContext, params: BootlogParams) -> ModuleResult:
        """Power-cycle the DUT and capture its boot log, then analyse it."""
        port = support.resolve_serial_port()
        if not port:
            return ModuleResult(data={"error": "no serial port"},
                                summary="No serial port available for boot-log capture.")
        power = support.PowerController(mode=params.mode)
        findings: list[FindingDraft] = []
        with support.open_serial(port, params.baud) as handle:
            if handle is None:
                return ModuleResult(
                    data={"port": port, "baud": params.baud, "error": "serial-open-failed"},
                    summary=f"Could not open serial port {port} (is it occupied / is "
                            "pyserial installed?).",
                )
            ctx.progress(15, "power-cycling target")
            if params.power_cycle and not power.is_mock():
                power.cycle(off_seconds=1.0)
            elif params.power_cycle:
                ctx.log("power cycle skipped (mock GPIO)")
            ctx.progress(35, f"capturing {params.read_seconds:.0f}s at {params.baud} baud")
            raw = support.read_serial_from(handle, params.read_seconds, cancel_cb=ctx.cancelled)
        text = raw.decode("latin-1", errors="replace")
        ctx.progress(65, "analysing boot log")
        report = analyse_bootlog(text)

        for f in report.findings:
            findings.append(
                FindingDraft(
                    title=f.title, category=f.category, severity=f.severity,
                    description=f.description, remediation=f.remediation,
                    evidence=f.evidence, extra=f.extra,
                )
            )
        # Map versions/tokens to CVEs.
        ctx.progress(85, "mapping boot-log tokens to CVEs")
        hits = vuln_intel.search_keywords(report.tokens[:8] + report.versions[:4], limit=20)
        for h in hits:
            findings.append(
                FindingDraft(
                    title=f"{h.id} referenced by boot-log component ({h.matched_on})",
                    category="firmware-cve",
                    severity=_sev(h.severity, h.cvss),
                    description=h.description[:1200], cvss_score=h.cvss, epss_score=h.epss,
                    cve_ids=[h.id], references=h.references,
                )
            )
        ev = ctx.save_evidence(
            EvidenceDraft(kind="bootlog", filename=f"bootlog_{int(time.time())}.txt",
                          content=raw or b"(empty capture)",
                          note=f"UART boot log captured at {params.baud} baud from {port}")
        )
        if power.is_mock() and not raw:
            ctx.log("no UART data (mock GPIO backend - connect the rig for live capture)",
                    level="warn")
        return ModuleResult(
            data={"baud": params.baud, "port": port, "bytes": len(raw),
                  "bootlog_analysis": report.to_dict(),
                  "cves": [h.to_dict() for h in hits], "preview": text[:3000],
                  "mock": power.is_mock()},
            findings=findings, evidence=[ev],
            summary=f"Captured {len(raw)} bytes; {len(report.findings)} boot-log finding(s), "
                    f"{len(hits)} CVE(s).",
        )

    # ------------------------------------------------------------------ #
    @module(
        name="uart_console",
        title="Detect UART console / login",
        safety=Safety.ACTIVE,
        params_model=ConsoleParams,
        capabilities=[CAP_SERIAL],
        tags=["uart", "console"],
    )
    def uart_console(self, ctx: PluginContext, params: ConsoleParams) -> ModuleResult:
        """Listen on the UART and, if a bootloader/console is found, try a safe breakout."""
        port = support.resolve_serial_port()
        if not port:
            return ModuleResult(data={"error": "no serial port"}, summary="No serial port.")
        with support.open_serial(port, params.baud) as handle:
            if handle is None:
                return ModuleResult(
                    data={"port": port, "baud": params.baud, "error": "serial-open-failed"},
                    summary=f"Could not open serial port {port}.",
                )
            ctx.progress(30, "listening for console output")
            raw = support.read_serial_from(handle, params.listen_seconds, cancel_cb=ctx.cancelled)
            text = raw.decode("latin-1", errors="replace")
            lowered = text.lower()

            console_type = "none"
            if "login:" in lowered:
                console_type = "login-prompt"
            elif "u-boot" in lowered or "=>" in text:
                console_type = "u-boot"
            elif "grub" in lowered:
                console_type = "grub"
            elif text.strip():
                console_type = "serial-output"

            breakout = None
            if console_type == "u-boot" and params.attempt_bootloader_breakout:
                ctx.progress(65, "attempting bootloader interruption")
                # Interrupt autoboot with a newline-space burst; then listen again.
                sent = support.write_serial_to(handle, b" " * 8)
                time.sleep(1.0)
                post = support.read_serial_from(handle, 3.0, cancel_cb=ctx.cancelled)
                post_text = post.decode("latin-1", errors="replace")
                breakout = {"interrupted": "=>" in post_text or "u-boot" in post_text.lower(),
                            "output": post_text[:1500], "sent_break_key": sent}

        findings: list[FindingDraft] = []
        if console_type in ("u-boot", "grub"):
            findings.append(
                FindingDraft(
                    title=f"Bootloader console reachable ({console_type})",
                    category="bootloader",
                    severity="critical",
                    description="The bootloader prompt is reachable over UART. This permits "
                                "boot-argument tampering (e.g. init=/bin/sh) and full device "
                                "control if the flash is not integrity-protected.",
                    remediation="Password-protect the bootloader, set bootdelay=0, enable secure "
                                "boot, and disable the production UART.",
                    evidence=text[:1500], extra=breakout or {},
                )
            )
        elif console_type == "login-prompt":
            findings.append(
                FindingDraft(
                    title="Interactive login prompt on serial console",
                    category="console-login",
                    severity="medium",
                    description="A login prompt is exposed on UART; it is not protected by network "
                                "rate-limiting or CAPTCHA and enables offline brute-force.",
                    remediation="Disable the console login in production or enforce a unique, "
                                "strong credential.",
                    evidence=text[:1000],
                )
            )
        return ModuleResult(
            data={"port": port, "baud": params.baud, "console_type": console_type,
                  "breakout": breakout, "preview": text[:3000]},
            findings=findings,
            summary=f"Console type: {console_type}.",
        )

    # ------------------------------------------------------------------ #
    @module(
        name="serial_exec",
        title="Execute a command on the UART shell",
        safety=Safety.ACTIVE,
        params_model=SerialExecParams,
        capabilities=[CAP_SERIAL],
        tags=["uart", "console"],
    )
    def serial_exec(self, ctx: PluginContext, params: SerialExecParams) -> ModuleResult:
        """Run one bounded command on an established serial shell session."""
        port = params.port or support.resolve_serial_port()
        if not port:
            return ModuleResult(data={"error": "no serial port"}, summary="No serial port.")
        with support.open_serial(port, params.baud) as handle:
            if handle is None:
                return ModuleResult(data={"port": port, "error": "serial-open-failed"},
                                    summary=f"Could not open serial port {port}.")
            login = None
            if params.username is not None:
                login = support.serial_login(
                    handle, params.username, params.password or "",
                    timeout_s=60, cancel_cb=ctx.cancelled)
                if not login["logged_in"]:
                    return ModuleResult(
                        data={"port": port, "login": login},
                        summary=f"Login failed on {port} (transcript kept as evidence).")
            ctx.progress(40, "executing command")
            try:
                output = support.serial_command(handle, params.command,
                                                timeout_s=params.timeout_s,
                                                cancel_cb=ctx.cancelled)
            except (ValueError, RuntimeError) as exc:
                return ModuleResult(data={"error": str(exc)}, summary=str(exc))
        ctx.progress(90, "done")
        ev = ctx.save_evidence(
            EvidenceDraft(kind="uart", filename=f"serial_exec_{int(time.time())}.txt",
                          content=(f"$ {params.command}\n{output}").encode(),
                          note=f"UART exec '{params.command}' on {port}")
        )
        return ModuleResult(
            data={"port": port, "baud": params.baud, "command": params.command,
                  "output": output[:4000], "login": login},
            findings=[],
            evidence=[ev],
            summary=f"Executed '{params.command}' on {port} "
                    f"({len(output)} bytes of output).",
        )

    # ------------------------------------------------------------------ #
    @module(
        name="filesystem_dump",
        title="Acquire filesystem over UART shell",
        safety=Safety.ACTIVE,
        params_model=FileSystemDumpParams,
        capabilities=[CAP_SERIAL],
        tags=["uart", "exfiltration"],
    )
    def filesystem_dump(self, ctx: PluginContext, params: FileSystemDumpParams) -> ModuleResult:
        """Recover the DUT filesystem over the serial console (``dd | base64``).

        The canonical camera pipeline: establish a shell, enumerate ``/proc/mtd``,
        stream the rootfs partition out the UART at line speed, and hand the
        image to the firmware domain for unpacking, secrets and CVE mapping.
        Partial transfers are kept as evidence; nothing is assumed.
        """
        port = params.port or support.resolve_serial_port()
        if not port:
            return ModuleResult(data={"error": "no serial port"}, summary="No serial port.")

        with support.open_serial(port, params.baud) as handle:
            if handle is None:
                return ModuleResult(data={"port": port, "error": "serial-open-failed"},
                                    summary=f"Could not open serial port {port}.")

            # A shell may already be live (no login); probe before prompting.
            # The probe verdict is *parsed rows*, not a substring of the raw
            # transcript — shell echo / fallback text must not count as a live
            # mtd interface.
            login = None
            if params.username is not None:
                ctx.progress(20, "logging in over serial")
                login = support.serial_login(handle, params.username, params.password or "",
                                             timeout_s=60, cancel_cb=ctx.cancelled)
                if not login["logged_in"]:
                    return ModuleResult(
                        data={"port": port, "login": login},
                        summary=f"Login failed on {port}; transcript kept for evidence.")
            try:
                mtd_text = support.serial_command(handle, "cat /proc/mtd",
                                                  timeout_s=20, cancel_cb=ctx.cancelled)
            except RuntimeError as exc:
                return ModuleResult(data={"error": str(exc)}, summary=f"Shell unavailable: {exc}")
            part_map = support.parse_proc_mtd(mtd_text)

            if params.all_partitions:
                if not part_map:
                    return ModuleResult(
                        data={"port": port, "raw": mtd_text[:2000]},
                        summary="all_partitions set but /proc/mtd is empty — this device "
                                "is not MTD/NAND; use rootfs_archive (tar) or dump an "
                                "mmc/sd node explicitly.")
                evidences: list[EvidenceDraft] = []
                manifest: list[dict] = []
                total = len(part_map)
                for idx, p in enumerate(part_map):
                    if ctx.cancelled():
                        break
                    base = 5 + int(90 * idx / max(1, total))
                    ctx.progress(base, f"dumping {p['dev']} ({p['name']}) [{idx + 1}/{total}]")
                    res = support.serial_dump_mtd(
                        handle, p["dev"], p["size"],
                        timeout_s=params.timeout_s, cancel_cb=ctx.cancelled,
                        progress_cb=lambda done, tot, b=base, s=100 // max(1, total):
                            ctx.progress(min(95, b + int(s * done / max(1, tot)))),
                    )
                    payload = res.get("payload", b"")
                    ev = None
                    if payload:
                        ev = ctx.save_evidence(EvidenceDraft(
                            kind="filesystem",
                            filename=f"{p['dev'].replace('/', '_')}_{p['name']}_{int(time.time())}.bin",
                            content=payload,
                            note=f"partition '{p['name']}' ({p['dev']}) over UART {port}"))
                        evidences.append(ev)
                    manifest.append({
                        "name": p["name"], "dev": p["dev"], "declared_size": p["size"],
                        "recovered": len(payload), "ok": bool(res.get("ok")),
                        "sha256": ev.sha256 if ev else None,
                        "evidence": ev.filename if ev else None,
                        "error": res.get("error"),
                    })
                ok_n = sum(1 for m in manifest if m["ok"])
                findings = [FindingDraft(
                    title=f"Complete flash acquisition over serial: {ok_n}/{total} partitions ({port})",
                    category="uart-fs",
                    severity="medium" if ok_n else "low",
                    description="Every exposed /proc/mtd partition was streamed off the device "
                                "through the serial shell. Any shell access therefore yields the "
                                "whole flash (bootloader, kernel, rootfs, config). Local SHA-256 "
                                "hashes identify the saved bytes; they are not target-side checksums.",
                    remediation="Lock the bootloader, disable the console login, and encrypt "
                                "on-flash filesystems on high-value devices.",
                    evidence="; ".join(f"{m['name']}={m['recovered']}B" for m in manifest),
                    extra={"manifest": manifest, "partitions_ok": ok_n, "partitions_total": total},
                )]
                ctx.progress(100, f"acquired {ok_n}/{total} partitions")
                return ModuleResult(
                    data={"port": port, "baud": params.baud, "mode": "all_partitions",
                          "manifest": manifest, "partitions_ok": ok_n,
                          "partitions_total": total},
                    findings=findings, evidence=evidences,
                    summary=f"Complete dump: {ok_n}/{total} partitions off {port} "
                            f"({sum(m['recovered'] for m in manifest)} bytes) — "
                            "analyse each image with the firmware domain.")

            if params.list_only or not (params.device or params.partition):
                ctx.progress(100, "partition map collected")
                findings: list[FindingDraft] = []
                if part_map:
                    findings.append(FindingDraft(
                        title=f"Flash partitions enumerated over serial ({port})",
                        category="uart-fs",
                        severity="low",
                        description="The console exposes the flash partition map; "
                                    "partitions can be streamed off the device with any "
                                    "shell access.",
                        remediation="Restrict console access and lock the bootloader.",
                        evidence="; ".join(p["name"] for p in part_map),
                        extra={"partitions": part_map},
                    ))
                return ModuleResult(
                    data={"port": port, "baud": params.baud, "partitions": part_map,
                          "raw": mtd_text[:2000]},
                    findings=findings,
                    summary=f"{len(part_map)} partition(s) on {port}."
                            + ("" if part_map else " No /proc/mtd - set `device` manually "
                               "(e.g. /dev/mmcblk0p2)."),
                )

            # Resolve the dump target.
            if params.device:
                dev, part = params.device, next(
                    (p for p in part_map if p["dev"] == params.device), None)
            else:
                matches = [p for p in part_map if params.partition.lower() in p["name"].lower()]
                if len(matches) != 1:
                    return ModuleResult(
                        data={"partitions": part_map, "requested": params.partition},
                        summary=f"Select one unambiguous /proc/mtd partition for '{params.partition}'. "
                                f"Available: {[p['name'] for p in part_map]}")
                part = matches[0]
                dev = part["dev"]

            size = part["size"] if part else params.expected_size
            if not size:
                return ModuleResult(data={"error": "expected_size required"},
                                    summary="Specify the known partition byte size; it is not in /proc/mtd.")
            eta = f"{size * 4 / 3 * 10 / params.baud / 60:.1f} min at {params.baud} baud"
            ctx.progress(30, f"streaming {dev} ({eta} estimated)")

            def _progress(done: int, total: int) -> None:
                ctx.progress(30 + int(60 * done / max(1, total)), f"{done}/{total} bytes")

            result = support.serial_dump_mtd(
                handle, dev, size,
                timeout_s=params.timeout_s, cancel_cb=ctx.cancelled,
                progress_cb=(None if size is None else _progress),
            )
            payload = result["payload"]

        ev = None
        if payload:
            ev = ctx.save_evidence(
                EvidenceDraft(kind="filesystem",
                              filename=f"{dev.replace('/', '_')}_{int(time.time())}.bin",
                              content=payload,
                              note=f"filesystem dump of {dev} over UART {port}")
            )
        findings = []
        if result.get("ok"):
            findings.append(FindingDraft(
                title=f"DUT filesystem extracted over serial console ({dev})",
                category="uart-fs",
                severity="info",
                description="A size-matched partition image was recovered through the serial "
                            "shell. This records acquisition, not an authentication bypass. "
                            "The local SHA-256 identifies the saved bytes; it does not verify "
                            "them against a checksum from the target.",
                remediation="Lock the bootloader, disable console login, and encrypt "
                            "on-flash filesystems for high-value devices.",
                evidence=f"sha256={ev.sha256 if ev else '-'} size={len(payload)}",
                extra={"device": dev, "size": len(payload)},
            ))
        elif payload:
            findings.append(FindingDraft(
                title=f"Partial filesystem dump recovered ({dev})",
                category="uart-fs",
                severity="medium",
                description=result.get("error", "stream interrupted"),
                remediation="Retry with a longer timeout or lower baud; the partial image "
                            "may still contain recoverable files.",
                evidence=f"bytes={len(payload)}",
            ))
        summary = (f"Extracted {len(payload)} bytes from {dev} "
                   f"(sha256 {ev.sha256[:12]}…) — analyse it with the firmware domain."
                   if result.get("ok") and ev else
                   f"Dump incomplete: {result.get('error', 'no data')}")
        ctx.progress(100, summary)
        data_outcome = {k: v for k, v in result.items() if k != "payload"}
        return ModuleResult(
            data={"port": port, "baud": params.baud, "device": dev,
                  "partition": part, "size": len(payload),
                  "sha256": ev.sha256 if ev else None,
                  "outcome": data_outcome, "evidence": ev.filename if ev else None,
                  "path": ev.path if ev else None},
            findings=findings,
            evidence=[ev] if ev else [],
            summary=summary,
        )

    # ------------------------------------------------------------------ #
    @module(
        name="rootfs_archive",
        title="Archive live filesystem (tar)",
        safety=Safety.ACTIVE,
        params_model=RootfsArchiveParams,
        capabilities=[CAP_SERIAL],
        tags=["uart", "exfiltration", "filesystem"],
    )
    def rootfs_archive(self, ctx: PluginContext, params: RootfsArchiveParams) -> ModuleResult:
        """Capture the *running* filesystem of a live device as a tar(.gz).

        Unlike ``filesystem_dump`` (block-level ``dd`` of a flash partition),
        this walks the mounted rootfs over the shell — overlay, tmpfs and
        unpacked-squashfs included — which is what you actually want from a
        booted camera/router. Transports: base64 over UART (slow, universal)
        or a TCP push via netcat (fast, needs an IP on the DUT). The archive is
        handed to the firmware domain for carving.
        """
        port = params.port or support.resolve_serial_port()
        if not port:
            return ModuleResult(data={"error": "no serial port"}, summary="No serial port.")
        with support.open_serial(port, params.baud) as handle:
            if handle is None:
                return ModuleResult(data={"port": port, "error": "serial-open-failed"},
                                    summary=f"Could not open serial port {port}.")
            if params.username is not None:
                ctx.progress(15, "logging in over serial")
                login = support.serial_login(handle, params.username, params.password or "",
                                             timeout_s=60, cancel_cb=ctx.cancelled)
                if not login["logged_in"]:
                    return ModuleResult(data={"port": port, "login": login},
                                        summary=f"Login failed on {port}; transcript kept.")
            ext = "tar.gz" if params.compression == "gzip" else "tar"

            if params.transport == "netcat":
                if not params.host_ip or not re.fullmatch(r"[0-9a-fA-F:.]{3,45}", params.host_ip):
                    return ModuleResult(
                        data={"port": port},
                        summary="netcat transport needs a valid host_ip (this host's IP "
                                "as the DUT sees it).")
                out = ctx.workdir / f"rootfs_{int(time.time())}.{ext}"
                comp = "| gzip -c " if params.compression == "gzip" else ""
                excl = "".join(f" --exclude={e}" for e in params.exclude)
                dev_cmd = (f"tar cf - {' '.join(params.paths)}{excl} 2>/dev/null {comp}"
                           f"| nc {params.host_ip} {params.host_port}\n")
                ctx.progress(30, f"listening on :{params.host_port}; triggering DUT push")
                result = support.net_exfil_receive(
                    str(out), port=params.host_port, timeout_s=params.timeout_s,
                    max_bytes=params.max_bytes, cancel_cb=ctx.cancelled,
                    trigger_cb=lambda: support.write_serial_to(handle, dev_cmd.encode()),
                )
                payload = out.read_bytes() if out.exists() else b""
            else:
                ctx.progress(30, "streaming tar over UART (base64)")
                result = support.serial_tar_archive(
                    handle, params.paths, compression=params.compression,
                    exclude=params.exclude, max_bytes=params.max_bytes,
                    timeout_s=params.timeout_s, cancel_cb=ctx.cancelled,
                    progress_cb=lambda n: ctx.progress(
                        min(95, 30 + int(60 * n / max(1, params.max_bytes)))),
                )
                payload = result.get("payload", b"")

        ev = None
        if payload:
            ev = ctx.save_evidence(EvidenceDraft(
                kind="filesystem", filename=f"rootfs_{int(time.time())}.{ext}",
                content=payload,
                note=f"live rootfs archive ({params.transport}) from {port}"))
        findings: list[FindingDraft] = []
        if result.get("ok") and ev:
            findings.append(FindingDraft(
                title=f"Live filesystem archived from running device ({port})",
                category="uart-fs", severity="info",
                description="The mounted filesystem (including overlay/tmpfs) was captured over "
                            f"the {params.transport} transport. This records acquisition from an "
                            "existing shell, not an authentication bypass.",
                remediation="Disable the console login and restrict shell access; encrypt "
                            "sensitive on-device data.",
                evidence=f"sha256={ev.sha256} size={len(payload)}",
                extra={"paths": params.paths, "transport": params.transport}))
        elif payload:
            findings.append(FindingDraft(
                title=f"Partial filesystem archive recovered ({port})",
                category="uart-fs", severity="low",
                description=result.get("error", "stream interrupted"),
                remediation="Retry with fewer paths, gzip on, or the netcat transport for speed.",
                evidence=f"bytes={len(payload)}"))
        summary = (f"Archived {len(payload)} bytes of live rootfs (sha256 {ev.sha256[:12]}…) — "
                   "carve it with the firmware domain." if (result.get("ok") and ev)
                   else f"Archive incomplete: {result.get('error', 'no data')}")
        ctx.progress(100, summary)
        return ModuleResult(
            data={"port": port, "transport": params.transport, "size": len(payload),
                  "sha256": ev.sha256 if ev else None,
                  "outcome": {k: v for k, v in result.items() if k != "payload"},
                  "evidence": ev.filename if ev else None, "path": ev.path if ev else None},
            findings=findings, evidence=[ev] if ev else [], summary=summary)

    # ------------------------------------------------------------------ #
    @module(
        name="host_block_acquire",
        title="Acquire USB/SD device attached to this host",
        safety=Safety.ACTIVE,
        params_model=HostBlockParams,
        capabilities=[CAP_LINUX, CAP_LSBLK],
        tags=["usb", "firmware-extraction", "filesystem"],
    )
    def host_block_acquire(self, ctx: PluginContext, params: HostBlockParams) -> ModuleResult:
        """Read-only image of a device plugged into the PC (USB mass-storage / SD).

        The 'connected to the PC directly' path: when a camera exposes its
        storage as a USB disk, or you pull its SD/eMMC into a reader, it appears
        as ``/dev/sd*`` / ``/dev/mmcblk*``. This images it **read-only** (never
        mounts, never writes) and **refuses the host's own system disks**, then
        hands the image to the firmware domain.
        """
        inventory = support.storage_devices()
        if params.list_only:
            sys_disks = sorted(support.host_system_disks())
            return ModuleResult(
                data={"devices": inventory, "host_system_disks": sys_disks},
                summary=f"{len(inventory)} block device(s) visible; "
                        f"{len(sys_disks)} are host system disks (not imageable).")
        if params.confirm != params.device:
            return ModuleResult(
                data={"device": params.device, "devices": inventory},
                summary="Safety interlock: set `confirm` to the exact device path to "
                        "authorize imaging.")
        out = ctx.workdir / f"blockimg_{params.device.replace('/', '_')}_{int(time.time())}.img"
        ctx.progress(10, f"imaging {params.device} (read-only)")
        result = support.host_block_acquire(
            params.device, str(out), max_bytes=params.max_bytes,
            use_ddrescue=params.use_ddrescue, timeout_s=params.timeout_s,
            cancel_cb=ctx.cancelled,
            progress_cb=lambda n: ctx.progress(
                min(95, 10 + int(85 * n / max(1, params.max_bytes or n or 1)))),
        )
        if not result.get("ok"):
            return ModuleResult(data=result,
                                summary=f"Acquisition failed: {result.get('error')}")
        # dd already wrote the image into the job workdir; register it by path
        # (no re-read into memory — these can be gigabytes).
        ev = EvidenceDraft(kind="firmware", filename=out.name, content=b"",
                           note=f"host block image of {params.device} ({result['tool']})")
        ev.path, ev.sha256, ev.size = str(out), result["sha256"], result["bytes"]
        finding = FindingDraft(
            title=f"Storage device imaged from host ({params.device})",
            category="host-acquire", severity="info",
            description="A block device attached to the testbed host was imaged read-only. "
                        "The local SHA-256 identifies the saved bytes.",
            remediation="Treat exposed mass-storage/SD as a full data-at-rest disclosure; "
                        "encrypt device storage.",
            evidence=f"sha256={result['sha256']} size={result['bytes']}",
            extra={"device": params.device, "tool": result["tool"]})
        ctx.progress(100, "image saved")
        return ModuleResult(
            data={"device": params.device, "size": result["bytes"], "sha256": result["sha256"],
                  "evidence": ev.filename, "path": ev.path},
            findings=[finding], evidence=[ev],
            summary=f"Imaged {result['bytes']} bytes from {params.device} "
                    f"(sha256 {result['sha256'][:12]}…) — analyse with the firmware domain.")

    # ------------------------------------------------------------------ #
    @module(
        name="adb_acquire",
        title="Acquire filesystem from Android device (adb)",
        safety=Safety.ACTIVE,
        params_model=AdbParams,
        capabilities=[CAP_ADB],
        tags=["android", "adb", "firmware-extraction", "filesystem"],
    )
    def adb_acquire(self, ctx: PluginContext, params: AdbParams) -> ModuleResult:
        """Tar a filesystem off an Android-based device over ``adb exec-out``.

        Many IP cameras, doorbells and set-tops run Android. With USB debugging
        enabled and the host authorized, this streams a binary-safe tar of the
        requested paths to evidence for the firmware domain. Honest about an
        absent or unauthorized device rather than inventing success.
        """
        devices = support.adb_devices()
        if params.list_only:
            return ModuleResult(data={"devices": devices},
                                summary=f"{len(devices)} adb device(s) attached.")
        if not devices:
            return ModuleResult(data={"devices": []},
                                summary="No adb devices. Enable USB debugging and authorize this host.")
        unauthorized = [d for d in devices if d["state"] == "unauthorized"]
        if unauthorized and not any(d["state"] == "device" for d in devices):
            return ModuleResult(
                data={"devices": devices},
                summary="Device attached but unauthorized — accept the RSA prompt on the device.")
        out = ctx.workdir / f"adb_rootfs_{int(time.time())}.tar"
        ctx.progress(20, "streaming tar via adb exec-out")
        result = support.adb_archive(params.serial, params.paths, str(out),
                                     timeout_s=params.timeout_s)
        if not result.get("ok"):
            return ModuleResult(data=result,
                                summary=f"adb acquisition failed: {result.get('error')}")
        ev = EvidenceDraft(kind="firmware", filename=out.name, content=b"",
                           note=f"adb tar of {params.paths} (serial={params.serial or 'auto'})")
        ev.path, ev.sha256, ev.size = str(out), result["sha256"], result["bytes"]
        finding = FindingDraft(
            title="Android filesystem acquired over adb",
            category="adb-fs", severity="info",
            description="A tar of the requested paths was pulled over adb exec-out. "
                        "Records acquisition; enabled USB debugging on a shipped device is "
                        "itself an exposure.",
            remediation="Disable USB debugging in production images and require "
                        "verified-boot / locked bootloader.",
            evidence=f"sha256={result['sha256']} size={result['bytes']}",
            extra={"paths": params.paths})
        ctx.progress(100, "adb image saved")
        return ModuleResult(
            data={"size": result["bytes"], "sha256": result["sha256"],
                  "evidence": ev.filename, "path": ev.path},
            findings=[finding], evidence=[ev],
            summary=f"Pulled {result['bytes']} bytes via adb (sha256 {result['sha256'][:12]}…) "
                    "— analyse with the firmware domain.")

    # ------------------------------------------------------------------ #
    @module(
        name="power_control",
        title="Control target power",
        safety=Safety.ACTIVE,
        params_model=PowerParams,
        capabilities=[CAP_GPIO],
        tags=["power"],
    )
    def power_control(self, ctx: PluginContext, params: PowerParams) -> ModuleResult:
        """Manual relay/optocoupler power switching."""
        power = support.PowerController(mode=params.mode)
        if params.action == "on":
            power.power_on()
        elif params.action == "off":
            power.power_off()
        else:
            power.cycle(off_seconds=params.off_seconds)
        return ModuleResult(
            data={"action": params.action, "mode": power.mode, "pin": power.pin,
                  "power_on_level": "LOW" if power.mode == "optocoupler" else "HIGH",
                  "mock": power.is_mock()},
            summary=f"Power action '{params.action}' executed on BCM {power.pin} "
                    f"({power.mode})"
                    + (" (mock backend)" if power.is_mock() else ""),
        )

    # ======================== invasive (gated) ======================== #
    @module(
        name="spi_dump",
        title="Acquire SPI flash image",
        safety=Safety.INVASIVE,
        params_model=SpiParams,
        capabilities=[CAP_FLASHROM],
        tags=["spi", "firmware-extraction"],
    )
    def spi_dump(self, ctx: PluginContext, params: SpiParams) -> ModuleResult:
        """Read out an attached SPI flash chip with flashrom; hand off to firmware analysis."""
        ctx.log("starting SPI flash read-out (authorized engagement)", level="warn")
        out = ctx.workdir / f"spi_dump_{int(time.time())}.bin"
        ctx.progress(20, "reading flash via flashrom")
        result = support.spi_dump(str(out), chip=params.chip, programmer=params.programmer)
        if not result.get("ok"):
            return ModuleResult(data=result,
                                summary=f"SPI dump failed: {result.get('error', 'flashrom error')}")
        data = out.read_bytes()
        ctx.progress(80, f"read {len(data)} bytes; hashing")
        ev = ctx.save_evidence(
            EvidenceDraft(kind="firmware", filename=out.name, content=data,
                          note="SPI flash dump via flashrom")
        )
        return ModuleResult(
            data={"path": str(out), "size": len(data), "sha256": ev.sha256,
                  "note": "Run the firmware plugin's `extract`/`entropy`/`secrets` modules on "
                          "this artefact for static analysis."},
            evidence=[ev],
            summary=f"SPI flash dumped ({len(data)} bytes, sha256 {ev.sha256[:12]}…).",
        )

    @module(
        name="voltage_glitch",
        title="Voltage fault injection (bounded)",
        safety=Safety.INVASIVE,
        params_model=GlitchParams,
        capabilities=[CAP_GPIO],
        tags=["glitch", "fault-injection"],
        mitre=["T1499"],
    )
    def voltage_glitch(self, ctx: PluginContext, params: GlitchParams) -> ModuleResult:
        """Bounded voltage-glitch pulse train to attempt security-state bypass.

        Hard-capped pulse width/duration and always restores power. Requires a signed,
        in-scope RoE. GPIO busy-waiting means the *achieved* pulse rate - not the
        nominal one - is what the evidence records.
        """
        ctx.log(f"starting bounded glitch on BCM {params.pin or 'default'} "
                "(authorized engagement)", level="warn")

        def _cb(pulses: int, elapsed: float) -> None:
            ctx.progress(min(95, 10 + int(elapsed / max(params.duration_s, 0.1) * 85)),
                         f"{pulses} pulses")

        result = support.run_glitch(
            pin=params.pin, on_us=params.on_us, off_us=params.off_us,
            duration_s=params.duration_s, progress_cb=_cb, cancel_cb=ctx.cancelled,
        )
        if result.extra.get("stop_reason") == "cancelled_by_operator":
            ctx.log("cancelled by operator mid-glitch; power line restored", level="warn")
        ctx.progress(97, "power restored")
        findings = [
            FindingDraft(
                title="Voltage fault-injection cycle executed",
                category="fault-injection",
                severity="info",
                description=(
                    f"{result.pulses} glitch pulse(s) applied at ON={result.on_us}µs/"
                    f"OFF={result.off_us}µs for {result.duration_s:.2f}s. Correlate with device "
                    "behaviour (reboot, console, recovery mode) to determine whether the glitch "
                    "perturbed the security state machine."
                ),
                remediation="Enable brown-out detection, glitch detectors, and secure boot; move "
                            "security-critical checks out of glitchable timing windows.",
                evidence=result.log,
                extra={"pulses": result.pulses, "mock": result.mock,
                       "stop_reason": result.extra.get("stop_reason"),
                       "rate_hz": result.extra.get("rate_hz")},
            )
        ]
        ev = ctx.save_evidence(
            EvidenceDraft(kind="glitch-log", filename=f"glitch_{int(time.time())}.log",
                          content=(result.log or "no log").encode(),
                          note="voltage glitch parameters + result")
        )
        return ModuleResult(
            data=result.to_dict(), findings=findings, evidence=[ev],
            summary=f"Applied {result.pulses} glitch pulse(s); power restored."
                    + (" (mock backend)" if result.mock else ""),
        )


def _sev(severity: str, cvss: float | None) -> str:
    from app.services import risk

    if cvss is not None:
        return risk.cvss_to_severity(cvss)
    return severity if severity in risk.SEVERITY_ORDER else "info"
