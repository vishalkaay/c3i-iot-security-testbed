#!/usr/bin/env python3
"""Reproducible firmware-analysis fixtures, not bootable vendor firmware."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import random
import struct
import tarfile
import zlib

FILES = {
    "etc/os-release": b'NAME="C3i Camera Lab (synthetic)"\nVERSION="1.0"\n',
    "etc/camera.conf": b"# Deliberate test credentials, never used by a real device\nusername=admin\npassword=admin\napi_key=C3I_LAB_DUMMY_TOKEN_123456\n",
    "etc/versions": b"BusyBox v1.31.0\nOpenSSL 1.0.2u\ndropbear 2019.78\ndnsmasq-2.80\nU-Boot 2020.01\n",
    "etc/passwd": b"root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000:lab:/home/admin:/bin/false\n",
    "etc/shadow": b"root:$6$C3iLab$FAKEHASHFORPARSERTESTINGONLY:18000:0:99999:7:::\n",
    "www/index.html": b"<h1>C3i Camera Lab</h1><p>Synthetic static-analysis fixture.</p>\n",
    "usr/share/lab/README.txt": b"These files exercise archive parsers. Component banners are fixtures, not installed executables.\n",
}


def newc(files: dict[str, bytes]) -> bytes:
    out = bytearray()
    for ino, (name, payload) in enumerate([*files.items(), ("TRAILER!!!", b"")], 1):
        fields = [ino, 0o100644, 0, 0, 1, 0, len(payload), 0, 0, 0, 0, len(name.encode()) + 1, 0]
        out += b"070701" + b"".join(f"{n:08x}".encode() for n in fields)
        out += name.encode() + b"\x00"
        out += b"\x00" * (-len(out) % 4)
        out += payload
        out += b"\x00" * (-len(out) % 4)
    return bytes(out)


def build(output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    cpio = newc(FILES)
    packed = gzip.compress(cpio, mtime=0)
    # Valid legacy uImage envelope containing a gzip-compressed ramdisk.
    header = struct.pack(
        ">7I4B32s", 0x27051956, 0, 0, len(packed), 0, 0,
        zlib.crc32(packed), 5, 2, 3, 1, b"C3i synthetic test ramdisk",
    )
    header = header[:4] + struct.pack(">I", zlib.crc32(header)) + header[8:]
    image = bytearray(b"\xff" * (4 * 1024 * 1024))
    image[:64 + len(packed)] = header + packed
    image[4096:4096 + len(cpio)] = cpio
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, payload in FILES.items():
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.mtime = len(payload), 0o644, 0
            tar.addfile(entry, io.BytesIO(payload))
    image[262144:262144 + len(archive.getvalue())] = archive.getvalue()
    image[1048576:1048576 + 65536] = random.Random(303).randbytes(65536)
    artefacts = {
        "c3i-camera-lab.bin": bytes(image),
        "clean-control.bin": b"C3i clean control: no intentional credentials or component banners.\n" + bytes(65536),
        "truncated-stream.bin": packed[:-8],
        "camera-rootfs.cpio.gz": packed,
        "camera-rootfs.tar": archive.getvalue(),
    }
    manifest = {"kind": "synthetic calibration corpus; not bootable", "files": {},
                "expected_components": ["busybox", "openssl", "dropbear", "dnsmasq", "u-boot"],
                "expected_secret_rules": ["generic-password", "api-key", "shadow-hash"],
                "layout": {"uimage": 0, "gzip": 64, "cpio": 4096, "tar": 262144, "high_entropy_region": 1048576},
                "rootfs_files": {name: hashlib.sha256(data).hexdigest() for name, data in FILES.items()},
                "controls": {"clean-control.bin": "No intentional secret/component hits", "truncated-stream.bin": "Signature candidate, extraction must report incomplete/invalid stream"}}
    for name, data in artefacts.items():
        (output / name).write_bytes(data)
        manifest["files"][name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "fixtures")
    args = parser.parse_args()
    for name, details in build(args.output)["files"].items():
        print(f"{args.output / name}: {details['bytes']} bytes, sha256={details['sha256']}")
