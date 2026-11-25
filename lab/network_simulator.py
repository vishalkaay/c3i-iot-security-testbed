#!/usr/bin/env python3
"""Loopback camera + IoT service simulator for Wi-Fi/IP modules.

No radio, monitor mode, or root privileges are used. Everything binds to
127.0.0.1. This is an IP-service lab, not a Wi-Fi access-point simulator.
"""
from __future__ import annotations

import argparse
import base64
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import socketserver
import ssl
import subprocess
import threading


class CameraHandler(BaseHTTPRequestHandler):
    server_version = "C3iCameraLab/1.0"
    sys_version = ""

    def do_GET(self):
        authorized = self.headers.get("Authorization") == "Basic " + base64.b64encode(b"admin:admin").decode()
        status = 200 if authorized else 401
        self.send_response(status)
        if not authorized:
            self.send_header("WWW-Authenticate", 'Basic realm="C3i lab camera"')
        body = json.dumps({"lab": True, "authenticated": authorized,
                           "model": "C3i synthetic camera", "firmware": "lab-1.0"}).encode()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"[lab] {self.client_address[0]} {fmt % args}", flush=True)


# --------------------------------------------------------------------------- #
# Banner services: enough protocol shape for nmap/service fingerprinting and
# for the MQTT module to exercise an anonymous-subscribe path.
# --------------------------------------------------------------------------- #
class BannerServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, handler, *, banner: bytes = b"", kind: str = ""):
        self.banner = banner
        self.kind = kind
        super().__init__(address, handler)


class BannerHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(3)
        try:
            self._serve()
        except (EOFError, OSError, ValueError):
            # Probes (nmap, port checks) connect and close without a full
            # protocol exchange. A broken pipe is expected, not an error.
            return

    def _serve(self):
        if self.server.kind == "mqtt":
            self._mqtt()
            return
        self.wfile.write(self.server.banner)
        self.wfile.flush()
        if self.server.kind == "ftp":
            self._ftp()
        elif self.server.kind == "telnet":
            self._telnet()
        else:
            # SSH and generic services: keep the socket alive long enough for
            # nmap's version probe to read the banner, then close.
            try:
                self.connection.recv(1024)
            except (TimeoutError, OSError):
                pass

    def _line(self) -> str:
        return self.rfile.readline(2048).decode("latin-1", errors="replace").strip()

    def _ftp(self):
        while True:
            line = self._line()
            if not line:
                return
            command = line.split(maxsplit=1)[0].upper()
            if command == "USER":
                self.wfile.write(b"331 Please specify the password.\r\n")
            elif command == "PASS":
                self.wfile.write(b"230 Login successful.\r\n")
            elif command == "SYST":
                self.wfile.write(b"215 UNIX Type: L8\r\n")
            elif command == "FEAT":
                self.wfile.write(b"211-Features:\r\n UTF8\r\n211 End\r\n")
            elif command == "QUIT":
                self.wfile.write(b"221 Goodbye.\r\n")
                return
            else:
                self.wfile.write(b"502 Command not implemented.\r\n")
            self.wfile.flush()

    def _telnet(self):
        self.wfile.write(b"login: ")
        self.wfile.flush()
        self._line()
        self.wfile.write(b"Password: ")
        self.wfile.flush()
        self._line()
        self.wfile.write(
            b"\r\nBusyBox v1.31.0 (C3i lab) built-in shell (ash)\r\n"
            b"/ # "
        )
        self.wfile.flush()
        try:
            self.connection.recv(1024)
        except (TimeoutError, OSError):
            pass

    def _mqtt_varint(self) -> int:
        value, multiplier = 0, 1
        while True:
            raw = self.rfile.read(1)
            if not raw:
                raise EOFError
            value += (raw[0] & 0x7F) * multiplier
            if not raw[0] & 0x80:
                return value
            multiplier *= 128
            if multiplier > 128 ** 3:
                raise ValueError("malformed MQTT remaining length")

    @staticmethod
    def _mqtt_varint_bytes(value: int) -> bytes:
        encoded = bytearray()
        while True:
            digit = value % 128
            value //= 128
            encoded.append(digit | (0x80 if value else 0))
            if not value:
                return bytes(encoded)

    def _mqtt(self):
        """Minimal MQTT 3.1/3.1.1 broker: CONNECT, SUBSCRIBE, PING, DISCONNECT."""
        header = self.rfile.read(1)
        if not header or header[0] >> 4 != 1:
            return
        self.rfile.read(self._mqtt_varint())
        self.wfile.write(b"\x20\x02\x00\x00")  # CONNACK, accepted
        self.wfile.flush()
        while True:
            header = self.rfile.read(1)
            if not header:
                return
            packet_type = header[0] >> 4
            body = self.rfile.read(self._mqtt_varint())
            if packet_type == 8:  # SUBSCRIBE
                packet_id = body[:2] or b"\x00\x01"
                self.wfile.write(b"\x90\x03" + packet_id + b"\x00")
                topic, payload = b"camera/telemetry", b'{"lab":true,"temperature":21.4}'
                message = len(topic).to_bytes(2, "big") + topic + payload
                self.wfile.write(b"\x30" + self._mqtt_varint_bytes(len(message)) + message)
                self.wfile.flush()
            elif packet_type == 12:  # PINGREQ
                self.wfile.write(b"\xd0\x00")
                self.wfile.flush()
            elif packet_type == 14:  # DISCONNECT
                return


SERVICES = [
    ("ftp", 18021, b"220 (vsFTPd 3.0.3)\r\n", "FTP"),
    ("ssh", 18022, b"SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\r\n", "SSH"),
    ("telnet", 18023, b"\r\nC3i camera lab console\r\n", "Telnet"),
    ("mqtt", 18883, b"", "MQTT"),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--http-port", type=int, default=18080)
    parser.add_argument("--https-port", type=int, default=18443)
    parser.add_argument("--state-dir", type=Path, default=Path(__file__).parent / "state")
    parser.add_argument("--no-tls", action="store_true")
    parser.add_argument("--no-services", action="store_true",
                        help="HTTP/HTTPS only; skip FTP, SSH, Telnet and MQTT banners")
    args = parser.parse_args()
    servers = []
    started = []
    try:
        servers.append(ThreadingHTTPServer(("127.0.0.1", args.http_port), CameraHandler))
        if not args.no_tls:
            if not shutil.which("openssl"):
                raise RuntimeError("openssl is needed for the lab certificate; install it or use --no-tls")
            args.state_dir.mkdir(parents=True, exist_ok=True)
            cert, key = args.state_dir / "localhost.crt", args.state_dir / "localhost.key"
            if not (cert.exists() and key.exists()):
                subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
                                "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                                "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
                key.chmod(0o600)
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.minimum_version = ssl.TLSVersion.TLSv1_2
            tls.load_cert_chain(cert, key)
            secure = ThreadingHTTPServer(("127.0.0.1", args.https_port), CameraHandler)
            servers.append(secure)
            secure.socket = tls.wrap_socket(secure.socket, server_side=True)

        if not args.no_services:
            for kind, port, banner, label in SERVICES:
                try:
                    server = BannerServer(("127.0.0.1", port), BannerHandler, banner=banner, kind=kind)
                except OSError as exc:
                    print(f"[lab] {label} not started on {port}: {exc}", flush=True)
                    continue
                servers.append(server)
                print(f"Lab {label}: 127.0.0.1:{port}" + (" · anonymous MQTT" if kind == "mqtt" else ""), flush=True)

        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
            started.append(server)
        print(f"C3i lab HTTP: 127.0.0.1:{args.http_port} · test credentials admin / admin", flush=True)
        if not args.no_tls:
            print(f"Lab HTTPS: 127.0.0.1:{args.https_port} · self-signed certificate", flush=True)
        print("Bound to loopback only. This simulates IP services, not a Wi-Fi access point. Ctrl+C stops it.", flush=True)
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            # Only shut down serve_forever loops that were started.
            if server in started:
                server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
