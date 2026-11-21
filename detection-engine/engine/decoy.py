"""The decoy: a fake camera nobody legitimate ever talks to.

Any device that connects is flagged. Any username/password it tries is recorded as evidence.
Runs Telnet on 23/2323 and a fake camera login page on 80, bound to DECOY_IP only.
"""
import asyncio
import time
from urllib.parse import parse_qs

from . import config
from .detectors import make_alert

LOGIN_PAGE = b"""<html><head><title>NVR Login</title></head><body>
<h3>Network Video Recorder</h3>
<form method="POST" action="/login">User <input name="user"> Password <input name="pass" type="password">
<button>Login</button></form></body></html>"""


class Decoy:
    def __init__(self, emit):
        self.emit = emit          # function(list_of_alerts)

    def _flag(self, peer_ip, how, creds=None):
        if peer_ip in (config.GATEWAY_IP, config.DECOY_IP):
            return
        detail = f"{how} on decoy {config.DECOY_IP}"
        if creds:
            detail += f", tried login {creds[0]}/{creds[1]}"
        self.emit(make_alert(peer_ip, "decoy_login", "critical", detail, time.time(),
                             key=how + (f"{creds}" if creds else "")))

    async def _readline(self, reader, timeout=10):
        try:
            data = await asyncio.wait_for(reader.readline(), timeout)
        except asyncio.TimeoutError:
            return None
        # strip Telnet negotiation bytes (IAC = 0xff + 2 bytes)
        out, i = bytearray(), 0
        while i < len(data):
            if data[i] == 0xFF:
                i += 3
                continue
            out.append(data[i])
            i += 1
        return out.decode(errors="replace").strip()

    async def telnet(self, reader, writer):
        peer = writer.get_extra_info("peername")[0]
        port = writer.get_extra_info("sockname")[1]
        self._flag(peer, f"Telnet connection (port {port})")
        try:
            writer.write(b"\r\nIPC login: ")
            await writer.drain()
            user = await self._readline(reader)
            if user is not None:
                writer.write(b"Password: ")
                await writer.drain()
                pw = await self._readline(reader)
                self._flag(peer, f"Telnet login (port {port})", (user, pw or ""))
                await asyncio.sleep(1)
                writer.write(b"\r\nLogin incorrect\r\n")
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()

    async def http(self, reader, writer):
        peer = writer.get_extra_info("peername")[0]
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            text = head.decode(errors="replace")
            length = 0
            for line in text.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    length = int(line.split(":", 1)[1].strip() or 0)
            body = (await reader.readexactly(length)).decode(errors="replace") if length else ""
            if text.startswith("POST"):
                form = parse_qs(body)
                creds = (form.get("user", [""])[0], form.get("pass", [""])[0])
                self._flag(peer, "Web login", creds)
            else:
                self._flag(peer, "Web request")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: DNVRS-Webs\r\n"
                         b"Content-Length: " + str(len(LOGIN_PAGE)).encode() + b"\r\n\r\n" + LOGIN_PAGE)
            await writer.drain()
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError, ValueError):
            pass
        finally:
            writer.close()

    async def serve(self):
        servers = [await asyncio.start_server(self.telnet, config.DECOY_IP, p)
                   for p in config.DECOY_TELNET_PORTS]
        servers.append(await asyncio.start_server(self.http, config.DECOY_IP, config.DECOY_HTTP_PORT))
        print(f"[decoy] listening on {config.DECOY_IP} ports "
              f"{config.DECOY_TELNET_PORTS + [config.DECOY_HTTP_PORT]}")
        await asyncio.gather(*(s.serve_forever() for s in servers))

    def run(self):
        asyncio.run(self.serve())
