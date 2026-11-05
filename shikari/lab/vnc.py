"""Graphical VM consoles: a WebSocket↔TCP bridge to a per-machine VNC endpoint (#28).

A text PTY can't drive a Windows desktop, so a GUI console needs a pixel protocol. noVNC speaks RFB, so the
server bridges the browser's WebSocket to a VNC (RFB) target over raw TCP and serves noVNC against it.

The one rule that makes this safe is where the endpoint comes from: the `host:port` is **trusted
per-machine config** (shikari.lab.registry.set_vnc), set by the owner out-of-band — never a value the
client passes on the wire. The WebSocket route resolves the endpoint from the registry by engine+name and
ignores any host/port in the request, so a caller can't point the bridge at an arbitrary address (SSRF).
As defence in depth, `valid_endpoint` additionally refuses anything that isn't loopback/private/link-local.

UTM's own display is SPICE, not VNC, and utmctl exposes no VNC port, so a UTM VM can't be auto-wired; the
endpoint is whatever VNC target the owner stands up (a QEMU `-vnc` display, a Tart VM, a bare host). See
docs/implementation-plans/28-vm-consoles.md.
"""
from __future__ import annotations

import asyncio
import ipaddress


def valid_endpoint(host: str, port) -> bool:
    """A VNC endpoint is acceptable only if the port is 1-65535 and the host is localhost or a
    loopback/private/link-local IP literal. Public addresses are refused — a lab console has no business
    bridging to the internet, and this is the backstop if trusted config is ever mis-set."""
    try:
        p = int(port)
    except (TypeError, ValueError):
        return False
    if not (1 <= p <= 65535):
        return False
    host = (host or "").strip()
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # hostnames (other than localhost) are not resolved — require an IP literal
    return ip.is_loopback or ip.is_private or ip.is_link_local


async def bridge(websocket, host: str, port: int) -> None:
    """Pump bytes both ways between an accepted WebSocket and a TCP connection to host:port, until either
    side closes. The caller has already authorised the user and resolved host:port from trusted config."""
    try:
        reader, writer = await asyncio.open_connection(host, int(port))
    except OSError:
        await websocket.close(code=1011)  # couldn't reach the VNC target
        return

    async def tcp_to_ws() -> None:
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                await websocket.send_bytes(data)
        except Exception:  # noqa: BLE001 — socket/ws teardown races; the finally cleans up
            pass
        finally:
            try:
                await websocket.close()
            except Exception:  # noqa: BLE001
                pass

    pump = asyncio.ensure_future(tcp_to_ws())
    try:
        while True:
            msg = await websocket.receive()
            if msg.get("type") == "websocket.disconnect":
                break
            data = msg.get("bytes")
            if data is None and msg.get("text") is not None:
                data = msg["text"].encode()
            if data:
                writer.write(data)
                await writer.drain()
    except Exception:  # noqa: BLE001 — WebSocketDisconnect and friends
        pass
    finally:
        pump.cancel()
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
