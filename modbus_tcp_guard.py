#!/usr/bin/env python3
"""modbus-tcp-guard: a small, safe-by-default proxy in front of a Modbus TCP gateway.

- Serialises the requests of several clients (e.g. Home Assistant and a
  laptop) over ONE connection to the gateway, for gateways that accept a
  single client at a time.
- READ-ONLY by default: only function codes 1, 2, 3 and 4 are forwarded.
  Anything else gets a Modbus exception and never reaches the device.
- WRITE ALLOW-LIST when WRITE_ENABLED=1, and only if:
    * the function code is 6 (write single register); 5, 15, 16, 22, 23 and
      diagnostics stay refused;
    * the client IP is listed in WRITE_CLIENTS;
    * the register is listed in WRITE_REGISTERS, with a value inside its range.
  Example: WRITE_REGISTERS=5061:160-220,5072:160-220
  An empty or unreadable list means no write goes through.
  Every write, forwarded or refused, is logged.
- Only accepts client IPs listed in ALLOWED_CLIENTS.

Configuration through environment variables (see examples/modbus-tcp-guard.env).
No dependency outside the Python standard library (Python >= 3.8).
"""
import asyncio
import logging
import os
import struct

TARGET_HOST, _, TARGET_PORT = os.environ.get("TARGET", "192.168.0.4:502").partition(":")
TARGET_PORT = int(TARGET_PORT or 502)
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "502"))
ALLOWED_CLIENTS = {ip.strip() for ip in os.environ.get("ALLOWED_CLIENTS", "").split(",") if ip.strip()}
WRITE_ENABLED = os.environ.get("WRITE_ENABLED", "0") == "1"
WRITE_CLIENTS = {ip.strip() for ip in os.environ.get("WRITE_CLIENTS", "").split(",") if ip.strip()}
TIMEOUT = float(os.environ.get("TIMEOUT", "5"))

READ_FUNCTIONS = {1, 2, 3, 4}
WRITE_SINGLE_REGISTER = 6

ILLEGAL_FUNCTION, ILLEGAL_ADDRESS, ILLEGAL_VALUE, GATEWAY_NO_RESPONSE = 0x01, 0x02, 0x03, 0x0B

log = logging.getLogger("modbus-tcp-guard")


def parse_allow_list(text):
    """'5061:160-220,5072:160-220' -> ({5061: (160, 220), 5072: (160, 220)}, None).

    Returns ({}, message) if the text cannot be read: no write will go through.
    """
    allowed = {}
    for chunk in (c.strip() for c in text.split(",")):
        if not chunk:
            continue
        try:
            register, _, value_range = chunk.partition(":")
            low, _, high = value_range.partition("-")
            register, low, high = int(register), int(low), int(high)
        except ValueError:
            return {}, "WRITE_REGISTERS cannot be parsed (%r)" % chunk
        if not (0 <= register <= 0xFFFF and 0 <= low <= high <= 0xFFFF):
            return {}, "WRITE_REGISTERS out of bounds (%r)" % chunk
        allowed[register] = (low, high)
    return allowed, None


WRITE_REGISTERS, ALLOW_LIST_ERROR = parse_allow_list(os.environ.get("WRITE_REGISTERS", ""))


def check_write(ip, pdu):
    """Return None if this non-read request may go through, else (exception code, reason)."""
    function = pdu[0]
    if not WRITE_ENABLED:
        return ILLEGAL_FUNCTION, "writes are disabled (WRITE_ENABLED=0)"
    if function != WRITE_SINGLE_REGISTER:
        return ILLEGAL_FUNCTION, "function %d refused (only 6 is allowed)" % function
    if ip not in WRITE_CLIENTS:
        return ILLEGAL_FUNCTION, "client is not allowed to write"
    if len(pdu) != 5:
        return ILLEGAL_VALUE, "malformed write request"
    register, value = struct.unpack(">HH", pdu[1:5])
    if register not in WRITE_REGISTERS:
        return ILLEGAL_ADDRESS, "register %d is not in the allow-list (value %d)" % (register, value)
    low, high = WRITE_REGISTERS[register]
    if not low <= value <= high:
        return ILLEGAL_VALUE, "register %d: value %d outside %d-%d" % (register, value, low, high)
    return None


class Gateway:
    """Single connection to the gateway, used by one client at a time."""

    def __init__(self):
        self.lock = asyncio.Lock()
        self.reader = self.writer = None

    async def _connect(self):
        if self.writer is None or self.writer.is_closing():
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(TARGET_HOST, TARGET_PORT), TIMEOUT)
            log.info("connected to gateway %s:%s", TARGET_HOST, TARGET_PORT)

    def _close(self):
        if self.writer is not None:
            self.writer.close()
        self.reader = self.writer = None

    async def forward(self, frame, attempts):
        """Send the frame and return the response, or None after `attempts` failures.

        Some gateways drop a connection that stays idle for about a minute:
        a read (no effect on the device) is therefore retried once on a new
        connection. A write is never replayed.
        """
        async with self.lock:
            for attempt in range(1, attempts + 1):
                try:
                    await self._connect()
                    self.writer.write(frame)
                    await self.writer.drain()
                    header = await asyncio.wait_for(self.reader.readexactly(7), TIMEOUT)
                    length = struct.unpack(">H", header[4:6])[0]
                    body = await asyncio.wait_for(self.reader.readexactly(length - 1), TIMEOUT)
                    return header + body
                except (OSError, asyncio.IncompleteReadError, asyncio.TimeoutError) as e:
                    log.warning("gateway unreachable (attempt %d/%d): %s", attempt, attempts, e or type(e).__name__)
                    self._close()
            return None


def exception(header, function, code):
    """Modbus exception response with the same transaction and unit identifiers."""
    return header[:4] + struct.pack(">H", 3) + header[6:7] + bytes([function | 0x80, code])


async def handle_client(reader, writer, gateway):
    ip = writer.get_extra_info("peername")[0]
    if ip not in ALLOWED_CLIENTS:
        log.warning("connection refused from %s", ip)
        writer.close()
        return
    try:
        while True:
            header = await reader.readexactly(7)
            length = struct.unpack(">H", header[4:6])[0]
            if not 2 <= length <= 254:
                break
            pdu = await reader.readexactly(length - 1)
            function = pdu[0]
            if function in READ_FUNCTIONS:
                response = await gateway.forward(header + pdu, 2) or exception(header, function, GATEWAY_NO_RESPONSE)
            else:
                refusal = check_write(ip, pdu)
                if refusal:
                    log.warning("write REFUSED for %s: %s", ip, refusal[1])
                    response = exception(header, function, refusal[0])
                else:
                    register, value = struct.unpack(">HH", pdu[1:5])
                    response = await gateway.forward(header + pdu, 1)
                    if response is None:
                        outcome = "no response from gateway"
                        response = exception(header, function, GATEWAY_NO_RESPONSE)
                    elif response[7] & 0x80:
                        outcome = "gateway exception %d" % response[8]
                    else:
                        outcome = "accepted by gateway"
                    log.info("write from %s: register %d = %d -> %s", ip, register, value, outcome)
            writer.write(response)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        writer.close()


async def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if ALLOW_LIST_ERROR:
        log.error("%s: no write will go through", ALLOW_LIST_ERROR)
    gateway = Gateway()
    server = await asyncio.start_server(lambda r, w: handle_client(r, w, gateway), "0.0.0.0", LISTEN_PORT)
    if WRITE_ENABLED and WRITE_REGISTERS and WRITE_CLIENTS:
        writes = "ALLOW-LIST: function 6, clients %s, registers %s" % (
            sorted(WRITE_CLIENTS),
            ", ".join("%d [%d-%d]" % (r, *p) for r, p in sorted(WRITE_REGISTERS.items())))
    else:
        writes = "BLOCKED"
    log.info("listening on port %d, target %s:%d, clients %s, writes %s",
             LISTEN_PORT, TARGET_HOST, TARGET_PORT, sorted(ALLOWED_CLIENTS), writes)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
