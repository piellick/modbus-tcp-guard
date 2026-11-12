"""End-to-end tests against a fake Modbus TCP gateway on localhost.

Run:  python3 tests/test_guard.py
Needs 127.0.0.2 to be usable as a second loopback address (Linux default).
"""
import asyncio, os, socket, struct, subprocess, sys, time

GUARD = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modbus_tcp_guard.py")
GATEWAY_PORT, GUARD_PORT = 15020, 15502
received = []


async def fake_gateway(reader, writer):
    try:
        while True:
            header = await reader.readexactly(7)
            pdu = await reader.readexactly(struct.unpack(">H", header[4:6])[0] - 1)
            received.append(pdu)
            if pdu[0] == 3:
                count = struct.unpack(">HH", pdu[1:5])[1]
                data = struct.pack(">H", 200) * count
                body = bytes([3, len(data)]) + data
            else:
                body = pdu  # echo, like a successful write
            writer.write(header[:4] + struct.pack(">H", len(body) + 1) + header[6:7] + body)
            await writer.drain()
    except asyncio.IncompleteReadError:
        pass


def request(pdu, source="127.0.0.1"):
    s = socket.socket(); s.bind((source, 0)); s.settimeout(3); s.connect(("127.0.0.1", GUARD_PORT))
    s.sendall(struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1) + pdu)
    response = s.recv(256); s.close()
    return response[7:]


def start(env):
    full = dict(os.environ, TARGET="127.0.0.1:%d" % GATEWAY_PORT, LISTEN_PORT=str(GUARD_PORT),
                ALLOWED_CLIENTS="127.0.0.1,127.0.0.2", **env)
    p = subprocess.Popen([sys.executable, GUARD], env=full, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(0.6)
    return p


def fc6(register, value):
    return struct.pack(">BHH", 6, register, value)


READ = struct.pack(">BHH", 3, 5110, 1)
READ_OK = bytes([3, 2, 0, 200])
ALLOW = dict(WRITE_ENABLED="1", WRITE_CLIENTS="127.0.0.1", WRITE_REGISTERS="5061:160-220,5072:160-220")

SCENARIOS = [
    ("allow-list active", ALLOW, [
        ("read", READ, READ_OK, "127.0.0.1", True),
        ("read from the read-only client", READ, READ_OK, "127.0.0.2", True),
        ("allowed write 5061=195", fc6(5061, 195), fc6(5061, 195), "127.0.0.1", True),
        ("allowed write 5072=200", fc6(5072, 200), fc6(5072, 200), "127.0.0.1", True),
        ("lower bound 160", fc6(5061, 160), fc6(5061, 160), "127.0.0.1", True),
        ("upper bound 220", fc6(5072, 220), fc6(5072, 220), "127.0.0.1", True),
        ("register not listed (5052)", fc6(5052, 0), bytes([0x86, 2]), "127.0.0.1", False),
        ("register not listed (5050)", fc6(5050, 0), bytes([0x86, 2]), "127.0.0.1", False),
        ("value above range", fc6(5061, 300), bytes([0x86, 3]), "127.0.0.1", False),
        ("value below range", fc6(5072, 159), bytes([0x86, 3]), "127.0.0.1", False),
        ("function 16 on an allowed register", struct.pack(">BHHBH", 16, 5061, 1, 2, 195), bytes([0x90, 1]), "127.0.0.1", False),
        ("function 5", struct.pack(">BHH", 5, 5061, 0xFF00), bytes([0x85, 1]), "127.0.0.1", False),
        ("function 8 (diagnostics)", struct.pack(">BHH", 8, 0, 0), bytes([0x88, 1]), "127.0.0.1", False),
        ("write from a read-only client", fc6(5061, 195), bytes([0x86, 1]), "127.0.0.2", False),
    ]),
    ("writes disabled", dict(ALLOW, WRITE_ENABLED="0"), [
        ("write refused", fc6(5061, 195), bytes([0x86, 1]), "127.0.0.1", False),
        ("read still works", READ, READ_OK, "127.0.0.1", True),
    ]),
    ("unreadable allow-list", dict(ALLOW, WRITE_REGISTERS="5061:16O-220"), [
        ("write refused", fc6(5061, 195), bytes([0x86, 2]), "127.0.0.1", False),
    ]),
    ("defaults (no write variable set)", {}, [
        ("write refused", fc6(5061, 195), bytes([0x86, 1]), "127.0.0.1", False),
    ]),
]


async def main():
    server = await asyncio.start_server(fake_gateway, "127.0.0.1", GATEWAY_PORT)
    loop = asyncio.get_running_loop()
    failures = 0
    for title, env, cases in SCENARIOS:
        print("== " + title)
        process = await loop.run_in_executor(None, start, env)
        for name, pdu, expected, source, must_reach in cases:
            before = len(received)
            response = await loop.run_in_executor(None, request, pdu, source)
            reached = len(received) > before
            ok = response[:len(expected)] == expected and reached == must_reach
            failures += not ok
            print("  %s %-38s %s (%s)" % ("ok  " if ok else "FAIL", name, response.hex(),
                                          "reached the gateway" if reached else "stopped by the guard"))
        process.terminate()
        process.communicate()
    server.close()
    print("ALL TESTS PASSED" if not failures else "%d FAILURE(S)" % failures)
    sys.exit(1 if failures else 0)


asyncio.run(main())
