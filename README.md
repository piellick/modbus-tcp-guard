# modbus-tcp-guard

A small proxy that sits between your home automation and a Modbus TCP gateway,
and only lets through what you decided to allow.

It was written to put a heat pump gateway (Hitachi HC-A16MB) behind Home
Assistant without giving Home Assistant, or anything else on the network, the
ability to switch the heat pump off or change its settings by accident. It is
not specific to that hardware: it works with any Modbus TCP server.

One Python file, standard library only.

## What it does

- **Read-only by default.** Only function codes 1, 2, 3 and 4 are forwarded.
  Every other request is answered with a Modbus exception by the guard itself
  and never reaches the device.
- **Write allow-list, if you turn it on.** A write goes through only when all
  of these are true:
  - it is a "write single register" request (function code 6);
  - it comes from a client IP you allowed to write;
  - it targets a register you listed;
  - its value is inside the range you gave for that register.
- **Several clients, one gateway connection.** Many gateways accept a single
  Modbus TCP client. The guard queues the requests of all its clients over one
  connection.
- **Reconnects quietly.** Some gateways close a connection that stays idle for
  a minute. A read is retried once on a fresh connection. A write is never
  replayed.
- **Client IP filter.** Connections from addresses that are not listed are
  dropped.
- **Everything about writes is logged**, whether forwarded or refused.

## Install

Requirements: Python 3.8 or later, on a machine that can reach both the
gateway and your clients (a Raspberry Pi works well).

```sh
sudo install -m 755 modbus_tcp_guard.py /usr/local/bin/modbus_tcp_guard.py
sudo install -m 644 examples/modbus-tcp-guard.env /etc/default/modbus-tcp-guard
sudo install -m 644 examples/modbus-tcp-guard.service /etc/systemd/system/modbus-tcp-guard.service
sudoedit /etc/default/modbus-tcp-guard        # set TARGET and ALLOWED_CLIENTS
sudo systemctl daemon-reload
sudo systemctl enable --now modbus-tcp-guard
journalctl -u modbus-tcp-guard -f
```

Then point your clients at the guard's address instead of the gateway's.

To try it without installing anything:

```sh
TARGET=192.168.0.4:502 LISTEN_PORT=1502 ALLOWED_CLIENTS=127.0.0.1 python3 modbus_tcp_guard.py
```

## Configuration

All settings are environment variables.

| Variable | Default | Meaning |
|---|---|---|
| `TARGET` | `192.168.0.4:502` | Gateway to protect, as `host:port` |
| `LISTEN_PORT` | `502` | Port the guard listens on |
| `ALLOWED_CLIENTS` | empty | Comma-separated client IPs allowed to connect. Empty means nobody. |
| `WRITE_ENABLED` | `0` | `1` turns the write allow-list on |
| `WRITE_CLIENTS` | empty | Client IPs allowed to write |
| `WRITE_REGISTERS` | empty | `register:min-max` entries, comma-separated |
| `TIMEOUT` | `5` | Seconds to wait for the gateway |

If `WRITE_REGISTERS` is empty or cannot be parsed, no write goes through and
an error is logged at start-up. Reads keep working.

Register numbers are the addresses found in the Modbus request (zero-based
protocol addresses), and values are the raw 16-bit register values.

### Exception codes returned by the guard

| Code | When |
|---|---|
| 01 illegal function | Writes disabled, function other than 6, or client not allowed to write |
| 02 illegal data address | Register not in the allow-list |
| 03 illegal data value | Value outside the allowed range, or malformed request |
| 0B gateway target failed to respond | The gateway did not answer |

## Example: room setpoints of a Hitachi Yutaki heat pump

With an HC-A16MB gateway and indoor unit 0, the room temperature setpoints of
circuits 1 and 2 are written to registers 5061 and 5072, in tenths of a
degree. This lets Home Assistant change the two setpoints between 16.0 and
22.0 °C, and nothing else:

```sh
WRITE_ENABLED=1
WRITE_CLIENTS=192.168.1.10
WRITE_REGISTERS=5061:160-220,5072:160-220
```

Switching the unit off, changing the mode or touching domestic hot water all
use other registers, so they are refused. Check your own gateway's register
map before relying on these numbers.

Typical log lines:

```
INFO listening on port 502, target 192.168.0.4:502, clients ['192.168.1.10', '192.168.1.20'], writes ALLOW-LIST: function 6, clients ['192.168.1.10'], registers 5061 [160-220], 5072 [160-220]
INFO write from 192.168.1.10: register 5072 = 195 -> accepted by gateway
WARNING write REFUSED for 192.168.1.20: client is not allowed to write
WARNING write REFUSED for 192.168.1.10: register 5052 is not in the allow-list (value 0)
```

## Limits

- Modbus TCP has no authentication. The IP filter stops accidents and casual
  access on a trusted home network; it is not a defence against someone who
  can spoof an address on that network. Keep the gateway on a network segment
  that only the guard can reach.
- Only function code 6 can be allowed for writing. Clients that write with
  function 16 (write multiple registers) will be refused.
- The unit identifier is passed through unchanged and is not filtered.
- Modbus TCP only (MBAP framing). No RTU, no TLS.

## Tests

The tests start the guard against a fake gateway on localhost and check every
rule, including that refused requests never reach the gateway.

```sh
python3 tests/test_guard.py
```

## Disclaimer

Not affiliated with Hitachi or any other manufacturer. You are responsible for
what you allow to be written to your equipment.

## License

MIT, see [LICENSE](LICENSE).
