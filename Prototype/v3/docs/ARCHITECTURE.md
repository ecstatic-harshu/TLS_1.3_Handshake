# Architecture

## Purpose

QSCP middleware is a **terminate-and-forward proxy** for quantum-safe communication.

1. Accept a client connection
2. Complete TLS 1.3 + post-quantum handshake
3. Decrypt application messages
4. Forward them to a backend
5. Encrypt backend responses back to the client

Existing backends do not need to understand ML-KEM or ML-DSA unless you enable the double-PQ hop.

## High-level diagram

```text
┌──────────┐     TLS 1.3 + PQ      ┌─────────────┐      chosen hop      ┌──────────┐
│  Client  │ ───────────────────► │   Proxy     │ ──────────────────► │ Backend  │
│          │ ◄─────────────────── │  Middleware │ ◄────────────────── │          │
└──────────┘   AES-GCM messages   └─────────────┘                     └──────────┘
```

## Operating modes

| Mode | Role |
|---|---|
| `client` | Initiates PQ session; interactive message shell |
| `server` | Accepts PQ clients; replies `ACK: <message>` |
| `proxy` | Accepts PQ clients; relays to a configured backend |

## Proxy backend hop options

| Option | Flag | Backend speaks |
|---|---|---|
| Raw TCP | `--no-backend-http` | Any TCP service |
| HTTP | `--backend-http` (default) | HTTP API; each message → `POST /echo` |
| Classical TLS | `--backend-tls` | TLS server |
| PQ hop | `--backend-pq` | This same protocol (`--mode server` or another gateway) |

`--backend-pq` takes priority over HTTP/raw modes.

### Double PQ hop

```text
Client ── PQ ──► Proxy ── PQ ──► Server (--mode server on :6000)
```

Both public and internal links use the same quantum-safe stack.

## Layered stack (each connection)

```text
Application bytes
        │
SecureSession (AES-256-GCM + sequence / replay)
        │
PQ handshake (ML-KEM-768 + ML-DSA-65 + transcript + HMAC confirm)
        │
TLS 1.3
        │
TCP
```

## Component map

| Path | Responsibility |
|---|---|
| `middleware/main.py` | CLI: mode, host/port, backend flags |
| `middleware/proxy.py` | Proxy runner / banner |
| `client/client.py` | Interactive client shell |
| `server/server.py` | Echo server wrapper |
| `common/middleware.py` | `secure_connect`, `run_secure_server`, `run_secure_gateway` |
| `common/handshake.py` | Client/server PQ handshake state machine |
| `common/protocol.py` / `serializer.py` / `transport.py` | Wire encoding + framing |
| `common/pq_kem.py` / `pq_dsa.py` | liboqs ML-KEM / ML-DSA |
| `common/hybrid.py` | HKDF master key derivation |
| `common/secure_channel.py` / `session.py` | Directional AES-GCM + sequencing |
| `common/backend.py` | Dial plain/TLS backend |
| `common/relay.py` | Raw, HTTP, and PQ↔PQ relays |
| `common/tls.py` / `tls_session.py` | TLS contexts + TLS contribution |
| `backend_http_demo.py` | Demo HTTP API on :8080 |
| `backend_tcp_echo.py` | Demo TCP echo on :8080 |

## Connection lifecycle (proxy)

1. Accept TCP client
2. Wrap TLS (handshake in worker thread)
3. Run server-side PQ handshake → `SecureSession`
4. Depending on flags:
   - **PQ:** `secure_connect()` to backend → `relay_secure_to_secure`
   - **HTTP:** per message `POST` → response body back
   - **Raw:** long-lived TCP byte pump
5. On idle timeout / error / EOF: close both legs

## Design choices

- **Terminate-and-reissue**, not blind pass-through — ordinary backends cannot speak this PQ protocol
- **Message-framed** client leg (`send_secure` / `receive_secure`), not a raw byte stream
- **Thread-per-connection** model — fine for prototype scale
- **One static backend** target per proxy process (v1)

## Related docs

- [DEMO_GUIDE.md](DEMO_GUIDE.md)
- [SECURITY_MODEL.md](SECURITY_MODEL.md)
- [PROTOCOL.md](PROTOCOL.md)
- [CONFIGURATION.md](CONFIGURATION.md)
