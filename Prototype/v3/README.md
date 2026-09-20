# Nutech Quantum Secure Middleware (QSCP)

**Version:** 1.0.0  
**Status:** Working technical prototype (not production-ready)

Quantum-safe middleware that sits between a client and a backend service. It protects the client-facing connection with post-quantum cryptography, then forwards application data to a normal backend — or to a second quantum-safe hop.

Client ── PQ secure channel ──► Middleware / Proxy ──► Backend
│
├── plain TCP
├── HTTP API
└── PQ again (--backend-pq)

## What this prototype demonstrates

- Post-quantum key exchange: **ML-KEM-768**
- Post-quantum signatures: **ML-DSA-65**
- Outer transport: **TLS 1.3**
- Application encryption: **AES-256-GCM** (HKDF-derived keys)
- Three operating modes: **client**, **server**, **proxy**
- Proxy backends: raw TCP, HTTP (`POST /echo`), or PQ-to-PQ

## Quick start

```powershell
python -m venv venv
venv\Scripts\activate
pip install cryptography pyopenssl
# Also requires liboqs / liboqs-python (see Docker build)
```

### A) Double PQ hop (recommended demo)

```powershell
# Terminal 1 — PQ server
python -m middleware.main --mode server --host 0.0.0.0 --port 6000

# Terminal 2 — Proxy (PQ on both sides)
python -m middleware.main --mode proxy --host 0.0.0.0 --port 5000 --backend-host 127.0.0.1 --backend-port 6000 --backend-pq --no-backend-http

# Terminal 3 — Client
python -m middleware.main --mode client --host 127.0.0.1 --port 5000
```

Type `Hi` → expect `ACK: Hi`.

### B) Proxy → HTTP backend

```powershell
python backend_http_demo.py
python -m middleware.main --mode proxy --host 0.0.0.0 --port 5000 --backend-host 127.0.0.1 --backend-port 8080 --backend-http
python -m middleware.main --mode client --host 127.0.0.1 --port 5000
```

Type `Hi` → expect `echo: Hi`.

### C) Echo server only (no proxy)

```powershell
python -m middleware.main --mode server --port 5000
python -m middleware.main --mode client --host 127.0.0.1 --port 5000
```

## Docker

```powershell
docker build -t pqtls-middleware:1.0.0 .
docker run --rm -p 5000:5000 pqtls-middleware:1.0.0 --mode server
docker run -it --rm pqtls-middleware:1.0.0 --mode client --host host.docker.internal --port 5000
```

## Live demo dashboard (UI)

Builds a browser UI that starts a PQ server + Docker proxy (PQ↔PQ hop), streams live logs, and walks through handshake stages when you send a message.

```powershell
# 1) Build image once (needs Docker + liboqs build time)
docker build -t pqtls-middleware:1.0.0 .

# 2) Run dashboard from host Python (stdlib only)
python -m dashboard.server
```

Open http://127.0.0.1:8090 — click **Send Secure Message**.

Demo path: `Client --PQ--> Proxy --PQ--> Server (--mode server)`.

Optional: attach to services you already started:

```powershell
$env:MANAGE_BACKEND="0"; $env:MANAGE_PROXY="0"; python -m dashboard.server
```

## Documentation

| Doc                                              | Audience              |
| ------------------------------------------------ | --------------------- |
| [docs/IMPLEMENTATION_REPORT.md](docs/IMPLEMENTATION_REPORT.md) | Full technical + business report |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)     | Engineers             |
| [docs/DEMO_GUIDE.md](docs/DEMO_GUIDE.md)         | Investors / demos     |
| [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) | Security / product    |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md)   | Operators             |
| [docs/PROTOCOL.md](docs/PROTOCOL.md)             | Protocol implementers |
| [docs/ROADMAP.md](docs/ROADMAP.md)               | Planning              |

## Project layout

```text
middleware/     CLI entry (--mode client|server|proxy)
client/         Interactive PQ client
server/         PQ echo server wrapper
common/         Handshake, crypto, session, proxy relay
dashboard/      Live browser demo UI + SSE server
backend_*.py    Demo backends (HTTP / TCP echo)
certs/          TLS certificate + key
tests/          Unit tests (relay covered; crypto tests planned)
```

## Honest scope

This is a **prototype**. It proves the architecture and crypto path end-to-end. It is not yet a hardened commercial gateway. See [SECURITY_MODEL.md](docs/SECURITY_MODEL.md) and [ROADMAP.md](docs/ROADMAP.md).
