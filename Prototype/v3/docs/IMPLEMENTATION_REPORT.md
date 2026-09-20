# QSCP Quantum-Safe Middleware — Implementation Report

**Product:** Nutech Quantum Secure Middleware (QSCP)  
**Version:** 1.0.0 (prototype)  
**Scope:** Single middleware executable — client, server, and proxy modes  

---

## 1. What exactly this code is solving

### 1.1 The core problem

Most of today’s internet security (HTTPS, VPNs, APIs) depends on **classical public-key cryptography** such as RSA and Elliptic-Curve Diffie–Hellman (ECDH).

A sufficiently powerful **quantum computer** is expected to break those algorithms (notably via Shor’s algorithm). That creates a practical threat known as:

> **Harvest now, decrypt later**  
> An attacker records encrypted traffic today, stores it, and decrypts it years later when quantum capability arrives.

Sensitive data with long confidentiality life (health, finance, government, intellectual property) is especially exposed.

### 1.2 What this prototype solves

This codebase provides a **working quantum-safe communication layer** that:

1. Establishes a shared secret using **ML-KEM-768** (NIST post-quantum key encapsulation)
2. Authenticates the handshake using **ML-DSA-65** (NIST post-quantum signatures)
3. Encrypts application messages with **AES-256-GCM**
4. Can sit as **middleware/proxy** in front of existing systems so backends do not need to be rewritten

In short:

> **Problem:** classical TLS alone is not future-proof against quantum attacks on key exchange/signatures.  
> **Solution:** add a post-quantum handshake and secure channel, optionally as a proxy in front of normal servers.

### 1.3 What it is *not* (yet)

- Not a finished commercial product
- Not a full replacement for every TLS deployment worldwide
- Not claiming formal certification or audit completion
- Not assuming every internal hop is automatically quantum-safe unless configured (`--backend-pq`)

---

## 2. How this is useful in the real world

### 2.1 Who benefits

| Sector | Why it matters |
|---|---|
| Banking / fintech | Transaction and customer data must stay confidential for years |
| Healthcare | Medical records have long retention and high sensitivity |
| Government / defense | Classified or citizen data must resist future cryptanalysis |
| Critical infrastructure | OT/IT links that cannot be redesigned overnight |
| Enterprises with legacy APIs | Want quantum readiness without rewriting every backend |

### 2.2 Real-world deployment pattern

Organizations rarely want to rebuild every application for new crypto. They prefer a **gateway**:

```text
Users / Apps  →  Quantum-safe middleware  →  Existing APIs / services
```

That is the same operational pattern as:

- TLS-terminating load balancers
- API gateways
- Reverse proxies (nginx, Envoy)  

…but with a **post-quantum client-facing protocol** on top of TLS 1.3.

### 2.3 Concrete usefulness of this prototype

| Capability | Real-world value |
|---|---|
| Client ↔ middleware PQ channel | Protect public/edge traffic against harvest-now-decrypt-later |
| Proxy to normal HTTP/TCP backend | Reuse existing services unchanged |
| Optional `--backend-pq` | Also protect middleware ↔ internal server with PQ |
| Single executable / Docker image | Easy PoC for demos, pilots, lab evaluations |
| Echo / HTTP demo backends | Prove end-to-end message flow quickly |

### 2.4 Business narrative

> “We do not ask you to quantum-upgrade every microservice tomorrow. We put a quantum-safe front door in front of what you already run.”

That is the product thesis this code is designed to demonstrate.

---

## 3. Everything this code does

### 3.1 Operating modes

| Mode | Behavior |
|---|---|
| `--mode client` | Connects to middleware; interactive secure messaging shell |
| `--mode server` | Accepts PQ clients; replies `ACK: <message>` (echo demo) |
| `--mode proxy` | Accepts PQ clients; terminates security; relays to a backend |

### 3.2 End-to-end technical pipeline

For each client connection the stack does:

```text
1. TCP connect
2. TLS 1.3 handshake (outer pipe)
3. Custom PQ handshake on that pipe:
      - ML-KEM-768 key agreement
      - ML-DSA-65 mutual transcript signatures
      - HMAC key confirmation
4. Hybrid HKDF → 32-byte master key
5. Directional AES-256-GCM traffic keys
6. Application messages (sequence + AEAD)
7. If proxy: forward plaintext (or PQ again) to backend
```

### 3.3 Cryptographic and protocol modules

| Module / area | What it does |
|---|---|
| `common/tls.py` | Create TLS 1.3-only client/server contexts |
| `common/tls_session.py` | Read TLS metadata; export “TLS contribution” |
| `common/handshake.py` | Full client/server PQ handshake state machine |
| `common/pq_kem.py` | ML-KEM-768 via liboqs |
| `common/pq_dsa.py` | ML-DSA-65 via liboqs |
| `common/transcript.py` | Running SHA-256 transcript of handshake messages |
| `common/protocol.py` / `serializer.py` / `transport.py` | Binary message types + length-prefixed framing |
| `common/hybrid.py` | HKDF master key from PQ secret + TLS contribution + transcript |
| `common/secure_channel.py` | Derive directional AES-GCM keys; encrypt/decrypt |
| `common/session.py` | Secure send/receive with sequence, nonce, AAD, replay checks |
| `common/middleware.py` | Orchestrates connect/accept/gateway pipelines |
| `common/backend.py` | Dial plain TCP or classical TLS backend |
| `common/relay.py` | Raw byte relay, HTTP POST wrap, or PQ↔PQ relay |
| `middleware/main.py` | CLI entrypoint |
| `backend_http_demo.py` | Demo HTTP API |
| `backend_tcp_echo.py` | Demo TCP echo |

### 3.4 Proxy backend behaviors

| Flag / mode | What happens to each client message |
|---|---|
| Raw TCP (`--no-backend-http`) | Bytes forwarded as-is to backend socket |
| HTTP (`--backend-http`) | Wrapped as `POST /echo` (or configured path); response body returned |
| Classical TLS (`--backend-tls`) | Backend dial uses standard TLS |
| PQ hop (`--backend-pq`) | Proxy opens second PQ session to a PQ server and relays securely |

### 3.5 Application message protections

After handshake, each app message includes:

- Monotonic sequence number
- Deterministic direction-tagged nonce (`CLNT`/`SRVR` + sequence)
- AES-GCM ciphertext + auth tag
- Sequence bound in AAD

Effects:

- Confidentiality
- Integrity
- Replay / out-of-order rejection

### 3.6 Packaging and operations scaffolding

- Docker image building liboqs from source
- `docker-compose` services
- Env/CLI configuration
- Logging and in-memory metrics
- Documentation under `docs/`

### 3.7 Current limitations (important)

- Client TLS certificate verification defaults off in prototype path
- PQ identity is largely trust-on-first-use (no full CA for ML-DSA yet)
- Hybrid TLS input is metadata-based, not a true TLS exporter
- Not a full enterprise HTTP gateway (routing, pooling, HTTP/2, etc.)
- Test coverage still incomplete outside relay basics

---

## 4. Where this sits in the OSI / Internet model

### 4.1 OSI model mapping

| OSI layer | Name | What this project uses |
|---|---|---|
| 7 | Application | Your message text / HTTP API semantics |
| 6 | Presentation | Encoding of app payloads; AEAD ciphertext as opaque bytes |
| 5 | Session | Custom PQ handshake + `SecureSession` (logical secure session) |
| 4 | Transport | **TCP** |
| 3 | Network | IP (normal internet/LAN routing) |
| 2 | Data link | Ethernet/Wi-Fi (OS/network stack) |
| 1 | Physical | Cable/radio |

### 4.2 More precise “Internet stack” view

In practice, engineers describe this as:

```text
┌──────────────────────────────────────────────┐
│ Application data (chat text / API payload)   │  ← what users care about
├──────────────────────────────────────────────┤
│ Custom PQ secure channel (AES-GCM messages)  │  ← this project's inner security
├──────────────────────────────────────────────┤
│ Custom PQ handshake (ML-KEM + ML-DSA)        │  ← this project's key agreement
├──────────────────────────────────────────────┤
│ TLS 1.3                                      │  ← standard session/crypto layer over TCP
├──────────────────────────────────────────────┤
│ TCP                                          │  ← transport
├──────────────────────────────────────────────┤
│ IP / network                                 │
└──────────────────────────────────────────────┘
```

### 4.3 Where the “TLS handshake” sits

- **TLS handshake** happens at the **TLS layer above TCP** (commonly associated with OSI session/presentation concerns, implemented as part of the secure transport stack).
- It runs **first**, creating an encrypted TLS tunnel.
- Then this project runs its **own PQ handshake inside that TLS tunnel**.

So:

```text
Internet path:
  App → PQ session → TLS 1.3 → TCP → IP → network

Order in time:
  1) TCP connect
  2) TLS handshake          ← classical secure channel setup
  3) PQ handshake           ← quantum-safe key agreement/auth
  4) Encrypted app messages
```

### 4.4 Why both TLS and PQ?

- **TLS** provides a standard, widely supported encrypted pipe and current best-practice transport security.
- **PQ layer** adds cryptographic primitives believed to resist quantum attacks on key exchange/signatures.
- Together they form a defense-in-depth prototype for migration toward post-quantum readiness.

### 4.5 Where the proxy sits on the Internet path

```text
Client machine                    Datacenter / cloud
──────────────                    ─────────────────
Browser/App
   │
   │  (Internet / VPN / LAN)
   ▼
Middleware host (public or DMZ)   ← PROXY lives here
   │
   │  (usually private network)
   ▼
Backend application server
```

The proxy is an **application-level gateway** (L7 intent), even though underneath it uses TCP/TLS sockets.

---

## 5. How the proxy is used and why

### 5.1 What “proxy” means here

A proxy is a middle program:

```text
Client  →  Proxy  →  Backend
```

The client does **not** talk directly to the backend.  
The proxy:

1. Speaks the PQ protocol with the client
2. Decrypts the message
3. Sends it onward in a form the backend understands
4. Encrypts the backend response back to the client

This is **terminate-and-reissue** (also called terminate-and-forward), not blind pass-through of encrypted PQ bytes.

### 5.2 Why use a proxy architecture?

| Reason | Explanation |
|---|---|
| **No backend rewrite** | Existing HTTP/TCP services keep running unchanged |
| **Central security upgrade** | Quantum-safe controls are added in one place |
| **Edge enforcement** | Public clients hit the hardened front door |
| **Flexible backend policy** | Same proxy can forward to TCP, HTTP, TLS, or PQ backend |
| **Incremental migration** | Start with edge PQ; later protect inner hop too |

### 5.3 How proxy is implemented in this code

1. `run_secure_gateway` listens on a port (e.g. 5000)
2. For each client:
   - TLS + PQ handshake → client `SecureSession`
3. Then one of:
   - **Raw relay:** long-lived TCP to backend, pump bytes both ways
   - **HTTP relay:** each secure message becomes `POST /echo`, await response
   - **PQ relay:** `secure_connect` to backend PQ server, pump secure messages both ways
4. Idle timeout / errors close both legs

### 5.4 Why not make every backend speak PQ directly?

Possible, but costly:

- Every language/runtime needs a PQ SDK
- Every service must be upgraded and tested
- Migration becomes years-long

Proxy approach:

- Upgrade the **edge once**
- Keep backends as-is initially
- Optionally add `--backend-pq` for high-value internal links later

### 5.5 Proxy threat note (honest)

When proxy terminates PQ:

- Proxy can see plaintext application data (same as TLS-terminating load balancers)
- Proxy must be trusted and hardened
- Proxy→backend must be protected by network controls and/or TLS/PQ

That is normal for gateway architectures.

### 5.6 Demo topologies

**A. Double PQ (both hops quantum-safe)**
```text
Client --PQ--> Proxy --PQ--> Server(--mode server)
```

**B. PQ edge + normal HTTP backend**
```text
Client --PQ--> Proxy --HTTP--> backend_http_demo.py
```

**C. PQ edge + raw TCP backend**
```text
Client --PQ--> Proxy --TCP--> backend_tcp_echo.py
```

---

## Summary

| Question | Answer |
|---|---|
| **What is it solving?** | Future quantum risk to classical key exchange by adding PQ-secure sessions and a middleware path |
| **Real-world use?** | Edge gateway for banks/gov/enterprise to adopt PQ without rewriting all backends |
| **What does the code do?** | TLS + PQ handshake, AEAD messaging, client/server/proxy modes, TCP/HTTP/PQ backend relays |
| **Where in OSI/Internet?** | App data over custom PQ session over TLS 1.3 over TCP/IP; proxy is an application gateway on the path |
| **Why proxy?** | Terminate PQ at the edge, forward to existing systems, centralize upgrade and optionally PQ-protect the inner hop |

---

## Related documents

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [SECURITY_MODEL.md](SECURITY_MODEL.md)
- [PROTOCOL.md](PROTOCOL.md)
- [DEMO_GUIDE.md](DEMO_GUIDE.md)
- [CONFIGURATION.md](CONFIGURATION.md)
- [ROADMAP.md](ROADMAP.md)
- [../README.md](../README.md)
