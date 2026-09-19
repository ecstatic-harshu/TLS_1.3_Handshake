# Proxy Conversion Plan — Quantum-Safe Middleware

**Goal:** turn the current point-to-point secure-channel demo into a real middleware **proxy** — something that sits between an external client and a backend service, terminates the PQC/hybrid handshake with the client, and relays traffic to/from the backend.

**Companion doc:** `PRODUCTION_READINESS_REVIEW.md` covers security/reliability/testing gaps independent of proxying (default `verify_server=False`, the non-exporter "TLS contribution", empty test suite, broken `requirements.txt`, etc.). Those are not re-solved by this plan and should be tracked separately — item 5 and item 3 below touch overlapping code, so it's efficient to fix them in the same pass, but the rest of that review is out of scope here.

---

## 1. What exists today

Traced directly from the code (`common/middleware.py`, `middleware/main.py`, `server/server.py`, `client/client.py`, `common/config.py`, `common/session.py`):

- **`secure_connect()`** (`common/middleware.py:466`) — full client-side pipeline: TCP → TLS 1.3 → ML-KEM-768/ML-DSA-65 handshake → hybrid HKDF → directional AES-256-GCM `SecureSession`. This is solid and reusable as-is.
- **`run_secure_server()` / `_create_server_session()`** (`common/middleware.py:1667, 1160`) — server-side mirror of the same pipeline, one thread per accepted client (`handle_secure_client`, `middleware.py:1532`).
- **What a server thread actually *does* with a session** — `server_receive_loop()` (`middleware.py:1500`): reads one secure message, decodes it as UTF-8, replies with a hardcoded `f"ACK: {message}"`. There is no other server-side behavior anywhere in the codebase.
- **`client/client.py`** — an interactive CLI shell: connects via `secure_connect()`, then reads lines from stdin and sends them as secure messages, printing whatever comes back.
- **`middleware/main.py`** — a CLI with `--mode client|server`, picking between the two roles above. There is no third mode and no concept of "sit in the middle."
- **`common/config.py`** — `HOST`, `PORT`, `CERT_FILE`, `KEY_FILE`, `LOG_LEVEL`. **No backend/upstream host, port, or target concept exists anywhere in configuration.**
- **The secure transport is message-oriented, not stream-oriented.** `SecureSession.send_secure(bytes)` / `receive_secure() -> bytes` (`common/session.py:466, 689`) send/receive one length-prefixed, AEAD-framed application message at a time (capped at the transport layer's packet-size limit). It is not a raw duplex byte pipe the way a plain TCP socket is — this matters directly for how relaying has to be implemented (see Step 3).

**Confirmed via grep:** searching `client/`, `common/`, `middleware/`, `server/` for `backend|upstream|forward|proxy_to` returns zero matches. There is no dialer that connects *out* to anything; both roles only ever talk to each other.

## 2. The gap, concretely

| Capability a proxy needs | Status |
|---|---|
| Backend/upstream configuration (host, port, or multiple targets) | **Missing entirely** |
| Outbound dialer to a backend (plain TCP or standard TLS) | **Missing entirely** |
| A "gateway" role that is simultaneously a PQ-server (toward the client) and a plain/TLS client (toward the backend) | **Missing entirely** — only pure client and pure echo-server roles exist |
| Bidirectional relay/pump between the two legs of a connection | **Missing entirely** — existing loops are one-directional read-then-respond, not a two-socket pump |
| Adapter between message-framed `send_secure`/`receive_secure` and a backend's raw byte stream | **Missing entirely** — needs an explicit chunking strategy since these are different transport models |
| Coordinated connection-lifecycle teardown (closing one leg closes the other) | **Missing** — no second leg exists to coordinate with |
| Pass-through vs. terminate-and-reissue decision | **Not decided in code** — see architecture note below |
| Multi-backend routing / target selection | **Missing** — no field in the protocol or config for it |
| Connection pooling to backend | **Missing** — not applicable yet since there's no backend connection at all |
| Tests covering relay behavior | **Missing** (all of `tests/*.py` are empty — see companion review) |

### Architecture decision: terminate-and-reissue, not blind pass-through

Blind pass-through (forwarding encrypted bytes untouched, the way an SNI-routing TLS proxy does) only makes sense if the backend itself speaks this exact bespoke PQC/hybrid protocol — which no ordinary backend service does. So the proxy must **terminate** the PQC channel with the client (existing handshake code, unchanged), obtain plaintext application bytes, and **reissue** them to the backend over a plain or standard-TLS connection — then encrypt the backend's response back to the client. This is the same shape as a TLS-terminating load balancer, just with the client-facing leg being PQC/hybrid instead of classical TLS. A future "PQC-to-PQC tunnel" mode (backend also speaks this protocol) is possible later but is not the default and isn't needed for a working proxy.

---

## 3. Steps, in dependency order

### Step 1 — Backend/upstream configuration
**What:** Add `BACKEND_HOST` / `BACKEND_PORT` (start with one static target) to `common/config.py`, mirroring the existing `HOST`/`PORT` pattern. Add `--backend-host` / `--backend-port` flags to `middleware/main.py`. Shape the config as a single target for v1, but keep the field names ready to become a list later (e.g. `BACKEND_TARGETS`).
**Depends on:** nothing.
**Effort: S (2–4 hours).** Pure plumbing, same pattern already used for `HOST`/`PORT`.

### Step 2 — Backend dialer
**What:** New helper, e.g. `common/backend.py::connect_backend(host, port, use_tls=False, timeout=...)`, returning a connected plain or standard-TLS socket. The backend does **not** need to understand PQC — this is an ordinary outbound connection using Python's `socket`/`ssl` modules. Include a connect timeout and metrics events consistent with the existing `_record_duration` pattern in `middleware.py`.
**Depends on:** Step 1 (needs config values to dial).
**Effort: S–M (3–6 hours).**

### Step 3 — Bidirectional relay primitive
**What:** The core new mechanism — nothing like it exists in the codebase today. A function, e.g. `relay_secure_to_backend(session, backend_sock, logger, metrics)`, running two concurrent loops (this codebase is thread-based, so two threads per connection):
  - **client → backend:** `session.receive_secure()` → `backend_sock.sendall(chunk)`.
  - **backend → client:** `backend_sock.recv(4096)` in a loop → `session.send_secure(chunk)` per chunk received.

  Key design points to get right:
  - Because `send_secure`/`receive_secure` are **message-framed**, not a raw stream, each `recv()` from the backend becomes one discrete secure message — this is a deliberate chunking strategy, not a limitation to work around.
  - **Coordinated shutdown:** either leg closing (EOF from backend, or the client session raising on receive) must stop both pump threads and close both sockets — use a shared `threading.Event` or check-and-close pattern, not independent unguarded loops (which is exactly the bug pattern already flagged in the companion review for the existing accept loop).
  - Backpressure: `sendall` on the backend socket will block under slow-consumer conditions — acceptable for a thread-per-connection v1, but note as a scaling constraint.
**Depends on:** Steps 1–2 (needs a live backend socket to relay against for testing).
**Effort: M (1–2 days).** This is genuinely new design, not plumbing — partial reads, chunk-boundary handling, and clean bidirectional teardown all need care and are the most likely source of subtle bugs.

### Step 4 — Gateway server role
**What:** New function in `common/middleware.py`, e.g. `handle_gateway_client(conn, addr, server_dsa_keypair, backend_host, backend_port)`: reuse `_create_server_session()` unchanged to complete the PQC handshake with the inbound client, dial the backend with Step 2's helper, then call Step 3's relay instead of `server_receive_loop()`. Add `run_secure_gateway(host, port, backend_host, backend_port, backlog=...)`, mirroring `run_secure_server()`'s accept loop but spawning `handle_gateway_client` threads.
**Depends on:** Steps 1–3.
**Effort: S–M (4–8 hours).** Mostly wiring — the accept loop structure already exists in `run_secure_server` (`middleware.py:1667`) and can be closely mirrored.

### Step 5 — Fix the blocking accept-loop handshake (while touching this code anyway)
**What:** `run_secure_server`'s accept loop currently runs `conn.do_handshake()` synchronously on the main accept thread before spawning the client thread (`middleware.py:1836`) — one slow/stalled client blocks all new connections. Since Step 4 requires rewriting this loop for the gateway anyway, move the TLS handshake into the per-connection thread in the new `run_secure_gateway` (and ideally backport the fix to `run_secure_server` too).
**Depends on:** Step 4 (same code region).
**Effort: S (2–3 hours).**

### Step 6 — Timeouts on both legs
**What:** `conn.settimeout(...)` on the inbound PQC socket and `backend_sock.settimeout(...)` on the outbound leg, so a stalled client or an unresponsive backend can't hang a relay thread indefinitely. Decide read-timeout behavior in Step 3's pump loops (v1: treat a timeout as a hard close; revisit keepalive/idle-timeout semantics later if needed).
**Depends on:** Step 3.
**Effort: S (2–4 hours).**

### Step 7 — CLI entry point for proxy mode
**What:** Add `--mode proxy` to `middleware/main.py`, invoking a new `run_proxy()` (new `middleware/proxy.py`, or extend `server/server.py`) that calls `run_secure_gateway()` with the backend host/port resolved from Step 1's config/CLI. Update `docker-compose.yml`/Dockerfile to expose a runnable proxy service (as a new service definition or a `--mode proxy` command override), separate from the existing plain client/server demo modes.
**Depends on:** Steps 1, 4.
**Effort: S (2–4 hours).**

### Step 8 — Integration tests for the relay path
**What:** This is where the currently-empty `tests/` directory should start getting real content relevant to proxying specifically: spin up a throwaway backend (simple echo or HTTP server) in-process, start the gateway on a local port, connect through it with `secure_connect()`, and assert:
  - bytes sent by the client arrive at the backend unmodified,
  - the backend's response round-trips back to the client correctly across chunk boundaries,
  - closing the client side tears down the backend leg (and vice versa),
  - a backend read timeout closes the client session cleanly rather than hanging.
**Depends on:** Step 4 (needs something to test against). Should not be deferred past this point — the relay is exactly the kind of logic (two concurrent loops, shared teardown state) that silently breaks under refactors without a test catching it.
**Effort: M (1–2 days).**

### Step 9 — Load/soak test the relay path
**What:** A script opening N concurrent secure sessions through the gateway to a test backend, measuring latency/throughput overhead from the PQC handshake plus AEAD message framing versus a raw TCP proxy baseline. Use this to decide whether the thread-per-connection model (Step 4) needs revisiting (e.g., a bounded thread pool, or an asyncio rewrite) before real traffic volumes.
**Depends on:** Step 4, ideally Step 8 passing first.
**Effort: S–M (4–8 hours)** for a basic version; more if you want to establish real capacity numbers.

---

## 4. Optional / v2 stretch work (not required for a working proxy)

### Step 10 — Multi-backend routing
**What:** Support selecting among several backend targets per connection. Two approaches:
  - **Simplest (recommended to start):** one gateway process/config = one backend target; run multiple gateway instances behind a load balancer or on different ports for different backends. No protocol changes needed.
  - **In-protocol routing:** add a target-selector field to the handshake's initial Hello message (`common/protocol.py`) so a single gateway can route by an opaque service name. This touches transcript-hashed, signature-covered handshake data, so it requires re-validating handshake correctness — meaningfully more risk than the port-per-backend approach.
**Depends on:** Step 4.
**Effort: M–L (1–2+ days)** depending on which approach; treat the in-protocol option as a deliberate design decision, not a default requirement.

### Step 11 — HTTP-aware relaying
**What:** If backends are specifically HTTP services and you want header rewriting (`X-Forwarded-For`, `Host` rewrite, etc.) or connection reuse rather than raw byte relay, add an HTTP-parsing mode (`Content-Length`/chunked-transfer-aware framing instead of naive chunk forwarding). Note the raw-byte relay from Steps 1–9 already works transparently for HTTP backends today — this step only adds application-layer awareness/rewriting on top.
**Depends on:** Steps 1–9 stable.
**Effort: L (1+ week).** Full HTTP/1.1 request/response parsing and keep-alive semantics is a substantial feature in its own right.

### Step 12 — Backend connection pooling
**What:** Reuse backend connections across client sessions instead of dialing fresh per connection. Only makes sense for short request/response-style backends (e.g., HTTP); for persistent full-duplex sessions, one backend connection per client session — already the model from Step 4 — is the natural default.
**Depends on:** Steps 4 and 9 (validate need under load before optimizing).
**Effort: S–M (4–8 hours).**

---

## 5. Rollup

- **Minimum viable proxy (Steps 1–7):** ~3–5 engineer-days. Gets you a working terminate-and-reissue gateway: client does the existing PQC/hybrid handshake, proxy relays plaintext bytes to a configured backend and back.
- **Plus tests and basic load validation (Steps 8–9):** ~2–3 more days. Don't ship Step 4 without Step 8 — the relay's coordinated-teardown logic is exactly the kind of thing that regresses silently.
- **Optional v2 work (Steps 10–12):** 1–3+ additional weeks depending on how much routing/HTTP-awareness/pooling sophistication is actually needed — treat these as follow-on scope decisions, not blockers to calling the core proxy done.
