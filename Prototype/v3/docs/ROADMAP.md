# Roadmap

## Current status (prototype v1.0.0)

### Done

- [x] TLS 1.3 + ML-KEM-768 + ML-DSA-65 handshake
- [x] Transcript binding, signatures, HMAC key confirmation
- [x] AES-256-GCM session with sequence / replay checks
- [x] Client interactive shell
- [x] Echo server mode
- [x] Proxy mode (terminate-and-forward)
- [x] Raw TCP backend relay
- [x] HTTP wrap mode (`POST /echo` per message)
- [x] Optional classical TLS to backend
- [x] PQ backend hop (`--backend-pq`, PQ↔PQ relay)
- [x] TLS handshake moved to worker threads
- [x] Docker packaging (liboqs build)
- [x] Demo backends (`backend_http_demo.py`, `backend_tcp_echo.py`)
- [x] Core documentation set under `docs/`

### Explicitly not done

- Production identity (CA / pinning / verify-on by default)
- Real TLS exporter–based hybrid binding
- Full HTTP reverse-proxy features (HTTP/2, websockets, header rewrite)
- Multi-backend routing / pooling / load balancing
- Connection caps, graceful SIGTERM drain
- Comprehensive automated crypto + e2e test suite
- Market packaging, support SLAs, certifications

---

## Phase A — Demo & trust hardening (near term)

Goal: safer demos and clearer security story.

1. Default `verify_server=True` for client TLS (with documented local override)
2. Persist / pin server ML-DSA identity (or load from files)
3. Fix `requirements.txt` encoding and declare real dependencies (`cryptography`, oqs)
4. Fill empty crypto unit tests (handshake, KEM, signature, replay, tamper)
5. End-to-end test: client → proxy → backend (TCP, HTTP, PQ)

**Exit criteria:** CI runs tests; demo uses verify-on path without confusion.

---

## Phase B — Usable internal proxy (pilot)

Goal: first design-partner pilot on a controlled network.

1. Stream-friendly or keep-alive HTTP proxying (beyond single POST wrap)
2. Connection limits + timeouts tuned for ops
3. SIGTERM graceful drain for Docker/K8s
4. Structured logs + exportable metrics (Prometheus or file)
5. Deeper healthcheck (TLS or PQ smoke)
6. Deployment guide + cert rotation notes

**Exit criteria:** one partner runs proxy in staging in front of a real API.

---

## Phase C — Productization

Goal: commercial middleware offering.

1. Multi-target routing / virtual hosts
2. Policy controls (who can connect, rate limits)
3. Optional mutual auth / enterprise IdP hooks
4. Horizontal scale story (or clear single-node limits)
5. Security review / pen-test
6. Support runbooks and SLA packaging

**Exit criteria:** versioned product release with support boundary.

---

## Optional research track

- True hybrid with TLS exporters (RFC 5705 / OpenSSL export)
- PQ algorithm agility (negotiate ML-KEM/ML-DSA profiles)
- Language SDKs (`secure_connect` bindings)
- Sidecar / service-mesh packaging

---

## Suggested investor narrative

| Now | Next funding use |
|---|---|
| Working PQ middleware prototype | Harden identity + tests |
| Proxy with TCP / HTTP / double-PQ demos | Pilot with one design partner |
| Clear docs for architecture & security limits | Turn pilot into productized gateway |

---

## Related docs

- [README.md](../README.md)
- [SECURITY_MODEL.md](SECURITY_MODEL.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [DEMO_GUIDE.md](DEMO_GUIDE.md)
