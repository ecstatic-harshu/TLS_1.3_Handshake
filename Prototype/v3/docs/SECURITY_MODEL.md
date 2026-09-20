# Security Model

## Status

**Prototype security model.** Core PQ primitives are real (liboqs ML-KEM-768 / ML-DSA-65). Defaults and trust infrastructure are not yet production-hardened.

## Goals

1. Protect client↔middleware confidentiality against future quantum attacks on classical key exchange
2. Authenticate the PQ handshake transcript (detect tampering)
3. Encrypt application messages with AEAD (AES-256-GCM)
4. Optionally protect middleware↔backend with the same PQ stack (`--backend-pq`)

## Non-goals (today)

- Full PKI / certificate pinning for ML-DSA identities
- Formal verification or third-party audit
- High-assurance multi-tenant gateway hardening
- Guaranteed protection of every internal network path without configuration

## Cryptographic building blocks

| Mechanism | Role |
|---|---|
| TLS 1.3 | Outer encrypted transport; classical |
| ML-KEM-768 | Post-quantum shared secret (key encapsulation) |
| ML-DSA-65 | Post-quantum signatures over handshake transcript |
| SHA-256 transcript | Bind handshake messages in order |
| HMAC-SHA256 | Key confirmation (both sides share KEM secret) |
| HKDF-SHA256 | Derive 32-byte master key + directional traffic keys |
| AES-256-GCM | Encrypt/authenticate application messages |
| Sequence numbers in AAD | Replay / reorder detection |

## Trust boundaries

```text
[ Untrusted network ]     [ Gateway ]     [ Backend network ]
 Client ◄── PQ/TLS ──►   Proxy   ◄── ? ──►  Backend
```

| Hop | Default protection | Notes |
|---|---|---|
| Client → Proxy | TLS 1.3 + PQ session | Main prototype value |
| Proxy → Backend | TCP, optional TLS, or PQ | Depends on flags |

### Backend hop modes

- **Raw TCP:** no crypto on that hop (demo / trusted LAN only)
- **`--backend-tls`:** classical TLS to backend
- **`--backend-pq`:** full PQ session to a PQ-speaking backend (`--mode server` or another gateway)

## Known limitations (be honest)

1. **Client TLS verify defaults off** (`verify_server=False` in `secure_connect`) — MITM risk on TLS identity if left as-is
2. **ML-DSA keys are trust-on-first-use** in the handshake — no CA/pinning of long-term PQ identity yet
3. **“Hybrid” TLS contribution** is derived from public TLS metadata, not a real TLS exporter secret
4. **No connection admission control** — thread-per-connection can be flooded
5. **Shallow container healthcheck** — TCP open ≠ crypto healthy
6. **Limited automated crypto tests** — relay unit test exists; handshake/KEM suites are incomplete

## Threat examples

| Threat | Mitigated by prototype? |
|---|---|
| Passive eavesdropper recording client↔proxy for later quantum break of ECDH | Aimed yes (ML-KEM) |
| Active swap of handshake public keys without detection | Partially (ML-DSA + transcript); identity root of trust still weak |
| Replay of application messages | Yes (sequences + GCM) |
| Attacker on plain proxy→backend TCP | No (unless `--backend-tls` or `--backend-pq`) |
| Malicious client DoS via many connections | Not yet |

## Recommended demo posture

- Prefer **`--backend-pq`** when demonstrating “both sides protected”
- State clearly: prototype, next phase adds PKI / verify-on / tests
- Do not claim certification or production clearance

## Related docs

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [PROTOCOL.md](PROTOCOL.md)
- [ROADMAP.md](ROADMAP.md)
