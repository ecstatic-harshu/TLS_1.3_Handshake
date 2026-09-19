# Production-Readiness Review — Quantum-Safe Middleware Proxy

**Scope:** `client/`, `common/`, `middleware/`, `server/`, `tests/`, `test.py`, `requirements.txt`, `Dockerfile`, `docker-compose.yml`, `README.md`. The vendored `liboqs/` and `liboqs-python/` trees are treated as third-party dependencies, not audited for their own internal correctness (upstream's responsibility), except to confirm they're actually wired in and not dead weight.

**Date:** 2026-09-14
**Reviewed by:** Claude Code (audit only — no code changes applied)

---

## Verdict: **Not Production Ready**

The core PQC primitives (ML-KEM-768 / ML-DSA-65 via real `liboqs-python` bindings), transcript binding, and replay/sequence protection are solid, spec-correct engineering. But the system has a **default-on MITM vulnerability**, the codebase does not yet implement the core behavior implied by "middleware proxy" (backend traffic forwarding), and there is **zero automated test coverage** for a project whose entire value proposition is cryptographic correctness. Any one of these would block production sign-off; together they make this a prototype, not a deployable proxy.

---

## Security-Critical Blockers (fix before anything else)

| # | Issue | Location | Severity |
|---|---|---|---|
| 1 | `secure_connect()` defaults to `verify_server=False`, disabling outer TLS certificate/hostname verification by default | `common/middleware.py:470` | **CRITICAL** |
| 2 | The "hybrid" TLS contribution is not a real TLS exporter secret (RFC 5705) — it's a hash of **public** metadata (negotiated version, cipher, session_reused), so it contributes no entropy or authentication to the hybrid key derivation. Self-documented in the code's own comment. | `common/tls_session.py:32-76` | **CRITICAL** |
| 3 | Combined effect of #1 + #2: PQ handshake public keys (KEM/DSA) are trust-on-first-use with no external root of trust (no CA, no pinning), and outer TLS verification is off by default → a full active MITM can transparently substitute its own keys and complete an "authenticated" handshake, with default settings, no downgrade trick required | `common/middleware.py`, `common/handshake.py:663-680, 1439-1459` | **CRITICAL** |
| 4 | `requirements.txt` is UTF-16LE-encoded → `pip install -r requirements.txt` fails/mis-parses → breaks the documented Docker build | `requirements.txt`, `Dockerfile:47` | **CRITICAL** (deployment blocker) |
| 5 | Zero automated test coverage. `tests/test_handshake.py`, `test_kem.py`, `test_protocol.py`, `test_replay.py`, `test_signature.py`, `test_tampering.py`, `test_transcript.py` are all **0 bytes** — named for exactly the security-critical paths, entirely empty (not even stubs). `test.py` at repo root is a manual demo script, not a test. No `pytest.ini`/`conftest.py`/`tox.ini` anywhere. | `tests/*.py`, `test.py` | **CRITICAL** |
| 6 | `conn.do_handshake()` executes synchronously in the single-threaded accept loop, *before* the per-client thread is spawned → one slow or stalled client blocks all new incoming connections (trivial DoS) | `common/middleware.py:1836` | **HIGH** |
| 7 | The codebase does not implement proxying. No backend-forwarding logic exists anywhere (`grep` for `backend\|upstream\|forward\|proxy_to` across `client/`, `common/`, `middleware/`, `server/` returns zero matches). The server's only behavior on receiving a message is to reply with a hardcoded `ACK: {message}`. This is a point-to-point secure chat/demo, not a proxy that terminates PQC and forwards traffic to a configurable backend. | `common/middleware.py:1517-1521`; entire `middleware/`, `server/`, `client/` | **CRITICAL** (scope gap) |

---

## Checklist Evaluation

### Security

- **PQC algorithm usage — Yes, spec-correct.** ML-KEM-768 (`common/pq_kem.py:8`) and ML-DSA-65 (`common/pq_dsa.py:8`), both via `import oqs` (liboqs-python), confirmed live in `common/handshake.py:22-32`. Proper use of `oqs.KeyEncapsulation`/`oqs.Signature` context managers, byte-output validation, and signature-verification return values are checked before proceeding (`handshake.py:783-817, 1584-1618`) — no silent-trust bug found in the real path.
- **Dead mock crypto present — flag.** `common/pq.py` is a separate, non-cryptographic mock KEM/signature class (`b"mock_public_key"`, HMAC-based fake "signatures"). Not imported anywhere today, but a latent landmine given its innocuous name next to the real `pq_kem.py`/`pq_dsa.py`.
- **Hybrid handshake / downgrade protection — No, this is the critical gap.** See blockers #1–#3 above. The "hybrid" design does not actually bind to outer-TLS secrecy, and outer TLS verification is off by default.
- **Key management — Partial.** Keys are generated fresh per-handshake via liboqs (ephemeral, appropriate for a handshake). No persistence/rotation logic in these files, no hardcoded production secrets found. Nonces are CSPRNG-based (`os.urandom`, `transcript.py:349`), not Python's `random`.
- **Transcript/handshake integrity — Yes, strong.** `transcript.py` binds role+type+length+payload per message with domain separation and SHA-256; `auth_digest`/`final_digest` are checked into signatures and confirmation tags; key-confirmation uses HMAC with `hmac.compare_digest` (constant-time) at `handshake.py:999-1006, 1692-1699`. No skipped verification steps found in the state machine.
- **TLS layer — Partial.** `tls.py` correctly pins TLS 1.3 exact (min=max=TLSv1_3) using the real `ssl` module — no custom TLS reimplementation. But `create_client_context(verify_server=False)` sets `check_hostname=False` + `CERT_NONE`, and this is the default reachable from the public API.
- **Input validation on proxied traffic — Yes, within the protocol/session layer.** Every wire field has type/length checks before use; length-prefixed sub-fields are bounds-checked against remaining payload length before slicing (`protocol.py:316-539`); UTF-8 decode errors are caught and converted to typed `ValueError` rather than crashing (`protocol.py:574-584`). Minor gap: sub-field lengths (KEM key, ciphertext, DSA key, signature) are bounded only by the generic 10MB transport cap, not by expected per-algorithm sizes — recommend validating against the negotiated algorithm's known sizes before handing data to the crypto layer.
- **No unsafe deserialization.** `serializer.py` is a custom binary struct format (`>BI` header). No `pickle`, `marshal`, `eval`, or `yaml.load` anywhere in the protocol/session layer.
- **`.env` file present at repo root** — untracked content not inspected as part of this audit; flag for a dedicated secrets review before any deployment.

### Performance

- Not load-tested as part of this audit (no load/stress test infra exists to run — see Testing section). Architecturally: thread-per-client model (`common/middleware.py`, `run_secure_server`) will not scale to very high concurrent-connection counts the way an async/event-loop model would, but is a reasonable starting point for moderate load.
- No connection pooling exists (consistent with there being no backend-forwarding yet — there's nothing to pool connections to).
- No client- or server-side read timeouts on the data path (only a connect timeout on the client, `middleware.py:571`) — a stalled peer can hang a handler thread indefinitely.

### Reliability

- **Error handling — Partial/Good within scope.** Per-connection exceptions are caught and logged (`middleware.py:1606, 1883`), so one client crashing does not take down the server process. Protocol/session layer fails closed: replay, out-of-order, bad nonce, bad message type, and AEAD-auth failures all raise `ValueError` and never advance sequence counters or mark a session established (`session.py:733-981, 177-196`). No silent downgrade/plaintext fallback found.
- **Blocking accept-loop handshake — Blocker #6 above.**
- **No retry/circuit-breaker logic anywhere.**
- **No graceful shutdown** — only `KeyboardInterrupt` is handled; no signal handling, no draining of in-flight handler threads.
- **Health check is shallow** — the Dockerfile healthcheck opens a raw TCP socket; it does not validate that a TLS/PQ handshake actually succeeds, so the container can report "healthy" while the crypto path is broken.
- **Strict in-order delivery, no resync** — a single dropped/corrupted frame kills the session (reasonable given TCP's ordering guarantees, but worth documenting as a reliability trade-off, not a security gap).
- Minor: `transport.py` keeps a module-level `_socket_locks` dict keyed by `id(sock)` that's only cleaned up if `release_socket_lock()` is explicitly called on every close — unverified whether all call sites do this; potential slow lock-object leak if not.

### Observability

- **Metrics — Partial.** `common/metrics.py` is a thread-safe in-memory event collector (`record`, `record_duration`, `count`, `summary`, `dump`), and it is genuinely wired into every handshake stage in `middleware.py` (not dead code). But: no fixed schema (callers must label consistently), no export path (no Prometheus/StatsD endpoint, no periodic flush), and the underlying event list is **unbounded** — never trimmed, so it grows indefinitely on a long-running process.
- **Logging — Partial, with a risk to verify.** `common/logger.py` uses standard `logging` with sensible per-name singleton handlers, stdout only (no rotation, no file/syslog sink). `middleware_logger.py` produces plain-text, unstructured log lines (not JSON, not easily machine-parseable). `DEFAULT_LOG_LEVEL = logging.DEBUG` is the default (`metrics.py:11`/`logger.py:11`) — in a crypto middleware this needs a dedicated pass over `logger.debug(...)` call sites in `handshake.py`/`secure_channel.py` to confirm no key material or shared secrets are logged at DEBUG level; not confirmed clean or unclean in this audit.
- **No tracing, no alerting hooks.**

### Scalability

- Session objects (`SecureSession`) are per-connection, not pooled/keyed in a shared registry within the audited files — no predictable-session-ID issue found at this layer.
- No horizontal-scaling-specific design found (e.g., no shared session store for multi-instance deployments) — likely fine for a stateless-per-connection proxy once backend forwarding exists, but unverified since that feature doesn't exist yet.
- No concept of "multiple backend targets" exists at all, since there is no backend-forwarding capability (see blocker #7).

### Testing

- **Fail — this is a standout gap.** All seven files under `tests/` are confirmed 0 bytes: `test_handshake.py`, `test_kem.py`, `test_protocol.py`, `test_replay.py`, `test_signature.py`, `test_tampering.py`, `test_transcript.py`. Named-but-empty test files are worse than no test files at all — they signal abandoned intent rather than an untouched area.
- `test.py` at repo root is a manual exploratory script (prints enabled KEM/signature mechanisms; contains a large block of commented-out manual demo code) — not an automated test.
- No `pytest.ini`, `conftest.py`, `tox.ini`, or test-related `pyproject.toml`/`setup.cfg` at the repo root.
- No load/stress tests, no fuzz testing of the crypto/protocol layer.
- (The vendored `liboqs`/`liboqs-python` trees carry their own upstream test suites — out of scope, not this project's responsibility.)

### Configuration & Deployment

- **Two divergent config paths.** `common/config.py` reads `HOST`/`PORT`/`CERT_FILE`/`KEY_FILE`/`LOG_LEVEL` from environment variables with sensible defaults — good pattern. But `middleware/main.py` (the actual Docker entrypoint) defines and uses its *own* argparse defaults (`0.0.0.0`/`127.0.0.1`, port `5000`) and ignores `common/config.py` entirely. This is confusing and risks operators configuring the wrong knob.
- **Docker build is broken** — see blocker #4 (`requirements.txt` UTF-16 encoding).
- `requirements.txt` pins large, apparently unrelated packages (`qiskit==2.5.0`, `qiskit-aer`, `rustworkx`, `pypdf`, `dill`) with no evident use in the application code, bloating the image and raising provenance questions — while never declaring `oqs`/liboqs-python, the one dependency the crypto layer actually hard-requires (`import oqs` in `pq_kem.py`/`pq_dsa.py`).
- Dockerfile itself is otherwise reasonable (slim base image, builds liboqs from source); running as non-root would be a further hardening improvement but isn't fatal.
- **No CI/CD anywhere at the repo root.** No `.github/workflows` or equivalent (the vendored `liboqs`/`liboqs-python` submodules have their own upstream CI, which is irrelevant to this project's own pipeline).

### Documentation

- `README.md` and `Readme.md` are two git-tracked paths that collapse to the same file on a case-insensitive filesystem (Windows) — almost certainly a merge artifact, consistent with both showing as modified in `git status`.
- Content is minimal (~22 lines): venv setup and run commands for `server.server`/`client.client` and `middleware.main --mode server`, plus Docker build/run commands. No architecture explanation, no configuration reference, no security notes, no troubleshooting guidance.
- No runbook, incident-response, or architecture document anywhere in the repository.

---

## Prioritized Action Plan

1. **Close the MITM hole.** Make `verify_server=True` the default in `common/middleware.py` (or remove the flag from the public API entirely), and either implement a real TLS exporter (RFC 5705 / `SSL_export_keying_material`) for the hybrid contribution in `common/tls_session.py`, or drop the "hybrid" claim and rely on the PQ handshake alone backed by real PKI/pinning for the DSA public keys.
2. **Fix the build.** Re-save `requirements.txt` as UTF-8, remove unrelated packages (`qiskit`, `qiskit-aer`, `rustworkx`, `pypdf`, `dill` unless actually used elsewhere), and explicitly pin `oqs`/liboqs-python as a dependency.
3. **Decide and implement the actual product scope.** Either build real backend-forwarding (accept → PQC-terminate → forward to a configurable upstream target) so this is genuinely a proxy, or update positioning/docs to describe it accurately as a secure point-to-point channel library — this materially changes what "production ready" means for the project.
4. **Write the tests the filenames already promise.** Handshake, replay, tampering, signature, and KEM tests are exactly the paths where a silent regression would be catastrophic for a security product; prioritize these over general coverage.
5. **Fix the accept-loop DoS.** Move `do_handshake()` off the main accept thread in `common/middleware.py:1836`; add server-side socket read/handshake timeouts.
6. **Remove or quarantine `common/pq.py`.** Either delete the mock crypto class or rename/relocate it so it cannot be mistaken for `pq_kem.py`/`pq_dsa.py`.
7. **Consolidate configuration** into a single source of truth (`common/config.py`, consumed by `middleware/main.py` instead of a parallel argparse default set).
8. **Add CI** — at minimum, a workflow that installs dependencies, runs lint, and runs the test suite from item 4 on every push/PR.
9. **Harden observability** — cap/rotate the in-memory metrics event store or add a real export path (Prometheus endpoint or periodic flush); audit all `logger.debug(...)` call sites in `handshake.py`/`secure_channel.py` for accidental secret/key-material logging given the DEBUG-by-default log level.
10. **Deepen the health check** so it validates a full TLS+PQ handshake, not just a raw TCP accept.
11. **Clean up documentation** — resolve the `README.md`/`Readme.md` duplication, add an architecture overview, configuration reference, and a basic security/runbook doc.

---

## What's Already Solid (don't regress these)

- Correct, spec-conformant use of real liboqs bindings for ML-KEM-768 and ML-DSA-65, including checking signature-verification return values before trusting them.
- CSPRNG-based nonce generation (`os.urandom`), not Python's `random` module.
- Strong transcript binding (SHA-256, domain separation) and constant-time HMAC key confirmation.
- Robust replay/tampering protection: per-direction monotonic sequence numbers folded into AEAD AAD, strict rejection of replayed/out-of-order messages, fail-closed error handling throughout the session layer.
- No unsafe deserialization (`pickle`/`eval`/`yaml.load`) anywhere in the wire-protocol path; custom binary framing with bounds-checked, length-prefixed fields and a sane maximum-packet-size cap.
- Metrics/logging scaffolding is genuinely wired into the handshake path, not dead code — it just needs an export path and a secret-leakage audit.
