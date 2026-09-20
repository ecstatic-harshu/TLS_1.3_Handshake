# Protocol

Custom binary protocol carried **inside** a TLS 1.3 connection, after TCP connect.

## Transport framing

Every logical packet on the TLS socket:

```text
| 4 bytes big-endian length N | N bytes payload |
```

- Implemented in `common/transport.py`
- Max packet size: 10 MB
- Partial TLS reads assembled via `recv_exact`

## Inner message header

Payload of each transport frame (`common/serializer.py`):

```text
| 1 byte msg_type | 4 bytes payload_len | payload |
```

### Message types

| Type | Name | Phase |
|---|---|---|
| `0x01` | `HELLO` | Handshake |
| `0x02` | `CIPHERTEXT` | Handshake |
| `0x03` | `DSA_PUBKEY` | Handshake |
| `0x04` | `SIGNATURE` | Handshake |
| `0x05` | `DONE` | Handshake (key confirmation) |
| `0x10` | `SECURE_MESSAGE` | Application data |
| `0xFF` | `ERROR` | Handshake failure notice |

## Handshake overview

Label: `QSCP-HYBRID-HANDSHAKE-v1`  
KEM: ML-KEM-768  
DSA: ML-DSA-65  
Nonces: 32 bytes (`os.urandom`)

```text
Client                                              Server
  │                                                   │
  │  HELLO (client_nonce ‖ kem_public_key)            │
  │──────────────────────────────────────────────────►│
  │  CIPHERTEXT (server_nonce ‖ kem_ciphertext)       │
  │◄──────────────────────────────────────────────────│
  │  DSA_PUBKEY (server)                              │
  │◄──────────────────────────────────────────────────│
  │  DSA_PUBKEY (client)                              │
  │──────────────────────────────────────────────────►│
  │         auth_digest = transcript.digest()         │
  │  SIGNATURE (server signs auth_digest)             │
  │◄──────────────────────────────────────────────────│
  │  SIGNATURE (client signs auth_digest)             │
  │──────────────────────────────────────────────────►│
  │         final_digest = transcript.digest()        │
  │  DONE (client HMAC confirmation)                  │
  │──────────────────────────────────────────────────►│
  │  DONE (server HMAC confirmation)                  │
  │◄──────────────────────────────────────────────────│
```

### HELLO payload

```text
| 32-byte client nonce | 4-byte kem_pk_len | kem_public_key |
```

### CIPHERTEXT payload

```text
| 32-byte server nonce | 4-byte ct_len | kem_ciphertext |
```

### DSA_PUBKEY / SIGNATURE payloads

```text
| 4-byte length | bytes |
```

### DONE payload

Exactly 32 bytes: HMAC-SHA256 confirmation tag.

```text
HMAC(pq_shared_secret,
     "QSCP-PQ-CONFIRM-v1" ‖ role ‖ auth_digest ‖ client_nonce ‖ server_nonce)
```

Compared with `hmac.compare_digest`.

## Transcript

`common/transcript.py` hashes each logical message as:

```text
role_len ‖ role ‖ msg_type ‖ data_len ‖ data
```

Domain-separated with the handshake label. Signatures cover the auth digest (after HELLO, CIPHERTEXT, both DSA pubkeys). Final digest feeds hybrid HKDF.

## Hybrid master key

`common/hybrid.py` (HKDF-SHA256):

```text
IKM  = "QSCP-HYBRID-IKM-V1" ‖ pq_secret ‖ tls_contribution
salt = SHA256("QSCP-HYBRID-CONTEXT-V1" ‖ final_transcript ‖ nonces)
info = "QSCP_HYBRID_KEY_V1" ‖ final_transcript
→ 32-byte master key
```

`tls_contribution` today is SHA-256 of public TLS metadata (not a TLS exporter).

## Traffic keys

`common/secure_channel.py` expands master key:

- `QSCP-v1|traffic|client-to-server`
- `QSCP-v1|traffic|server-to-client`

Role selects send vs receive AES-GCM key.

## Application messages (`SECURE_MESSAGE`)

After handshake, `common/session.py` sends:

```text
| 8-byte sequence | 12-byte nonce | ciphertext ‖ 16-byte GCM tag |
```

Nonce format:

- Client outbound: `b"CLNT" ‖ sequence_u64_be`
- Server outbound: `b"SRVR" ‖ sequence_u64_be`

AAD:

```text
b"QSCP-v1|SECURE_MESSAGE|" ‖ sequence_u64_be
```

Receiver requires exact next sequence (no gaps, no replays). Failure closes the session.

## Proxy application mapping

| Proxy mode | Client secure message becomes |
|---|---|
| Raw TCP | Exact bytes on backend socket |
| HTTP | `POST {path}` body = message bytes; response body returned |
| PQ backend | `send_secure` on second PQ session |

## Related docs

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [SECURITY_MODEL.md](SECURITY_MODEL.md)
- [CONFIGURATION.md](CONFIGURATION.md)
