# Configuration

## CLI entry point

```powershell
python -m middleware.main --mode <client|server|proxy> [options]
```

## Common flags

| Flag | Default | Applies to | Description |
|---|---|---|---|
| `--mode` | (required) | all | `client`, `server`, or `proxy` |
| `--host` | server/proxy: `0.0.0.0`; client: `127.0.0.1` | all | Bind or connect host |
| `--port` | `5000` | all | Listen or connect port |
| `--version` | — | all | Print version from `VERSION` file |

## Client flags

| Flag | Default | Description |
|---|---|---|
| `--message` | `Hello From Middleware Client` | Reserved/legacy message field |
| `--count` | `1` | Legacy send count (interactive shell is primary UX) |
| `--interval` | `1.0` | Legacy delay between sends |

Interactive client: type lines at `[CLIENT] >`, `/quit` to exit.

## Proxy / backend flags

| Flag | Default | Description |
|---|---|---|
| `--backend-host` | `127.0.0.1` | Backend hostname/IP |
| `--backend-port` | `8080` | Backend port |
| `--backend-tls` / `--no-backend-tls` | off | Use classical TLS when dialing backend |
| `--backend-connect-timeout` | `10.0` | Backend connect timeout (seconds) |
| `--idle-timeout` | `300.0` | Idle read timeout; closes relay |
| `--backend-http` / `--no-backend-http` | on | Wrap each client message as HTTP `POST` |
| `--backend-http-path` | `/echo` | Path used for HTTP wrapping |
| `--backend-pq` / `--no-backend-pq` | off | Dial backend with PQ `secure_connect` |

### Mode precedence (proxy)

1. If `--backend-pq` → PQ↔PQ relay (HTTP/raw ignored for the hop)
2. Else if `--backend-http` → per-message HTTP POST
3. Else → raw TCP byte relay

## Environment variables

Defined in `common/config.py`:

| Variable | Default | Meaning |
|---|---|---|
| `HOST` | `0.0.0.0` | Default bind host (server helpers) |
| `PORT` | `5000` | Default port |
| `CERT_FILE` | `certs/server.crt` | TLS certificate |
| `KEY_FILE` | `certs/server.key` | TLS private key |
| `LOG_LEVEL` | `INFO` | Logging level |
| `BACKEND_HOST` | `127.0.0.1` | Proxy backend host |
| `BACKEND_PORT` | `8080` | Proxy backend port |
| `BACKEND_USE_TLS` | `false` | Backend classical TLS |
| `BACKEND_CONNECT_TIMEOUT` | `10.0` | Connect timeout seconds |
| `PROXY_IDLE_TIMEOUT` | `300.0` | Idle timeout seconds |
| `BACKEND_HTTP` | `true` | Enable HTTP wrap mode |
| `BACKEND_HTTP_PATH` | `/echo` | HTTP wrap path |
| `BACKEND_PQ` | `false` | Enable PQ backend hop |

Boolean env values accepted: `1`, `true`, `yes`, `on` (case-insensitive).

Note: `middleware/main.py` primarily uses CLI argparse; env values feed argparse defaults.

## TLS certificates

Server/proxy TLS identity loads from:

- `CERT_FILE` / `KEY_FILE`, or
- `certs/server.crt` + `certs/server.key`

Client `secure_connect()` currently defaults to `verify_server=False` for local prototype use.

## Example configurations

### Double PQ hop

```powershell
python -m middleware.main --mode server --port 6000
python -m middleware.main --mode proxy --port 5000 --backend-host 127.0.0.1 --backend-port 6000 --backend-pq --no-backend-http
python -m middleware.main --mode client --host 127.0.0.1 --port 5000
```

### HTTP demo backend

```powershell
python backend_http_demo.py
python -m middleware.main --mode proxy --backend-host 127.0.0.1 --backend-port 8080 --backend-http
python -m middleware.main --mode client --host 127.0.0.1 --port 5000
```

### Raw TCP echo

```powershell
python backend_tcp_echo.py
python -m middleware.main --mode proxy --no-backend-http --backend-host 127.0.0.1 --backend-port 8080
python -m middleware.main --mode client --host 127.0.0.1 --port 5000
```

## Docker

```powershell
docker build -t pqtls-middleware:1.0.0 .
docker run --rm -p 5000:5000 pqtls-middleware:1.0.0 --mode server
docker run --rm -p 5000:5000 pqtls-middleware:1.0.0 --mode proxy --backend-host host.docker.internal --backend-port 8080
docker run -it --rm pqtls-middleware:1.0.0 --mode client --host host.docker.internal --port 5000
```

`docker-compose.yml` includes `pqtls-server` and a `pqtls-proxy` profile.

## Related docs

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [DEMO_GUIDE.md](DEMO_GUIDE.md)
- [SECURITY_MODEL.md](SECURITY_MODEL.md)
