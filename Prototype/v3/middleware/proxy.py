from common.config import (
    HOST,
    PORT,
    BACKEND_HOST,
    BACKEND_PORT,
    BACKEND_USE_TLS,
    BACKEND_CONNECT_TIMEOUT,
    PROXY_IDLE_TIMEOUT,
    BACKEND_HTTP,
    BACKEND_HTTP_PATH,
    BACKEND_PQ
)

from common.version import get_version

from common.middleware import (
    run_secure_gateway
)


def print_banner():

    print(
        "\n"
        "==========================================\n"
        " Hybrid Secure Middleware Proxy\n"
        f" Version : {get_version()}\n"
        " TLS 1.3 + ML-KEM-768 + ML-DSA-65\n"
        " HKDF-SHA256 + AES-256-GCM\n"
        " Terminate PQ → relay to backend\n"
        "==========================================\n"
    )


def run_proxy(
    host=HOST,
    port=PORT,
    backend_host=BACKEND_HOST,
    backend_port=BACKEND_PORT,
    backend_use_tls=BACKEND_USE_TLS,
    backend_connect_timeout=BACKEND_CONNECT_TIMEOUT,
    idle_timeout=PROXY_IDLE_TIMEOUT,
    backend_http=BACKEND_HTTP,
    backend_http_path=BACKEND_HTTP_PATH,
    backend_pq=BACKEND_PQ
):

    print_banner()

    print("[PROXY] Configuration")
    print(f"         Listen  : {host}:{port}")
    print(
        f"         Backend : "
        f"{backend_host}:{backend_port}"
    )
    print(
        f"         Backend TLS : "
        f"{backend_use_tls}"
    )
    print(
        f"         Backend PQ  : "
        f"{backend_pq}"
    )
    print(
        f"         Backend HTTP : "
        f"{backend_http and not backend_pq}"
    )
    if backend_pq:
        print(
            "         Backend hop : "
            "quantum-safe (secure_connect)"
        )
    elif backend_http:
        print(
            f"         HTTP path : "
            f"POST {backend_http_path}"
        )
    print(
        f"         Idle timeout : "
        f"{idle_timeout}s"
    )

    print("\n[PROXY] Starting gateway...\n")

    try:

        run_secure_gateway(
            host=host,
            port=port,
            backend_host=backend_host,
            backend_port=backend_port,
            backend_use_tls=backend_use_tls,
            backend_connect_timeout=
                backend_connect_timeout,
            idle_timeout=idle_timeout,
            backend_http=backend_http,
            backend_http_path=backend_http_path,
            backend_pq=backend_pq
        )

    except KeyboardInterrupt:

        print(
            "\n[PROXY] Shutdown requested"
        )

    except Exception as exc:

        print(
            f"\n[PROXY] Fatal error: {exc}"
        )
        raise

    finally:

        print("[PROXY] Proxy stopped")


def main():

    run_proxy()


if __name__ == "__main__":

    main()
