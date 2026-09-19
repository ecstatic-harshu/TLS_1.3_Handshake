from common.config import (
    HOST,
    PORT,
    BACKEND_HOST,
    BACKEND_PORT,
    BACKEND_USE_TLS,
    BACKEND_CONNECT_TIMEOUT,
    PROXY_IDLE_TIMEOUT,
    DASHBOARD_ENABLED,
    DASHBOARD_HOST,
    DASHBOARD_PORT
)

from common.version import get_version

from common.middleware import (
    run_secure_gateway
)

from common.dashboard import (
    get_dashboard,
    start_dashboard_server
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
    dashboard_enabled=DASHBOARD_ENABLED,
    dashboard_host=DASHBOARD_HOST,
    dashboard_port=DASHBOARD_PORT
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
        f"         Idle timeout : "
        f"{idle_timeout}s"
    )

    if dashboard_enabled:

        start_dashboard_server(
            get_dashboard(),
            host=dashboard_host,
            port=dashboard_port
        )

        print(
            f"         Dashboard : "
            f"http://{dashboard_host}:{dashboard_port}"
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
            idle_timeout=idle_timeout
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
