import argparse

from common.version import get_version

from common.config import (
    BACKEND_HOST,
    BACKEND_PORT,
    BACKEND_USE_TLS,
    BACKEND_CONNECT_TIMEOUT,
    PROXY_IDLE_TIMEOUT
)

from client.client import run_client
from server.server import run_server
from middleware.proxy import run_proxy


# =====================================
# BANNER
# =====================================

def print_banner(mode):
    print(
        "\n"
        "==========================================\n"
        " Nutech Quantum Secure Middleware\n"
        f" Version : {get_version()}\n"
        f" Mode    : {mode.upper()}\n"
        " TLS 1.3 + ML-KEM-768 + ML-DSA-65\n"
        " HKDF-SHA256 + AES-256-GCM\n"
        "==========================================\n"
    )


# =====================================
# CLI ARGUMENTS
# =====================================

def parse_args():

    parser = argparse.ArgumentParser(
        description=(
            "Nutech Quantum Secure Middleware "
            "supporting client, server, and "
            "proxy modes."
        )
    )

    parser.add_argument(
        "--mode",
        required=True,
        choices=[
            "client",
            "server",
            "proxy"
        ],
        help=(
            "Middleware operating mode: "
            "client, server, or proxy"
        )
    )

    parser.add_argument(
        "--host",
        default=None,
        help=(
            "Host/IP address. "
            "Server/proxy default to 0.0.0.0, "
            "client defaults to 127.0.0.1."
        )
    )

    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="TCP listen/connect port (default: 5000)"
    )

    # ---------------------------------
    # PROXY / BACKEND OPTIONS
    # ---------------------------------

    parser.add_argument(
        "--backend-host",
        default=BACKEND_HOST,
        help=(
            "Backend host for proxy mode "
            f"(default: {BACKEND_HOST})"
        )
    )

    parser.add_argument(
        "--backend-port",
        type=int,
        default=BACKEND_PORT,
        help=(
            "Backend port for proxy mode "
            f"(default: {BACKEND_PORT})"
        )
    )

    parser.add_argument(
        "--backend-tls",
        action=argparse.BooleanOptionalAction,
        default=BACKEND_USE_TLS,
        help=(
            "Use / do not use standard TLS when "
            "dialing the backend "
            f"(default: {BACKEND_USE_TLS})"
        )
    )

    parser.add_argument(
        "--backend-connect-timeout",
        type=float,
        default=BACKEND_CONNECT_TIMEOUT,
        help=(
            "Backend connect timeout in seconds "
            f"(default: {BACKEND_CONNECT_TIMEOUT})"
        )
    )

    parser.add_argument(
        "--idle-timeout",
        type=float,
        default=PROXY_IDLE_TIMEOUT,
        help=(
            "Proxy idle read timeout in seconds "
            f"(default: {PROXY_IDLE_TIMEOUT})"
        )
    )

    # ---------------------------------
    # CLIENT OPTIONS
    # ---------------------------------

    parser.add_argument(
        "--message",
        default="Hello From Middleware Client",
        help="Client message"
    )

    parser.add_argument(
        "--count",
        type=int,
        default=1,
        help="Number of messages to send"
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Delay between messages in seconds"
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {get_version()}"
    )

    return parser.parse_args()


# =====================================
# MAIN
# =====================================

def main():

    args = parse_args()

    if args.count <= 0:
        raise ValueError(
            "--count must be greater than 0"
        )

    if args.interval < 0:
        raise ValueError(
            "--interval cannot be negative"
        )

    if args.backend_connect_timeout <= 0:
        raise ValueError(
            "--backend-connect-timeout must be positive"
        )

    if args.idle_timeout <= 0:
        raise ValueError(
            "--idle-timeout must be positive"
        )

    if args.mode in ("server", "proxy"):
        host = args.host if args.host else "0.0.0.0"
    else:
        host = args.host if args.host else "127.0.0.1"

    print_banner(args.mode)

    if args.mode == "server":

        print("[MIDDLEWARE] Starting SERVER mode...")

        try:
            run_server(host=host, port=args.port)
        except KeyboardInterrupt:
            print(
                "\n[MIDDLEWARE] Server "
                "shutdown requested"
            )
        except Exception as exc:
            print(
                f"\n[MIDDLEWARE] Server error: {exc}"
            )
            raise

    elif args.mode == "proxy":

        print("[MIDDLEWARE] Starting PROXY mode...")

        try:
            run_proxy(
                host=host,
                port=args.port,
                backend_host=args.backend_host,
                backend_port=args.backend_port,
                backend_use_tls=args.backend_tls,
                backend_connect_timeout=
                    args.backend_connect_timeout,
                idle_timeout=args.idle_timeout
            )
        except KeyboardInterrupt:
            print(
                "\n[MIDDLEWARE] Proxy "
                "shutdown requested"
            )
        except Exception as exc:
            print(
                f"\n[MIDDLEWARE] Proxy error: {exc}"
            )
            raise

    elif args.mode == "client":

        print("[MIDDLEWARE] Starting CLIENT mode...")

        try:
            run_client(
                host=host,
                port=args.port,
                message=args.message,
                count=args.count,
                interval=args.interval
            )
        except KeyboardInterrupt:
            print(
                "\n[MIDDLEWARE] Client interrupted"
            )
        except Exception as exc:
            print(
                f"\n[MIDDLEWARE] Client error: {exc}"
            )
            raise


if __name__ == "__main__":

    main()
