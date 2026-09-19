import argparse

from common.config import HOST, PORT
from common.version import get_version

from common.middleware import (
    run_secure_server
)


# =====================================
# BANNER
# =====================================

def print_banner():

    print(
        "\n"
        "==========================================\n"
        " Hybrid Secure Middleware Server\n"
        f" Version : {get_version()}\n"
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
            "Hybrid Secure Middleware Server "
            "using TLS 1.3, ML-KEM-768, "
            "ML-DSA-65, HKDF-SHA256, "
            "and AES-256-GCM"
        )
    )

    parser.add_argument(
        "--host",
        default=HOST,
        help=(
            f"Host/IP address to bind "
            f"(default: {HOST})"
        )
    )

    parser.add_argument(
        "--port",
        type=int,
        default=PORT,
        help=(
            f"TCP port to bind "
            f"(default: {PORT})"
        )
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {get_version()}"
    )

    return parser.parse_args()


# =====================================
# SERVER RUNNER
# =====================================

def run_server(
    host="0.0.0.0",
    port=5000
):

    print_banner()

    print(
        "[SERVER] Configuration"
    )

    print(
        f"         Host : {host}"
    )

    print(
        f"         Port : {port}"
    )

    print(
        "\n"
        "[SERVER] Security Stack"
    )

    print(
        "         Transport     : TLS 1.3"
    )

    print(
        "         PQ KEM        : ML-KEM-768"
    )

    print(
        "         PQ Signature  : ML-DSA-65"
    )

    print(
        "         Key Derivation: HKDF-SHA256"
    )

    print(
        "         Secure Channel: AES-256-GCM"
    )

    print(
        "\n"
        "[SERVER] Starting multi-session server...\n"
    )

    try:

        run_secure_server(
            host=host,
            port=port
        )

    except KeyboardInterrupt:

        print(
            "\n"
            "[SERVER] Shutdown requested"
        )

    except Exception as exc:

        print(
            "\n"
            f"[SERVER] Fatal error: {exc}"
        )

        raise

    finally:

        print(
            "[SERVER] Server stopped"
        )


# =====================================
# LEGACY CLI ENTRY POINT
# =====================================

def main():

    args = parse_args()

    run_server(
        host=args.host,
        port=args.port
    )


# =====================================
# ENTRY POINT
# =====================================

if __name__ == "__main__":

    main()