import argparse

from common.version import get_version

from client.client import run_client
from server.server import run_server


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
            "supporting Client and Server modes."
        )
    )

    # ---------------------------------
    # MODE
    # ---------------------------------

    parser.add_argument(
        "--mode",
        required=True,
        choices=[
            "client",
            "server"
        ],
        help=(
            "Middleware operating mode: "
            "client or server"
        )
    )

    # ---------------------------------
    # HOST
    # ---------------------------------

    parser.add_argument(
        "--host",
        default=None,
        help=(
            "Host/IP address. "
            "Server defaults to 0.0.0.0, "
            "client defaults to 127.0.0.1."
        )
    )

    # ---------------------------------
    # PORT
    # ---------------------------------

    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="TCP port (default: 5000)"
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

    # ---------------------------------
    # VERSION
    # ---------------------------------

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

    # =================================
    # VALIDATE CLIENT OPTIONS
    # =================================

    if args.count <= 0:

        raise ValueError(
            "--count must be greater than 0"
        )

    if args.interval < 0:

        raise ValueError(
            "--interval cannot be negative"
        )

    # =================================
    # RESOLVE HOST
    # =================================

    if args.mode == "server":

        host = (
            args.host
            if args.host
            else "0.0.0.0"
        )

    else:

        host = (
            args.host
            if args.host
            else "127.0.0.1"
        )

    # =================================
    # BANNER
    # =================================

    print_banner(
        args.mode
    )

    # =================================
    # SERVER MODE
    # =================================

    if args.mode == "server":

        print(
            "[MIDDLEWARE] Starting "
            "SERVER mode..."
        )

        try:

            run_server(
                host=host,
                port=args.port
            )

        except KeyboardInterrupt:

            print(
                "\n"
                "[MIDDLEWARE] Server "
                "shutdown requested"
            )

        except Exception as exc:

            print(
                "\n"
                f"[MIDDLEWARE] Server error: "
                f"{exc}"
            )

            raise

    # =================================
    # CLIENT MODE
    # =================================

    elif args.mode == "client":

        print(
            "[MIDDLEWARE] Starting "
            "CLIENT mode..."
        )

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
                "\n"
                "[MIDDLEWARE] Client "
                "interrupted"
            )

        except Exception as exc:

            print(
                "\n"
                f"[MIDDLEWARE] Client error: "
                f"{exc}"
            )

            raise


# =====================================
# ENTRY POINT
# =====================================

if __name__ == "__main__":

    main()