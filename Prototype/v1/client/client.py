import argparse
import threading

from common.version import get_version

from common.middleware import (
    secure_connect
)


# =====================================
# BANNER
# =====================================

def print_banner():

    print(
        "\n"
        "==========================================\n"
        " Hybrid Secure Middleware Client\n"
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
            "Hybrid Secure Middleware Client "
            "using TLS 1.3, ML-KEM-768, "
            "ML-DSA-65, HKDF-SHA256, "
            "and AES-256-GCM"
        )
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help=(
            "Secure middleware server host "
            "(default: 127.0.0.1)"
        )
    )

    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help=(
            "Secure middleware server port "
            "(default: 5000)"
        )
    )

    parser.add_argument(
        "--message",
        default=(
            "Hello From Middleware Client"
        ),
        help=(
            "Application message to send "
            "through the secure session"
        )
    )

    parser.add_argument(
        "--count",
        type=int,
        default=1,
        help=(
            "Number of secure messages "
            "to send (default: 1)"
        )
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help=(
            "Delay in seconds between "
            "messages (default: 1.0)"
        )
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {get_version()}"
    )

    return parser.parse_args()


# =====================================
# PRINT SESSION INFORMATION
# =====================================

def print_session_info(session):

    print(
        "\n"
        "=========================================="
    )

    print(
        "[CLIENT] Secure Session Established"
    )

    print(
        "=========================================="
    )

    print(
        f"Authenticated : "
        f"{session.is_authenticated}"
    )

    print(
        f"Established   : "
        f"{session.is_established}"
    )

    if session.transcript_hash:

        transcript_value = (
            session.transcript_hash
        )

        if isinstance(
            transcript_value,
            bytes
        ):

            transcript_value = (
                transcript_value.hex()
            )

        print(
            f"Transcript    : "
            f"{transcript_value}"
        )

    print(
        "==========================================\n"
    )


# =====================================
# PRINT METRICS
# =====================================

def print_metrics(session):

    print(
        "\n"
        "=========================================="
    )

    print(
        "[CLIENT METRICS]"
    )

    print(
        "=========================================="
    )

    for event in session.metrics.dump():

        print(event)

    print(
        "\n[METRICS SUMMARY]"
    )

    print(
        session.metrics.summary()
    )

    print(
        "=========================================="
    )


# =====================================
# RECEIVE LOOP
# =====================================

def client_receive_loop(session):

    while True:

        try:

            data = session.receive_secure()

            print(
                f"\n[SERVER] {data.decode('utf-8')}"
            )

        except Exception:

            break


# =====================================
# CLIENT RUNNER
# =====================================

def run_client(
    host="127.0.0.1",
    port=5000,
    message="Hello From Middleware Client",
    count=1,
    interval=1.0
):

    if count <= 0:

        raise ValueError(
            "count must be greater than 0"
        )

    if interval < 0:

        raise ValueError(
            "interval cannot be negative"
        )

    session = None

    print_banner()

    try:

        # =====================================
        # ESTABLISH SECURE SESSION
        # =====================================

        print(
            "[CLIENT] Connecting to "
            f"{host}:{port}..."
        )

        session = secure_connect(
            host=host,
            port=port
        )

        print_session_info(
            session
        )

        # =====================================
        # RECEIVE THREAD
        # =====================================

        receiver = threading.Thread(
            target=client_receive_loop,
            args=(session,),
            daemon=True
        )

        receiver.start()

        # =====================================
        # INTERACTIVE SHELL
        # =====================================

        print(
            "\nInteractive secure shell"
        )

        print(
            "Type /quit to exit\n"
        )

        while True:

            msg = input(
                "[CLIENT] > "
            )

            if msg.lower() == "/quit":

                break

            if not msg:

                continue

            session.send_secure(
                msg.encode("utf-8")
            )

        # =====================================
        # METRICS
        # =====================================

        print_metrics(
            session
        )

    except KeyboardInterrupt:

        print(
            "\n"
            "[CLIENT] Interrupted by user"
        )

    except Exception as exc:

        print(
            "\n"
            f"[CLIENT] Error: {exc}"
        )

        raise

    finally:

        # =====================================
        # CLEAN CONNECTION CLOSE
        # =====================================

        if (
            session is not None
            and
            session.socket is not None
        ):

            try:

                session.socket.close()

            except Exception:

                pass

        print(
            "\n"
            "[CLIENT] Connection closed"
        )


# =====================================
# LEGACY CLI ENTRY POINT
# =====================================

def main():

    args = parse_args()

    run_client(
        host=args.host,
        port=args.port,
        message=args.message,
        count=args.count,
        interval=args.interval
    )


# =====================================
# ENTRY POINT
# =====================================

if __name__ == "__main__":

    main()