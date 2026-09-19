import logging
import sys
import threading


# =====================================
# LOGGER CONFIGURATION
# =====================================

DEFAULT_LOG_LEVEL = (
    logging.DEBUG
)

DEFAULT_FORMAT = (
    "[%(asctime)s] "
    "%(levelname)s "
    "[%(name)s] "
    "[%(threadName)s] "
    "- %(message)s"
)

DEFAULT_DATE_FORMAT = (
    "%Y-%m-%d %H:%M:%S"
)


# =====================================
# LOGGER CREATION LOCK
# =====================================

_logger_lock = (
    threading.Lock()
)


# =====================================
# SETUP LOGGER
# =====================================

def setup_logger(
    name: str,
    level: int = DEFAULT_LOG_LEVEL
) -> logging.Logger:
    """
    Create or return a configured logger.

    Designed for:
        - multi-client middleware
        - threaded server sessions
        - handshake debugging
        - cryptographic stage logging

    Prevents:
        - duplicate handlers
        - duplicate propagated messages
    """

    if not isinstance(
        name,
        str
    ):

        raise TypeError(
            "Logger name must be a string"
        )

    if not name.strip():

        raise ValueError(
            "Logger name cannot be empty"
        )

    with _logger_lock:

        logger = logging.getLogger(
            name
        )

        logger.setLevel(
            level
        )

        # Prevent messages from also being
        # emitted by the root logger.
        logger.propagate = False

        # =====================================
        # ADD HANDLER ONCE
        # =====================================

        if not logger.handlers:

            formatter = (
                logging.Formatter(
                    fmt=DEFAULT_FORMAT,
                    datefmt=
                        DEFAULT_DATE_FORMAT
                )
            )

            console_handler = (
                logging.StreamHandler(
                    sys.stdout
                )
            )

            console_handler.setLevel(
                level
            )

            console_handler.setFormatter(
                formatter
            )

            logger.addHandler(
                console_handler
            )

        # =====================================
        # UPDATE EXISTING HANDLER LEVELS
        # =====================================

        else:

            for handler in (
                logger.handlers
            ):

                handler.setLevel(
                    level
                )

        return logger