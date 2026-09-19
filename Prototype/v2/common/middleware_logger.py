import time


class MiddlewareLogger:

    @staticmethod
    def log_stage(logger, stage):

        logger.info(
            f"[MIDDLEWARE] {stage}"
        )

    @staticmethod
    def log_event(logger, event, value=None):

        if value is not None:

            logger.info(
                f"[EVENT] {event}: {value}"
            )

        else:

            logger.info(
                f"[EVENT] {event}"
            )

    @staticmethod
    def log_timer(logger, label, start_time):

        elapsed = time.time() - start_time

        logger.info(
            f"[TIMER] {label}: "
            f"{elapsed:.4f}s"
        )