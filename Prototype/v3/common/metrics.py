import time
import threading
from copy import deepcopy


class Metrics:
    """
    Thread-safe metrics collector.

    Designed for:
        - TLS timing
        - ML-KEM timing
        - ML-DSA timing
        - transcript timing
        - HKDF timing
        - AES-GCM timing
        - secure message metrics
        - multi-session server operation
    """

    def __init__(self):

        # Wall-clock timestamp is useful
        # for readable event timestamps.
        self.start_time = time.time()

        # Monotonic clock is better for
        # elapsed-duration measurement.
        self._start_monotonic = (
            time.perf_counter()
        )

        self.events = []

        self._lock = (
            threading.RLock()
        )

    # =====================================
    # INTERNAL ELAPSED TIME
    # =====================================

    def _elapsed(self) -> float:

        return round(
            time.perf_counter()
            -
            self._start_monotonic,
            6
        )

    # =====================================
    # RECORD EVENT
    # =====================================

    def record(
        self,
        label,
        metadata=None
    ):
        """
        Record one metrics event.
        """

        if not isinstance(
            label,
            str
        ):

            raise TypeError(
                "Metric label must be a string"
            )

        if not label.strip():

            raise ValueError(
                "Metric label cannot be empty"
            )

        if metadata is None:

            metadata = {}

        if not isinstance(
            metadata,
            dict
        ):

            raise TypeError(
                "Metric metadata must be a dict"
            )

        current_timestamp = (
            time.time()
        )

        event = {
            "label":
                label,

            "timestamp":
                current_timestamp,

            "elapsed":
                self._elapsed(),

            "metadata":
                deepcopy(metadata)
        }

        with self._lock:

            self.events.append(
                event
            )

        return event

    # =====================================
    # RECORD DURATION
    # =====================================

    def record_duration(
        self,
        label,
        start_time,
        metadata=None
    ):
        """
        Record a duration measured using
        time.perf_counter().

        Example:

            start = time.perf_counter()

            ...

            metrics.record_duration(
                "ML_KEM_ENCAPSULATION",
                start
            )
        """

        if metadata is None:

            metadata = {}

        if not isinstance(
            metadata,
            dict
        ):

            raise TypeError(
                "Metric metadata must be a dict"
            )

        duration_ms = (
            time.perf_counter()
            -
            start_time
        ) * 1000

        event_metadata = (
            deepcopy(metadata)
        )

        event_metadata[
            "duration_ms"
        ] = round(
            duration_ms,
            4
        )

        return self.record(
            label,
            event_metadata
        )

    # =====================================
    # COUNT EVENTS
    # =====================================

    def count(
        self,
        label=None
    ) -> int:
        """
        Count all events or events matching
        one label.
        """

        with self._lock:

            if label is None:

                return len(
                    self.events
                )

            return sum(
                1
                for event
                in self.events
                if event["label"] == label
            )

    # =====================================
    # GET EVENTS BY LABEL
    # =====================================

    def get_events(
        self,
        label
    ):
        """
        Return events matching one label.
        """

        with self._lock:

            return deepcopy([
                event
                for event
                in self.events
                if event["label"] == label
            ])

    # =====================================
    # DUMP EVENTS
    # =====================================

    def dump(self):
        """
        Return a safe copy of all events.
        """

        with self._lock:

            return deepcopy(
                self.events
            )

    # =====================================
    # SUMMARY
    # =====================================

    def summary(self):
        """
        Return high-level metrics summary.
        """

        with self._lock:

            labels = {}

            for event in self.events:

                label = event[
                    "label"
                ]

                labels[label] = (
                    labels.get(
                        label,
                        0
                    )
                    +
                    1
                )

            return {
                "total_events":
                    len(self.events),

                "total_runtime":
                    self._elapsed(),

                "event_counts":
                    labels
            }

    # =====================================
    # RESET
    # =====================================

    def reset(self):
        """
        Reset metrics collection.
        """

        with self._lock:

            self.start_time = (
                time.time()
            )

            self._start_monotonic = (
                time.perf_counter()
            )

            self.events.clear()