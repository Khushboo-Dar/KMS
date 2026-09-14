"""
KAVACH KMS Scheduler

Responsible for:
    - Calculating randomized request timing
    - Calculating next polling time
    - Calculating retry timing

SRS concept:

    KAVACH Subsystem sends Authentication Query
    every 6 hours.

    Request timing within the 2-hour window is
    randomized using:

        KAVACH Subsystem ID mod (2 * 60 minutes)

    If the first request fails:

        Retry every 5 minutes

Important:
    This module only handles TIME/SCHEDULING.
    It does not send UDP packets.
"""


from datetime import datetime, timedelta

from .config import (
    POLLING_INTERVAL_SECONDS,
    RANDOM_REQUEST_WINDOW_MINUTES,
    RETRY_INTERVAL_SECONDS,
)


# ============================================================
# RANDOMIZED REQUEST TIME
# ============================================================

def calculate_random_request_minute(
    kavach_id: int
) -> int:
    """
    Calculate the randomized request minute.

    SRS formula:

        KAVACH ID % (2 * 60)

    Result:
        0 to 119 minutes
    """

    if kavach_id < 0:
        raise ValueError(
            "KAVACH ID cannot be negative"
        )

    return (
        kavach_id
        % RANDOM_REQUEST_WINDOW_MINUTES
    )


# ============================================================
# RANDOMIZED REQUEST DELAY
# ============================================================

def calculate_random_request_delay(
    kavach_id: int
) -> timedelta:
    """
    Return randomized request delay.

    Example:

        KAVACH ID = 50002

        50002 % 120 = 82

        Delay = 82 minutes
    """

    minute = calculate_random_request_minute(
        kavach_id
    )

    return timedelta(
        minutes=minute
    )


# ============================================================
# NEXT REQUEST TIME
# ============================================================

def calculate_next_request_time(
    kavach_id: int,
    base_time: datetime | None = None,
) -> datetime:
    """
    Calculate next randomized request time.

    Parameters
    ----------
    kavach_id:
        KAVACH subsystem ID.

    base_time:
        Starting point for the request window.

    Returns
    -------
    datetime:
        Scheduled request time.
    """

    if base_time is None:
        base_time = datetime.now()

    delay = calculate_random_request_delay(
        kavach_id
    )

    return base_time + delay


# ============================================================
# NEXT 6-HOUR POLLING TIME
# ============================================================

def calculate_next_poll_time(
    current_time: datetime | None = None,
) -> datetime:
    """
    Calculate next 6-hour polling time.
    """

    if current_time is None:
        current_time = datetime.now()

    return (
        current_time
        + timedelta(
            seconds=POLLING_INTERVAL_SECONDS
        )
    )


# ============================================================
# RETRY TIME
# ============================================================

def calculate_retry_time(
    current_time: datetime | None = None,
) -> datetime:
    """
    Calculate next retry time.

    SRS:
        Retry every 5 minutes if first request fails.
    """

    if current_time is None:
        current_time = datetime.now()

    return (
        current_time
        + timedelta(
            seconds=RETRY_INTERVAL_SECONDS
        )
    )


# ============================================================
# WAIT SECONDS
# ============================================================

def seconds_until(
    target_time: datetime,
    current_time: datetime | None = None,
) -> float:
    """
    Return number of seconds until target time.

    If target time has already passed,
    returns 0.
    """

    if current_time is None:
        current_time = datetime.now()

    seconds = (
        target_time - current_time
    ).total_seconds()

    return max(
        0.0,
        seconds
    )


# ============================================================
# DEBUG
# ============================================================

if __name__ == "__main__":

    kavach_id = 50002

    minute = calculate_random_request_minute(
        kavach_id
    )

    print(
        f"KAVACH ID       : {kavach_id}"
    )

    print(
        f"Request minute  : {minute}"
    )

    next_request = calculate_next_request_time(
        kavach_id
    )

    print(
        f"Next request    : {next_request}"
    )

    next_poll = calculate_next_poll_time()

    print(
        f"Next poll       : {next_poll}"
    )

    retry = calculate_retry_time()

    print(
        f"Retry time      : {retry}"
    )