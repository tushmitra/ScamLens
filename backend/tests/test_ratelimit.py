from helpers import BACKEND  # noqa: F401

from app.ratelimit import SlidingWindowLimiter


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def test_limit_and_window_expiry():
    clock = Clock()
    limiter = SlidingWindowLimiter(3, 60, clock)
    assert [limiter.allow("a") for _ in range(4)] == [True, True, True, False]
    assert limiter.allow("b") is True  # separate key
    clock.now = 61
    assert limiter.allow("a") is True


def test_zero_disables():
    limiter = SlidingWindowLimiter(0)
    assert all(limiter.allow("a") for _ in range(1000))
