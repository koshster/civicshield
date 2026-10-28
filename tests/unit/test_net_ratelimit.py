from civicshield.engine.net.ratelimit import TokenBucket


async def test_token_bucket_allows_burst_then_throttles() -> None:
    now = [0.0]
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
        now[0] += seconds

    bucket = TokenBucket(rate=2.0, capacity=3, clock=lambda: now[0], sleep=fake_sleep)
    for _ in range(3):
        await bucket.acquire()
    assert slept == []  # burst of 3 is free
    await bucket.acquire()
    assert slept == [0.5]  # 4th waits 1 token / 2 per second
    now[0] += 10  # idle refills, capped at capacity
    for _ in range(3):
        await bucket.acquire()
    assert slept == [0.5]
