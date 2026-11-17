from bench.common import percentile, summarize


def test_percentile_nearest_rank() -> None:
    v = [float(x) for x in range(1, 21)]  # 1..20
    assert percentile(v, 50) == 10.0
    assert percentile(v, 95) == 19.0
    assert percentile(v, 100) == 20.0


def test_summarize() -> None:
    assert summarize([3.0, 1.0, 2.0]) == {"n": 3, "median": 2.0, "p95": 3.0, "max": 3.0}
