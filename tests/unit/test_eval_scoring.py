from pathlib import Path

from eval.scoring import ZoneTruth, load_ground_truth, score, to_markdown
from lab.cases import ZONES

ROOT = Path(__file__).resolve().parents[2]


def test_score_counts_tp_fp_fn_per_category() -> None:
    truth = [
        ZoneTruth("a.test", hosts=("tls.cert.expired",)),
        ZoneTruth("b.test", zone_types=("email.spf.missing",)),
        ZoneTruth("w.test", www_types=("headers.csp.missing",)),
        ZoneTruth("clean.test"),
        ZoneTruth("skip.test", hosts=("tls.x",), score=False),
    ]
    found = [
        ("tls.cert.expired", "a.test"),
        ("tls.cert.expired", "WWW.a.test"),  # case-insensitive asset
        ("email.spf.missing", "b.test"),
        ("headers.hsts.missing", "clean.test"),  # noise on the control → FP
        ("headers.csp.missing", "www.w.test"),
        ("headers.csp.missing", "w.test"),  # www-only type reported on the apex → FP
        ("headers.hsts.missing", "skip.test"),  # unscored zone → ignored
        ("headers.hsts.missing", "unrelated.test"),  # not a lab asset → ignored
    ]
    r = score(truth, found)
    assert (r.overall.tp, r.overall.fp, r.overall.fn) == (4, 2, 0)
    assert r.by_category["headers"].precision == 1 / 3
    assert r.by_category["tls"].recall == 1.0
    assert sorted(r.false_positives) == [
        ("headers.csp.missing", "w.test"),
        ("headers.hsts.missing", "clean.test"),
    ]


def test_missing_finding_is_false_negative() -> None:
    r = score([ZoneTruth("a.test", hosts=("tls.protocol.tls10",))], [])
    assert r.overall.fn == 2  # apex and www
    assert r.overall.recall == 0.0
    assert r.overall.precision == 1.0  # nothing reported, nothing wrong
    assert "False negatives" in to_markdown(r)


def test_ground_truth_matches_lab_cases_and_real_finding_types() -> None:
    from civicshield.engine.checks import ALL_CHECKS

    known = set().union(*(c.meta.finding_types for c in ALL_CHECKS))
    truth = load_ground_truth(ROOT / "lab" / "ground_truth.yaml")
    assert {t.zone for t in truth} == {z.name for z in ZONES}
    for t in truth:
        assert set(t.hosts) | set(t.www_types) | set(t.zone_types) <= known, t.zone
