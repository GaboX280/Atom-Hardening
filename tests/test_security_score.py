import pytest

from atom_core.core.security_score import SecurityScore
from atom_core.models.finding import Finding


def make_finding(status: str, severity: str, severity_score: int = 0) -> Finding:
    return Finding(
        title="T1",
        status=status,
        severity=severity,
        severity_score=severity_score,
    )


def test_perfect_score() -> None:
    score = SecurityScore.calculate([make_finding("PASS", "HIGH")])
    assert score == 100
    assert "EXCELENTE (90-100)" in SecurityScore.rating(score)


def test_single_critical_score() -> None:
    score = SecurityScore.calculate([make_finding("FAIL", "CRITICAL")])
    assert score == 40
    assert "CRITICO (0-49)" in SecurityScore.rating(score)


def test_error_does_not_reduce_score() -> None:
    score = SecurityScore.calculate([make_finding("ERROR", "CRITICAL")])
    assert score == 100


def test_custom_severity_score_overrides_default_penalty() -> None:
    score = SecurityScore.calculate(
        [make_finding("FAIL", "HIGH", severity_score=7)]
    )
    assert score == 93


@pytest.mark.parametrize(
    ("score", "rating"),
    [
        (100, "EXCELENTE (90-100)"),
        (90, "EXCELENTE (90-100)"),
        (89, "BUENO (75-89)"),
        (75, "BUENO (75-89)"),
        (74, "MODERADO (50-74)"),
        (50, "MODERADO (50-74)"),
        (49, "CRITICO (0-49)"),
        (0, "CRITICO (0-49)"),
    ],
)
def test_rating_ranges(score: int, rating: str) -> None:
    assert rating in SecurityScore.rating(score)


def test_empty_findings() -> None:
    score = SecurityScore.calculate([])
    assert score == 100
    assert "EXCELENTE (90-100)" in SecurityScore.rating(score)


def test_rating_rejects_out_of_range_score() -> None:
    with pytest.raises(ValueError, match="between 0 and 100"):
        SecurityScore.rating(101)
