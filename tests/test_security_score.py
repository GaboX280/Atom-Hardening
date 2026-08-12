import pytest
from atom_core.core.security_score import SecurityScore
from atom_core.models.finding import Finding


def test_perfect_score():
    findings = [
        Finding(
            title="T1",
            status="PASS",
            severity="HIGH",
            details="",
            recommendation="",
            category="",
            module="M",
            reference="",
            impact="",
            compliance=[],
        )
    ]
    score = SecurityScore.calculate(findings)
    assert score == 100
    # The rating should contain the word EXCELENTE and be colored
    assert "EXCELENTE" in SecurityScore.rating(score)


def test_low_score():
    findings = [
        Finding(
            title="T1",
            status="FAIL",
            severity="CRITICAL",
            details="",
            recommendation="",
            category="",
            module="M",
            reference="",
            impact="",
            compliance=[],
        )
    ]
    score = SecurityScore.calculate(findings)
    # With our penalties, a single CRITICAL gives a score of 40
    assert score == 40
    # Rating should be CRITICO colored
    assert "CRITICO" in SecurityScore.rating(score)


def test_empty_findings():
    score = SecurityScore.calculate([])
    assert score == 100
    assert "EXCELENTE" in SecurityScore.rating(score)
