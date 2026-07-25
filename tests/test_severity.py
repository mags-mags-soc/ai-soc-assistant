import pytest

from soc.severity import Severity, severity_from_level


@pytest.mark.parametrize(
    "level,expected",
    [
        (0, Severity.INFO),
        (3, Severity.INFO),
        (4, Severity.LOW),
        (6, Severity.LOW),
        (7, Severity.MEDIUM),
        (9, Severity.MEDIUM),
        (10, Severity.HIGH),
        (12, Severity.HIGH),
        (13, Severity.CRITICAL),
        (15, Severity.CRITICAL),
    ],
)
def test_severity_from_level(level, expected):
    assert severity_from_level(level) is expected


def test_negative_level_raises():
    with pytest.raises(ValueError):
        severity_from_level(-1)


def test_ranks_are_ordered():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.MEDIUM.rank > Severity.LOW.rank > Severity.INFO.rank


def test_every_severity_has_color():
    for sev in Severity:
        assert sev.color.startswith("#") and len(sev.color) == 7
