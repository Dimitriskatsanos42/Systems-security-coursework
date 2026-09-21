import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from log_analyzer import analyze, parse_line  # noqa: E402

SAMPLE_LOG_PATH = os.path.join(
    os.path.dirname(__file__), "..", "sample_data", "sample_auth.log"
)


def load_sample_lines() -> list[str]:
    with open(SAMPLE_LOG_PATH, encoding="utf-8") as f:
        return f.readlines()


def test_parse_line_matches_failed_password():
    line = (
        "Jan 15 10:20:12 server sshd[1001]: Failed password for invalid "
        "user test from 198.51.100.23 port 40011 ssh2"
    )
    result = parse_line(line)
    assert result is not None
    timestamp, ip, user = result
    assert ip == "198.51.100.23"
    assert user == "test"
    assert timestamp.hour == 10
    assert timestamp.minute == 20


def test_parse_line_ignores_successful_login():
    line = "Jan 15 12:14:09 server sshd[1030]: Accepted publickey for dimitris from 192.168.1.10 port 60111 ssh2"
    assert parse_line(line) is None


def test_parse_line_ignores_unrelated_line():
    assert parse_line("Jan 15 09:00:00 server kernel: some unrelated message") is None


def test_analyze_detects_brute_force_ip():
    lines = load_sample_lines()
    alerts = analyze(lines, threshold=5, window_minutes=10)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.ip == "198.51.100.23"
    assert alert.attempts >= 5
    assert "admin" in alert.usernames


def test_analyze_respects_threshold():
    lines = load_sample_lines()
    # Με πολύ υψηλό threshold, δεν πρέπει να βρεθεί κανένα alert.
    alerts = analyze(lines, threshold=100, window_minutes=10)
    assert alerts == []


def test_analyze_empty_input_returns_no_alerts():
    assert analyze([], threshold=5, window_minutes=10) == []
