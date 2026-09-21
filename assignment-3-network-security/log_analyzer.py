"""
SSH Brute-Force Log Analyzer
==============================

Αναλύει logs τύπου `/var/log/auth.log` (OpenSSH στο Linux) και εντοπίζει
πιθανές επιθέσεις brute-force: πολλαπλές αποτυχημένες προσπάθειες σύνδεσης
από την ίδια IP μέσα σε συγκεκριμένο χρονικό παράθυρο.

Καθαρά αμυντικό εργαλείο — απλή ανάλυση κειμένου, χωρίς δικτυακή πρόσβαση,
οπότε τρέχει (και τεστάρεται) οπουδήποτε χωρίς ειδικά δικαιώματα.

Χρήση:
    python log_analyzer.py sample_data/sample_auth.log
    python log_analyzer.py /var/log/auth.log --threshold 5 --window 10
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

# Παράδειγμα γραμμής: "Jan 15 10:22:31 server sshd[1234]: Failed password for
# invalid user admin from 203.0.113.7 port 51514 ssh2"
FAILED_LOGIN_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*"
    r"Failed password for(?: invalid user)? (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

CURRENT_YEAR = datetime.now().year


@dataclass
class BruteForceAlert:
    ip: str
    attempts: int
    usernames: set[str]
    first_seen: datetime
    last_seen: datetime


def parse_line(line: str) -> tuple[datetime, str, str] | None:
    """Επιστρέφει (timestamp, ip, username) αν η γραμμή είναι αποτυχημένο login."""
    match = FAILED_LOGIN_RE.search(line)
    if not match:
        return None
    ts_str = f"{CURRENT_YEAR} {match['month']} {match['day']} {match['time']}"
    try:
        timestamp = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    return timestamp, match["ip"], match["user"]


def analyze(
    lines: list[str],
    threshold: int = 5,
    window_minutes: int = 10,
) -> list[BruteForceAlert]:
    """
    Ομαδοποιεί αποτυχημένες προσπάθειες ανά IP και επιστρέφει alerts για IPs
    που ξεπέρασαν το threshold μέσα στο window_minutes.
    """
    events: dict[str, list[tuple[datetime, str]]] = defaultdict(list)

    for line in lines:
        parsed = parse_line(line)
        if parsed is None:
            continue
        timestamp, ip, user = parsed
        events[ip].append((timestamp, user))

    alerts: list[BruteForceAlert] = []
    window = window_minutes * 60

    for ip, attempts in events.items():
        attempts.sort(key=lambda a: a[0])
        start = 0
        for end in range(len(attempts)):
            while (attempts[end][0] - attempts[start][0]).total_seconds() > window:
                start += 1
            count = end - start + 1
            if count >= threshold:
                usernames = {a[1] for a in attempts[start:end + 1]}
                alerts.append(
                    BruteForceAlert(
                        ip=ip,
                        attempts=count,
                        usernames=usernames,
                        first_seen=attempts[start][0],
                        last_seen=attempts[end][0],
                    )
                )
                break  # μία αναφορά ανά IP αρκεί

    return sorted(alerts, key=lambda a: a.attempts, reverse=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Ανίχνευση SSH brute-force επιθέσεων από log αρχεία.")
    parser.add_argument("logfile", help="Path σε αρχείο log (π.χ. /var/log/auth.log)")
    parser.add_argument("--threshold", type=int, default=5, help="Αριθμός αποτυχιών για alert")
    parser.add_argument("--window", type=int, default=10, help="Χρονικό παράθυρο σε λεπτά")
    args = parser.parse_args()

    with open(args.logfile, encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    alerts = analyze(lines, threshold=args.threshold, window_minutes=args.window)

    if not alerts:
        print("[*] Δεν εντοπίστηκαν ύποπτες προσπάθειες brute-force.")
        return

    print(f"[+] Εντοπίστηκαν {len(alerts)} πιθανές επιθέσεις brute-force:\n")
    for alert in alerts:
        print(
            f"  IP {alert.ip}: {alert.attempts} αποτυχημένες προσπάθειες "
            f"({alert.first_seen} -> {alert.last_seen}), "
            f"usernames: {', '.join(sorted(alert.usernames))}"
        )


if __name__ == "__main__":
    main()
