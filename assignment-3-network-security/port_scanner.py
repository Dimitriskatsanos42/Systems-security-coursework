"""
Educational TCP Port Scanner
=============================

ΠΡΟΣΟΧΗ / DISCLAIMER
--------------------
Το scanning συστημάτων για τα οποία δεν έχεις ρητή άδεια είναι παράνομο σε
πολλές χώρες (π.χ. Ν. 4411/2016 στην Ελλάδα για κυβερνοεγκλήματα, Computer
Fraud and Abuse Act στις ΗΠΑ). Αυτό το script προορίζεται αποκλειστικά για
εκπαιδευτική χρήση σε lab/CTF περιβάλλοντα ή σε συστήματα που ελέγχεις εσύ.

Από προεπιλογή, το εργαλείο επιτρέπει scanning ΜΟΝΟ σε:
  - localhost (127.0.0.1 / ::1)
  - ιδιωτικά εύρη IP (RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)

Για οποιοδήποτε άλλο target απαιτείται ρητά το flag --i-have-permission,
που λειτουργεί ως ενσυνείδητη επιβεβαίωση (όχι τεχνικό εμπόδιο).
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


class PermissionError_(Exception):
    """Εξαιρεση όταν προσπαθεί να γίνει scan σε μη-επιτρεπτό target."""


@dataclass
class ScanResult:
    port: int
    is_open: bool
    banner: str | None = None


def is_authorized_target(host: str, allow_flag: bool) -> bool:
    """Ελέγχει αν το target επιτρέπεται χωρίς ρητή σημαία άδειας."""
    if allow_flag:
        return True
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
    except socket.gaierror:
        return False
    return ip.is_loopback or ip.is_private


def scan_port(host: str, port: int, timeout: float = 0.6) -> ScanResult:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        is_open = result == 0
        banner = None
        if is_open:
            try:
                sock.settimeout(0.5)
                banner = sock.recv(64).decode(errors="ignore").strip() or None
            except (socket.timeout, OSError):
                banner = None
        return ScanResult(port=port, is_open=is_open, banner=banner)


def scan_range(
    host: str,
    start_port: int,
    end_port: int,
    max_workers: int = 100,
) -> list[ScanResult]:
    results: list[ScanResult] = []
    ports = range(start_port, end_port + 1)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, p): p for p in ports}
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda r: r.port)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Εκπαιδευτικός TCP port scanner (μόνο για εξουσιοδοτημένα targets)."
    )
    parser.add_argument("host", help="Target host (π.χ. 127.0.0.1)")
    parser.add_argument("--start-port", type=int, default=1)
    parser.add_argument("--end-port", type=int, default=1024)
    parser.add_argument(
        "--i-have-permission",
        action="store_true",
        help="Ρητή επιβεβαίωση ότι έχεις άδεια να κάνεις scan σε αυτό το target.",
    )
    args = parser.parse_args()

    if not is_authorized_target(args.host, args.i_have_permission):
        print(
            f"[!] Το '{args.host}' δεν είναι localhost/ιδιωτικό δίκτυο.\n"
            "    Αν έχεις ρητή άδεια, τρέξε ξανά με --i-have-permission.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"[*] Scanning {args.host} ports {args.start_port}-{args.end_port} ...")
    results = scan_range(args.host, args.start_port, args.end_port)
    open_ports = [r for r in results if r.is_open]

    if not open_ports:
        print("[*] Δεν βρέθηκαν ανοιχτές θύρες.")
        return

    print(f"[+] Βρέθηκαν {len(open_ports)} ανοιχτές θύρες:")
    for r in open_ports:
        banner_txt = f"  banner: {r.banner}" if r.banner else ""
        print(f"    {r.port:>5}/tcp OPEN{banner_txt}")


if __name__ == "__main__":
    main()
