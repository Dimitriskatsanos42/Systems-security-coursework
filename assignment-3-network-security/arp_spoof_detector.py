"""
ARP Spoofing Detector
======================

Αμυντικό εργαλείο: παρακολουθεί την κίνηση ARP στο τοπικό δίκτυο και ελέγχει
αν μια διεύθυνση IP "αλλάζει ξαφνικά" MAC address χωρίς προηγούμενη ειδοποίηση
DHCP — κλασικό σημάδι επίθεσης ARP spoofing / ARP cache poisoning.

Δεν επιτίθεται πουθενά· μόνο παρακολουθεί (sniff) και ειδοποιεί.

Απαιτεί:
  - βιβλιοθήκη `scapy`
  - δικαιώματα root/administrator για raw packet capture
  - εκτέλεση στο δικό σου/εξουσιοδοτημένο δίκτυο

Χρήση:
    sudo python arp_spoof_detector.py --iface eth0
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from dataclasses import dataclass, field

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("arp_alerts.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("arp-spoof-detector")


@dataclass
class ArpTable:
    """Απλός πίνακας IP -> MAC με ανίχνευση συγκρούσεων (mismatch)."""

    table: dict[str, str] = field(default_factory=dict)

    def observe(self, ip: str, mac: str) -> bool:
        """Καταγράφει ζεύγος (ip, mac). Επιστρέφει True αν εντοπίστηκε mismatch."""
        known_mac = self.table.get(ip)
        if known_mac is None:
            self.table[ip] = mac
            return False
        if known_mac.lower() != mac.lower():
            log.warning(
                "Πιθανό ARP spoofing! IP %s ήταν %s, τώρα εμφανίζεται ως %s",
                ip,
                known_mac,
                mac,
            )
            self.table[ip] = mac
            return True
        return False


def run(interface: str | None) -> None:
    try:
        from scapy.all import ARP, sniff  # type: ignore
    except ImportError:
        print(
            "[!] Χρειάζεται η βιβλιοθήκη scapy: pip install scapy",
            file=sys.stderr,
        )
        sys.exit(1)

    arp_table = ArpTable()

    def handle_packet(pkt) -> None:  # noqa: ANN001
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # op 2 = is-at (ARP reply)
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            mismatch = arp_table.observe(ip, mac)
            if not mismatch:
                log.info("ARP reply: %s is-at %s", ip, mac)

    log.info("Ξεκινάει η παρακολούθηση ARP στο interface=%s ...", interface or "default")
    sniff(iface=interface, filter="arp", prn=handle_packet, store=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="Ανίχνευση ARP spoofing (παρακολούθηση, όχι επίθεση).")
    parser.add_argument("--iface", default=None, help="Network interface (π.χ. eth0, wlan0)")
    args = parser.parse_args()

    try:
        run(args.iface)
    except PermissionError:
        print(
            "[!] Χρειάζονται δικαιώματα root/administrator για packet capture.",
            file=sys.stderr,
        )
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Διακοπή παρακολούθησης.")
        time.sleep(0.1)


if __name__ == "__main__":
    main()
