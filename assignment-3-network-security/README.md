# Assignment 3 — Network Security Toolkit

Σύνολο εργαλείων γύρω από δικτυακή ασφάλεια: ανίχνευση ανοιχτών θυρών,
ανίχνευση ARP spoofing και ανίχνευση επιθέσεων brute-force σε SSH μέσω
ανάλυσης logs.

## ⚠️ Νομικό & Ηθικό πλαίσιο

Τα εργαλεία `port_scanner.py` και `arp_spoof_detector.py` αλληλεπιδρούν με
δίκτυα. **Χρησιμοποίησέ τα μόνο σε συστήματα/δίκτυα που σου ανήκουν ή για τα
οποία έχεις ρητή γραπτή άδεια** (π.χ. προσωπικό home lab, CTF περιβάλλον,
εργαστήριο μαθήματος). Το `port_scanner.py` έχει ενσωματωμένο έλεγχο που
επιτρέπει scanning μόνο σε localhost/ιδιωτικά δίκτυα εκτός αν δοθεί ρητά το
flag `--i-have-permission`.

## Εργαλεία

### 1. `port_scanner.py` — Εκπαιδευτικός TCP scanner

```bash
python port_scanner.py 127.0.0.1 --start-port 1 --end-port 1024
```

Threaded TCP connect scan με banner grabbing, ενσωματωμένο safety check.

### 2. `arp_spoof_detector.py` — Ανίχνευση ARP spoofing

```bash
sudo python arp_spoof_detector.py --iface eth0
```

Παρακολουθεί ARP replies στο δίκτυο· αν μια IP αλλάξει MAC address χωρίς
προφανή λόγο, γράφει προειδοποίηση στο `arp_alerts.log`. Απαιτεί `scapy` και
δικαιώματα root. **Καθαρά αμυντικό εργαλείο** — δεν επιτίθεται, μόνο ακούει.

### 3. `log_analyzer.py` — Ανίχνευση SSH brute-force

```bash
python log_analyzer.py sample_data/sample_auth.log --threshold 5 --window 10
```

Διαβάζει αρχεία τύπου `/var/log/auth.log` και εντοπίζει IPs με πολλαπλές
αποτυχημένες συνδέσεις μέσα σε συγκεκριμένο χρονικό παράθυρο (sliding
window) — κλασική τεχνική ανίχνευσης brute-force. Δεν χρειάζεται δίκτυο ή
ειδικά δικαιώματα, οπότε τρέχει και μέσα στο CI pipeline.

## Εγκατάσταση

```bash
cd assignment-3-network-security
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Tests

```bash
pytest -v
```

Τα tests καλύπτουν το parsing λογικής του `log_analyzer.py` (με το
`sample_data/sample_auth.log`) και τα safety guardrails του
`port_scanner.py`. Το `arp_spoof_detector.py` δεν έχει unit tests, καθώς
απαιτεί raw sockets/root και live δικτυακή κίνηση — δοκιμάστηκε χειροκίνητα
(δες `REPORT.md`).

## Δομή

```
assignment-3-network-security/
├── port_scanner.py
├── arp_spoof_detector.py
├── log_analyzer.py
├── requirements.txt
├── REPORT.md
├── sample_data/
│   └── sample_auth.log
└── tests/
    ├── test_port_scanner.py
    └── test_log_analyzer.py
```
