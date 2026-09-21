# Roadmap

Ιστορικό και πλάνο εξέλιξης του repository, ώστε να φαίνεται η πρόοδος με τον
χρόνο.

## ✅ Ολοκληρωμένα

- [x] **Linux User Management** — scripts διαχείρισης χρηστών, ομάδων και
      δικαιωμάτων σε Linux.
- [x] **Assignment 1 — Hashing & 2FA** — υπολογισμός hash, ακεραιότητα
      αρχείων, εντροπία Shannon, υλοποίηση 2FA (OTP), χρήση salt.
- [x] **Assignment 2 — Secure Storage** — ασφαλές σύστημα αποθήκευσης
      αρχείων με PBKDF2, RSA, AES-256-GCM, ψηφιακή υπογραφή, anti-replay
      protection.
- [x] **Password Strength Checker** — εργαλείο αξιολόγησης ισχύος κωδικών
      πρόσβασης.
- [x] Ρύθμιση **CI pipeline** (lint + tests) με GitHub Actions.
- [x] Ρύθμιση **deployment τεκμηρίωσης** στο GitHub Pages.
- [x] Καθορισμός **branching strategy** (`main` / `develop` / `feature/*`).

## 🚧 Σε εξέλιξη / Επόμενα βήματα

- [ ] Assignment 3 — Δικτυακή Ασφάλεια (π.χ. packet sniffing, ARP spoofing
      detection).
- [ ] Προσθήκη unit tests (pytest) σε κάθε project για να ανεβεί το
      coverage του CI.
- [ ] Ανάλυση κακόβουλου λογισμικού (θεωρητικό/εκπαιδευτικό υλικό, sandboxed
      analysis).
- [ ] Badge για test coverage (π.χ. Codecov).
- [ ] Dockerization ενός project για reproducible environment.

## 💡 Ιδέες για μελλοντικά projects

- Static analysis / vulnerability scanning σε μικρή εφαρμογή (π.χ. με
  `bandit`).
- Log analysis / SIEM-style script για ανίχνευση ύποπτης δραστηριότητας.
- Πλήρης πλατφόρμα CTF-style challenges για εκπαιδευτική χρήση.
