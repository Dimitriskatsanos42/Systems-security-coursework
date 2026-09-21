# 🔐 Systems Security Coursework

## Development Branch

[![CI](https://github.com/Dimitriskatsanos42/Systems-security-coursework/actions/workflows/ci.yml/badge.svg)](https://github.com/Dimitriskatsanos42/Systems-security-coursework/actions/workflows/ci.yml)
[![Deploy Docs](https://github.com/Dimitriskatsanos42/Systems-security-coursework/actions/workflows/deploy-docs.yml/badge.svg)](https://github.com/Dimitriskatsanos42/Systems-security-coursework/actions/workflows/deploy-docs.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)

> Υλικό, σημειώσεις και projects πάνω στην **Ασφάλεια Συστημάτων** και την
> **Κυβερνοασφάλεια** — πανεπιστημιακές εργασίες και προσωπικά projects σε
> θέματα κρυπτογραφίας, ακεραιότητας δεδομένων, αυθεντικοποίησης, διαχείρισης
> χρηστών σε Linux και ανάλυσης ασφάλειας κωδικών.

📖 **[Δες την τεκμηρίωση online →](https://dimitriskatsanos42.github.io/Systems-security-coursework/)**
*(δημοσιεύεται αυτόματα μέσω GitHub Actions κάθε φορά που ενημερώνεται το `main`)*

---

## 📂 Projects

| Project | Περιγραφή | Θεματικές | Status |
|---|---|---|---|
| [`Linux-user-management`](./Linux-user-management) | Scripts διαχείρισης χρηστών/δικαιωμάτων σε Linux (δημιουργία, sudo, permissions, auditing) | linux, IAM, permissions, shell scripting | ✅ |
| [`assignment-1-hashing-2fa`](./assignment-1-hashing-2fa) | Υπολογισμός hash, ακεραιότητα αρχείων, εντροπία Shannon, 2FA (OTP), salt | hashing, integrity, entropy, 2FA | ✅ |
| [`assignment-2-secure-storage`](./assignment-2-secure-storage) | Ασφαλές σύστημα αποθήκευσης αρχείων: PBKDF2, OTP εγγραφή, RSA, AES-256-GCM, ψηφιακή υπογραφή, anti-replay | password hashing, RSA, AES-GCM, digital signatures | ✅ |
| [`password-strength-checker`](./password-strength-checker) | Εργαλείο αξιολόγησης ισχύος κωδικών πρόσβασης (entropy, dictionary/pattern checks) | password security, entropy, CLI tooling | ✅ |
| *...θα προστεθούν κι άλλα* | | | 🚧 |

Δες το [`ROADMAP.md`](./docs/roadmap.md) για το πλάνο εξέλιξης του repository.

---

## 🛠️ Τεχνολογίες

- **Γλώσσα:** Python 3.11
- **CI/CD:** GitHub Actions (lint + tests σε κάθε push/PR)
- **Docs:** MkDocs Material, δημοσιευμένο μέσω GitHub Pages
- **Branching:** GitHub Flow (`main` → `develop` → `feature/*`) — δες [`CONTRIBUTING.md`](./CONTRIBUTING.md)

Κάθε project έχει το δικό του `requirements.txt` και αναλυτικό `README.md`/`REPORT.md`
με οδηγίες εγκατάστασης, εκτέλεσης και ανάλυση αποτελεσμάτων.

---

## 🚀 Γρήγορη εκκίνηση

```bash
git clone https://github.com/Dimitriskatsanos42/Systems-security-coursework.git
cd Systems-security-coursework/<project-folder>
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py                    # ή το αντίστοιχο entry point του project
```

---

## 🌳 Δομή Repository

```
.
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── .gitignore
├── mkdocs.yml
├── .github/
│   └── workflows/
│       ├── ci.yml                 <- lint + tests σε κάθε project
│       └── deploy-docs.yml        <- deployment της τεκμηρίωσης στο GitHub Pages
├── docs/                          <- πηγή για το documentation site
│   ├── index.md
│   ├── roadmap.md
│   └── ...
├── Linux-user-management/
├── assignment-1-hashing-2fa/
│   ├── main.py
│   ├── hashing_utils.py
│   ├── entropy_utils.py
│   ├── auth_2fa.py
│   ├── requirements.txt
│   └── REPORT.md
├── assignment-2-secure-storage/
│   ├── secure_storage.py
│   ├── requirements.txt
│   ├── report.pdf
│   └── build_report.py
└── password-strength-checker/
```

---

## 🎯 Θεματικές Ενότητες

- 🔐 Κρυπτογραφία & Hashing
- 🛡️ Ακεραιότητα & Αυθεντικοποίηση Δεδομένων
- 📊 Ανάλυση Εντροπίας / Τυχαιότητας
- 🐧 Διαχείριση Χρηστών & Δικαιωμάτων σε Linux
- 🔑 Ασφάλεια Κωδικών Πρόσβασης
- 🧰 Εργαλεία & Scripts Ασφάλειας

## 📜 Άδεια Χρήσης

Το υλικό αυτό δημιουργήθηκε για εκπαιδευτικούς/ακαδημαϊκούς σκοπούς και
διανέμεται υπό την άδεια [MIT](./LICENSE).

## 👤 Author

**Dimitris Katsanos** — [GitHub](https://github.com/Dimitriskatsanos42)
