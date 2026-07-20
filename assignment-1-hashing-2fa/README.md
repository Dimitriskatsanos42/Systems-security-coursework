# Security Toolkit — 1η Εργασία: Ασφάλεια Συστημάτων

Εφαρμογή σε Python που υλοποιεί:

- **Μέρος Α** — Υπολογισμό hash (MD5, SHA-1, SHA-256, SHA-3/Keccak) και έλεγχο ακεραιότητας αρχείων
- **Μέρος Β** — Υπολογισμό εντροπίας Shannon για ανάλυση τυχαιότητας δεδομένων
- **Μέρος Γ** — Αυθεντικοποίηση δύο παραγόντων (2FA) με TOTP (One-Time Password)
- **Μέρος Δ** — Ενσωμάτωση salt στον υπολογισμό hash

Πανεπιστήμιο Ιωαννίνων — Τμήμα Πληροφορικής & Τηλεπικοινωνιών

## Δομή Project

```
security-toolkit/
├── main.py              # Διαδραστικό μενού (entry point)
├── hashing_utils.py      # Μέρος Α + Δ: hashing, salt, integrity check
├── entropy_utils.py       # Μέρος Β: υπολογισμός εντροπίας Shannon
├── auth_2fa.py            # Μέρος Γ: TOTP-based 2FA
├── requirements.txt
├── REPORT.md              # Αναφορά (παραδοτέο)
└── .gitignore
```

## Εγκατάσταση

```bash
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Εκτέλεση

```bash
python3 main.py
```

Θα εμφανιστεί το διαδραστικό μενού:

```
1. Υπολογισμός Hash
2. Έλεγχος Ακεραιότητας
3. Υπολογισμός Εντροπίας
4. 2FA Authentication
5. Έξοδος
```

## Σημειώσεις Υλοποίησης

- Ο έλεγχος ακεραιότητας (επιλογή 2) είναι "κρίσιμη λειτουργία" και προστατεύεται
  με 2FA πριν εκτελεστεί, όπως ζητά η εκφώνηση.
- Το hash αποθηκεύεται σε αρχείο `<filename>.hash` που περιέχει τον αλγόριθμο,
  το hash και (αν χρησιμοποιήθηκε) το salt σε hex μορφή.
- Το 2FA υλοποιείται με τη βιβλιοθήκη [`pyotp`](https://pyauth.github.io/pyotp/),
  που ακολουθεί το πρότυπο TOTP (RFC 6238) — το ίδιο πρότυπο που χρησιμοποιεί
  το Google Authenticator. Σε demo λειτουργία ο κωδικός εμφανίζεται στην οθόνη
  ώστε να μπορεί να ελεγχθεί η ροή χωρίς εξωτερική εφαρμογή.

## Παραδοτέα

- Πηγαίος κώδικας (αυτό το repository)
- Αναφορά υλοποίησης: [`REPORT.md`](./REPORT.md)
