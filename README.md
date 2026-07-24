# Security & Cybersecurity

Σημειώσεις, πανεπιστημιακές εργασίες και προσωπικά projects πάνω στην Ασφάλεια
Συστημάτων και την Κυβερνοασφάλεια. Το repository ενημερώνεται συνεχώς καθώς
προστίθεται νέο υλικό (εργασίες μαθημάτων, εργαλεία, πειράματα, σημειώσεις).

## Περιεχόμενα

| Project | Περιγραφή | Θεματικές |
|---|---|---|
| [`assignment-1-hashing-2fa`](./assignment-1-hashing-2fa) | Υπολογισμός hash, ακεραιότητα αρχείων, εντροπία Shannon, 2FA (OTP), salt | hashing, integrity, entropy, 2FA |
| [`assignment-2-secure-storage`](./assignment-2-secure-storage) | Ασφαλές σύστημα αποθήκευσης αρχείων: PBKDF2, OTP εγγραφή, RSA, AES-256-GCM, ψηφιακή υπογραφή, anti-replay | password hashing, RSA, AES-GCM, digital signatures, anti-replay |
| _...θα προστεθούν κι άλλα_ | | |

> Κάθε φάκελος project περιέχει το δικό του `README.md` / αναφορά με
> αναλυτικές οδηγίες εγκατάστασης, εκτέλεσης και ανάλυση αποτελεσμάτων.

## Θεματικές Ενότητες

- 🔐 Κρυπτογραφία & Hashing
- 🛡️ Ακεραιότητα & Αυθεντικοποίηση Δεδομένων
- 📊 Ανάλυση Εντροπίας / Τυχαιότητας
- 🌐 Δικτυακή Ασφάλεια
- 🐛 Ανάλυση Ευπαθειών & Malware (θεωρητικό/εκπαιδευτικό υλικό)
- 🧰 Εργαλεία & Scripts Ασφάλειας

## Τεχνολογίες

Το μεγαλύτερο μέρος του κώδικα είναι σε **Python 3**. Κάθε project έχει το δικό
του `requirements.txt` και οδηγίες εγκατάστασης στο αντίστοιχο README του.

## Δομή Repository

```
.
├── README.md                          <- αυτό το αρχείο
├── assignment-1-hashing-2fa/          <- 1η εργασία: Hash, Εντροπία, 2FA, Salt
│   ├── main.py
│   ├── hashing_utils.py
│   ├── entropy_utils.py
│   ├── auth_2fa.py
│   ├── requirements.txt
│   └── REPORT.md
├── assignment-2-secure-storage/       <- 2η εργασία: Secure File Storage
│   ├── secure_storage.py
│   ├── requirements.txt
│   ├── report.pdf
│   └── build_report.py
└── ...
```

## Σκοπός

Το repository λειτουργεί ως προσωπικό αρχείο μάθησης και εργασιών γύρω από την
ασφάλεια πληροφοριακών συστημάτων — τόσο για ακαδημαϊκούς σκοπούς (εργασίες
μαθημάτων) όσο και για προσωπική εξάσκηση σε θέματα κυβερνοασφάλειας.

## Άδεια Χρήσης

Το υλικό αυτό δημιουργήθηκε για εκπαιδευτικούς/ακαδημαϊκούς σκοπούς.
