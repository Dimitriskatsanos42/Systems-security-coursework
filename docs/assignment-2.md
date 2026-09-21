# Assignment 2 — Secure File Storage

Ασφαλές σύστημα αποθήκευσης αρχείων που συνδυάζει:

- **PBKDF2** για παραγωγή κλειδιού από password
- **OTP εγγραφή** για επιπλέον επαλήθευση
- **RSA** για ασύμμετρη κρυπτογράφηση/ανταλλαγή κλειδιών
- **AES-256-GCM** για συμμετρική κρυπτογράφηση με authentication
- **Ψηφιακή υπογραφή** για επαλήθευση προέλευσης/ακεραιότητας
- **Anti-replay protection** για αποτροπή επαναχρησιμοποίησης μηνυμάτων

## Δομή

```
assignment-2-secure-storage/
├── secure_storage.py
├── requirements.txt
├── report.pdf
└── build_report.py
```

## Εκτέλεση

```bash
cd assignment-2-secure-storage
pip install -r requirements.txt
python secure_storage.py
```

Πλήρης ανάλυση στο [`report.pdf`](https://github.com/Dimitriskatsanos42/Systems-security-coursework/blob/main/assignment-2-secure-storage/report.pdf).

[↩ Πηγαίος κώδικας στο GitHub](https://github.com/Dimitriskatsanos42/Systems-security-coursework/tree/main/assignment-2-secure-storage)
