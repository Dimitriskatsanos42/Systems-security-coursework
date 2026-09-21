# Systems Security Coursework

Καλώς ήρθες στην τεκμηρίωση του repository **Systems Security Coursework**.

Εδώ συγκεντρώνονται πανεπιστημιακές εργασίες και προσωπικά projects πάνω σε
θέματα Ασφάλειας Συστημάτων και Κυβερνοασφάλειας: κρυπτογραφία, ακεραιότητα
δεδομένων, αυθεντικοποίηση, διαχείριση χρηστών σε Linux και ασφάλεια κωδικών
πρόσβασης.

## Projects

| Project | Περιγραφή |
|---|---|
| [Linux User Management](linux-user-management.md) | Διαχείριση χρηστών, ομάδων και δικαιωμάτων σε Linux |
| [Assignment 1 — Hashing & 2FA](assignment-1.md) | Hashing, εντροπία Shannon, 2FA (OTP), salt |
| [Assignment 2 — Secure Storage](assignment-2.md) | PBKDF2, RSA, AES-256-GCM, ψηφιακή υπογραφή |
| [Password Strength Checker](password-strength-checker.md) | Αξιολόγηση ισχύος κωδικών πρόσβασης |

## Πηγαίος κώδικας

Ο πλήρης κώδικας βρίσκεται στο [GitHub repository](https://github.com/Dimitriskatsanos42/Systems-security-coursework).

## CI/CD

Κάθε αλλαγή περνάει αυτόματα από:

- **Lint & Tests** ([`ci.yml`](https://github.com/Dimitriskatsanos42/Systems-security-coursework/actions/workflows/ci.yml)) σε κάθε push/PR σε `main` ή `develop`.
- **Deployment τεκμηρίωσης** ([`deploy-docs.yml`](https://github.com/Dimitriskatsanos42/Systems-security-coursework/actions/workflows/deploy-docs.yml)) στο GitHub Pages, σε κάθε ενημέρωση του `main`.

Δες το [Roadmap](roadmap.md) για το πλάνο εξέλιξης.
