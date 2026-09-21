# Workflow & Branching Strategy

Αυτό το repository ακολουθεί μια απλοποιημένη εκδοχή του **GitHub Flow**, ώστε
να φαίνεται καθαρά η εξέλιξη κάθε εργασίας μέσα από branches, pull requests
και commits, αντί να γίνονται όλα απευθείας στο `main`.

## Branches

| Branch | Σκοπός |
|---|---|
| `main` | Σταθερή, "ολοκληρωμένη" έκδοση. Protected — δεν γίνεται push απευθείας, μόνο μέσω PR. |
| `develop` | Branch ενοποίησης για υλικό που είναι σε εξέλιξη (work in progress). |
| `feature/<όνομα>` | Ένα branch ανά νέα εργασία/βελτίωση, π.χ. `feature/assignment-3-network-security`, `feature/ci-pipeline`, `feature/docs-site`. |
| `fix/<όνομα>` | Διορθώσεις σφαλμάτων, π.χ. `fix/entropy-calculation-bug`. |

## Τυπική ροή εργασίας

```bash
# 1. Ξεκίνα από ενημερωμένο develop
git checkout develop
git pull origin develop

# 2. Δημιούργησε feature branch
git checkout -b feature/assignment-3-network-security

# 3. Δούλεψε, κάνε commits με σαφή μηνύματα
git add .
git commit -m "Add ARP spoofing detection script"

# 4. Push και άνοιξε Pull Request προς develop
git push origin feature/assignment-3-network-security

# 5. Μετά από review/merge στο develop, όταν είναι έτοιμο ->
#    Pull Request από develop προς main (release)
```

## Commit messages

Χρησιμοποίησε σύντομα, περιγραφικά μηνύματα, κατά προτίμηση σε imperative mood:

- `Add PBKDF2 key derivation to secure storage`
- `Fix entropy calculation for empty strings`
- `Update README with deployment badge`
- `Docs: add roadmap page`

## Releases / Tags

Για κάθε ολοκληρωμένη εργασία, δημιούργησε ένα tag στο `main` ώστε να
φαίνεται ιστορικά η πρόοδος:

```bash
git tag -a v1.0-assignment1 -m "Assignment 1: Hashing & 2FA completed"
git push origin v1.0-assignment1
```

Αυτά εμφανίζονται στο GitHub κάτω από **Releases**, δίνοντας ένα ξεκάθαρο
timeline εξέλιξης του repository.

## Pull Requests

- Κάθε PR πρέπει να περνάει το CI pipeline (`ci.yml`) πριν το merge.
- Χρησιμοποίησε την περιγραφή του PR για να εξηγήσεις τι άλλαξε και γιατί.
- Προαιρετικά, σύνδεσε το PR με ένα Issue (π.χ. `Closes #4`).
