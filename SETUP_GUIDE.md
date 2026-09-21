# Οδηγός εγκατάστασης — βήμα προς βήμα

Αυτός ο οδηγός εξηγεί πώς να ενσωματώσεις όλα τα παραπάνω αρχεία στο υπάρχον
repository σου, ώστε να αποκτήσει **branches**, **GitHub Actions (CI/CD)** και
**Deployments** ορατά στο GitHub.

## 1. Αντιγραφή αρχείων στο repository

```bash
git clone https://github.com/Dimitriskatsanos42/Systems-security-coursework.git
cd Systems-security-coursework

# Αντέγραψε εδώ μέσα όλα τα αρχεία/φακέλους από το πακέτο:
# README.md (αντικαθιστά το υπάρχον), LICENSE, CONTRIBUTING.md, .gitignore,
# mkdocs.yml, .github/, docs/
```

## 2. Δημιουργία branch `develop`

```bash
git checkout -b develop
git add .
git commit -m "Add CI/CD pipelines, docs site and branching strategy"
git push origin develop
```

## 3. Άνοιγμα Pull Request develop → main

Πήγαινε στο GitHub → **Pull requests** → **New pull request** → base: `main`,
compare: `develop` → **Create pull request** → μετά το review, **Merge**.

Αυτό είναι το πρώτο σου ορατό PR/merge στο ιστορικό του repository.

## 4. Ενεργοποίηση GitHub Pages

1. Repository → **Settings** → **Pages**
2. Στο **Source**, επίλεξε **GitHub Actions** (όχι "Deploy from a branch")
3. Μόλις τρέξει το `deploy-docs.yml` (μετά από push στο `main`), θα δεις το
   site στο: `https://dimitriskatsanos42.github.io/Systems-security-coursework/`
4. Στο repository homepage θα εμφανιστεί και **Environments → github-pages**
   με ιστορικό deployments.

## 5. Branch protection στο `main`

1. **Settings** → **Branches** → **Add branch ruleset / protection rule**
2. Branch name pattern: `main`
3. Ενεργοποίησε:
   - Require a pull request before merging
   - Require status checks to pass before merging → επίλεξε το `CI` workflow
4. **Create** / **Save**

Έτσι το `main` παραμένει πάντα σταθερό και "πράσινο" (περνάει CI).

## 6. Repository settings για επαγγελματική εμφάνιση

- **About** (πάνω δεξιά στη σελίδα του repo) → πρόσθεσε:
  - Description (ήδη υπάρχει)
  - Website: το link του GitHub Pages
  - Topics: `python`, `cybersecurity`, `cryptography`, `linux`,
    `authentication`, `hashing`, `aes`, `rsa`, `2fa`
- Ενεργοποίησε **Issues** και δημιούργησε 2-3 issues για το Roadmap
  (π.χ. "Add Assignment 3: Network Security")
- Προαιρετικά, δημιούργησε ένα **Project board** (Projects tab) με στήλες
  To do / In progress / Done, συνδεδεμένο με τα issues.

## 7. Tags/Releases για ιστορικό εξέλιξης

```bash
git checkout main
git pull origin main
git tag -a v1.0-assignment1 -m "Assignment 1: Hashing & 2FA completed"
git tag -a v1.1-assignment2 -m "Assignment 2: Secure Storage completed"
git push origin --tags
```

Στη συνέχεια, στο GitHub → **Releases** → **Draft a new release** για κάθε
tag, με σύντομες release notes. Αυτό δίνει ένα ξεκάθαρο, ορατό timeline
εξέλιξης του repository στους επισκέπτες.

## 8. Επόμενες εργασίες

Για κάθε νέα εργασία στο μέλλον, ακολούθα τη ροή του `CONTRIBUTING.md`:
`feature/<όνομα>` branch → PR στο `develop` → μετά PR `develop → main` → tag.

---

**Αποτέλεσμα:** Το repository θα δείχνει branches (`main`, `develop`,
`feature/*`), ένα πράσινο CI badge, ένα live documentation site μέσω
Deployments/Environments, tags/releases ως ιστορικό προόδου, και μια σαφή
δομή/τεκμηρίωση — όλα δείκτες ενός επαγγελματικά συντηρημένου repository.
