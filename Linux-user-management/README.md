# Linux User Management Automation

Bash script αυτοματοποίησης διαχείρισης χρηστών σε Linux (Debian/Ubuntu-based).
Καλύπτει έναν πλήρη κύκλο system administration: δημιουργία/διαγραφή χρηστών,
groups, δικαιώματα αρχείων, περιορισμένη πρόσβαση sudo, και πολιτική λήξης
κωδικών — όλα μέσω ενός ενιαίου CLI εργαλείου.

Δοκιμασμένο πραγματικά (όχι μόνο θεωρητικά) σε Ubuntu 24.04, με πλήρη κύκλο:
δημιουργία → ανάθεση groups/sudo/policy → audit → revoke → διαγραφή.

## Γιατί αυτό το project

Οι δεξιότητες αυτές (user/group management, δικαιώματα, sudoers, password
policy) είναι θεμελιώδεις για system administration αλλά και άμεσα σχετικές
με privilege escalation σενάρια σε πλατφόρμες όπως το **HackTheBox** — το να
καταλαβαίνεις πώς ρυθμίζεται σωστά ένα sudoers αρχείο είναι το ίδιο νόμισμα
με το να καταλαβαίνεις πώς εκμεταλλεύεται ένα λάθος ρυθμισμένο.

## Λειτουργίες

| Εντολή | Περιγραφή |
|---|---|
| `create-user` | Δημιουργία χρήστη (home dir, shell, groups). Κωδικός κλειδωμένος έως ότου οριστεί ρητά. |
| `delete-user` | Διαγραφή χρήστη (προαιρετικά με το home directory), καθαρισμός τυχόν sudoers. |
| `create-group` / `add-to-group` | Δημιουργία groups και ανάθεση χρηστών. |
| `grant-sudo` | Περιορισμένη πρόσβαση sudo σε συγκεκριμένες εντολές (**όχι** πλήρες sudo από προεπιλογή) μέσω `/etc/sudoers.d/`, με υποχρεωτικό `visudo -c` validation πριν εφαρμοστεί οτιδήποτε. |
| `revoke-sudo` | Αφαίρεση sudo πρόσβασης (custom αρχείο + αφαίρεση από group `sudo`). |
| `set-policy` | Πολιτική λήξης κωδικού μέσω `chage` (max/min days, warning period). |
| `set-perms` | `chown`/`chmod` σε αρχεία/φακέλους. |
| `bulk-create` | Μαζική δημιουργία χρηστών από αρχείο CSV. |
| `audit` | Πλήρες ή ανά-χρήστη report: groups, shell, home, password aging, sudo status. |

Κάθε προνομιούχα εντολή υποστηρίζει **`--dry-run`**: εμφανίζει τι ΘΑ έκανε το
script, χωρίς να αλλάξει τίποτα.

## Γιατί είναι ασφαλές by design

- **Least privilege στο sudo**: το `grant-sudo` περιορίζει σε συγκεκριμένες
  εντολές από προεπιλογή· πλήρες sudo χορηγείται μόνο ρητά με `--full`.
- **Υποχρεωτικό `visudo -c`**: κάθε αλλαγή στο sudoers επικυρώνεται πριν
  εγκατασταθεί — ένα λάθος syntax εκεί μπορεί να κλειδώσει την πρόσβαση root
  σε όλο το σύστημα, οπότε δεν εφαρμόζεται ποτέ χωρίς έλεγχο.
- **Κλειδωμένος κωδικός by default**: `create-user` καλεί `passwd -l` αμέσως
  μετά τη δημιουργία — δεν υπάρχει ποτέ λογαριασμός με κενό/προβλέψιμο κωδικό.
- **Πλήρες logging**: κάθε ενέργεια (συμπεριλαμβανομένων dry-run) καταγράφεται
  σε `logs/user_management.log` με timestamp.
- **`set -euo pipefail`**: το script σταματά αμέσως σε οποιοδήποτε
  απροσδόκητο σφάλμα, αντί να συνεχίσει σε μη προβλέψιμη κατάσταση.

## Χρήση

```bash
chmod +x user_management.sh

# Δείτε πρώτα τι θα κάνει, χωρίς να αλλάξει τίποτα:
sudo ./user_management.sh --dry-run create-user --username alice --groups developers,docker

# Πραγματική εκτέλεση:
sudo ./user_management.sh create-user --username alice --groups developers,docker
sudo ./user_management.sh grant-sudo --username alice --commands "/usr/bin/systemctl restart nginx"
sudo ./user_management.sh set-policy --username alice --max-days 90 --warn-days 7
sudo ./user_management.sh set-perms --path /srv/webapp --owner alice --group developers --mode 750

# Μαζική δημιουργία από CSV:
sudo ./user_management.sh bulk-create --file config/users.csv

# Έλεγχος:
sudo ./user_management.sh audit                    # όλοι οι χρήστες
sudo ./user_management.sh audit --username alice    # συγκεκριμένος χρήστης

# Ανάκληση/καθαρισμός:
sudo ./user_management.sh revoke-sudo --username alice
sudo ./user_management.sh delete-user --username alice --remove-home
```

Πλήρη λίστα εντολών: `./user_management.sh help`

## Μορφή CSV για bulk-create

```csv
username,shell,groups
devuser1,/bin/bash,developers
devuser2,/bin/bash,developers,docker
qauser1,/bin/bash,qa
```

Δες [`config/users.csv`](./config/users.csv) για πλήρες παράδειγμα.

## Testing

```bash
./tests/run_tests.sh
```

Το test suite τρέχει sanity checks σε `--dry-run` mode και σε read-only
λειτουργίες (`audit`, `help`) — έτσι δουλεύει και χωρίς root/σε CI runner.
Δοκιμάστηκε επίσης manually με πλήρη root δικαιώματα, σε Ubuntu 24.04:
δημιουργία μεμονωμένου χρήστη, bulk-create 4 χρηστών από CSV, grant/revoke
sudo, set-policy, set-perms, και πλήρες audit — όλα επιβεβαιωμένα σωστά.

Static analysis: το script περνάει καθαρά από
[shellcheck](https://www.shellcheck.net/) χωρίς καμία προειδοποίηση.

```bash
shellcheck user_management.sh tests/run_tests.sh
```

## Απαιτήσεις

- Linux (δοκιμασμένο σε Ubuntu/Debian)· βασίζεται σε `useradd`, `usermod`,
  `userdel`, `groupadd`, `chage`, `passwd`, `visudo` (πακέτο `sudo`)
- Bash 4+ (χρησιμοποιεί associative arrays)
- Root δικαιώματα για όλες τις προνομιούχες εντολές (`audit` είναι read-only
  και δεν απαιτεί root)

## Πιθανές επεκτάσεις

- Ενσωμάτωση `pwquality.conf` για επιβολή πολυπλοκότητας κωδικού (μήκος,
  character classes) σε επίπεδο συστήματος, όχι μόνο aging
- Υποστήριξη YAML αντί για CSV στο bulk-create
- Rollback μηχανισμός (snapshot πριν από μαζικές αλλαγές)
