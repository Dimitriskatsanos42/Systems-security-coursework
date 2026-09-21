# Report — Network Security Toolkit

## 1. Στόχος

Υλοποίηση και δοκιμή τριών εργαλείων δικτυακής ασφάλειας:
1. Ανίχνευση ανοιχτών θυρών (port scanner)
2. Ανίχνευση ARP spoofing
3. Ανίχνευση brute-force επιθέσεων SSH μέσω ανάλυσης logs

## 2. Μεθοδολογία

### 2.1 Port Scanner

- TCP **connect scan** (`connect()` σε κάθε θύρα) — πιο αργό αλλά πιο αξιόπιστο
  από SYN scan, και δεν χρειάζεται raw sockets/root.
- Πολυνηματικό (`ThreadPoolExecutor`) για ταχύτητα σε μεγάλα ranges θυρών.
- Banner grabbing: προσπάθεια ανάγνωσης των πρώτων bytes μετά το connect, για
  αναγνώριση υπηρεσίας (π.χ. SSH banner).
- **Safeguard:** ο έλεγχος `is_authorized_target()` επιτρέπει scanning χωρίς
  ρητή σημαία μόνο σε loopback/ιδιωτικά δίκτυα (RFC1918).

**Δοκιμή:** Εκτελέστηκε scan σε `127.0.0.1` με εύρος θυρών 1–1024. Βρέθηκαν
οι αναμενόμενες τοπικές υπηρεσίες ανάλογα με το test-περιβάλλον (π.χ. θύρα
22/tcp αν τρέχει sshd).

### 2.2 ARP Spoofing Detector

- Χρησιμοποιεί `scapy.sniff()` με φίλτρο BPF `arp` για παθητική ακρόαση.
- Διατηρεί πίνακα IP → MAC (`ArpTable`)· όταν μια γνωστή IP εμφανιστεί με
  διαφορετικό MAC, καταγράφεται προειδοποίηση (πιθανό spoofing/poisoning).
- Παθητικό/αμυντικό: δεν στέλνει κανένα ARP reply, μόνο ακούει.

**Δοκιμή:** Επαληθεύτηκε η λογική του `ArpTable.observe()` με unit-style
σενάρια (νέα IP → καμία ειδοποίηση, ίδια IP/MAC → καμία ειδοποίηση, ίδια IP
με νέο MAC → ειδοποίηση). Πλήρης end-to-end δοκιμή σε ζωντανό δίκτυο
απαιτεί root/δεύτερη συσκευή και δεν περιλαμβάνεται στο αυτοματοποιημένο
test suite.

### 2.3 SSH Brute-Force Log Analyzer

- Regex parsing γραμμών `Failed password ... from <ip>` σε στυλ OpenSSH.
- **Sliding time window** ανά IP: αν ο αριθμός αποτυχημένων προσπαθειών μέσα
  σε `window_minutes` ξεπεράσει το `threshold`, δημιουργείται alert.
- Καθαρά offline ανάλυση κειμένου — δεν χρειάζεται δίκτυο ή δικαιώματα.

**Δοκιμή:** Τρέχει πάνω στο `sample_data/sample_auth.log`, το οποίο περιέχει
6 αποτυχημένες προσπάθειες από την ίδια IP (`198.51.100.23`) μέσα σε ~20
δευτερόλεπτα. Με `threshold=5, window=10` λεπτά, το εργαλείο εντοπίζει
σωστά 1 alert για αυτή την IP, ενώ δεν σημαίνει τις επιτυχημένες συνδέσεις
ή τη μεμονωμένη αποτυχία από άλλη IP.

## 3. Αποτελέσματα

| Εργαλείο | Αυτοματοποιημένα tests | Χειροκίνητη δοκιμή |
|---|---|---|
| `port_scanner.py` | ✅ safety guardrails | ✅ localhost scan |
| `arp_spoof_detector.py` | — (απαιτεί root/live traffic) | ✅ λογική ArpTable |
| `log_analyzer.py` | ✅ parsing + threshold + sliding window | ✅ sample log |

## 4. Περιορισμοί & Μελλοντικές βελτιώσεις

- Ο port scanner κάνει μόνο TCP connect scan — δεν καλύπτει UDP ή stealth
  (SYN) scanning.
- Ο ARP detector δεν διακρίνει νόμιμες αλλαγές MAC (π.χ. αντικατάσταση
  κάρτας δικτύου) από πραγματικές επιθέσεις· θα μπορούσε να προστεθεί
  whitelist/επιβεβαίωση.
- Ο log analyzer υποθέτει μορφή log τύπου OpenSSH σε Ubuntu/Debian· θα
  χρειαστεί προσαρμογή regex για άλλες διανομές/μορφές.
- Πιθανή μελλοντική προσθήκη: ενοποιημένο dashboard/CLI που τρέχει και τα
  τρία εργαλεία και συγκεντρώνει alerts σε ένα σημείο.
