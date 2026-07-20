"""
entropy_utils.py
-----------------
Μέρος Β: Υπολογισμός και Ανάλυση Εντροπίας (Shannon Entropy)

Το αρχείο θεωρείται ακολουθία bytes (τιμές 0-255). Υπολογίζεται η εντροπία
Shannon:
    H = - sum( p(x_i) * log2( p(x_i) ) )  for i = 0..255
"""

import math
from collections import Counter


def calculate_entropy(data: bytes) -> float:
    """
    Υπολογίζει την εντροπία Shannon (σε bits/byte) για μια ακολουθία bytes.
    Τιμές κοντά στο 8.0 -> υψηλή τυχαιότητα (π.χ. κρυπτογραφημένα/συμπιεσμένα δεδομένα)
    Χαμηλότερες τιμές  -> πιο προβλέψιμα/δομημένα δεδομένα (π.χ. απλό κείμενο)
    """
    if len(data) == 0:
        return 0.0

    counts = Counter(data)
    total = len(data)
    entropy = 0.0

    for count in counts.values():
        p_x = count / total
        entropy -= p_x * math.log2(p_x)

    return entropy


def interpret_entropy(value: float) -> str:
    """Επιστρέφει μια σύντομη, ανθρώπινα κατανοητή ερμηνεία της τιμής εντροπίας."""
    if value >= 7.5:
        return "Πολύ υψηλή εντροπία -> πιθανώς κρυπτογραφημένα ή συμπιεσμένα δεδομένα."
    elif value >= 5.0:
        return "Μέτρια/υψηλή εντροπία -> μικτά ή μερικώς δομημένα δεδομένα (π.χ. εκτελέσιμα, εικόνες)."
    elif value >= 2.0:
        return "Μέτρια εντροπία -> δομημένο κείμενο ή δεδομένα με επαναλαμβανόμενα μοτίβα."
    else:
        return "Χαμηλή εντροπία -> πολύ προβλέψιμα δεδομένα (π.χ. επαναλαμβανόμενοι χαρακτήρες)."


def byte_frequency_table(data: bytes) -> dict:
    """Επιστρέφει το πλήθος εμφανίσεων κάθε τιμής byte (0-255) που εμφανίζεται στο αρχείο."""
    return dict(Counter(data))
