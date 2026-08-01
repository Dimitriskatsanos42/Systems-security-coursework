#!/usr/bin/env python3
"""
password_strength_checker.py
------------------------------
Εκτιμά την ισχύ ενός κωδικού πρόσβασης με βάση:
  - Μήκος και ποικιλία χαρακτήρων (πεζά, κεφαλαία, ψηφία, σύμβολα)
  - Εντροπία (bits), κατ' αναλογία με τη Shannon entropy που χρησιμοποιήθηκε
    στην 1η εργασία (assignment-1-hashing-2fa), εδώ εφαρμοσμένη σε επίπεδο
    "χώρου αναζήτησης κωδικού" αντί για bytes αρχείου.
  - Έλεγχο έναντι λίστας συνηθισμένων/διαρρευσμένων κωδικών.
  - Εκτιμώμενο χρόνο "σπασίματος" (crack time) σε διαφορετικά σενάρια επίθεσης.

Καθαρά εκπαιδευτικό/αμυντικό εργαλείο: δεν αποθηκεύει, δεν στέλνει πουθενά
τον κωδικό, και δεν πραγματοποιεί καμία πραγματική επίθεση.
"""

import math
import getpass
import sys

# Μια μικρή, ενδεικτική λίστα από τους πιο συνηθισμένους κωδικούς παγκοσμίως
# (βασισμένη σε δημόσιες ετήσιες αναφορές "most common passwords").
# Σε πραγματική εφαρμογή θα χρησιμοποιούσε κανείς μια πολύ μεγαλύτερη λίστα,
# π.χ. το rockyou.txt ή το "Have I Been Pwned" API.
COMMON_PASSWORDS = {
    "123456", "123456789", "qwerty", "password", "12345", "12345678",
    "111111", "1234567", "sunshine", "iloveyou", "admin", "welcome",
    "monkey", "login", "abc123", "starwars", "123123", "dragon",
    "passw0rd", "master", "hello", "freedom", "whatever", "qazwsx",
    "letmein", "trustno1", "000000", "1q2w3e4r", "football", "baseball",
}


def analyze_charset(password: str) -> dict:
    """Επιστρέφει ποια σύνολα χαρακτήρων χρησιμοποιούνται και το συνολικό μέγεθος αλφαβήτου."""
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    alphabet_size = 0
    if has_lower:
        alphabet_size += 26
    if has_upper:
        alphabet_size += 26
    if has_digit:
        alphabet_size += 10
    if has_symbol:
        alphabet_size += 32  # ενδεικτικό μέγεθος για σύνολο συνηθισμένων συμβόλων

    return {
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "alphabet_size": alphabet_size,
    }


def calculate_entropy_bits(password: str) -> float:
    """
    Εκτιμά την εντροπία ενός κωδικού σε bits, θεωρώντας τον ως τυχαία επιλογή
    από το αλφάβητο που χρησιμοποιεί (μέγεθος αλφαβήτου ^ μήκος -> log2).

    Πρόκειται για upper-bound εκτίμηση: αν ο κωδικός βασίζεται σε λέξη του
    λεξικού ή προβλέψιμο μοτίβο, η πραγματική εντροπία είναι μικρότερη από
    αυτή την τιμή (γι' αυτό ελέγχουμε ξεχωριστά και έναντι λίστας συνηθισμένων
    κωδικών).
    """
    if len(password) == 0:
        return 0.0
    charset = analyze_charset(password)
    alphabet_size = max(charset["alphabet_size"], 1)
    return len(password) * math.log2(alphabet_size)


def estimate_crack_times(entropy_bits: float) -> dict:
    """
    Εκτιμά τον χρόνο εξαντλητικής αναζήτησης (brute force) στο μισό του
    χώρου αναζήτησης, για διαφορετικά ρεαλιστικά σενάρια επίθεσης
    (ενδεικτικές τιμές guesses/second, 2024-2025 τάξης μεγέθους):
    """
    search_space = 2 ** entropy_bits
    scenarios = {
        "Online, με rate-limiting (π.χ. 10 προσπάθειες/sec)": 10,
        "Online, χωρίς rate-limiting (π.χ. 10.000/sec)": 10_000,
        "Offline, αργό hash (bcrypt/scrypt/argon2, ~10.000/sec σε GPU)": 10_000,
        "Offline, γρήγορο hash (απλό SHA-256/MD5, ~10 δισ./sec σε GPU cluster)": 10_000_000_000,
    }
    results = {}
    for label, guesses_per_second in scenarios.items():
        seconds = (search_space / 2) / guesses_per_second
        results[label] = _human_readable_duration(seconds)
    return results


def _human_readable_duration(seconds: float) -> str:
    """Μετατρέπει δευτερόλεπτα σε ανθρώπινα αναγνώσιμη διάρκεια."""
    if seconds < 1:
        return "λιγότερο από 1 δευτερόλεπτο"

    units = [
        ("αιώνες", 60 * 60 * 24 * 365 * 100),
        ("χρόνια", 60 * 60 * 24 * 365),
        ("ημέρες", 60 * 60 * 24),
        ("ώρες", 60 * 60),
        ("λεπτά", 60),
        ("δευτερόλεπτα", 1),
    ]
    for name, unit_seconds in units:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            if value > 1_000_000:
                return f"πάνω από {value:.2e} {name}"
            return f"~{value:,.1f} {name}"
    return f"{seconds:.1f} δευτερόλεπτα"


def check_common_password(password: str) -> bool:
    """Ελέγχει αν ο κωδικός βρίσκεται στη λίστα συνηθισμένων/αδύναμων κωδικών."""
    return password.lower() in COMMON_PASSWORDS


def score_password(password: str) -> dict:
    """
    Συγκεντρωτική αξιολόγηση κωδικού. Επιστρέφει dict με:
      - length, charset info, entropy_bits, crack_times
      - is_common (bool)
      - rating: "Πολύ Αδύναμος" -> "Πολύ Ισχυρός"
      - suggestions: λίστα με προτάσεις βελτίωσης
    """
    length = len(password)
    charset = analyze_charset(password)
    entropy = calculate_entropy_bits(password)
    is_common = check_common_password(password)
    crack_times = estimate_crack_times(entropy)

    suggestions = []
    if length < 12:
        suggestions.append("Χρησιμοποιήστε τουλάχιστον 12 χαρακτήρες (ιδανικά 16+).")
    if not charset["has_upper"]:
        suggestions.append("Προσθέστε κεφαλαία γράμματα.")
    if not charset["has_digit"]:
        suggestions.append("Προσθέστε ψηφία.")
    if not charset["has_symbol"]:
        suggestions.append("Προσθέστε σύμβολα (π.χ. !@#$%).")
    if is_common:
        suggestions.append(
            "Αυτός ο κωδικός βρίσκεται σε λίστες συνηθισμένων/διαρρευσμένων "
            "κωδικών — αποφύγετέ τον εντελώς, ανεξαρτήτως εντροπίας."
        )
    if not suggestions:
        suggestions.append("Καλή δουλειά — ο κωδικός καλύπτει τις βασικές συστάσεις.")

    # Βαθμολόγηση: η ύπαρξη σε λίστα κοινών κωδικών υπερισχύει της εντροπίας.
    if is_common:
        rating = "Πολύ Αδύναμος (συνηθισμένος κωδικός)"
    elif entropy < 28:
        rating = "Πολύ Αδύναμος"
    elif entropy < 36:
        rating = "Αδύναμος"
    elif entropy < 60:
        rating = "Μέτριος"
    elif entropy < 80:
        rating = "Ισχυρός"
    else:
        rating = "Πολύ Ισχυρός"

    return {
        "length": length,
        "charset": charset,
        "entropy_bits": entropy,
        "is_common": is_common,
        "rating": rating,
        "crack_times": crack_times,
        "suggestions": suggestions,
    }


def print_report(password: str):
    """Εκτυπώνει μια αναλυτική, ανθρώπινα κατανοητή αναφορά για τον κωδικό."""
    result = score_password(password)

    print("\n" + "=" * 60)
    print(" ΑΝΑΦΟΡΑ ΙΣΧΥΟΣ ΚΩΔΙΚΟΥ")
    print("=" * 60)
    print(f"Μήκος: {result['length']} χαρακτήρες")

    charset = result["charset"]
    used = []
    if charset["has_lower"]:
        used.append("πεζά")
    if charset["has_upper"]:
        used.append("κεφαλαία")
    if charset["has_digit"]:
        used.append("ψηφία")
    if charset["has_symbol"]:
        used.append("σύμβολα")
    print(f"Σύνολα χαρακτήρων: {', '.join(used) if used else 'κανένα'}")

    print(f"Εκτιμώμενη εντροπία: {result['entropy_bits']:.1f} bits")
    print(f"Βαθμολογία: {result['rating']}")
    print(f"Σε λίστα συνηθισμένων κωδικών: {'ΝΑΙ ⚠️' if result['is_common'] else 'Όχι'}")

    print("\nΕκτιμώμενος χρόνος εξαντλητικής αναζήτησης (brute force):")
    for scenario, duration in result["crack_times"].items():
        print(f"  - {scenario}: {duration}")

    print("\nΠροτάσεις βελτίωσης:")
    for suggestion in result["suggestions"]:
        print(f"  • {suggestion}")
    print("=" * 60)


def main():
    print("Password Strength Checker")
    print("(Ο κωδικός δεν αποθηκεύεται ούτε στέλνεται πουθενά — ελέγχεται μόνο τοπικά.)\n")
    try:
        password = getpass.getpass("Εισάγετε κωδικό για έλεγχο: ")
    except Exception:
        # Fallback αν το τερματικό δεν υποστηρίζει κρυφή εισαγωγή (π.χ. some IDEs)
        password = input("Εισάγετε κωδικό για έλεγχο (θα εμφανιστεί): ")

    if not password:
        print("Δεν εισήχθη κωδικός. Έξοδος.")
        sys.exit(0)

    print_report(password)


if __name__ == "__main__":
    main()
