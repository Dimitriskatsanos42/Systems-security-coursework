"""
auth_2fa.py
-----------
Μέρος Γ: Αυθεντικοποίηση Δύο Παραγόντων (2FA) με One-Time Password (OTP)

Χρησιμοποιεί τη βιβλιοθήκη pyotp για την υλοποίηση TOTP (Time-based OTP),
η οποία ακολουθεί το ίδιο πρότυπο (RFC 6238) με εφαρμογές όπως το Google
Authenticator.

Ροή:
1. generate_secret()      -> δημιουργεί ένα μυστικό κλειδί (secret key)
2. get_current_otp()      -> υπολογίζει τον τρέχοντα, έγκυρο κωδικό OTP
3. verify_otp()           -> ελέγχει αν ο κωδικός που έδωσε ο χρήστης είναι σωστός
"""

import pyotp


def generate_secret() -> str:
    """Δημιουργεί ένα νέο, τυχαίο μυστικό κλειδί (base32) για χρήση σε TOTP."""
    return pyotp.random_base32()


def get_totp(secret: str) -> pyotp.TOTP:
    """Επιστρέφει ένα αντικείμενο TOTP για το δοσμένο secret."""
    return pyotp.TOTP(secret)


def get_current_otp(secret: str) -> str:
    """Υπολογίζει και επιστρέφει τον τρέχοντα έγκυρο κωδικό OTP (6 ψηφία, ισχύει 30 δευτ.)."""
    totp = get_totp(secret)
    return totp.now()


def verify_otp(secret: str, user_code: str) -> bool:
    """
    Επαληθεύει αν ο κωδικός που έδωσε ο χρήστης είναι έγκυρος για το τρέχον
    χρονικό παράθυρο (με ανοχή ενός παραθύρου πριν/μετά για ρολόι που δεν
    είναι απόλυτα συγχρονισμένο).
    """
    totp = get_totp(secret)
    return totp.verify(user_code, valid_window=1)


def require_2fa(secret: str) -> bool:
    """
    Βοηθητική συνάρτηση που εμφανίζει τον κωδικό (για διδακτικούς σκοπούς -
    σε πραγματικό σενάριο ο κωδικός θα δινόταν μέσω εφαρμογής/SMS και όχι
    θα εκτυπωνόταν στην οθόνη) και ζητά από τον χρήστη να τον εισάγει,
    πριν επιτραπεί μια κρίσιμη ενέργεια (π.χ. έλεγχος ακεραιότητας).
    Επιστρέφει True αν η αυθεντικοποίηση πέτυχε.
    """
    current_code = get_current_otp(secret)
    print(f"\n[2FA] (Demo) Ο τρέχων κωδικός OTP είναι: {current_code}")
    print("[2FA] Σε πραγματική εφαρμογή αυτός ο κωδικός θα εμφανιζόταν μόνο")
    print("      στην εφαρμογή αυθεντικοποίησης του χρήστη (π.χ. Google Authenticator).")

    user_code = input("[2FA] Εισάγετε τον κωδικό OTP: ").strip()
    if verify_otp(secret, user_code):
        print("[2FA] ✅ Επιτυχής αυθεντικοποίηση. Πρόσβαση επιτρέπεται.\n")
        return True
    else:
        print("[2FA] ❌ Λανθασμένος κωδικός. Πρόσβαση απορρίπτεται.\n")
        return False
