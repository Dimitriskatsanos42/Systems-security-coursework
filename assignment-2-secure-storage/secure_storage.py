#!/usr/bin/env python3
"""
2η Εργασία — Ασφάλεια Συστημάτων
Secure File Storage System

ΟΔΗΓΙΕΣ:
  • Συμπληρώστε ΜΟΝΟ τα τμήματα # TODO
  • Για hash_password() και verify_password() χρησιμοποιήστε
    ΤΗ ΔΙΚΗ ΣΑΣ υλοποίηση από την Εργασία 1
  • Μην τροποποιείτε τις υπόλοιπες συναρτήσεις
"""

import os, json, secrets, base64
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# ──────────────────────────────────────────────────────
# ΣΤΑΘΕΡΕΣ
# ──────────────────────────────────────────────────────
USERS_DB    = Path('users.json')
STORAGE_DIR = Path('secure_storage')
KEYS_DIR    = Path('keys')
NONCE_DB    = Path('nonces.json')
OTP_DB      = Path('otp_store.json')  # Δίνεται από διαχειριστή

def initialize_system():
    STORAGE_DIR.mkdir(exist_ok=True)
    KEYS_DIR.mkdir(exist_ok=True)
    for f, default in [(USERS_DB, {}), (NONCE_DB, []), (OTP_DB, {})]:
        if not f.exists():
            f.write_text(json.dumps(default))


# ──────────────────────────────────────────────────────
# ΜΕΡΟΣ Α — Hash & Salt (από Εργασία 1 — ΜΑΥΡΟ ΚΟΥΤΙ)
# ──────────────────────────────────────────────────────
# Αντιγράψτε εδώ τις δύο συναρτήσεις σας από την Εργασία 1:
#
#   hash_password(password: str, salt: str = None) -> tuple[str, str]
#     Επιστρέφει (hash_hex, salt_hex)
#
#   verify_password(password: str, stored_hash: str, salt: str) -> bool
#     Επιστρέφει True αν ο κωδικός είναι σωστός
#
# TODO — ΜΕΡΟΣ Α: Επικολλήστε τις υλοποιήσεις σας από Εργασία 1
#
# Σημείωση: Η 1η Εργασία μας ζητούσε hashing αρχείων (MD5/SHA-1/SHA-256/SHA-3),
# όχι hashing κωδικών με salt+επαναλήψεις. Εδώ επεκτείνουμε εκείνη τη λογική
# του salt (Μέρος Δ της 1ης Εργασίας) σε hashing κωδικών, χρησιμοποιώντας
# PBKDF2-HMAC-SHA256 με πολλαπλές επαναλήψεις (απαίτηση της εκφώνησης: απλό
# MD5/SHA1 χωρίς επαναλήψεις δεν γίνεται αποδεκτό). Χρησιμοποιείται μόνο η
# βιβλιοθήκη `cryptography`, όπως ζητείται.

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 390_000  # OWASP-recommended τάξη μεγέθους για PBKDF2-SHA256
PBKDF2_KEY_LENGTH = 32       # bytes (256 bits)


def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    """
    Υπολογίζει PBKDF2-HMAC-SHA256 hash ενός κωδικού με salt.
    Αν δεν δοθεί salt, δημιουργείται νέο τυχαίο salt (16 bytes).
    Επιστρέφει (hash_hex, salt_hex).
    """
    if salt is None:
        salt_bytes = os.urandom(16)
    else:
        salt_bytes = bytes.fromhex(salt)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PBKDF2_KEY_LENGTH,
        salt=salt_bytes,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    derived_key = kdf.derive(password.encode("utf-8"))
    return derived_key.hex(), salt_bytes.hex()


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """
    Επαληθεύει αν ο κωδικός που δόθηκε αντιστοιχεί στο αποθηκευμένο hash,
    επαναϋπολογίζοντας το PBKDF2 hash με το ίδιο salt.
    """
    computed_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(computed_hash, stored_hash)


# ──────────────────────────────────────────────────────
# ΜΕΡΟΣ Β — OTP & Εγγραφή Χρήστη (Δίνεται μερικώς)
# ──────────────────────────────────────────────────────

def admin_issue_otp(username: str) -> str:
    """Διαχειριστής: δημιουργεί και αποθηκεύει OTP για username."""
    otp = secrets.token_hex(4).upper()  # 8-ψήφιο hex OTP
    store = json.loads(OTP_DB.read_text())
    store[username] = {
        "otp": otp,
        "issued_at": datetime.now().isoformat(),
        "used": False
    }
    OTP_DB.write_text(json.dumps(store, indent=2))
    print(f"[ADMIN] OTP για '{username}': {otp}")
    return otp


def register_user(username: str, otp_input: str, password: str) -> bool:
    """
    ΜΕΡΟΣ Β:
    Εγγραφή χρήστη με επαλήθευση OTP.
    Ροή:
      1. Φορτώστε το OTP_DB και ελέγξτε αν υπάρχει OTP για το username
      2. Ελέγξτε αν το OTP δεν έχει χρησιμοποιηθεί ξανά (used == False)
      3. Συγκρίνετε το otp_input με το αποθηκευμένο (case-insensitive)
      4. Αν είναι σωστό: σημειώστε το ως used=True
      5. Ελέγξτε αν ο χρήστης υπάρχει ήδη στο USERS_DB
      6. Δημιουργήστε hash+salt του password (από Εργασία 1)
      7. Αποθηκεύστε χρήστη στο USERS_DB
      8. Καλέστε generate_user_keys(username)
      9. Επιστρέψτε True αν όλα πήγαν καλά
    """
    # 1. Φόρτωση OTP_DB
    otp_store = json.loads(OTP_DB.read_text())

    if username not in otp_store:
        print(f"[ΣΦΑΛΜΑ] Δεν έχει εκδοθεί OTP για τον χρήστη '{username}'.")
        return False

    otp_record = otp_store[username]

    # 2. Έλεγχος αν το OTP έχει ήδη χρησιμοποιηθεί
    if otp_record.get("used", False):
        print("[ΣΦΑΛΜΑ] Αυτό το OTP έχει ήδη χρησιμοποιηθεί.")
        return False

    # 3. Σύγκριση OTP (case-insensitive)
    if otp_input.upper() != otp_record["otp"].upper():
        print("[ΣΦΑΛΜΑ] Λανθασμένο OTP.")
        return False

    # 4. Σημείωση OTP ως χρησιμοποιημένο
    otp_record["used"] = True
    otp_store[username] = otp_record
    OTP_DB.write_text(json.dumps(otp_store, indent=2))

    # 5. Έλεγχος αν ο χρήστης υπάρχει ήδη
    users = json.loads(USERS_DB.read_text())
    if username in users:
        print(f"[ΣΦΑΛΜΑ] Ο χρήστης '{username}' υπάρχει ήδη.")
        return False

    # 6. Υπολογισμός hash+salt του κωδικού
    password_hash, salt = hash_password(password)

    # 7. Αποθήκευση χρήστη
    users[username] = {
        "password_hash": password_hash,
        "salt": salt,
        "created_at": datetime.now().isoformat(),
    }
    USERS_DB.write_text(json.dumps(users, indent=2))

    # 8. Δημιουργία ζεύγους κλειδιών RSA
    generate_user_keys(username)

    # 9. Επιβεβαίωση
    print(f"[OK] Ο χρήστης '{username}' εγγράφηκε επιτυχώς.")
    return True


# ──────────────────────────────────────────────────────
# ΜΕΡΟΣ Γ — Αυθεντικοποίηση (Δίνεται δομή)
# ──────────────────────────────────────────────────────

def authenticate_user(username: str, password: str) -> bool:
    """
    ΜΕΡΟΣ Γ:
    Ελέγξτε τα στοιχεία σύνδεσης.
      1. Φορτώστε USERS_DB
      2. Ελέγξτε αν ο χρήστης υπάρχει
      3. Ανακτήστε stored_hash και salt
      4. Καλέστε verify_password() από Εργασία 1
      5. Επιστρέψτε True/False

    Ασφάλεια: δεν αποκαλύπτουμε αν το πρόβλημα ήταν "χρήστης δεν υπάρχει"
    ή "λάθος κωδικός" — πάντα το ίδιο γενικό μήνυμα, ώστε να μην διαρρέουν
    πληροφορίες σε έναν επιτιθέμενο (π.χ. user enumeration).
    """
    GENERIC_ERROR = "[ΣΦΑΛΜΑ] Λάθος στοιχεία σύνδεσης."

    # 1. Φόρτωση USERS_DB
    users = json.loads(USERS_DB.read_text())

    # 2. Έλεγχος αν ο χρήστης υπάρχει
    if username not in users:
        print(GENERIC_ERROR)
        return False

    # 3. Ανάκτηση stored_hash και salt
    user_record = users[username]
    stored_hash = user_record["password_hash"]
    salt = user_record["salt"]

    # 4. Επαλήθευση κωδικού
    if not verify_password(password, stored_hash, salt):
        print(GENERIC_ERROR)
        return False

    # 5. Επιτυχής αυθεντικοποίηση
    print(f"[OK] Επιτυχής σύνδεση ως '{username}'.")
    return True


# ──────────────────────────────────────────────────────
# ΜΕΡΟΣ Δ — Κλειδιά RSA (Δίνεται)
# ──────────────────────────────────────────────────────

def generate_user_keys(username: str):
    """Δημιουργία RSA-2048 ζεύγους κλειδιών."""
    pk = rsa.generate_private_key(65537, 2048, default_backend())
    (KEYS_DIR / f"{username}_private.pem").write_bytes(
        pk.private_bytes(serialization.Encoding.PEM,
                          serialization.PrivateFormat.TraditionalOpenSSL,
                          serialization.NoEncryption()))
    (KEYS_DIR / f"{username}_public.pem").write_bytes(
        pk.public_key().public_bytes(serialization.Encoding.PEM,
                                      serialization.PublicFormat.SubjectPublicKeyInfo))

def load_private_key(username: str):
    return serialization.load_pem_private_key(
        (KEYS_DIR / f"{username}_private.pem").read_bytes(),
        password=None, backend=default_backend())

def load_public_key(username: str):
    return serialization.load_pem_public_key(
        (KEYS_DIR / f"{username}_public.pem").read_bytes(),
        backend=default_backend())


# ──────────────────────────────────────────────────────
# ΜΕΡΟΣ Ε — Nonce / Anti-Replay (Δίνεται δομή)
# ──────────────────────────────────────────────────────

def generate_nonce() -> str:
    return secrets.token_hex(16)

def is_nonce_valid(nonce: str) -> bool:
    """
    ΜΕΡΟΣ Ε:
    Ελέγξτε αν το nonce είναι μοναδικό.
      1. Φορτώστε τη λίστα από NONCE_DB
      2. Αν υπάρχει ήδη → return False (Replay Attack)
      3. Αλλιώς → αποθηκεύστε το, return True

    Bonus: αποθηκεύουμε και timestamp μαζί με κάθε nonce, και καθαρίζουμε
    nonces παλαιότερα των 24 ωρών ώστε το αρχείο να μην μεγαλώνει απεριόριστα.
    """
    # 1. Φόρτωση λίστας nonces (bonus: μπορεί να είναι λίστα από dict {nonce, timestamp}
    #    ή λίστα από απλά strings αν προϋπάρχει παλαιότερη μορφή αρχείου)
    raw_entries = json.loads(NONCE_DB.read_text())

    # Κανονικοποίηση: μετατροπή σε λίστα από dict {"nonce":..., "timestamp":...}
    entries = []
    for entry in raw_entries:
        if isinstance(entry, str):
            entries.append({"nonce": entry, "timestamp": datetime.now().isoformat()})
        else:
            entries.append(entry)

    existing_nonces = {e["nonce"] for e in entries}

    # 2. Έλεγχος αν το nonce έχει ξαναχρησιμοποιηθεί
    if nonce in existing_nonces:
        print("[ΠΡΟΕΙΔΟΠΟΙΗΣΗ] Εντοπίστηκε πιθανή Replay Attack — το nonce έχει ήδη χρησιμοποιηθεί!")
        return False

    # Bonus: καθαρισμός nonces παλαιότερων των 24 ωρών
    now = datetime.now()
    fresh_entries = []
    for e in entries:
        try:
            ts = datetime.fromisoformat(e["timestamp"])
            age_hours = (now - ts).total_seconds() / 3600
            if age_hours <= 24:
                fresh_entries.append(e)
        except (KeyError, ValueError):
            # Αν λείπει/είναι άκυρο το timestamp, το κρατάμε για ασφάλεια
            fresh_entries.append(e)

    # 3. Προσθήκη νέου nonce και αποθήκευση
    fresh_entries.append({"nonce": nonce, "timestamp": now.isoformat()})
    NONCE_DB.write_text(json.dumps(fresh_entries, indent=2))
    return True


# ──────────────────────────────────────────────────────
# ΜΕΡΟΣ ΣΤ — Κρυπτογράφηση & Υπογραφή (Δίνεται δομή)
# ──────────────────────────────────────────────────────

def encrypt_file(data: bytes) -> tuple:
    """
    ΜΕΡΟΣ ΣΤ (α):
    Κρυπτογράφηση με AES-256-GCM.
    Επιστρέφει: (ciphertext, key_bytes, nonce_aes_bytes)
    """
    key = os.urandom(32)          # AES-256 -> κλειδί 32 bytes
    nonce_aes = os.urandom(12)    # Συνιστώμενο μέγεθος nonce για GCM: 12 bytes
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce_aes, data, None)
    return ciphertext, key, nonce_aes

def decrypt_file(ciphertext: bytes, key: bytes, nonce_aes: bytes) -> bytes:
    """
    ΜΕΡΟΣ ΣΤ (α):
    Αποκρυπτογράφηση AES-256-GCM.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce_aes, ciphertext, None)

def sign_data(username: str, data: bytes, nonce: str) -> bytes:
    """
    ΜΕΡΟΣ ΣΤ (β):
    Ψηφιακή υπογραφή RSA-PSS+SHA256.
    payload = data + nonce.encode()
    """
    private_key = load_private_key(username)
    payload = data + nonce.encode()
    signature = private_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(username: str, data: bytes, nonce: str, sig: bytes) -> bool:
    """
    ΜΕΡΟΣ ΣΤ (β):
    Επαλήθευση ψηφιακής υπογραφής.
    Επιστρέφει True/False.
    """
    public_key = load_public_key(username)
    payload = data + nonce.encode()
    try:
        public_key.verify(
            sig,
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


# ──────────────────────────────────────────────────────
# ΜΕΡΟΣ Ζ — Upload / Download / CLI (Δίνεται δομή)
# ──────────────────────────────────────────────────────

def upload_file(username: str, filepath: str):
    """
    ΜΕΡΟΣ Ζ (α):
    Ανέβασμα αρχείου με ασφάλεια.
    Ροή: read → nonce → sign → validate_nonce → encrypt → save
    """
    path = Path(filepath)
    if not path.is_file():
        print(f"[ΣΦΑΛΜΑ] Το αρχείο '{filepath}' δεν βρέθηκε.")
        return

    # 30. Ανάγνωση bytes
    data = path.read_bytes()

    # 31. Παραγωγή nonce
    nonce = generate_nonce()

    # 32. Υπογραφή δεδομένων (πριν την κρυπτογράφηση, πάνω στο plaintext + nonce)
    signature = sign_data(username, data, nonce)

    # 33. Έλεγχος εγκυρότητας nonce (anti-replay)
    if not is_nonce_valid(nonce):
        print("[ΣΦΑΛΜΑ] Μη έγκυρο nonce — το ανέβασμα ακυρώθηκε.")
        return

    # 34. Κρυπτογράφηση δεδομένων
    ciphertext, key, nonce_aes = encrypt_file(data)

    # 35. Αποθήκευση κρυπτογραφημένων bytes
    enc_path = STORAGE_DIR / f"{path.name}.enc"
    enc_path.write_bytes(ciphertext)

    # 36. Αποθήκευση metadata JSON
    metadata = {
        "signature": base64.b64encode(signature).decode("ascii"),
        "key": base64.b64encode(key).decode("ascii"),
        "nonce_aes": base64.b64encode(nonce_aes).decode("ascii"),
        "nonce": nonce,
        "uploader": username,
        "original_filename": path.name,
        "timestamp": datetime.now().isoformat(),
    }
    meta_path = STORAGE_DIR / f"{path.name}.json"
    meta_path.write_text(json.dumps(metadata, indent=2))

    print(f"[OK] Το αρχείο '{path.name}' ανέβηκε και κρυπτογραφήθηκε επιτυχώς.")


def download_file(username: str, filename: str):
    """
    ΜΕΡΟΣ Ζ (β):
    Λήψη και αποκρυπτογράφηση αρχείου.
    Ροή: load metadata → decrypt → verify_signature → save locally
    """
    meta_path = STORAGE_DIR / f"{filename}.json"
    enc_path = STORAGE_DIR / f"{filename}.enc"

    # 37. Φόρτωση metadata JSON
    if not meta_path.is_file() or not enc_path.is_file():
        print(f"[ΣΦΑΛΜΑ] Δεν βρέθηκε αποθηκευμένο αρχείο με όνομα '{filename}'.")
        return

    metadata = json.loads(meta_path.read_text())

    # 38. Ανάγνωση κρυπτογραφημένων bytes
    ciphertext = enc_path.read_bytes()

    # 39. Αποκωδικοποίηση base64
    key = base64.b64decode(metadata["key"])
    nonce_aes = base64.b64decode(metadata["nonce_aes"])
    signature = base64.b64decode(metadata["signature"])
    nonce = metadata["nonce"]
    uploader = metadata["uploader"]
    original_filename = metadata["original_filename"]

    # 40. Αποκρυπτογράφηση
    try:
        plaintext = decrypt_file(ciphertext, key, nonce_aes)
    except Exception:
        print("[ΣΦΑΛΜΑ] Αποτυχία αποκρυπτογράφησης — το αρχείο ίσως έχει αλλοιωθεί.")
        return

    # 41. Επαλήθευση ψηφιακής υπογραφής (πάνω στον uploader, όχι στον τρέχοντα χρήστη,
    #     αφού η υπογραφή αποδεικνύει ΠΟΙΟΣ ανέβασε το αρχείο)
    if not verify_signature(uploader, plaintext, nonce, signature):
        print("[ΠΡΟΕΙΔΟΠΟΙΗΣΗ] Η ψηφιακή υπογραφή ΔΕΝ είναι έγκυρη! "
              "Το αρχείο ενδέχεται να έχει αλλοιωθεί ή να μην προέρχεται από τον δηλωμένο χρήστη.")
    else:
        print(f"[OK] Η ψηφιακή υπογραφή του χρήστη '{uploader}' επαληθεύτηκε επιτυχώς.")

    # 42. Αποθήκευση τοπικά
    output_path = Path(f"downloaded_{original_filename}")
    output_path.write_bytes(plaintext)
    print(f"[OK] Το αρχείο αποθηκεύτηκε ως '{output_path}'.")


def show_menu():
    print("\n" + "="*48)
    print("   Secure File Storage — Εργασία 2")
    print("="*48)
    print(" 1. Εγγραφή (με OTP)")
    print(" 2. Σύνδεση")
    print(" 3. Ανέβασμα αρχείου")
    print(" 4. Κατέβασμα αρχείου")
    print(" 9. Admin: Έκδοση OTP")
    print(" 0. Έξοδος")
    print("="*48)


def main():
    """
    ΜΕΡΟΣ Ζ (γ):
    Κύριο CLI loop.
      - Αρχικοποίηση συστήματος
      - Loop: εμφάνιση μενού, ανάγνωση επιλογής
      - Διαχείριση session (logged_in_user = None)
      - Οι επιλογές 3 & 4 απαιτούν ενεργό session
    """
    initialize_system()
    logged_in_user = None

    while True:
        show_menu()
        if logged_in_user:
            print(f"(Συνδεδεμένος ως: {logged_in_user})")
        choice = input("Επιλέξτε λειτουργία: ").strip()

        if choice == "1":
            # Εγγραφή
            username = input("Username: ").strip()
            otp_input = input("OTP: ").strip()
            password = input("Νέος κωδικός: ").strip()
            register_user(username, otp_input, password)

        elif choice == "2":
            # Σύνδεση
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            if authenticate_user(username, password):
                logged_in_user = username

        elif choice == "3":
            # Ανέβασμα (απαιτεί session)
            if not logged_in_user:
                print("[ΣΦΑΛΜΑ] Πρέπει πρώτα να συνδεθείτε.")
                continue
            filepath = input("Διαδρομή αρχείου προς ανέβασμα: ").strip()
            upload_file(logged_in_user, filepath)

        elif choice == "4":
            # Κατέβασμα (απαιτεί session)
            if not logged_in_user:
                print("[ΣΦΑΛΜΑ] Πρέπει πρώτα να συνδεθείτε.")
                continue
            filename = input("Όνομα αρχείου προς κατέβασμα: ").strip()
            download_file(logged_in_user, filename)

        elif choice == "9":
            # Βοηθητική επιλογή για testing: έκδοση OTP από τον admin
            username = input("Username για έκδοση OTP: ").strip()
            admin_issue_otp(username)

        elif choice == "0":
            print("Αντίο!")
            break

        else:
            print("Μη έγκυρη επιλογή, δοκιμάστε ξανά.")


if __name__ == "__main__":
    main()
