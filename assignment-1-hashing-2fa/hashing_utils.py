"""
hashing_utils.py
-----------------
Μέρος Α: Υπολογισμός Hash και Έλεγχος Ακεραιότητας
Μέρος Δ:  Ενσωμάτωση Salt

Παρέχει συναρτήσεις για:
- Ανάγνωση αρχείου σε binary μορφή
- Υπολογισμό MD5, SHA-1, SHA-256, SHA-3(Keccak) hashes
- Αποθήκευση hash (με προαιρετικό salt) σε αρχείο .hash
- Έλεγχο ακεραιότητας αρχείου (με ή χωρίς salt)
"""

import hashlib
import os

# Διαθέσιμοι αλγόριθμοι κατακερματισμού.
# Σημείωση: το hashlib.sha3_256 υλοποιεί το πρότυπο NIST SHA-3 (FIPS 202).
# Δεν είναι bit-for-bit ταυτόσημο με το "αρχικό" Keccak (πριν την τυποποίηση),
# αλλά είναι αυτό που αναφέρεται σήμερα ως "SHA-3 / Keccak" στην πράξη.
SUPPORTED_ALGORITHMS = {
    "1": ("MD5", hashlib.md5),
    "2": ("SHA-1", hashlib.sha1),
    "3": ("SHA-256", hashlib.sha256),
    "4": ("SHA3-256 (Keccak)", hashlib.sha3_256),
}


def read_file_binary(filepath: str) -> bytes:
    """Διαβάζει ένα αρχείο σε δυαδική (binary) μορφή και επιστρέφει τα bytes του."""
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Το αρχείο '{filepath}' δεν βρέθηκε.")
    with open(filepath, "rb") as f:
        return f.read()


def generate_salt(size: int = 16) -> bytes:
    """Δημιουργεί ένα κρυπτογραφικά ασφαλές τυχαίο salt (προεπιλογή 16 bytes)."""
    return os.urandom(size)


def compute_hash(data: bytes, algo_key: str) -> str:
    """Υπολογίζει το hash (hex) των δεδομένων με τον δοσμένο αλγόριθμο."""
    name, func = SUPPORTED_ALGORITHMS[algo_key]
    return func(data).hexdigest()


def compute_all_hashes(data: bytes) -> dict:
    """Υπολογίζει το hash των δεδομένων με ΟΛΟΥΣ τους διαθέσιμους αλγόριθμους."""
    return {name: func(data).hexdigest() for name, func in SUPPORTED_ALGORITHMS.values()}


def apply_salt(data: bytes, salt: bytes) -> bytes:
    """Ενσωματώνει το salt στα δεδομένα πριν τον υπολογισμό του hash (salt + data)."""
    return salt + data


def save_hash_file(filepath: str, algo_name: str, hash_value: str, salt: bytes | None = None) -> str:
    """
    Αποθηκεύει το hash (και προαιρετικά το salt σε hex) σε αρχείο <filename>.hash
    Μορφή αρχείου:
        algorithm=<όνομα αλγόριθμου>
        hash=<hex digest>
        salt=<hex salt>          (μόνο αν χρησιμοποιήθηκε salt)
    """
    hash_filepath = filepath + ".hash"
    with open(hash_filepath, "w") as f:
        f.write(f"algorithm={algo_name}\n")
        f.write(f"hash={hash_value}\n")
        if salt is not None:
            f.write(f"salt={salt.hex()}\n")
    return hash_filepath


def load_hash_file(filepath: str) -> dict:
    """Διαβάζει το αποθηκευμένο .hash αρχείο και επιστρέφει dict με algorithm/hash/salt."""
    hash_filepath = filepath + ".hash"
    if not os.path.isfile(hash_filepath):
        raise FileNotFoundError(
            f"Δεν βρέθηκε αποθηκευμένο hash για το '{filepath}'. "
            f"Πρέπει πρώτα να υπολογίσετε και να αποθηκεύσετε το hash."
        )
    result = {}
    with open(hash_filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, value = line.split("=", 1)
            result[key] = value
    return result


def _algo_key_from_name(name: str) -> str:
    for key, (algo_name, _) in SUPPORTED_ALGORITHMS.items():
        if algo_name == name:
            return key
    raise ValueError(f"Άγνωστος αλγόριθμος στο αρχείο hash: {name}")


def check_integrity(filepath: str) -> bool:
    """
    Επαναϋπολογίζει το hash του αρχείου (χρησιμοποιώντας το ίδιο salt αν υπήρχε
    κατά την αποθήκευση) και το συγκρίνει με το αποθηκευμένο hash.
    Επιστρέφει True αν το αρχείο ΔΕΝ έχει τροποποιηθεί, False αν έχει αλλοιωθεί.
    """
    stored = load_hash_file(filepath)
    algo_key = _algo_key_from_name(stored["algorithm"])
    data = read_file_binary(filepath)

    if "salt" in stored:
        salt = bytes.fromhex(stored["salt"])
        data = apply_salt(data, salt)

    new_hash = compute_hash(data, algo_key)
    return new_hash == stored["hash"]
