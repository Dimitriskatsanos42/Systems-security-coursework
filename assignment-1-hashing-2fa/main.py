"""
main.py
-------
Κύριο πρόγραμμα με διαδραστικό μενού που ενσωματώνει:
  1. Υπολογισμός Hash (Μέρος Α)   - με προαιρετική χρήση salt (Μέρος Δ)
  2. Έλεγχος Ακεραιότητας (Μέρος Α / Δ) - προστατεύεται με 2FA (Μέρος Γ)
  3. Υπολογισμός Εντροπίας (Μέρος Β)
  4. 2FA Authentication (Μέρος Γ) - demo/επίδειξη λειτουργίας
  5. Έξοδος

Εργασία στο μάθημα: Ασφάλεια Συστημάτων
Πανεπιστήμιο Ιωαννίνων - Τμήμα Πληροφορικής & Τηλεπικοινωνιών
"""

import os
import sys

from hashing_utils import (
    SUPPORTED_ALGORITHMS,
    read_file_binary,
    generate_salt,
    compute_hash,
    compute_all_hashes,
    apply_salt,
    save_hash_file,
    check_integrity,
)
from entropy_utils import calculate_entropy, interpret_entropy
from auth_2fa import generate_secret, require_2fa

# Ένα secret key για την τρέχουσα εκτέλεση του προγράμματος (demo σκοπός).
# Σε πραγματική εφαρμογή θα αποθηκευόταν με ασφάλεια (π.χ. κρυπτογραφημένο)
# και θα συνδεόταν με τον συγκεκριμένο χρήστη.
_SESSION_2FA_SECRET = generate_secret()


def ask_filename() -> str:
    return input("Δώστε το όνομα/διαδρομή του αρχείου: ").strip()


def choose_algorithm() -> str:
    print("\nΔιαθέσιμοι αλγόριθμοι:")
    for key, (name, _) in SUPPORTED_ALGORITHMS.items():
        print(f"  {key}. {name}")
    print("  0. Όλοι οι αλγόριθμοι")
    return input("Επιλέξτε αλγόριθμο: ").strip()


def ask_use_salt() -> bool:
    answer = input("Να χρησιμοποιηθεί salt; (ν/ο): ").strip().lower()
    return answer in ("ν", "y", "yes", "ναι")


def menu_compute_hash():
    print("\n=== Υπολογισμός Hash ===")
    filepath = ask_filename()
    try:
        data = read_file_binary(filepath)
    except FileNotFoundError as e:
        print(f"Σφάλμα: {e}")
        return

    use_salt = ask_use_salt()
    salt = generate_salt(16) if use_salt else None
    salted_data = apply_salt(data, salt) if use_salt else data

    choice = choose_algorithm()

    if choice == "0":
        results = compute_all_hashes(salted_data)
        print("\nΑποτελέσματα:")
        for name, digest in results.items():
            print(f"  {name}: {digest}")
        # Αποθήκευση: αποθηκεύουμε το πρώτο διαθέσιμο ως προεπιλογή; Καλύτερα
        # ζητάμε ποιο θα αποθηκευτεί ως το "επίσημο" hash αναφοράς.
        save_choice = input(
            "\nΠοιο από τα παραπάνω να αποθηκευτεί ως hash αναφοράς; (1-4): "
        ).strip()
        if save_choice in SUPPORTED_ALGORITHMS:
            algo_name, _ = SUPPORTED_ALGORITHMS[save_choice]
            hash_file = save_hash_file(filepath, algo_name, results[algo_name], salt)
            print(f"Το hash αποθηκεύτηκε στο: {hash_file}")
    elif choice in SUPPORTED_ALGORITHMS:
        algo_name, _ = SUPPORTED_ALGORITHMS[choice]
        digest = compute_hash(salted_data, choice)
        print(f"\n{algo_name}: {digest}")
        hash_file = save_hash_file(filepath, algo_name, digest, salt)
        print(f"Το hash αποθηκεύτηκε στο: {hash_file}")
    else:
        print("Μη έγκυρη επιλογή.")


def menu_check_integrity():
    print("\n=== Έλεγχος Ακεραιότητας ===")
    print("Αυτή η ενέργεια θεωρείται κρίσιμη και απαιτεί επιβεβαίωση 2FA.")
    if not require_2fa(_SESSION_2FA_SECRET):
        return

    filepath = ask_filename()
    try:
        ok = check_integrity(filepath)
    except FileNotFoundError as e:
        print(f"Σφάλμα: {e}")
        return

    if ok:
        print("✅ Το αρχείο ΔΕΝ έχει τροποποιηθεί.")
    else:
        print("⚠️  Το αρχείο ΕΧΕΙ αλλοιωθεί!")


def menu_entropy():
    print("\n=== Υπολογισμός Εντροπίας ===")
    filepath = ask_filename()
    try:
        data = read_file_binary(filepath)
    except FileNotFoundError as e:
        print(f"Σφάλμα: {e}")
        return

    h = calculate_entropy(data)
    print(f"\nΜέγεθος αρχείου: {len(data)} bytes")
    print(f"Εντροπία (Shannon): {h:.4f} bits/byte")
    print(f"Ερμηνεία: {interpret_entropy(h)}")


def menu_2fa_demo():
    print("\n=== 2FA Authentication (Demo) ===")
    require_2fa(_SESSION_2FA_SECRET)


def print_menu():
    print("\n" + "=" * 50)
    print(" ΔΙΑΔΡΑΣΤΙΚΟ ΜΕΝΟΥ - ΑΣΦΑΛΕΙΑ ΣΥΣΤΗΜΑΤΩΝ")
    print("=" * 50)
    print("1. Υπολογισμός Hash")
    print("2. Έλεγχος Ακεραιότητας")
    print("3. Υπολογισμός Εντροπίας")
    print("4. 2FA Authentication")
    print("5. Έξοδος")


def main():
    while True:
        print_menu()
        choice = input("Επιλέξτε λειτουργία (1-5): ").strip()

        if choice == "1":
            menu_compute_hash()
        elif choice == "2":
            menu_check_integrity()
        elif choice == "3":
            menu_entropy()
        elif choice == "4":
            menu_2fa_demo()
        elif choice == "5":
            print("Έξοδος από το πρόγραμμα. Αντίο!")
            sys.exit(0)
        else:
            print("Μη έγκυρη επιλογή, δοκιμάστε ξανά.")


if __name__ == "__main__":
    main()
