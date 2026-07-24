"""
Βοηθητικό script (δεν αποτελεί μέρος της παράδοσης) που παράγει το report.pdf
από τα περιεχόμενα παρακάτω, χρησιμοποιώντας reportlab.
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Preformatted, Table, TableStyle
)
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# --- Καταχώρηση Unicode γραμματοσειράς (DejaVu Sans) ---
# Η προεπιλεγμένη Helvetica του reportlab ΔΕΝ υποστηρίζει ελληνικούς χαρακτήρες
# (εμφανίζονται ως μαύρα τετράγωνα). Το DejaVu Sans καλύπτει πλήρως το ελληνικό
# αλφάβητο, οπότε το καταχωρούμε ρητά και το χρησιμοποιούμε σε όλα τα styles.
FONT_DIR = "/usr/share/fonts/truetype/dejavu/"
pdfmetrics.registerFont(TTFont("DejaVuSans", FONT_DIR + "DejaVuSans.ttf"))
pdfmetrics.registerFont(TTFont("DejaVuSans-Bold", FONT_DIR + "DejaVuSans-Bold.ttf"))
pdfmetrics.registerFont(TTFont("DejaVuSansMono", FONT_DIR + "DejaVuSansMono.ttf"))
pdfmetrics.registerFontFamily(
    "DejaVuSans", normal="DejaVuSans", bold="DejaVuSans-Bold"
)

styles = getSampleStyleSheet()

title_style = ParagraphStyle("TitleGR", parent=styles["Title"], fontName="DejaVuSans-Bold", fontSize=15, spaceAfter=3, leading=18)
h1 = ParagraphStyle("H1", parent=styles["Heading1"], fontName="DejaVuSans-Bold", fontSize=11.5, spaceBefore=8, spaceAfter=3, textColor=colors.HexColor("#1F4E79"))
h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontName="DejaVuSans-Bold", fontSize=9.5, spaceBefore=5, spaceAfter=2, textColor=colors.HexColor("#2E6DA4"))
body = ParagraphStyle("BodyGR", parent=styles["Normal"], fontName="DejaVuSans", fontSize=8, leading=10.5, alignment=TA_LEFT, spaceAfter=3)
small = ParagraphStyle("SmallGR", parent=styles["Normal"], fontName="DejaVuSans", fontSize=7, leading=9, textColor=colors.HexColor("#444444"))
subtitle = ParagraphStyle("SubtitleGR", parent=styles["Heading3"], fontName="DejaVuSans-Bold", fontSize=11)
code_style = ParagraphStyle("Code", fontName="DejaVuSansMono", fontSize=6.3, leading=7.8, backColor=colors.HexColor("#f2f2f2"))

doc = SimpleDocTemplate(
    "report.pdf", pagesize=A4,
    topMargin=1.1*cm, bottomMargin=1.1*cm, leftMargin=1.5*cm, rightMargin=1.5*cm
)

story = []

story.append(Paragraph("2η Εργασία — Ασφάλεια Συστημάτων", title_style))
story.append(Paragraph("Secure File Storage System — Αναφορά Υλοποίησης", subtitle))
story.append(Paragraph("Πανεπιστήμιο Ιωαννίνων — Τμήμα Πληροφορικής &amp; Τηλεπικοινωνιών", small))
story.append(Spacer(1, 10))

# --- 1. Περιγραφή ανά μέρος ---
story.append(Paragraph("1. Περιγραφή Υλοποίησης ανά Μέρος", h1))

parts = [
    ("Α — Hash &amp; Salt",
     "hash_password()/verify_password() με PBKDF2-HMAC-SHA256 (390.000 επαναλήψεις, "
     "salt 16 bytes, κλειδί 32 bytes) μέσω cryptography. Salt ανά χρήστη + πολλαπλές "
     "επαναλήψεις δυσκολεύουν brute-force/rainbow table."),
    ("Β — OTP &amp; Εγγραφή",
     "register_user() ελέγχει ύπαρξη, μη-χρήση και ορθότητα (case-insensitive) του OTP. "
     "Μετά την επιτυχή χρήση σημειώνεται used=True (μονόχρηστο), υπολογίζεται hash+salt "
     "και δημιουργούνται αυτόματα κλειδιά RSA."),
    ("Γ — Αυθεντικοποίηση",
     "authenticate_user() ανακτά hash/salt και καλεί verify_password(). Σε κάθε αποτυχία "
     "(user δεν υπάρχει ή λάθος κωδικός) εμφανίζεται το ίδιο γενικό μήνυμα, ώστε να μην "
     "είναι δυνατή η απαρίθμηση έγκυρων usernames (user enumeration)."),
    ("Δ — Κλειδιά RSA",
     "Δόθηκε έτοιμο, χρησιμοποιήθηκε αυτούσιο: RSA-2048 ζεύγος αποθηκευμένο σε PEM στο keys/."),
    ("Ε — Anti-Replay / Nonce",
     "is_nonce_valid() ελέγχει αν το nonce έχει ξαναχρησιμοποιηθεί (→ απόρριψη) ή είναι "
     "νέο (→ αποθήκευση με timestamp). Bonus: αυτόματος καθαρισμός nonces &gt;24 ωρών."),
    ("ΣΤ — Κρυπτογράφηση &amp; Υπογραφή",
     "encrypt_file(): τυχαίο κλειδί 32B + nonce 12B, AES-256-GCM (authenticated "
     "encryption). sign_data(): RSA-PSS/SHA-256 πάνω στο (data+nonce), ώστε η υπογραφή να "
     "δεσμεύεται και στο συγκεκριμένο αίτημα, όχι μόνο στο περιεχόμενο."),
    ("Ζ — Upload / Download / CLI",
     "upload_file(): read → nonce → sign → anti-replay check → encrypt → save (.enc + "
     "metadata .json σε base64). download_file(): αντίστροφη ροή + επαλήθευση υπογραφής "
     "πριν την τοπική αποθήκευση. Το CLI διατηρεί session (logged_in_user) — Upload/"
     "Download απαιτούν ενεργή σύνδεση."),
]

for name, desc in parts:
    story.append(Paragraph(f"<b>{name}:</b> {desc}", body))

# --- 2. Παράδειγμα εκτέλεσης ---
story.append(Paragraph("2. Παράδειγμα Εκτέλεσης (πραγματικό transcript)", h1))
story.append(Paragraph(
    "Πραγματική εκτέλεση: έκδοση OTP → αποτυχημένη εγγραφή (λάθος OTP) → επιτυχής εγγραφή → "
    "αποτυχημένη/επιτυχής σύνδεση → upload → download με επαλήθευση υπογραφής → replay attack.",
    body))

transcript = """>>> admin_issue_otp('bob')
[ADMIN] OTP για 'bob': 93AF0752

>>> register_user('bob', <λάθος OTP>, 'Str0ngP@ss')
[ΣΦΑΛΜΑ] Λανθασμένο OTP.

>>> register_user('bob', '93AF0752', 'Str0ngP@ss')
[OK] Ο χρήστης 'bob' εγγράφηκε επιτυχώς.

>>> authenticate_user('bob', 'WrongPassword')
[ΣΦΑΛΜΑ] Λάθος στοιχεία σύνδεσης.

>>> authenticate_user('bob', 'Str0ngP@ss')
[OK] Επιτυχής σύνδεση ως 'bob'.

>>> upload_file('bob', 'confidential.txt')
[OK] Το αρχείο 'confidential.txt' ανέβηκε και κρυπτογραφήθηκε επιτυχώς.

>>> download_file('bob', 'confidential.txt')
[OK] Η ψηφιακή υπογραφή του χρήστη 'bob' επαληθεύτηκε επιτυχώς.
[OK] Το αρχείο αποθηκεύτηκε ως 'downloaded_confidential.txt'.

>>> --- Προσομοίωση Replay Attack ---
>>> is_nonce_valid('940e24...f51')   # 1η χρήση -> True

>>> is_nonce_valid('940e24...f51')   # 2η χρήση (replay)
[ΠΡΟΕΙΔΟΠΟΙΗΣΗ] Εντοπίστηκε πιθανή Replay Attack — το nonce έχει ήδη χρησιμοποιηθεί!"""

story.append(Preformatted(transcript, code_style))

story.append(Paragraph(
    "<b>Σημείωση:</b> Επισυνάψτε επίσης πραγματικά screenshots από την εκτέλεση του CLI "
    "(python secure_storage.py): εγγραφή με OTP, σύνδεση, upload, download, απόρριψη replay.",
    small))

# --- 3. Ανάλυση ασφάλειας ---
story.append(Paragraph("3. Ανάλυση Μηχανισμών Ασφάλειας", h1))

analysis_rows = [
    ["Μηχανισμός", "Τι προστατεύει", "Πώς"],
    ["PBKDF2 + Salt", "Επιθέσεις brute-force / rainbow table στους κωδικούς",
     "390.000 επαναλήψεις SHA-256 + μοναδικό salt ανά χρήστη"],
    ["OTP μονής χρήσης", "Μη εξουσιοδοτημένη εγγραφή λογαριασμών",
     "Το OTP επισημαίνεται used=True μετά την πρώτη επιτυχή χρήση"],
    ["Γενικό μήνυμα σφάλματος", "User enumeration κατά τη σύνδεση",
     "Το ίδιο μήνυμα για «δεν υπάρχει» και «λάθος κωδικός»"],
    ["AES-256-GCM", "Εμπιστευτικότητα + ακεραιότητα αρχείων",
     "Authenticated encryption· νέο τυχαίο κλειδί/nonce ανά αρχείο"],
    ["RSA-PSS + SHA-256", "Μη-αποποίηση (non-repudiation) και ακεραιότητα ανεβασμένου αρχείου",
     "Ψηφιακή υπογραφή πάνω στο (data + nonce) με το ιδιωτικό κλειδί του χρήστη"],
    ["Nonce / Anti-Replay", "Replay attacks (επανάληψη παλιού έγκυρου αιτήματος)",
     "Κάθε nonce καταγράφεται· επανάχρησή του απορρίπτεται"],
]
tbl = Table(analysis_rows, colWidths=[3.4*cm, 5.4*cm, 9.2*cm])
tbl.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F4E79")),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("FONTSIZE", (0, 0), (-1, -1), 6.3),
    ("FONTNAME", (0, 0), (-1, 0), "DejaVuSans-Bold"),
    ("FONTNAME", (0, 1), (-1, -1), "DejaVuSans"),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f8fb")]),
    ("TOPPADDING", (0, 0), (-1, -1), 2.5),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
]))
story.append(tbl)

story.append(Spacer(1, 4))
story.append(Paragraph(
    "<b>Nonce στην υπογραφή:</b> αν η υπογραφή κάλυπτε μόνο το περιεχόμενο του αρχείου, "
    "ένας επιτιθέμενος θα μπορούσε να υποκλέψει ένα παλιό έγκυρο ζεύγος (δεδομένα+υπογραφή) "
    "και να το ξαναστείλει — η υπογραφή θα παρέμενε έγκυρη. Επειδή το nonce συμπεριλαμβάνεται "
    "στο υπογεγραμμένο payload, κάθε αίτημα δένεται με ένα μοναδικό, μονόχρηστο αναγνωριστικό.",
    body))

story.append(Paragraph(
    "<b>AEAD (AES-GCM) αντί απλού AES-CBC:</b> το GCM παρέχει ταυτόχρονα εμπιστευτικότητα "
    "και ακεραιότητα. Τροποποιώντας πειραματικά ένα byte ενός αποθηκευμένου .enc αρχείου, "
    "η decrypt_file() απέτυχε με σφάλμα επαλήθευσης, όπως αναμενόταν, αντί να επιστρέψει "
    "αθόρυβα λανθασμένα δεδομένα.", body))

# --- 4. Συμπεράσματα ---
story.append(Paragraph("4. Συμπεράσματα", h1))
story.append(Paragraph(
    "Η εργασία συνδύασε πρακτικά πολλαπλούς μηχανισμούς ασφάλειας σε ένα ενιαίο pipeline: "
    "ασφαλή αποθήκευση κωδικών (PBKDF2+salt), ελεγχόμενη εγγραφή μέσω μονόχρηστου OTP, "
    "συμμετρική κρυπτογράφηση με ακεραιότητα (AES-GCM), ασύμμετρη ψηφιακή υπογραφή για "
    "μη-αποποίηση (RSA-PSS), και προστασία από replay attacks μέσω nonce. Κάθε επίπεδο "
    "καλύπτει διαφορετική απειλή, δείχνοντας πώς σχεδιάζεται ένα ρεαλιστικό σύστημα ασφαλούς "
    "αποθήκευσης αρχείων.", body))

doc.build(story)
print("report.pdf δημιουργήθηκε επιτυχώς.")
