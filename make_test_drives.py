"""Creates three fake USB folders in ./test_usb  (A = clean, B = suspicious, C = mixed).
Everything here is HARMLESS: the "suspicious" files are plain text with scary names.
The EICAR file is the industry-standard antivirus TEST string - it is not a virus,
but every antivirus (including ClamAV) is designed to flag it."""
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent / "test_usb"
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
JPG = b"\xff\xd8\xff\xe0" + b"harmless fake jpeg bytes" * 20
PDF = b"%PDF-1.4\n% harmless fake pdf for testing\n%%EOF\n"
TXT = b"This is a harmless test file.\n"

drives = {
    "USB-A_clean": {
        "vacation_1.jpg": JPG, "vacation_2.jpg": JPG,
        "resume.pdf": PDF, "tax_notes.pdf": PDF, "todo.txt": TXT,
    },
    "USB-B_suspicious": {
        "eicar_test.txt": EICAR.encode(),
        "setup.exe": b"harmless text pretending to be a program\n",
        "photo.jpg.scr": b"harmless text with a disguised name\n",
    },
    "USB-C_mixed": {
        "family_photo.jpg": JPG, "thesis.docx": TXT, "notes.txt": TXT,
        "update_helper.vbs": b"' harmless text, never executed\n",
        "invoice_scan.pdf.exe": b"harmless text with a disguised name\n",
    },
}

if ROOT.exists():
    shutil.rmtree(ROOT)
for drive, files in drives.items():
    d = ROOT / drive
    d.mkdir(parents=True)
    for name, content in files.items():
        (d / name).write_bytes(content)
print(f"Created {len(drives)} fake USB drives in {ROOT}")
