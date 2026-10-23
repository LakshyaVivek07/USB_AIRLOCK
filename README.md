# USB Airlock - backend

    pip install -r requirements.txt     # (or: sudo apt install python3-flask)
    python3 make_test_drives.py         # creates fake USB-A / USB-B / USB-C in ./test_usb
    python3 app.py                      # http://localhost:5000

Needs ClamAV: `sudo apt install clamav` then `sudo freshclam` (downloads virus definitions).
API docs for the dashboard: FRONTEND_CONTRACT.md
