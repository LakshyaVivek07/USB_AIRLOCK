# USB Airlock - Frontend Contract (for the dashboard developer)

The backend is a Flask server. You only talk to it with `fetch()` and JSON. You do **not** need to touch Python.

## How to run things on your side
- Your files live in `frontend/`. The backend serves `frontend/index.html` at `http://localhost:5000/`
  so you can use `const API = ""` and there are no CORS problems.
- `frontend/index.html` already in the repo is a **plain reference page** that uses every endpoint.
  Restyle / replace it freely. Keep the logic of the `fetch` calls.
- If you develop on your own laptop and the backend runs in the VM: ask the backend dev to set up
  VirtualBox port forwarding (host 5000 -> guest 5000), then use `const API = "http://localhost:5000"`.

## The 3 golden rules
1. **Never put file names into the page with `innerHTML`.** A malicious USB can have a file called
   `<img src=x onerror=alert(1)>.txt`. Always use `element.textContent = name`.
2. **Scanning takes 10-30 seconds** (ClamAV loads its database). Show a spinner and disable the Scan button.
3. **Show backend messages as they are** (`message`, `explanation`, `error`). They are written to be read by humans/judges.

## Endpoints
All responses are JSON. Errors look like `{"error": "text"}` with HTTP 4xx.

### GET /api/health
`{"status":"ok","time":"...","clamav":{"available":true,"version":"ClamAV 1.x"}}`
Use it for a small "ClamAV: active" indicator in the header.

### GET /api/devices
`{"devices":[{"name":"sdb1","label":"MYUSB","size":"7.5G","mountpoint":"/media/user/MYUSB","demo":false}]}`
Fill a dropdown. `demo:true` entries are fake test drives (label starts with "DEMO").

### POST /api/scan      body: `{"source": "<mountpoint from /api/devices>"}`
Returns the full scan report (below). Takes 10-30 s.

### GET /api/scans/<scan_id>      -> same report, use it to refresh after approving
### GET /api/scans                -> `{"scans":[{scan_id, source, started_at, summary}]}`

### Scan report shape
```json
{
  "scan_id": "20261023-153034-989762",
  "source": "/media/user/MYUSB",
  "started_at": "2026-10-23 15:30:34",
  "clamav_status": "ok",            // "ok" | "unavailable" | "error"  -> if not "ok" show a yellow warning banner
  "clamav_message": "ClamAV scan completed.",
  "summary": {"total":5,"low":3,"medium":1,"high":1,"infected":0,"approved":0},
  "files": [{
    "id": "f2",                      // use this id in approve / quarantine calls
    "name": "invoice_scan.pdf.exe",
    "rel_path": "invoice_scan.pdf.exe",
    "ext": ".exe",
    "size": 36,                      // bytes
    "sha256": "ab12...",             // null if skipped
    "risk_score": 70,
    "risk_level": "HIGH",            // "LOW" | "MEDIUM" | "HIGH"  -> badge colour green / amber / red
    "reasons": ["..."],
    "explanation": "Do not trust this file: ...",   // the plain-language sentence to display
    "clamav": {"status": "clean|infected|not_scanned", "signature": null},
    "status": "quarantined",         // "quarantined" | "approved" | "skipped"
    "note": null
  }]
}
```

### POST /api/approve      body: `{"scan_id": "...", "file_ids": ["f1","f3"], "force": false}`
Moves the files from quarantine to the trusted folder. Returns
`{"results":[{"id","name","ok":true|false,"message"}], "summary":{...}}`.
Per-file `ok:false` means the backend refused. Show the `message` next to that file. Policy:
- ClamAV-infected file -> **never** approvable (even with force)
- HIGH risk -> refused unless `force:true` (suggest a "Are you sure?" confirm dialog, then resend with force)
- If `clamav_status != "ok"` -> refused unless `force:true`

### POST /api/quarantine  body: `{"scan_id": "...", "file_ids": ["f2"]}`
Records "kept in quarantine" in the audit log. Returns `{"results":[{id,name,ok,message}]}`.

### GET /api/audit?limit=50
`{"entries":[{"time":"2026-10-23 15:30:34","event":"APPROVED","message":"thesis.docx: Moved to trusted folder."}]}` newest first.
Events: SCAN_STARTED, SCAN_COMPLETE, APPROVED, APPROVE_REFUSED, QUARANTINED, WARNING, BLOCKED.

## Screens the demo needs (Demo Day script in the prep guide)
1. Header: title, ClamAV indicator, drive dropdown, **Scan** button, spinner.
2. Summary strip: counts of LOW / MEDIUM / HIGH.
3. File table: checkbox, name, risk badge (+score), explanation, short hash. Select-all checkbox.
4. Buttons: **Transfer / Approve selected**, **Keep selected in Quarantine**.
5. Audit log panel (refresh it after every action).
6. After approve: refresh with `GET /api/scans/<id>` - approved rows show as "approved" and their checkbox is disabled.
