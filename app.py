"""
USB AIRLOCK - backend  (Team Ex Nihilo)

What this program does, in one breath:
  1. Takes a mounted USB folder and COPIES every file into a quarantine folder
     (the USB itself is only ever read, never modified, nothing is ever executed).
  2. Hashes each file (SHA-256) and scans the whole quarantine folder with ClamAV.
  3. Gives each file a Risk Score from OUR OWN rules (see RULES section below).
  4. The dashboard asks us to move chosen files from quarantine -> trusted folder.
  5. Everything that happens is written to an audit log.

Run:   python3 app.py        (then open http://localhost:5000)
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

# ----------------------------------------------------------------------------
# 1. CONFIG - folders and limits
# ----------------------------------------------------------------------------
BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
QUARANTINE = DATA / "quarantine"     # files land here first (locked down)
TRUSTED = DATA / "trusted"           # only approved files end up here
SCANS = DATA / "scans"               # one JSON report per scan
AUDIT_LOG = DATA / "audit.log"       # one JSON line per event
DEMO_ROOT = BASE / "test_usb"        # fake USB folders for testing without hardware
FRONTEND = BASE / "frontend"

MAX_FILE_MB = int(os.environ.get("AIRLOCK_MAX_FILE_MB", "100"))
CLAMSCAN_TIMEOUT = 600  # seconds

# We only agree to scan folders under these roots (stops someone asking us
# to "scan" /etc or /home). USBs mount under /media or /run/media on Ubuntu.
ALLOWED_ROOTS = [Path("/media"), Path("/run/media"), Path("/mnt"), DEMO_ROOT]
for extra in os.environ.get("AIRLOCK_EXTRA_ROOTS", "").split(":"):
    if extra.strip():
        ALLOWED_ROOTS.append(Path(extra.strip()))

for d in (QUARANTINE, TRUSTED, SCANS):
    d.mkdir(parents=True, exist_ok=True)

# ----------------------------------------------------------------------------
# 2. RULES - THE PRODUCT'S "BRAIN". Edit the numbers here; nothing else needed.
#    Everything is rule-based and explainable. No AI makes a detection decision.
# ----------------------------------------------------------------------------
POINTS_CLAMAV = 100        # ClamAV says it's a known threat
POINTS_EXECUTABLE = 40     # file type that can run code
POINTS_DOUBLE_EXT = 30     # looks like "invoice.pdf.exe" (disguised program)
POINTS_UNKNOWN = 10        # file type we don't recognise

EXECUTABLE_EXT = {
    # from our prep guide:
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".scr",
    # extra common ones (delete any you don't want to defend):
    ".com", ".msi", ".js", ".jse", ".wsf", ".hta", ".lnk", ".jar", ".dll", ".sh",
}
KNOWN_SAFE_EXT = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".pdf", ".txt", ".md",
    ".csv", ".json", ".rtf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".odt", ".mp3", ".wav", ".mp4", ".mov", ".avi", ".mkv", ".zip",
}
# Score bands:  0-20 LOW | 21-50 MEDIUM | 51+ HIGH
LOW_MAX, MEDIUM_MAX = 20, 50


def score_file(name, clam_signature, clam_ran):
    """Return (score, level, reasons[]) for one file. Pure rules, easy to explain."""
    score, reasons = 0, []
    suffixes = [s.lower() for s in Path(name).suffixes]
    ext = suffixes[-1] if suffixes else ""

    if clam_signature:
        score += POINTS_CLAMAV
        reasons.append(f"ClamAV antivirus detected a known threat ({clam_signature}).")
    if ext in EXECUTABLE_EXT:
        score += POINTS_EXECUTABLE
        reasons.append(f"'{ext}' files can run code on your computer.")
        if len(suffixes) >= 2 and suffixes[-2] in KNOWN_SAFE_EXT:
            score += POINTS_DOUBLE_EXT
            reasons.append(
                f"The name pretends to be a '{suffixes[-2]}' file but is really a '{ext}' program."
            )
    elif ext not in KNOWN_SAFE_EXT:
        score += POINTS_UNKNOWN
        reasons.append("Unrecognised file type.")

    level = "LOW" if score <= LOW_MAX else "MEDIUM" if score <= MEDIUM_MAX else "HIGH"
    return score, level, reasons


def explain(level, reasons, clam_ran):
    """Plain-language one-liner. Template-based on purpose (works offline).
    This is the ONLY place an LLM could be plugged in later - and it would only
    rephrase a decision already made by the rules above, never make one."""
    if level == "LOW":
        if clam_ran:
            return "Looks safe: a common file type and nothing flagged by the antivirus scan."
        return "No risky traits found by our rules, but the antivirus scan did not run, so this is only a partial check."
    prefix = "Review before trusting: " if level == "MEDIUM" else "Do not trust this file: "
    return prefix + " ".join(reasons)


# ----------------------------------------------------------------------------
# 3. SMALL HELPERS - audit log, hashing, path safety
# ----------------------------------------------------------------------------
_lock = threading.Lock()          # protects the audit log and approvals
_scan_lock = threading.Lock()     # only one scan at a time
JOBS = {}                         # background scans, by job id (progress + cancel flag)
SCAN_ID_RE = re.compile(r"^\d{8}-\d{6}-[a-f0-9]{6}$")


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def audit(event, message, **extra):
    entry = {"time": now(), "event": event, "message": message, **extra}
    with _lock, open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def source_allowed(path: Path):
    return any(path == root or root in path.parents for root in ALLOWED_ROOTS)


def load_scan(scan_id):
    if not SCAN_ID_RE.match(scan_id or ""):       # blocks path tricks like ../../
        return None
    p = SCANS / f"{scan_id}.json"
    return json.loads(p.read_text()) if p.exists() else None


def save_scan(scan):
    (SCANS / f"{scan['scan_id']}.json").write_text(json.dumps(scan, indent=2))


def summarize(files):
    return {
        "total": len(files),
        "low": sum(f["risk_level"] == "LOW" for f in files),
        "medium": sum(f["risk_level"] == "MEDIUM" for f in files),
        "high": sum(f["risk_level"] == "HIGH" for f in files),
        "infected": sum(f["clamav"]["status"] == "infected" for f in files),
        "approved": sum(f["status"] == "approved" for f in files),
    }


# ----------------------------------------------------------------------------
# 4. CLAMAV - we call the existing free antivirus, we do not build our own
# ----------------------------------------------------------------------------
def clamav_version():
    try:
        r = subprocess.run(["clamscan", "--version"], capture_output=True, text=True, timeout=20)
        return r.stdout.strip() or None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


class ScanCancelled(Exception):
    """Raised when the user presses Cancel during a scan."""


def run_clamscan(folder: Path, job=None):
    """Scan a whole folder in ONE call (ClamAV takes ~10-20s just to load its
    database, so we never call it once per file). We read its output line by
    line, which lets the dashboard show progress and lets the user cancel.
    Returns (status, message, {absolute_path: signature})."""
    if not shutil.which("clamscan"):
        return "unavailable", "ClamAV (clamscan) is not installed.", {}
    cmd = ["clamscan", "-r", "--no-summary", str(folder)]
    if shutil.which("stdbuf"):
        cmd = ["stdbuf", "-oL"] + cmd              # line-buffered, so progress is live
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, errors="replace")
    state = {"timed_out": False}

    def watchdog():                                 # enforces timeout + cancel
        started = time.time()
        while proc.poll() is None:
            if job is not None and job["cancel"]:
                proc.terminate()
                return
            if time.time() - started > CLAMSCAN_TIMEOUT:
                state["timed_out"] = True
                proc.kill()
                return
            time.sleep(0.3)

    threading.Thread(target=watchdog, daemon=True).start()

    found, tail = {}, []
    for line in proc.stdout:
        line = line.rstrip("\n")
        if line.endswith(" FOUND"):
            path, _, rest = line.rpartition(": ")
            found[path] = rest[: -len(" FOUND")]
        tail = (tail + [line])[-5:]
        if job is not None and (line.endswith(": OK") or line.endswith(" FOUND")
                                or line.endswith(": Empty file")):
            job["scanned"] += 1                     # one more file checked
    proc.wait()

    if job is not None and job["cancel"]:
        return "cancelled", "Scan cancelled.", found
    if state["timed_out"]:
        return "error", "ClamAV timed out.", found
    if proc.returncode in (0, 1):                   # 0 = clean, 1 = threats found
        return "ok", "ClamAV scan completed.", found
    return "error", ("\n".join(tail) or "ClamAV failed.")[:300], found


# ----------------------------------------------------------------------------
# 5. THE PIPELINE - USB folder -> quarantine copy -> hash -> ClamAV -> score
# ----------------------------------------------------------------------------
def run_scan(source: Path, job=None):
    """The whole pipeline. `job` is optional: when the dashboard starts a scan in
    the background we pass a dict that we keep updating with progress, and we
    watch it for a cancel request."""
    scan_id = datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    qdir = QUARANTINE / scan_id
    qdir.mkdir(parents=True)
    audit("SCAN_STARTED", f"Scan {scan_id} started on {source}", scan_id=scan_id)

    def check_cancel():
        if job is not None and job["cancel"]:
            shutil.rmtree(qdir, ignore_errors=True)         # nothing half-scanned is kept
            audit("SCAN_CANCELLED", f"Scan {scan_id} cancelled by the user; quarantine copy deleted",
                  scan_id=scan_id)
            raise ScanCancelled()

    # --- Step A: list the files (so we know the total), then copy them -------
    todo = []
    for root, _dirs, names in os.walk(source, followlinks=False):
        for name in sorted(names):
            todo.append(Path(root) / name)
    if job is not None:
        job.update(total=len(todo), phase="copying")

    records = []
    for src in todo:
        check_cancel()
        rel = src.relative_to(source)
        rec = {"name": src.name, "rel_path": str(rel), "ext": src.suffix.lower(),
               "size": 0, "sha256": None, "status": "quarantined", "note": None}
        try:
            if src.is_symlink():
                rec.update(status="skipped", note="Symbolic link skipped (could point at the host system).")
            else:
                size = src.stat().st_size
                rec["size"] = size
                if size > MAX_FILE_MB * 1024 * 1024:
                    rec.update(status="skipped", note=f"Larger than {MAX_FILE_MB} MB, not scanned.")
                else:
                    dest = qdir / rel
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(src, dest)      # copies data only, never runs it
                    os.chmod(dest, 0o600)           # no execute bit, owner-only
                    rec["sha256"] = sha256_of(dest)
        except OSError as e:
            rec.update(status="skipped", note=f"Could not read file: {e.strerror}")
        records.append(rec)
        if job is not None:
            job["copied"] += 1

    # --- Step B: ClamAV on the quarantine copy -------------------------------
    if job is not None:
        job["phase"] = "scanning"
    clam_status, clam_msg, found = run_clamscan(qdir, job)
    check_cancel()
    clam_ran = clam_status == "ok"

    # --- Step C: score every file --------------------------------------------
    files = []
    for i, rec in enumerate(records, start=1):
        sig = found.get(str(qdir / rec["rel_path"]))
        if rec["status"] == "skipped":
            score, level, reasons = 0, "MEDIUM", [rec["note"]]   # unscanned = not LOW
            clam = {"status": "not_scanned", "signature": None}
        else:
            score, level, reasons = score_file(rec["name"], sig, clam_ran)
            clam = {"status": "infected" if sig else ("clean" if clam_ran else "not_scanned"),
                    "signature": sig}
        rec.update(id=f"f{i}", risk_score=score, risk_level=level, reasons=reasons,
                   explanation=explain(level, reasons, clam_ran) if rec["status"] != "skipped" else rec["note"],
                   clamav=clam)
        files.append(rec)

    scan = {"scan_id": scan_id, "source": str(source), "started_at": now(),
            "clamav_status": clam_status, "clamav_message": clam_msg,
            "files": files, "summary": summarize(files)}
    save_scan(scan)
    s = scan["summary"]
    audit("SCAN_COMPLETE",
          f"Scan {scan_id}: {s['total']} files - {s['low']} low, {s['medium']} medium, "
          f"{s['high']} high, {s['infected']} flagged by ClamAV", scan_id=scan_id)
    if not clam_ran:
        audit("WARNING", f"ClamAV did not run ({clam_msg}). Results are rule-based only.", scan_id=scan_id)
    return scan


# ----------------------------------------------------------------------------
# 6. WEB API - this is what the dashboard talks to
# ----------------------------------------------------------------------------
app = Flask(__name__, static_folder=None)


@app.after_request
def add_cors(resp):          # lets a dashboard served from another address call us
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


def err(message, code=400):
    return jsonify({"error": message}), code


@app.get("/api/health")
def health():
    v = clamav_version()
    return jsonify({"status": "ok", "time": now(),
                    "clamav": {"available": v is not None, "version": v}})


def list_removable_devices():
    """Real removable drives that Ubuntu has mounted right now (uses `lsblk`)."""
    found = []
    try:
        out = subprocess.run(["lsblk", "-J", "-o", "NAME,LABEL,SIZE,RM,TRAN,MOUNTPOINT,FSTYPE"],
                             capture_output=True, text=True, timeout=10)
        tree = json.loads(out.stdout)
    except Exception:
        tree = {"blockdevices": []}

    def walk(node, inherited_removable):
        removable = inherited_removable or node.get("rm") in (True, 1, "1", "true") or node.get("tran") == "usb"
        mp = node.get("mountpoint") or (node.get("mountpoints") or [None])[0]
        if removable and mp and mp not in ("/", "[SWAP]"):
            found.append({"name": node.get("name"), "label": node.get("label") or node.get("name"),
                          "size": node.get("size"), "mountpoint": mp, "demo": False})
        for child in node.get("children") or []:
            walk(child, removable)

    for dev in tree.get("blockdevices", []):
        walk(dev, False)
    return found


@app.get("/api/devices")
def devices():
    found = list_removable_devices()
    if DEMO_ROOT.exists():                       # fake drives for testing
        for d in sorted(p for p in DEMO_ROOT.iterdir() if p.is_dir()):
            found.append({"name": d.name, "label": f"DEMO {d.name}", "size": None,
                          "mountpoint": str(d), "demo": True})
    return jsonify({"devices": found})


def device_watcher(interval=2.0):
    """Background thread: checks every 2 s which USB drives are mounted and writes
    DEVICE_INSERTED / DEVICE_REMOVED to the audit log when that list changes."""
    import time
    known = {d["mountpoint"]: d for d in list_removable_devices()}
    while True:
        time.sleep(interval)
        current = {d["mountpoint"]: d for d in list_removable_devices()}
        for mp, d in current.items():
            if mp not in known:
                audit("DEVICE_INSERTED", f"USB drive inserted: {d['label']} ({d['size']}) at {mp}")
        for mp, d in known.items():
            if mp not in current:
                audit("DEVICE_REMOVED", f"USB drive removed: {d['label']} (was at {mp})")
        known = current


def check_source(body):
    """Validate the folder the dashboard wants scanned. Returns (path, error_response)."""
    raw = body.get("source", "")
    if not raw:
        return None, err("Missing 'source' (folder path of the USB).")
    source = Path(raw).resolve()
    if not source.is_dir():
        return None, err(f"'{raw}' is not a folder.")
    if not source_allowed(source):
        audit("BLOCKED", f"Refused to scan {source} (outside allowed locations)")
        return None, err("That location is not allowed. Only removable-drive mount points can be scanned.", 403)
    return source, None


@app.post("/api/scan")
def scan_endpoint():
    """Simple version: waits until the scan is finished, then returns the report."""
    source, bad = check_source(request.get_json(silent=True) or {})
    if bad:
        return bad
    if not _scan_lock.acquire(blocking=False):
        return err("Another scan is already running. Please wait.", 409)
    try:
        return jsonify(run_scan(source))
    finally:
        _scan_lock.release()


@app.post("/api/scan/start")
def scan_start():
    """Dashboard version: starts the scan in the background and returns at once."""
    source, bad = check_source(request.get_json(silent=True) or {})
    if bad:
        return bad
    if not _scan_lock.acquire(blocking=False):
        return err("Another scan is already running. Please wait.", 409)
    job_id = uuid.uuid4().hex[:12]
    job = {"job_id": job_id, "state": "running", "phase": "copying", "total": 0,
           "copied": 0, "scanned": 0, "cancel": False, "scan_id": None, "error": None}
    JOBS[job_id] = job

    def worker():
        try:
            scan = run_scan(source, job)
            job.update(state="finished", scan_id=scan["scan_id"])
        except ScanCancelled:
            job["state"] = "cancelled"
        except Exception as e:                      # never leave the dashboard hanging
            job.update(state="error", error=str(e))
            audit("ERROR", f"Scan failed: {e}")
        finally:
            _scan_lock.release()

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({"job_id": job_id}), 202


@app.get("/api/scan/status/<job_id>")
def scan_status(job_id):
    job = JOBS.get(job_id)
    if not job:
        return err("Unknown scan job.", 404)
    total = job["total"]
    done = total if job["state"] == "finished" else min(total, (job["copied"] + job["scanned"]) // 2)
    return jsonify({"state": job["state"], "phase": job["phase"], "done": done, "total": total,
                    "scan_id": job["scan_id"], "error": job["error"]})


@app.post("/api/scan/cancel/<job_id>")
def scan_cancel(job_id):
    job = JOBS.get(job_id)
    if not job:
        return err("Unknown scan job.", 404)
    if job["state"] == "running":
        job["cancel"] = True
    return jsonify({"ok": True, "state": job["state"]})


@app.get("/api/scans")
def list_scans():
    items = []
    for p in sorted(SCANS.glob("*.json"), reverse=True):
        s = json.loads(p.read_text())
        items.append({k: s[k] for k in ("scan_id", "source", "started_at", "summary")})
    return jsonify({"scans": items})


@app.get("/api/scans/<scan_id>")
def get_scan(scan_id):
    scan = load_scan(scan_id)
    return jsonify(scan) if scan else err("Scan not found.", 404)


def _pick(scan, ids):
    wanted = set(ids or [])
    return [f for f in scan["files"] if f["id"] in wanted]


@app.post("/api/approve")
def approve():
    body = request.get_json(silent=True) or {}
    scan = load_scan(body.get("scan_id"))
    if not scan:
        return err("Scan not found.", 404)
    force = bool(body.get("force", False))
    picked = _pick(scan, body.get("file_ids"))
    if not picked:
        return err("No matching file_ids.")

    results = []
    with _lock:
        for f in picked:
            res = {"id": f["id"], "name": f["name"], "ok": False, "message": ""}
            qpath = QUARANTINE / scan["scan_id"] / f["rel_path"]
            if f["status"] == "approved":
                res["message"] = "Already approved."
            elif f["status"] == "skipped":
                res["message"] = "File was skipped during scan and cannot be approved."
            elif f["clamav"]["status"] == "infected":
                res["message"] = "BLOCKED: ClamAV detected a threat. This can never be approved."
            elif f["risk_level"] == "HIGH" and not force:
                res["message"] = "BLOCKED: HIGH risk. Send force=true to override."
            elif scan["clamav_status"] != "ok" and not force:
                res["message"] = "BLOCKED: ClamAV did not run for this scan. Send force=true to override."
            elif not qpath.exists():
                res["message"] = "File missing from quarantine."
            elif sha256_of(qpath) != f["sha256"]:
                res["message"] = "BLOCKED: file changed since it was scanned (hash mismatch)."
            else:
                dest = TRUSTED / scan["scan_id"] / f["rel_path"]
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(qpath), str(dest))
                os.chmod(dest, 0o644)
                f["status"] = "approved"
                res.update(ok=True, message="Moved to trusted folder.", trusted_path=str(dest))
            results.append(res)
        scan["summary"] = summarize(scan["files"])
        save_scan(scan)
    for r in results:
        audit("APPROVED" if r["ok"] else "APPROVE_REFUSED",
              f"{r['name']}: {r['message']}", scan_id=scan["scan_id"], file_id=r["id"])
    return jsonify({"results": results, "summary": scan["summary"]})


@app.post("/api/quarantine")
def keep_quarantined():
    body = request.get_json(silent=True) or {}
    scan = load_scan(body.get("scan_id"))
    if not scan:
        return err("Scan not found.", 404)
    picked = _pick(scan, body.get("file_ids"))
    if not picked:
        return err("No matching file_ids.")
    results = []
    for f in picked:
        if f["status"] == "approved":
            results.append({"id": f["id"], "name": f["name"], "ok": False,
                            "message": "Already approved; cannot be re-quarantined."})
        else:
            results.append({"id": f["id"], "name": f["name"], "ok": True,
                            "message": "Kept in quarantine."})
            audit("QUARANTINED", f"{f['name']} kept in quarantine ({f['risk_level']} risk)",
                  scan_id=scan["scan_id"], file_id=f["id"])
    return jsonify({"results": results})


@app.get("/api/audit")
def audit_log():
    limit = min(int(request.args.get("limit", 100)), 500)
    entries = []
    if AUDIT_LOG.exists():
        for line in AUDIT_LOG.read_text(encoding="utf-8").splitlines()[-limit:]:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return jsonify({"entries": entries[::-1]})          # newest first


# Serve the dashboard from the same address as the API (no CORS headaches)
@app.get("/")
def index():
    return send_from_directory(FRONTEND, "index.html")


@app.get("/<path:filename>")
def static_files(filename):
    return send_from_directory(FRONTEND, filename)


if __name__ == "__main__":
    threading.Thread(target=device_watcher, daemon=True).start()
    print(f"USB Airlock backend running. ClamAV: {clamav_version() or 'NOT FOUND'}")
    app.run(host="0.0.0.0", port=5000, debug=False)
