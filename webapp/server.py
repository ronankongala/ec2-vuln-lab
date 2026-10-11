#!/usr/bin/env python3
"""Local dashboard for the ec2-vuln-lab project.

Serves webapp/static/index.html and a small JSON API that wraps the scanner,
the remediation engine, and the dashboard data builder. Binds to 127.0.0.1
only and has no authentication, so it must never be exposed on a network.

Safety rules:
  * rule IDs are validated against ^CLD-0[1-9]$ before any subprocess call
  * subprocesses get a list of arguments, never a shell
  * apply and rollback are refused (403) when the rule's approved_by is pending
  * any output line containing "password", "secret", or "token" is dropped

The /stream variants of scan, dry-run, apply, and rollback run the same
commands but send output as newline-delimited JSON while it arrives. The job
runs in a worker thread that owns the lock, so a closed browser tab never
leaves the lock held or cuts a remediation short.

Usage:
    py -3.13 webapp/server.py [--port 8000]
"""

import argparse
import json
import os
import queue
import re
import subprocess
import sys
import threading
from pathlib import Path

import uvicorn
import yaml
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse

WEBAPP_DIR = Path(__file__).resolve().parent
ROOT = WEBAPP_DIR.parent
INDEX_HTML = WEBAPP_DIR / "static" / "index.html"
SIMPLE_HTML = WEBAPP_DIR / "static" / "simple.html"
DASHBOARD_DATA = ROOT / "results" / "dashboard-data.json"
HISTORY_DIR = ROOT / "results" / "history"
RULES_DIR = ROOT / "remediations" / "rules"
SCANNER = ROOT / "scanner" / "cloud_checks.py"
ENGINE = ROOT / "remediations" / "engine.py"
BUILDER = ROOT / "reports" / "build_dashboard_data.py"
MANIFEST = ROOT / "vulns" / "manifest.yaml"
PLAIN_FIELDS = ("plain_title", "plain_wrong", "technical", "plain_why", "plain_fix", "plain_open")

HOST = "127.0.0.1"
PROFILE = "sandbox-tf"
REGION = "us-east-1"
RULE_ID_RE = re.compile(r"CLD-0[1-9]")
SECRET_MARKERS = ("password", "secret", "token")
SUMMARY_PREFIXES = ("Account ", "Totals:", "Wrote ", "Warning:")
SUBPROCESS_TIMEOUT_S = 600

# Only one AWS-touching job at a time, so a scan never races an apply.
job_lock = threading.Lock()

app = FastAPI(title="ec2-vuln-lab dashboard", docs_url=None, redoc_url=None, openapi_url=None)


def has_secret_marker(text):
    lowered = str(text).lower()
    return any(m in lowered for m in SECRET_MARKERS)


def strip_secrets(text):
    lines = text.splitlines()
    kept = [line for line in lines if not has_secret_marker(line)]
    return "\n".join(kept)


def strip_secret_fields(value):
    """Recursively drop dict keys that look like secrets and string lines that mention them."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if has_secret_marker(k):
                continue
            cleaned = strip_secret_fields(v)
            if cleaned is not None:
                out[k] = cleaned
        return out
    if isinstance(value, list):
        return [c for c in (strip_secret_fields(v) for v in value) if c is not None]
    if isinstance(value, str):
        cleaned = strip_secrets(value)
        return cleaned if cleaned.strip() or not value.strip() else None
    return value


def run(args):
    """Run a Python script from the project root. Returns (exit_code, filtered output)."""
    cmd = [sys.executable, *args]
    try:
        proc = subprocess.run(
            cmd,
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=SUBPROCESS_TIMEOUT_S,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return -1, f"Timed out after {SUBPROCESS_TIMEOUT_S}s"
    output = proc.stdout
    if proc.stderr:
        output += ("\n" if output else "") + proc.stderr
    return proc.returncode, strip_secrets(output).strip()


def run_streaming(args, emit):
    """Like run(), but calls emit(line) for each kept output line as it arrives.

    stderr is merged into stdout, so lines keep their real order.
    """
    cmd = [sys.executable, *args]
    env = dict(os.environ, PYTHONUNBUFFERED="1")
    proc = subprocess.Popen(
        cmd,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        env=env,
        shell=False,
    )
    timed_out = threading.Event()

    def on_timeout():
        timed_out.set()
        proc.kill()

    timer = threading.Timer(SUBPROCESS_TIMEOUT_S, on_timeout)
    timer.daemon = True
    timer.start()
    kept = []
    try:
        for raw in proc.stdout:
            line = raw.rstrip("\r\n")
            if has_secret_marker(line):
                continue
            kept.append(line)
            emit(line)
        proc.wait()
    finally:
        timer.cancel()
        proc.stdout.close()
    if timed_out.is_set():
        message = f"Timed out after {SUBPROCESS_TIMEOUT_S}s"
        emit(message)
        kept.append(message)
        return -1, "\n".join(kept).strip()
    return proc.returncode, "\n".join(kept).strip()


def rebuild_dashboard():
    code, output = run([str(BUILDER)])
    return {"exit_code": code, "output": output}


def validate_rule_id(rule_id):
    if not RULE_ID_RE.fullmatch(rule_id):
        raise HTTPException(status_code=400, detail="rule_id must match ^CLD-0[1-9]$")
    return rule_id


def load_rule(rule_id):
    path = RULES_DIR / f"{rule_id}.yaml"
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"No rule file for {rule_id}")
    try:
        with path.open(encoding="utf-8") as fh:
            rule = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise HTTPException(status_code=500, detail=f"Could not read rule {rule_id}: {exc}") from None
    if not isinstance(rule, dict):
        raise HTTPException(status_code=500, detail=f"Rule {rule_id} is not a mapping")
    return rule


def require_approved(rule_id):
    rule = load_rule(rule_id)
    approver = str(rule.get("approved_by") or "").strip().lower()
    if approver in ("", "pending"):
        raise HTTPException(status_code=403, detail=f"{rule_id} approval is pending; apply and rollback are not allowed")


def load_plain_text():
    """Plain-language fields per CLD finding from vulns/manifest.yaml. Empty dict on any read error."""
    try:
        with MANIFEST.open(encoding="utf-8") as fh:
            manifest = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError):
        return {}
    if not isinstance(manifest, list):
        return {}
    plain = {}
    for entry in manifest:
        if not isinstance(entry, dict):
            continue
        finding_id = entry.get("id")
        if not isinstance(finding_id, str) or not RULE_ID_RE.fullmatch(finding_id):
            continue
        plain[finding_id] = {k: entry[k] for k in PLAIN_FIELDS if k in entry}
    return plain


def acquire_job():
    if not job_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Another scan or remediation is already running")


@app.get("/")
def index():
    return FileResponse(INDEX_HTML, media_type="text/html")


@app.get("/simple")
def simple():
    return FileResponse(SIMPLE_HTML, media_type="text/html")


@app.get("/api/data")
def data():
    if not DASHBOARD_DATA.is_file():
        raise HTTPException(
            status_code=404,
            detail="results/dashboard-data.json not found. Run: py -3.13 reports/build_dashboard_data.py",
        )
    try:
        with DASHBOARD_DATA.open(encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail=f"Could not read dashboard data: {exc}") from None
    if not isinstance(payload, dict):
        raise HTTPException(status_code=500, detail="Dashboard data is not a JSON object")
    payload["plain"] = load_plain_text()
    return payload


@app.get("/api/history/findings")
def history_findings():
    """Per-finding status for each history run, oldest first. Read-only."""
    runs = []
    if HISTORY_DIR.is_dir():
        for path in HISTORY_DIR.glob("cloud-scan-*.json"):
            try:
                with path.open(encoding="utf-8") as fh:
                    scan = json.load(fh)
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(scan, dict):
                continue
            statuses = {}
            for f in scan.get("findings") or []:
                if isinstance(f, dict) and isinstance(f.get("id"), str):
                    statuses[f["id"]] = f.get("status")
            runs.append({
                "run_id": scan.get("run_id"),
                "timestamp_utc": scan.get("timestamp_utc"),
                "statuses": statuses,
                "_sort": (str(scan.get("timestamp_utc") or ""), path.name),
            })
    runs.sort(key=lambda r: r["_sort"])
    for r in runs:
        del r["_sort"]
    return {"runs": runs}


@app.get("/api/rules/{rule_id}")
def get_rule(rule_id: str):
    """Return the parsed rule YAML with secret-looking keys and lines removed. Read-only."""
    validate_rule_id(rule_id)
    return strip_secret_fields(load_rule(rule_id))


SCAN_ARGS = [str(SCANNER), "--profile", PROFILE, "--region", REGION]


def scan_result(code, output, rebuild):
    summary = [line for line in output.splitlines() if line.startswith(SUMMARY_PREFIXES)]
    return {
        "ok": code == 0,
        "exit_code": code,
        "summary": summary,
        "output": output,
        "rebuild": rebuild,
    }


def engine_args(mode, rule_id):
    return [str(ENGINE), f"--{mode}", rule_id, "--profile", PROFILE, "--region", REGION]


@app.post("/api/scan")
def scan():
    acquire_job()
    try:
        code, output = run(SCAN_ARGS)
        rebuild = rebuild_dashboard()
    finally:
        job_lock.release()
    return scan_result(code, output, rebuild)


def run_engine(mode, rule_id, rebuild):
    acquire_job()
    try:
        code, output = run(engine_args(mode, rule_id))
        result = {"ok": code == 0, "exit_code": code, "rule_id": rule_id, "mode": mode, "output": output}
        if rebuild:
            result["rebuild"] = rebuild_dashboard()
    finally:
        job_lock.release()
    return result


def stream_job(job):
    """Run job(emit) in a worker thread and stream its output as NDJSON.

    Messages: {"type": "line", "text": ...} per output line, then one
    {"type": "result", "result": {...}} with the same fields as the
    non-streaming endpoint. The worker releases job_lock when the job ends.
    """
    acquire_job()
    q = queue.Queue()

    def emit(line):
        q.put({"type": "line", "text": line})

    def worker():
        result = None
        try:
            result = job(emit)
        except Exception as exc:  # report, never leave the client hanging
            result = {"ok": False, "exit_code": -1, "output": "", "detail": strip_secrets(f"Job failed: {exc}")}
        finally:
            job_lock.release()
            q.put({"type": "result", "result": result})
            q.put(None)

    try:
        threading.Thread(target=worker, daemon=True).start()
    except RuntimeError:
        job_lock.release()
        raise HTTPException(status_code=500, detail="Could not start job") from None

    def body():
        while True:
            item = q.get()
            if item is None:
                return
            yield json.dumps(item) + "\n"

    return StreamingResponse(
        body(),
        media_type="application/x-ndjson",
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


def engine_job(mode, rule_id, rebuild):
    def job(emit):
        code, output = run_streaming(engine_args(mode, rule_id), emit)
        result = {"ok": code == 0, "exit_code": code, "rule_id": rule_id, "mode": mode, "output": output}
        if rebuild:
            emit("Rebuilding dashboard data...")
            result["rebuild"] = rebuild_dashboard()
        return result
    return job


@app.post("/api/scan/stream")
def scan_stream():
    def job(emit):
        code, output = run_streaming(SCAN_ARGS, emit)
        emit("Rebuilding dashboard data...")
        return scan_result(code, output, rebuild_dashboard())
    return stream_job(job)


@app.post("/api/rules/{rule_id}/dry-run/stream")
def dry_run_stream(rule_id: str):
    validate_rule_id(rule_id)
    load_rule(rule_id)
    return stream_job(engine_job("dry-run", rule_id, rebuild=False))


@app.post("/api/rules/{rule_id}/apply/stream")
def apply_stream(rule_id: str):
    validate_rule_id(rule_id)
    require_approved(rule_id)
    return stream_job(engine_job("apply", rule_id, rebuild=True))


@app.post("/api/rules/{rule_id}/rollback/stream")
def rollback_stream(rule_id: str):
    validate_rule_id(rule_id)
    require_approved(rule_id)
    return stream_job(engine_job("rollback", rule_id, rebuild=True))


@app.post("/api/rules/{rule_id}/dry-run")
def dry_run(rule_id: str):
    validate_rule_id(rule_id)
    load_rule(rule_id)
    return run_engine("dry-run", rule_id, rebuild=False)


@app.post("/api/rules/{rule_id}/apply")
def apply(rule_id: str):
    validate_rule_id(rule_id)
    require_approved(rule_id)
    return run_engine("apply", rule_id, rebuild=True)


@app.post("/api/rules/{rule_id}/rollback")
def rollback(rule_id: str):
    validate_rule_id(rule_id)
    require_approved(rule_id)
    return run_engine("rollback", rule_id, rebuild=True)


def main():
    parser = argparse.ArgumentParser(description="Local ec2-vuln-lab dashboard (binds 127.0.0.1 only)")
    parser.add_argument("--port", type=int, default=8000, help="port to listen on (default: 8000)")
    args = parser.parse_args()
    print(f"ec2-vuln-lab dashboard: http://{HOST}:{args.port}/")
    uvicorn.run(app, host=HOST, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
