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
import copy
import json
import os
import queue
import re
import subprocess
import sys
import threading
import urllib.error
import urllib.request
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
DRAFTS_DIR = ROOT / "remediations" / "drafts"
DRAFT_ENV = WEBAPP_DIR / ".env"
DRAFT_ENV_KEYS = ("DRAFT_API_BASE", "DRAFT_API_KEY", "DRAFT_MODEL")
DRAFT_TIMEOUT_S = 300
PLAIN_FIELDS = ("plain_title", "short_name", "plain_wrong", "technical", "plain_why", "plain_fix", "plain_open")

HOST = "127.0.0.1"
PROFILE = "sandbox-tf"
REGION = "us-east-1"
RULE_ID_RE = re.compile(r"CLD-0[1-9]")
SECRET_MARKERS = ("password", "secret", "token")
SUMMARY_PREFIXES = ("Account ", "Totals:", "Wrote ", "Warning:")
SUBPROCESS_TIMEOUT_S = 600

# Identifiers that must never reach the drafting model. Each match is replaced
# with a placeholder before the prompt is sent.
PROMPT_SCRUBBERS = (
    (re.compile(r"arn:aws[\w-]*:[^\s\"']*"), "<arn>"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "<key>"),
    (re.compile(r"\b(?:i|sg|sgr|vpc|subnet|ami|vol|eni|snap|igw|rtb|acl|vpce|fl)-[0-9a-f]{8,17}\b"), "<resource-id>"),
    (re.compile(r"\b\d{12}\b"), "<account-id>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"), "<ip>"),
    (re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:/\d{1,3})?(?![\w:])"), "<ip>"),
)

# The only keys the drafting model may write. Every structural field of the
# draft is copied from the approved rule by the server, not by the model.
DRAFT_REPLY_TEMPLATE = """\
fix:
  description: >-
    <what the fix changes and what it does not affect>
  extra_steps: []

rollback:
  description: >-
    <how the rollback restores the original state>
  extra_steps: []
"""
DRAFT_STEP_KEYS = {"action", "target", "params"}

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


def load_draft_settings():
    """Read DRAFT_* keys from webapp/.env. Raises 503 if any is missing."""
    settings = {}
    try:
        with DRAFT_ENV.open(encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                if key.startswith("export "):
                    key = key[len("export "):].strip()
                if key in DRAFT_ENV_KEYS:
                    settings[key] = value.strip().strip("\"'")
    except OSError:
        pass
    missing = [k for k in DRAFT_ENV_KEYS if not settings.get(k)]
    if missing:
        raise HTTPException(
            status_code=503,
            detail=f"AI drafting is not configured: set {', '.join(missing)} in webapp/.env",
        )
    return settings


def scrub_prompt_text(text):
    """Drop secret-looking lines and replace account IDs, resource IDs, IPs, and ARNs."""
    text = strip_secrets(str(text))
    for pattern, placeholder in PROMPT_SCRUBBERS:
        text = pattern.sub(placeholder, text)
    return text.strip()


def load_finding_text(finding_id):
    """Title and control text for one finding from vulns/manifest.yaml, or {} if unavailable."""
    try:
        with MANIFEST.open(encoding="utf-8") as fh:
            manifest = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError):
        return {}
    if not isinstance(manifest, list):
        return {}
    for entry in manifest:
        if isinstance(entry, dict) and entry.get("id") == finding_id:
            return {k: entry[k] for k in ("title", "cis_or_nist") if isinstance(entry.get(k), str)}
    return {}


def describe_steps(steps):
    lines = []
    for step in steps:
        target = step.get("target") if isinstance(step.get("target"), dict) else {}
        lines.append(f"- {step.get('action')} on {target.get('type')} {target.get('name')}")
    return "\n".join(lines) or "(none)"


def build_draft_prompt(finding_id, finding, rule):
    title = scrub_prompt_text(finding.get("title", "")) or "(not available)"
    control = scrub_prompt_text(finding.get("cis_or_nist", "")) or "(not available)"
    allowed_actions = rule["scope"]["allowed_actions"]
    actions = "\n".join(f"- {a}" for a in allowed_actions) or "(none: leave both extra_steps lists empty)"
    targets = "\n".join(f"- {t} {n}" for t, n in rule_targets(rule)) or "(none)"
    system = (
        "You write the wording for remediation rules in a security lab. Reply with YAML only. "
        "Do not add commentary, explanations, or Markdown code fences."
    )
    user = (
        f"Write the descriptions for the remediation rule for finding {finding_id}.\n\n"
        f"Finding title: {title}\n"
        f"Control: {control}\n"
        f"Fix type: {rule['fix']['type']}\n\n"
        f"Fix steps (already fixed, do not repeat them):\n{describe_steps(rule['fix']['steps'])}\n\n"
        f"Rollback steps (already fixed, do not repeat them):\n{describe_steps(rule['rollback']['steps'])}\n\n"
        "Only add extra_steps if the steps above are not enough. Leave them as empty lists otherwise. "
        "Each extra step needs action, target (type and name), and optional params.\n"
        f"Extra steps may use only these actions:\n{actions}\n"
        f"Extra steps may target only these resources (type name):\n{targets}\n\n"
        "Use exactly this YAML shape and these keys, and no other keys. Replace each <placeholder>:\n\n"
        f"{DRAFT_REPLY_TEMPLATE}\n"
        "Output the YAML document only."
    )
    # Second pass over the finished text, in case anything slipped through.
    return scrub_prompt_text(system), scrub_prompt_text(user)


def request_draft(settings, system, user):
    """Call the OpenAI-compatible chat completions endpoint. Returns the reply text."""
    api_key = settings["DRAFT_API_KEY"]
    url = settings["DRAFT_API_BASE"].rstrip("/") + "/chat/completions"
    if not url.lower().startswith(("https://", "http://")):
        raise HTTPException(status_code=503, detail="DRAFT_API_BASE must start with https:// or http://")
    body = json.dumps({
        "model": settings["DRAFT_MODEL"],
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
    )

    def safe(message):
        return strip_secrets(str(message).replace(api_key, "<redacted>"))

    try:
        with urllib.request.urlopen(req, timeout=DRAFT_TIMEOUT_S) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Model request failed with HTTP {exc.code}") from None
    except TimeoutError:
        raise HTTPException(status_code=504, detail=f"Model request timed out after {DRAFT_TIMEOUT_S}s") from None
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise HTTPException(status_code=504, detail=f"Model request timed out after {DRAFT_TIMEOUT_S}s") from None
        raise HTTPException(status_code=502, detail=safe(f"Model request failed: {exc.reason}")) from None
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=safe(f"Model request failed: {exc}")) from None
    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise HTTPException(status_code=502, detail="Model reply had no choices[0].message.content") from None
    if not isinstance(content, str):
        raise HTTPException(status_code=502, detail="Model reply content was not text")
    return content


def strip_code_fence(text):
    text = text.strip()
    match = re.fullmatch(r"```[A-Za-z]*\n(.*?)\n?```", text, flags=re.DOTALL)
    return match.group(1) if match else text


def check_approved_rule_shape(rule_id, rule):
    """The structural fields a draft copies must all be present in the approved rule."""
    if rule.get("id") != rule_id:
        raise HTTPException(status_code=500, detail=f"Rule {rule_id} has id {rule.get('id')!r}")
    for key in ("version", "match", "scope", "fix", "rollback", "verify"):
        if key not in rule:
            raise HTTPException(status_code=500, detail=f"Rule {rule_id} has no {key}")
    allowed = rule["scope"].get("allowed_actions") if isinstance(rule["scope"], dict) else None
    if not isinstance(allowed, list) or not all(isinstance(a, str) for a in allowed):
        raise HTTPException(status_code=500, detail=f"Rule {rule_id} scope.allowed_actions is not a list of strings")
    if not isinstance(rule["fix"], dict) or "type" not in rule["fix"]:
        raise HTTPException(status_code=500, detail=f"Rule {rule_id} has no fix.type")
    for section in ("fix", "rollback"):
        part = rule[section]
        if not isinstance(part, dict) or not isinstance(part.get("steps"), list):
            raise HTTPException(status_code=500, detail=f"Rule {rule_id} {section}.steps is not a list")
        if not all(isinstance(s, dict) for s in part["steps"]):
            raise HTTPException(status_code=500, detail=f"Rule {rule_id} {section}.steps has a non-mapping step")


def rule_targets(rule):
    """(type, name) of every step target in the approved rule, in first-seen order."""
    found = []
    for section in ("fix", "rollback"):
        for step in rule[section]["steps"]:
            target = step.get("target")
            if isinstance(target, dict):
                pair = (target.get("type"), target.get("name"))
                if None not in pair and pair not in found:
                    found.append(pair)
    return found


def reply_text(parsed, section):
    part = parsed.get(section)
    text = part.get("description") if isinstance(part, dict) else None
    if not isinstance(text, str) or not text.strip():
        raise HTTPException(status_code=422, detail=f"Model reply has no {section}.description text")
    return text.strip()


def reply_extra_steps(parsed, section, rule):
    """Extra steps from the model, accepted only with an in-scope action and a target from the approved rule."""
    part = parsed.get(section)
    steps = part.get("extra_steps") if isinstance(part, dict) else None
    if steps is None:
        return []
    if not isinstance(steps, list):
        raise HTTPException(status_code=422, detail=f"Model reply {section}.extra_steps is not a list")
    allowed = set(rule["scope"]["allowed_actions"])
    targets = rule_targets(rule)
    accepted = []
    for i, step in enumerate(steps):
        where = f"{section}.extra_steps[{i}]"
        if not isinstance(step, dict):
            raise HTTPException(status_code=422, detail=f"Model reply {where} is not a mapping")
        unknown = sorted(str(k) for k in step if k not in DRAFT_STEP_KEYS)
        if unknown:
            raise HTTPException(status_code=422, detail=f"Model reply {where} has unknown keys: {', '.join(unknown)}")
        action = step.get("action")
        if not isinstance(action, str) or action not in allowed:
            raise HTTPException(
                status_code=422,
                detail=f"Model reply {where} action {action!r} is not in scope.allowed_actions",
            )
        target = step.get("target")
        pair = (target.get("type"), target.get("name")) if isinstance(target, dict) else None
        if pair not in targets:
            raise HTTPException(status_code=422, detail=f"Model reply {where} target is not a target in the approved rule")
        params = step.get("params", {})
        if not isinstance(params, dict):
            raise HTTPException(status_code=422, detail=f"Model reply {where} params is not a mapping")
        accepted.append({
            "action": action,
            "target": {"type": pair[0], "name": pair[1]},
            "params": copy.deepcopy(params),
        })
    return accepted


@app.post("/api/drafts/{finding_id}")
def create_draft(finding_id: str):
    """Ask the configured model for draft wording and save it to remediations/drafts/. Never applies it."""
    if not RULE_ID_RE.fullmatch(finding_id):
        raise HTTPException(status_code=400, detail="finding_id must match ^CLD-0[1-9]$")
    if not (RULES_DIR / f"{finding_id}.yaml").is_file():
        raise HTTPException(
            status_code=404,
            detail=f"No approved rule remediations/rules/{finding_id}.yaml; a draft needs an approved rule to copy from",
        )
    rule = load_rule(finding_id)
    check_approved_rule_shape(finding_id, rule)
    settings = load_draft_settings()

    system, user = build_draft_prompt(finding_id, load_finding_text(finding_id), rule)
    reply = request_draft(settings, system, user)

    try:
        parsed = yaml.safe_load(strip_code_fence(reply))
    except yaml.YAMLError:
        raise HTTPException(status_code=422, detail="Model reply is not valid YAML") from None
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=422, detail="Model reply is not a YAML mapping")
    fix_description = reply_text(parsed, "fix")
    rollback_description = reply_text(parsed, "rollback")
    fix_extra = reply_extra_steps(parsed, "fix", rule)
    rollback_extra = reply_extra_steps(parsed, "rollback", rule)

    # Every structural field comes from the approved rule. The model supplies
    # only the two descriptions and any validated extra steps.
    fix = {k: copy.deepcopy(v) for k, v in rule["fix"].items() if k not in ("description", "steps")}
    fix["description"] = fix_description
    fix["steps"] = copy.deepcopy(rule["fix"]["steps"]) + fix_extra
    rollback = {k: copy.deepcopy(v) for k, v in rule["rollback"].items() if k not in ("description", "steps")}
    rollback["description"] = rollback_description
    rollback["steps"] = copy.deepcopy(rule["rollback"]["steps"]) + rollback_extra
    draft = {
        "id": rule["id"],
        "version": copy.deepcopy(rule["version"]),
        "match": copy.deepcopy(rule["match"]),
        "scope": copy.deepcopy(rule["scope"]),
        "fix": fix,
        "rollback": rollback,
        "verify": copy.deepcopy(rule["verify"]),
    }
    draft.update({
        "draft": True,
        "drafted_by": "ai",
        "approved_by": "pending",
        "approved_on": "",
        "preview_required": True,
    })

    drafts_dir = DRAFTS_DIR.resolve()
    path = (DRAFTS_DIR / f"{finding_id}.draft.yaml").resolve()
    if path.parent != drafts_dir or RULES_DIR.resolve() in path.parents:
        raise HTTPException(status_code=500, detail="Refusing to write a draft outside remediations/drafts/")
    if path.exists() and not path.is_file():
        raise HTTPException(status_code=500, detail=f"{path.name} exists and is not a regular file")
    text = yaml.safe_dump(draft, sort_keys=False, allow_unicode=True, default_flow_style=False)
    try:
        drafts_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Could not write draft: {exc}") from None

    return {
        "ok": True,
        "finding_id": finding_id,
        "path": f"remediations/drafts/{path.name}",
        "content": text,
        "draft": draft,
        "applied": False,
    }


def main():
    parser = argparse.ArgumentParser(description="Local ec2-vuln-lab dashboard (binds 127.0.0.1 only)")
    parser.add_argument("--port", type=int, default=8000, help="port to listen on (default: 8000)")
    args = parser.parse_args()
    print(f"ec2-vuln-lab dashboard: http://{HOST}:{args.port}/")
    uvicorn.run(app, host=HOST, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
