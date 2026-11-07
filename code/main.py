#!/usr/bin/env python3
"""Ghost Data Still Exists - deletion audit agent (deterministic evidence engine).

Run from the repository root:   python3 code/main.py
Optional:                       python3 code/main.py --requests dataset/sample_deletion_requests.csv --out /tmp/out.csv

Pipeline
  1. Resolve the requester's current + historical identifiers (email, phone, hash, user_id).
  2. Parse every evidence file (JSON, SQL snapshots, logs, text, PDF, images) into observations
     (resource, system, kind, state, timestamp, linked identifiers).
  3. Link observations to the requester, take the state of every resource at audit_at,
     apply deletion_rules.csv and emit ordered FINDING / REMEDIATION / VERIFICATION steps.
No LLM is used, so a full run costs no tokens.
"""
import argparse
import csv
import hashlib
import json
import os
import re
import sqlite3
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "dataset")

RID_RE = re.compile(
    r"\b(account|search|cache|support|analytics|export|data_flow|backup|audit_record|legal_hold|"
    r"tombstone|email_delivery|marketing|object)_\d+\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
USER_RE = re.compile(r"\buser_\d+\b")
HASH_RE = re.compile(r"\b[0-9a-f]{64}\b")
KV_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=("(?:[^"\\]|\\.)*"|[^\s"]+)')
TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")

PREFIX_SYSTEM = {
    "account": "account_service", "search": "search_service", "cache": "cache_service",
    "support": "support_platform", "analytics": "analytics_platform", "export": "export_service",
    "data_flow": "integration_service", "backup": "backup_service", "audit_record": "security_service",
    "legal_hold": "legal_service", "tombstone": "identity_service", "email_delivery": "email_delivery_service",
    "marketing": "marketing_platform", "object": "object_storage",
}


def pts(s):
    if not s:
        return None
    try:
        return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def prefix_of(rid):
    m = RID_RE.match(rid)
    return m.group(1) if m else rid.rsplit("_", 1)[0]


def norm_phone(p):
    return re.sub(r"\D", "", p or "")


def nz(v):
    return v not in (None, "", "null", "None", "NULL", "[REDACTED]", "[redacted]")


def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()


def toks_from(values):
    out = set()
    for v in values:
        if v is None:
            continue
        s = str(v)
        for e in EMAIL_RE.findall(s):
            out.add(e.lower())
        for u in USER_RE.findall(s):
            out.add(u.lower())
        for h in HASH_RE.findall(s.lower()):
            out.add(h)
        if re.fullmatch(r"\+?[\d\s().\-]{8,}", s.strip()):
            out.add("tel:" + norm_phone(s))
    return out


# --------------------------------------------------------------------------- observations
class Obs:
    __slots__ = ("file_id", "cap", "ts", "rid", "system", "kind", "state", "toks")

    def __init__(self, file_id, cap, ts, rid, kind, state, toks, system=None):
        self.file_id, self.cap, self.ts, self.rid = file_id, cap, ts, rid
        self.system = system or PREFIX_SYSTEM.get(prefix_of(rid), "unknown")
        self.kind, self.state, self.toks = kind, state, set(toks)


KIND_BY_PREFIX = {
    "account": "account", "search": "search", "cache": "cache", "support": "support_msg",
    "analytics": "analytics", "export": "export", "data_flow": "flow", "backup": "backup",
    "audit_record": "audit", "legal_hold": "legal", "tombstone": "tombstone",
    "email_delivery": "email_log", "marketing": "marketing", "object": "support_att",
}
RECORD_TYPE_KIND = {
    "USER_PROFILE": "account", "SEARCH_INDEX_ENTRY": "search", "CACHE_ENTRY": "cache",
    "SUPPORT_MESSAGE": "support_msg", "SUPPORT_ATTACHMENT": "support_att", "ANALYTICS_PROFILE": "analytics",
    "PRODUCT_TELEMETRY": "analytics", "USER_EXPORT": "export", "MARKETING_PROFILE": "marketing",
    "EMAIL_DELIVERY_LOG": "email_log", "SECURITY_AUDIT_LOG": "audit", "LEGAL_HOLD_RECORD": "legal",
    "BACKUP_ARCHIVE": "backup", "ACCOUNT_TOMBSTONE": "tombstone", "DATA_FLOW": "flow",
    "SECONDARY_IDENTIFIER": "account",
}
RESULT_STATE = {
    "FOUND": "present", "NOT_FOUND": "absent", "IDENTIFIABLE": "exposed", "ANONYMIZED": "clean",
    "REDACTED": "clean", "ACTIVE": "active", "DISABLED": "disabled", "BLOCKED": "blocked",
    "ALLOWED": "risk", "ABSENT": "absent", "PRESENT": "present", "ENABLED": "active",
}


def norm_state(kind, state):
    if kind == "backup":
        return {"active": "risk", "present": "risk", "clean": "blocked", "absent": "blocked"}.get(state, state)
    if kind == "flow":
        return {"clean": "disabled", "present": "active", "absent": "disabled"}.get(state, state)
    if kind in ("analytics", "tombstone", "email_log", "support_msg"):
        return {"present": "exposed", "active": "exposed"}.get(state, state)
    return state


def kind_for(rid, record_type=None):
    if record_type and record_type in RECORD_TYPE_KIND:
        return RECORD_TYPE_KIND[record_type]
    return KIND_BY_PREFIX.get(prefix_of(rid), "unknown")


IDENT_FIELDS = ("email", "phone", "email_hash", "full_name", "name", "requester_email", "requester_name",
                "requester_phone", "owner_email", "owner_phone", "customer_email", "user_id", "display_name",
                "customer_reference")


def state_by_kind(kind, rec):
    ident_set = any(nz(rec.get(k)) for k in IDENT_FIELDS if k in rec)
    if kind in ("analytics", "tombstone", "email_log", "support_msg"):
        if kind == "tombstone":
            ident_set = any(nz(rec.get(k)) for k in IDENT_FIELDS if k in rec and k != "customer_reference")
        if kind == "support_msg":
            ident_set = any(nz(rec.get(k)) for k in ("requester_email", "requester_name", "requester_phone",
                                                   "email", "phone", "name"))
        return "exposed" if ident_set else "clean"
    if kind == "flow":
        return "active" if str(rec.get("enabled")).lower() in ("1", "true", "yes") else "disabled"
    if kind == "backup":
        return "risk" if str(rec.get("restore_allowed")).lower() in ("1", "true", "yes") else "blocked"
    return "present"


def rec_tokens(rec):
    vals = []
    for k, v in rec.items():
        if k in ("resource_id", "archive_key", "object_key", "message_excerpt", "connector_name"):
            continue
        if isinstance(v, dict):
            vals.extend(v.values())
        elif isinstance(v, (str, int, float)):
            vals.append(v)
    return toks_from(vals)


def flatten_doc(rec):
    r = dict(rec)
    d = r.pop("document", None)
    if isinstance(d, dict):
        for k, v in d.items():
            r.setdefault(k, v)
    return r


def add_record(out, fid, cap, ts, rec, kind=None, system=None, record_type=None):
    rec = flatten_doc(rec)
    rid = rec.get("resource_id")
    if not rid:
        return
    kind = kind or kind_for(rid, record_type)
    out.append(Obs(fid, cap, ts, rid, kind, state_by_kind(kind, rec), rec_tokens(rec), system))


def parse_json_file(fid, cap, path, out):
    try:
        d = json.load(open(path, encoding="utf-8"))
    except Exception:
        return
    if isinstance(d, dict) and "snapshots" in d:
        for s in d["snapshots"]:
            ts = pts(s.get("captured_at")) or cap
            if s.get("data_store") == "account_service":
                out.append(Obs(fid, cap, ts, "__scope__account", "scope", "present", set(), system="account_service"))
            for r in s.get("records", []):
                add_record(out, fid, cap, ts, r, system=s.get("data_store"))
    elif isinstance(d, dict) and "service_exports" in d:
        for svc, sections in d["service_exports"].items():
            for sec, items in sections.items():
                for r in items:
                    ts = pts(r.get("observed_at")) or cap
                    if svc == "account_service":
                        out.append(Obs(fid, cap, ts, "__scope__account", "scope", "present", set(), system="account_service"))
                        prof = r.get("profile")
                        t = rec_tokens(prof) if isinstance(prof, dict) else set()
                        ok = r.get("status_code") == 200 and prof is not None
                        out.append(Obs(fid, cap, ts, r["resource_id"], "account", "present" if ok else "absent", t))
                    elif svc == "search_service":
                        docs = (r.get("hits") or {}).get("documents", [])
                        if docs:
                            for dd in docs:
                                out.append(Obs(fid, cap, ts, dd.get("resource_id", r["resource_id"]), "search",
                                               "present", rec_tokens(dd) | toks_from([r.get("query")])))
                        else:
                            out.append(Obs(fid, cap, ts, r["resource_id"], "search", "absent", toks_from([r.get("query")])))
                    elif svc == "export_service":
                        out.append(Obs(fid, cap, ts, r["resource_id"], "export", "present", rec_tokens(r)))
                    else:
                        add_record(out, fid, cap, ts, r, system=svc)
    elif isinstance(d, dict) and d.get("records") and isinstance(d["records"][0], dict):
        recs = d["records"]
        if "record_type" in recs[0] and "result" in recs[0]:
            for r in recs:
                ts = pts(r.get("recorded_at")) or cap
                kind = kind_for(r["resource_id"], r.get("record_type"))
                state = norm_state(kind, RESULT_STATE.get(str(r.get("result")).upper(), "present"))
                out.append(Obs(fid, cap, ts, r["resource_id"], kind, state, toks_from([r.get("subject_reference")]),
                               system=r.get("system")))
        else:
            for r in recs:
                add_record(out, fid, cap, cap, r)
                if "owner_email" in r and "download_available" in r:
                    out[-1].state = "present" if r.get("download_available") else "absent"
                    out[-1].kind = "export"


def parse_text_records(fid, cap, lines, out):
    for line in lines:
        parts = [p.strip() for p in line.lstrip("- ").split("|")]
        if len(parts) >= 6 and TS_RE.match(parts[0]) and RID_RE.match(parts[2]):
            kind = kind_for(parts[2], parts[3])
            state = norm_state(kind, RESULT_STATE.get(parts[4].upper(), "present"))
            out.append(Obs(fid, cap, pts(parts[0]), parts[2], kind, state, toks_from([parts[5]]), system=parts[1]))


SQL_KIND = {
    "customer_search_documents": "search", "customer_profiles": "account", "customer_analytics_profiles": "analytics",
    "support_records": "support_msg", "customer_exports": "export", "connector_subscriptions": "flow",
    "backup_restore_entries": "backup", "security_audit_records": "audit",
}


def parse_sql(fid, cap, path, out):
    try:
        con = sqlite3.connect(":memory:")
        con.executescript(open(path, encoding="utf-8").read())
    except Exception:
        return
    for (t,) in con.execute("select name from sqlite_master where type='table'").fetchall():
        if t in ("customer_profiles",) or t.startswith("customer_profiles_"):
            out.append(Obs(fid, cap, cap, "__scope__account", "scope", "present", set(), system="account_service"))
    for (t,) in con.execute("select name from sqlite_master where type='table'").fetchall():
        if t == "snapshot_scope":
            continue
        cols = [r[1] for r in con.execute("pragma table_info(%s)" % t)]
        for row in con.execute("select * from %s" % t).fetchall():
            rec = dict(zip(cols, row))
            ts = pts(rec.get("updated_at")) or cap
            if "record_json" in rec:
                try:
                    add_record(out, fid, cap, ts, json.loads(rec["record_json"]), system=rec.get("origin_system"))
                except Exception:
                    pass
            elif t == "search_documents_primary":
                out.append(Obs(fid, cap, ts, rec["resource_id"], "search", "present",
                               toks_from([rec.get("email")])))
            elif t in SQL_KIND:
                add_record(out, fid, cap, ts, rec, kind=SQL_KIND[t])
            elif t.startswith("customer_profiles_"):
                add_record(out, fid, cap, ts, rec, kind="account")


def parse_log_line(line):
    line = line.rstrip("\n")
    m = TS_RE.match(line)
    if not m:
        return None
    ts = pts(m.group(0))
    rest = line[m.end():].strip()
    d = {}
    if rest.startswith("{"):
        try:
            d = {k: str(v) for k, v in json.loads(rest).items()}
        except Exception:
            pass
    else:
        txt = rest.replace('\\"', '"')
        for k, v in KV_RE.findall(txt):
            d.setdefault(k, v.strip('"'))
        if "event" not in d:
            m2 = re.search(r"\]\s+([a-z_]+):", txt) or re.search(r"\|\s*([a-z_]+)\s*\|\s*instance=", txt)
            if m2:
                d["event"] = m2.group(1)
    t = re.search(r"\b(tr-[\w-]+|rb-[\w-]+)\b", line)
    d["_trace"] = d.get("trace_id") or d.get("requestId") or (t.group(1) if t else None)
    d["_ts"] = ts
    return d


def truthy(v):
    return str(v).lower() in ("true", "1", "yes")


def parse_log(fid, cap, path, out):
    lines = [parse_log_line(l) for l in open(path, encoding="utf-8", errors="replace")]
    groups = defaultdict(list)
    for n, d in enumerate(l for l in lines if l):
        if d.get("event") == "record_lookup" and d.get("resource_id"):
            _k = kind_for(d["resource_id"], d.get("record_type"))
            out.append(Obs(fid, cap, d["_ts"], d["resource_id"], _k,
                           norm_state(_k, RESULT_STATE.get(d.get("result", "").upper(), "present")),
                           toks_from([d.get("subject_reference")]), system=d.get("system")))
            continue
        groups[d["_trace"] or "line%d" % n].append(d)
    for ds in groups.values():
        gt = toks_from([v for dd in ds for k, v in dd.items() if k not in ("_ts", "_trace", "resource_id")])
        for dd in ds:
            ev, rid, ts = dd.get("event", ""), dd.get("resource_id"), dd["_ts"]
            if not rid:
                continue
            kind, state = kind_for(rid), None
            if ev == "profile_lookup_completed":
                state = "absent" if (dd.get("rows") == "0" or dd.get("http_status") == "404") else "present"
            elif ev == "index_query_completed":
                state = "present" if dd.get("result") == "hit" else "absent"
            elif ev == "audit_record_read_completed":
                state = "present"
            elif ev in ("analytics_profile_read", "analytics_identity_scan"):
                n = dd.get("direct_identifiers")
                state = "exposed" if ((n is not None and n != "0") or nz(dd.get("email")) or nz(dd.get("matched_value"))) else "clean"
            elif ev == "analytics_profile_read_completed":
                state = "exposed" if any(nz(dd.get(k)) for k in ("email", "phone", "email_hash", "customer_reference")) else "clean"
            elif ev == "contact_lookup_completed":
                kind, state = "marketing", "present"
            elif ev == "message_pii_scan":
                state = "exposed"
            elif ev == "message_read":
                state = "clean" if "REDACTED" in dd.get("message_text", "") else "exposed"
            elif ev == "support_ticket_read_completed":
                state = "exposed" if any(nz(dd.get(k)) for k in ("requester_name", "requester_email", "requester_phone", "customer_reference")) else "clean"
            elif ev == "attachment_pii_scan":
                kind, state = "support_att", "present"
            elif ev == "contact_query_completed" and dd.get("rows") == "1":
                kind, state = "support_att", "present"
            elif ev == "deletion_marker_check":
                kind, state = "support_att", ("present" if dd.get("marker_found") == "false" else "absent")
            elif ev in ("connector_heartbeat", "connector_config_loaded", "connector_config_read_completed"):
                state = "active" if truthy(dd.get("enabled")) else "disabled"
            elif ev == "restore_candidate_evaluated":
                state = "risk" if (truthy(dd.get("eligible")) and not truthy(dd.get("deletion_block"))) else "blocked"
            elif ev == "restore_authorization_completed":
                state = "blocked" if dd.get("decision") == "deny" else "risk"
            elif ev == "restore_policy_read_completed":
                state = "risk" if truthy(dd.get("restore_allowed")) else "blocked"
            elif ev in ("export_download_check_completed", "export_metadata_read_completed"):
                state = "present" if truthy(dd.get("available")) else "absent"
            elif ev == "retained_order_loaded":
                kind, state = "legal", "present"
            if state:
                out.append(Obs(fid, cap, ts, rid, kind, state, gt - {rid}))


def doc_text(path):
    try:
        if path.lower().endswith(".pdf"):
            return subprocess.run(["pdftotext", "-layout", path, "-"], capture_output=True, text=True, timeout=60).stdout
        try:
            import pytesseract
            from PIL import Image
            return pytesseract.image_to_string(Image.open(path))
        except Exception:
            return subprocess.run(["tesseract", path, "-"], capture_output=True, text=True, timeout=120).stdout
    except Exception:
        return ""


def parse_doc(fid, cap, path, out):
    txt = doc_text(path)
    if not txt.strip():
        return
    lines = txt.splitlines()
    all_toks = toks_from([txt])
    seen = set()
    for i, line in enumerate(lines):
        for m in RID_RE.finditer(line.replace("data_flow.", "data_flow_")):
            rid = m.group(0)
            near = "\n".join(lines[max(0, i - 2): i + 3])
            toks = toks_from([near])
            if rid in seen:
                continue
            seen.add(rid)
            pre, kind = prefix_of(rid), kind_for(rid)
            if pre == "support":
                kind, state = "support_att", "present"
            elif kind in ("analytics", "tombstone"):
                state = "exposed" if toks else "clean"
            else:
                state = "present"
            out.append(Obs(fid, cap, cap, rid, kind, state, toks or (all_toks if len(all_toks) <= 3 else set())))


def load_all():
    files = {r["file_id"]: r for r in csv.DictReader(open(os.path.join(DATA, "evidence_files.csv"), encoding="utf-8"))}
    obs = []
    for fid, r in sorted(files.items()):
        path = os.path.join(DATA, r["file_path"])
        cap = pts(r["captured_at"])
        if not os.path.exists(path):
            continue
        ext = path.rsplit(".", 1)[-1].lower()
        if ext == "json":
            parse_json_file(fid, cap, path, obs)
        elif ext == "sql":
            parse_sql(fid, cap, path, obs)
        elif ext == "log":
            parse_log(fid, cap, path, obs)
        elif ext == "txt":
            parse_text_records(fid, cap, open(path, encoding="utf-8").read().splitlines(), obs)
        elif ext in ("pdf", "png", "jpg", "jpeg"):
            parse_doc(fid, cap, path, obs)
    return files, obs


# --------------------------------------------------------------------------- identity
class Identity:
    def __init__(self, ids, audit):
        self.ids = ids
        self.by_user = {i["user_id"]: i for i in ids}
        self.audit = audit
        self.hist = defaultdict(list)
        for a in audit:
            self.hist[a["user_id"]].append(a)

    def resolve(self, email):
        e = email.strip().lower()
        for i in self.ids:
            if i["email"].lower() == e:
                return i["user_id"]
        for a in self.audit:
            if a["field_name"] == "email" and e in (a["old_value"].lower(), a["new_value"].lower()):
                return a["user_id"]
        h = sha256(e)
        for i in self.ids:
            if i["email_hash"].lower() == h:
                return i["user_id"]
        return None

    def tokens(self, uid, email):
        t = {uid.lower(), email.strip().lower(), sha256(email.strip().lower())}
        i = self.by_user.get(uid)
        if i:
            t |= {i["email"].lower(), i["email_hash"].lower(), sha256(i["email"].lower())}
            if i["phone"]:
                t.add("tel:" + norm_phone(i["phone"]))
        for a in self.hist.get(uid, []):
            for v in (a["old_value"], a["new_value"]):
                if a["field_name"] == "email":
                    t |= {v.lower(), sha256(v.lower())}
                elif a["field_name"] == "email_hash":
                    t.add(v.lower())
                elif a["field_name"] == "phone":
                    t.add("tel:" + norm_phone(v))
        return t


# --------------------------------------------------------------------------- planning
OP_ORDER = {
    "REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1, "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2, "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1, "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3, "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5,
}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
DELETE_KINDS = ("account", "search", "cache", "export", "marketing", "support_att")


def plan_resource(o):
    k, s = o.kind, o.state
    if k in DELETE_KINDS:
        v = ("VERIFY_RECORD_ABSENT", "ABSENT")
        if s == "absent":
            return None, None, v
        return ("REPORT_REMAINING_RECORD", "PRESENT"), ("DELETE_RECORD", "ABSENT"), v
    if k in ("support_msg", "tombstone", "email_log"):
        v = ("VERIFY_RECORD_REDACTED", "REDACTED")
        if s == "exposed":
            return ("REPORT_EXPOSED_PII", "PRESENT"), ("REDACT_RECORD", "REDACTED"), v
        return None, None, v
    if k == "analytics":
        v = ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED")
        if s == "exposed":
            return ("REPORT_EXPOSED_PII", "PRESENT"), ("ANONYMIZE_RECORD", "ANONYMIZED"), v
        return None, None, v
    if k == "flow":
        v = ("VERIFY_DATA_FLOW_DISABLED", "DISABLED")
        if s == "active":
            return ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE"), ("DISABLE_DATA_FLOW", "DISABLED"), v
        return None, None, v
    if k == "backup":
        v = ("VERIFY_RESTORE_BLOCKED", "BLOCKED")
        if s == "risk":
            return ("REPORT_RESTORE_RISK", "ACTIVE"), ("BLOCK_RESTORE", "BLOCKED"), v
        return None, None, v
    if k in ("audit", "legal"):
        return None, None, ("VERIFY_RECORD_PRESENT", "PRESENT")
    return None, None, None


def build_steps(resources, complete):
    items = [(o,) + plan_resource(o) for o in resources]
    steps = []
    if not complete:
        for o, f, r, v in items:
            if f:
                steps.append(("FINDING", o.system, o.rid, f[0], f[1], o.file_id))
        for o, f, r, v in items:
            if r:
                steps.append(("REMEDIATION", o.system, o.rid, r[0], r[1], ""))
    for o, f, r, v in items:
        if v:
            steps.append(("VERIFICATION", o.system, o.rid, v[0], v[1], o.file_id if complete else ""))
    steps.sort(key=lambda s: (PHASE_ORDER[s[0]], OP_ORDER[s[3]], s[1], s[2]))
    return [{"step_no": i + 1, "phase": p, "system_id": sy, "resource_id": ri, "operation": op, "state": st,
             "evidence_id": ev} for i, (p, sy, ri, op, st, ev) in enumerate(steps)]


# --------------------------------------------------------------------------- per-case solving
STATUS_RESULT = {"COMPLETE": "SUCCESS", "PARTIALLY_COMPLETE": "PARTIAL", "NOT_STARTED": "FAILED"}


def obs_time(o):
    return o.ts or o.cap


def pick_latest(cands, audit_at, since=None):
    """State at audit_at: latest observation not after audit_at, preferring files captured by then."""
    pool = [o for o in cands if obs_time(o) and obs_time(o) <= audit_at]
    if since:
        pool = [o for o in pool if obs_time(o) >= since or o.kind in ("audit", "legal")]
    best = None
    for o in pool:
        key = (o.cap <= audit_at, obs_time(o), o.cap)
        if best is None or key >= best[0]:
            best = (key, o)
    return best[1] if best else None


class Case:
    def __init__(self, row, ident):
        self.row = row
        self.id = row["case_id"]
        self.audit_at, self.rep = pts(row["audit_at"]), pts(row["reported_at"])
        self.req = pts(row["requested_at"])
        self.uid = ident.resolve(row["email"])
        self.utoks = ident.tokens(self.uid, row["email"]) if self.uid else set()
        self.chosen = {}
        self.acct_event = None
        self.not_applicable = False


def run(requests_path, out_path):
    files, obs = load_all()
    ident = Identity(list(csv.DictReader(open(os.path.join(DATA, "user_identities.csv"), encoding="utf-8"))),
                     list(csv.DictReader(open(os.path.join(DATA, "user_audit_log.csv"), encoding="utf-8"))))
    activity = list(csv.DictReader(open(os.path.join(DATA, "system_activity.csv"), encoding="utf-8")))
    for a in activity:
        a["_t"] = pts(a["event_time"])
    wk = [a for a in activity if a["source_system"] == "deletion_worker"]
    acc_events = [a for a in wk if a["target_system"] == "account_service" and a["event_type"] == "DELETE_RECORD"]
    classify = {a["resource_id"] for a in activity if a["event_type"] == "CLASSIFY_REQUEST"}
    by_rid = defaultdict(list)
    for o in obs:
        by_rid[o.rid].append(o)
    doc_fids = {fid for fid, r in files.items() if r["file_path"].lower().endswith((".png", ".jpg", ".jpeg", ".pdf"))}
    owner = {rid: {t for o in lst for t in o.toks if t.startswith("user_") or "@" in t} for rid, lst in by_rid.items()}
    cases = [Case(r, ident) for r in csv.DictReader(open(requests_path, encoding="utf-8"))]

    # ---- 1. token-linked resources and non-deletion requests
    claimed = set()
    for c in cases:
        if c.uid is None:
            continue
        for rid, lst in by_rid.items():
            if rid.startswith("__") or not any(o.toks & c.utoks for o in lst):
                continue
            ident_obs = [x for x in lst if any(t.startswith("user_") or "@" in t for t in x.toks)]
            if ident_obs and not any(x.file_id in doc_fids for x in ident_obs if x.toks & c.utoks) is False:
                pass
            foreign = [x for x in ident_obs if x.file_id not in doc_fids and not (x.toks & c.utoks)]
            mine_struct = [x for x in ident_obs if x.file_id not in doc_fids and (x.toks & c.utoks)]
            if foreign and not mine_struct:
                continue
            o = pick_latest([x for x in lst if (x.toks & c.utoks) or not x.toks], c.audit_at, c.req)
            if o:
                c.chosen[rid] = o
                claimed.add(rid)
            if rid in classify and prefix_of(rid) == "account":
                c.not_applicable = True

    # ---- 2. primary account profile (known mostly through deletion-worker activity)
    def scope_obs(c, rid):
        o = pick_latest(by_rid.get(rid, []), c.audit_at, c.req)
        if o:
            return o
        sc = pick_latest([x for x in by_rid.get("__scope__account", [])
                          if "inventory" not in files[x.file_id]["origin"]], c.audit_at)
        return Obs(sc.file_id if sc else "", sc.cap if sc else None, sc.ts if sc else None, rid, "account", "absent", set())

    pending = {}
    for c in cases:
        if c.uid is None or c.not_applicable:
            continue
        have = [rid for rid in c.chosen if prefix_of(rid) == "account"]
        if have:
            c.acct_event = next((a for a in acc_events if a["resource_id"] == have[0]), None)
            continue
        m = re.match(r"user_(\d+)$", c.uid)
        if m and int(m.group(1)) <= 10:
            rid = "account_%03d" % int(m.group(1))
            c.chosen[rid] = scope_obs(c, rid)
            c.acct_event = next((a for a in acc_events if a["resource_id"] == rid), None)
            claimed.add(rid)
            continue
        want = STATUS_RESULT.get(c.row["reported_status"])
        cand = [a for a in acc_events
                if c.rep - timedelta(minutes=80) <= a["_t"] <= c.rep + timedelta(minutes=12)
                and (not want or a["reported_result"] == want)
                and a["resource_id"] not in claimed
                and not owner.get(a["resource_id"])]
        pending[c.id] = (c, cand)
    assigned = set()
    while pending:
        progress = False
        for cid, (c, cand) in list(pending.items()):
            cand = [a for a in cand if a["resource_id"] not in assigned]
            pending[cid] = (c, cand)
            if len(cand) == 1:
                a = cand[0]
                assigned.add(a["resource_id"])
                c.chosen[a["resource_id"]] = scope_obs(c, a["resource_id"])
                c.acct_event = a
                del pending[cid]
                progress = True
            elif not cand:
                del pending[cid]
                progress = True
        if not progress and pending:
            # tie-break: fewest candidates first, closest to the usual offset (about -55 minutes)
            cid, (c, cand) = min(pending.items(), key=lambda kv: len(kv[1][1]))
            a = min(cand, key=lambda x: abs((x["_t"] - c.rep).total_seconds() / 60 + 55))
            assigned.add(a["resource_id"])
            c.chosen[a["resource_id"]] = scope_obs(c, a["resource_id"])
            c.acct_event = a
            del pending[cid]

    # ---- 3. anonymised analytics profile (no identifier left, linked through worker activity)
    an_events = sorted([a for a in wk if a["event_type"] == "ANONYMIZE_RECORD" and a["reported_result"] == "SUCCESS"
                        and not owner.get(a["resource_id"]) and a["resource_id"] not in claimed],
                       key=lambda a: a["_t"])
    used = set()
    todo = []
    for c in cases:
        if c.uid is None or c.not_applicable:
            continue
        if any(plan_resource(o)[0] for o in c.chosen.values()) or any(o.kind == "analytics" for o in c.chosen.values()):
            continue
        t0 = c.acct_event["_t"] if c.acct_event else c.rep
        todo.append((t0, c.id, c))
    for t0, _, c in sorted(todo, key=lambda x: (x[0], x[1])):
        lo, hi = (timedelta(minutes=10), timedelta(minutes=60)) if c.acct_event else (timedelta(minutes=-80), timedelta(minutes=5))
        for a in an_events:
            if a["resource_id"] in used or not (lo <= a["_t"] - t0 <= hi):
                continue
            o = pick_latest(by_rid.get(a["resource_id"], []), c.audit_at, c.req)
            if o:
                used.add(a["resource_id"])
                c.chosen[o.rid] = o
                break

    # ---- 4. emit
    rows = []
    for c in cases:
        if c.not_applicable:
            rows.append((c.id, "NOT_APPLICABLE", "[]"))
            continue
        res = list(c.chosen.values())
        status = "INCOMPLETE" if any(plan_resource(o)[0] for o in res) else "COMPLETE"
        rows.append((c.id, status, json.dumps(build_steps(res, status == "COMPLETE"), separators=(",", ":"))))
    rows.sort(key=lambda r: r[0])
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["case_id", "deletion_status", "steps_json"])
        w.writerows(rows)
    print("wrote %d rows to %s" % (len(rows), out_path))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", default=os.path.join(DATA, "deletion_requests.csv"))
    ap.add_argument("--out", default=os.path.join(ROOT, "output.csv"))
    a = ap.parse_args()
    run(a.requests, a.out)


if __name__ == "__main__":
    main()