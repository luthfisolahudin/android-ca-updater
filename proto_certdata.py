import re
import sys
from pathlib import Path

sys.path.insert(0, "/tmp/commandcode-1000/-home-luthfi-code-work-noeffort-projects-aixel-pm-pm/f79971ba-e1f7-4ae7-ba13-946556231924/scratchpad/android-ca-updater")

import android_ca_updater as a
import hashlib

HEADER = re.compile(r'^# (Certificate|Trust for Certificate|Trust for) "(.*)"$')
OCTAL = re.compile(r"\\([0-7]{1,3})")


def octal_bytes(lines):
    return "".join(OCTAL.sub(lambda m: chr(int(m.group(1), 8)), line) for line in lines).strip().encode("latin-1")


def parse_date(raw):
    if raw.endswith("Z"):
        if len(raw) == 13:
            return a.datetime.strptime(raw, "%y%m%d%H%M%SZ").replace(tzinfo=a.timezone.utc)
        if len(raw) == 15:
            return a.datetime.strptime(raw, "%Y%m%d%H%M%SZ").replace(tzinfo=a.timezone.utc)
    return None


def blocks(text):
    out, cur = [], None
    for line in text.splitlines():
        m = HEADER.match(line)
        if m:
            if cur:
                out.append(cur)
            cur = {"kind": m.group(1), "label": m.group(2), "lines": []}
        elif cur is not None:
            cur["lines"].append(line)
    if cur:
        out.append(cur)
    return out


def attr(block, name):
    lines = block["lines"]
    for i, line in enumerate(lines):
        if line.startswith(name):
            if "MULTILINE_OCTAL" not in line:
                return line.split()[-1]
            buf = []
            for nxt in lines[i + 1:]:
                if nxt.strip() == "END":
                    break
                buf.append(nxt)
            return octal_bytes(buf).decode("latin-1")
    return None


def fingerprint(block):
    for line in block["lines"]:
        m = re.match(r"# Fingerprint \(SHA1\): (.+)$", line)
        if m:
            return m.group(1).replace(":", "").lower()
    raw = attr(block, "CKA_CERT_SHA1_HASH")
    return raw.encode("latin-1").hex() if raw else None


text = Path("/tmp/certdata.txt").read_text(encoding="utf-8", errors="replace")
records = {}
for block in blocks(text):
    fp = fingerprint(block)
    if not fp:
        continue
    rec = records.setdefault(fp, {"label": block["label"], "server_auth": None, "distrust_after": None})
    if block["kind"] == "Certificate":
        raw = attr(block, "CKA_NSS_SERVER_DISTRUST_AFTER")
        if raw and raw.upper().endswith("Z"):
            rec["distrust_after"] = parse_date(raw)
    else:
        rec["server_auth"] = attr(block, "CKA_TRUST_SERVER_AUTH")

print("records:", len(records), "| with trust:", sum(1 for r in records.values() if r["server_auth"]))
print("distrust dates:", sorted((r["label"], str(r["distrust_after"])) for r in records.values() if r["distrust_after"]))

adb = a.find_adb()
dev = a.pick_device(adb, None)
store = a.load_system_store(dev)
now = a.datetime.now(a.timezone.utc)
buckets = {"fine": 0, "expired": 0, "distrusted": 0, "removed": 0}
samples = {k: [] for k in buckets}
for cert in store.by_fingerprint.values():
    sha1 = hashlib.sha1(cert.der).hexdigest()
    rec = records.get(sha1)
    expired = cert.not_after <= now
    if rec and (rec["server_auth"] != "CKT_NSS_TRUSTED_DELEGATOR" or (rec["distrust_after"] and rec["distrust_after"] <= now)):
        buckets["distrusted"] += 1
        samples["distrusted"].append((rec["label"], rec["server_auth"], str(rec["distrust_after"])))
    elif rec is None:
        key = "expired" if expired else "removed"
        buckets[key] += 1
        samples[key].append(cert.common_name)
    else:
        buckets["fine"] += 1
print("device:", buckets)
for k in ("distrusted", "removed"):
    print(k, "->")
    for s in samples[k][:10]:
        print("   ", s)
