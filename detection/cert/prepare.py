"""Stream CERT r4.2 into a compact, sampled event file.

    python -m detection.cert.prepare --data r4.2.tar.bz2 --answers answers.tar.bz2 \
        --out data/cert/r42_events.csv.gz

Standard library only, so it runs wherever the 1+ GB archive lives without
extracting it (r4.2 is ~15 GB unpacked, ~90% of that is http.csv content).

WHAT IS KEPT
  Unit of analysis is the user-day, the usual unit in the CERT literature. A
  user-day is kept if
    - it contains at least one event listed in the answer key (every malicious
      day is kept), or
    - a deterministic hash of (user, date) falls under --keep (default 1/12).
  Sampling whole days keeps every within-day sequence intact; sampling events
  would break the window and entropy features.

WHAT IS WRITTEN per event (content is reduced to its length, never stored)
  session      user|YYYY-MM-DD
  user, date, secs (seconds since midnight), hour
  tool         logon | logoff | usb_connect | usb_disconnect | file | email | http
  target       coarse "who/what": pc (logon/logoff; own vs other PC is decided
               in evaluate.py, which knows the training split), file extension,
               email internal/external, http host
  nbytes       email size; 0 otherwise
  nrows        email attachment count; recipient count is folded into target
  text_len     length of the free-text content field
  is_attack    event id listed in the answer key
  scenario     1/2/3 for insiders' events, blank otherwise
A second file <out>.ldap.csv maps user -> role (latest LDAP snapshot) and
functional_unit, and <out>.insiders.csv lists the r4.2 insiders.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import os
import sys
import tarfile
import time
from datetime import datetime

EVENT_FILES = ("logon.csv", "device.csv", "file.csv", "email.csv", "http.csv")
INTERNAL_DOMAIN = "dtaa.com"
OUT_COLS = ["session", "user", "date", "secs", "hour", "tool", "target",
            "nbytes", "nrows", "text_len", "is_attack", "scenario"]


# --------------------------------------------------------------------------- io
def _iter_members(src):
    """Yield (name, text_stream) for every file under a tar(.bz2) or a folder."""
    if os.path.isdir(src):
        for root, _, files in os.walk(src):
            for f in sorted(files):
                p = os.path.join(root, f)
                with open(p, "r", encoding="utf-8", errors="replace", newline="") as fh:
                    yield p.replace("\\", "/"), fh
        return
    with tarfile.open(src, mode="r|*") as tf:            # streaming: no seeks, no extract
        for m in tf:
            if not m.isfile():
                continue
            fh = tf.extractfile(m)
            if fh is None:
                continue
            buf = io.BufferedReader(_Unseekable(fh), buffer_size=1 << 20)
            yield m.name, io.TextIOWrapper(buf, encoding="utf-8", errors="replace", newline="")


class _Unseekable(io.RawIOBase):
    """Stream-mode tar members cannot seek and lack seekable(); TextIOWrapper asks."""

    def __init__(self, fh):
        self.fh = fh

    def readable(self):
        return True

    def seekable(self):
        return False

    def readinto(self, b):
        data = self.fh.read(len(b))
        b[:len(data)] = data
        return len(data)


def _parse_date(s: str) -> datetime:
    return datetime.strptime(s.strip(), "%m/%d/%Y %H:%M:%S")


def _keep_day(user: str, day: str, keep: float) -> bool:
    h = hashlib.blake2b(f"{user}|{day}".encode(), digest_size=8).digest()
    return int.from_bytes(h, "big") / 2 ** 64 < keep


# ---------------------------------------------------------------------- answers
def load_answers(src: str, dataset: str = "4.2"):
    """-> (malicious event ids, malicious (user, day) set, insiders rows, id->scenario)."""
    insiders, details = [], {}
    for name, fh in _iter_members(src):
        base = name.rsplit("/", 1)[-1]
        if base == "insiders.csv":
            for row in csv.DictReader(fh):
                if str(row.get("dataset", "")).strip() in (dataset, "r" + dataset):
                    insiders.append(row)
        elif base.startswith("r" + dataset + "-") and base.endswith(".csv"):
            details[base] = fh.read()
    wanted = {row["details"].strip(): row for row in insiders}
    ids, days, scen = set(), set(), {}
    for base, text in details.items():
        row = wanted.get(base)
        if row is None:
            continue
        for line in text.splitlines():
            f = line.split(",", 5)
            if len(f) < 4 or not f[1].startswith("{"):
                continue
            ids.add(f[1])
            scen[f[1]] = str(row["scenario"]).strip()
            try:
                days.add((f[3].strip(), _parse_date(f[2]).strftime("%Y-%m-%d")))
            except ValueError:
                pass
    if not insiders:
        raise SystemExit(f"No r{dataset} rows in insiders.csv under {src}")
    missing = set(wanted) - set(details)
    if missing:
        print(f"  warning: {len(missing)} detail files listed in insiders.csv not found", file=sys.stderr)
    return ids, days, insiders, scen


# ----------------------------------------------------------------------- events
def _event_fields(kind: str, f: dict):
    """-> (tool, target, nbytes, nrows, text_len)."""
    content = f.get("content", "") or ""
    if kind == "logon.csv":
        act = f.get("activity", "").strip().lower()
        return ("logon" if act.startswith("logon") else "logoff"), f.get("pc", ""), 0, 0, 0
    if kind == "device.csv":
        act = f.get("activity", "").strip().lower()
        return ("usb_connect" if act.startswith("connect") else "usb_disconnect"), "usb", 0, 0, 0
    if kind == "file.csv":
        fn = f.get("filename", "")
        ext = fn.rsplit(".", 1)[-1].lower() if "." in fn else "(none)"
        return "file", ext, 0, 0, len(content)
    if kind == "email.csv":
        rcpts = [a.strip().lower() for k in ("to", "cc", "bcc")
                 for a in (f.get(k, "") or "").split(";") if a.strip()]
        ext = sum(1 for a in rcpts if not a.endswith("@" + INTERNAL_DOMAIN))
        target = "internal" if ext == 0 else ("external_only" if ext == len(rcpts) else "mixed")
        try:
            size = int(float(f.get("size", 0) or 0))
        except ValueError:
            size = 0
        att = f.get("attachments", "") or ""
        try:
            n_att = int(float(att))
        except ValueError:                       # later releases list file names
            n_att = len([a for a in att.split(";") if a.strip()])
        return "email", target, size, n_att, len(content)
    if kind == "http.csv":
        url = f.get("url", "")
        host = url.split("://", 1)[-1].split("/", 1)[0].lower()
        return "http", host, 0, 0, len(content)
    raise KeyError(kind)


DEFAULT_HEADERS = {
    "logon.csv": ["id", "date", "user", "pc", "activity"],
    "device.csv": ["id", "date", "user", "pc", "activity"],
    "file.csv": ["id", "date", "user", "pc", "filename", "content"],
    "email.csv": ["id", "date", "user", "pc", "to", "cc", "bcc", "from", "size", "attachments", "content"],
    "http.csv": ["id", "date", "user", "pc", "url", "content"],
}


def _rows(kind, fh):
    """Fast split: every field before the last is comma-free in r4.2, and the last
    (content) is free text, so split with maxsplit and keep the tail whole."""
    first = fh.readline()
    if first.lower().startswith("id,"):
        header = [h.strip().lower() for h in first.strip().split(",")]
        lines = fh
    else:
        header = DEFAULT_HEADERS[kind]
        lines = _chain(first, fh)
    n = len(header)
    for line in lines:
        parts = line.rstrip("\r\n").split(",", n - 1)
        if len(parts) < 3:
            continue
        yield dict(zip(header, parts))


def _chain(first, rest):
    yield first
    yield from rest


def prepare(data: str, answers: str, out: str, keep: float = 1 / 12, dataset: str = "4.2") -> dict:
    t0 = time.time()
    mal_ids, mal_days, insiders, scen = load_answers(answers, dataset)
    print(f"answer key: {len(insiders)} insiders, {len(mal_ids)} malicious events, "
          f"{len(mal_days)} malicious user-days")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    ldap: dict = {}
    counts = {"read": 0, "kept": 0, "attack_kept": 0}
    found = set()
    keep_cache: dict = {}
    with gzip.open(out, "wt", newline="", compresslevel=6) as gz:
        w = csv.writer(gz)
        w.writerow(OUT_COLS)
        for name, fh in _iter_members(data):
            base = name.rsplit("/", 1)[-1]
            if "/ldap/" in name.lower() and base.endswith(".csv"):
                for row in csv.DictReader(fh):
                    row = {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}
                    snap = base[:-4]
                    uid = row.get("user_id")
                    if uid and (uid not in ldap or snap >= ldap[uid][0]):
                        ldap[uid] = (snap, row.get("role", ""), row.get("functional_unit", ""),
                                     row.get("department", ""))
                continue
            if base not in EVENT_FILES:
                continue
            found.add(base)
            t1, n_read, n_kept = time.time(), 0, 0
            for f in _rows(base, fh):
                n_read += 1
                user = f.get("user", "").strip()
                ds = f.get("date", "").strip()
                if len(ds) != 19:                           # MM/DD/YYYY HH:MM:SS
                    continue
                day = f"{ds[6:10]}-{ds[0:2]}-{ds[3:5]}"     # slicing: ~20x faster than strptime
                eid = f.get("id", "").strip()
                attack = eid in mal_ids
                key = (user, day)
                keep_it = keep_cache.get(key)
                if keep_it is None:
                    keep_it = keep_cache[key] = key in mal_days or _keep_day(user, day, keep)
                if not (attack or keep_it):
                    continue
                try:
                    dt = _parse_date(ds)
                except ValueError:
                    continue
                tool, target, nb, nr, tl = _event_fields(base, f)
                w.writerow([f"{user}|{day}", user, day,
                            dt.hour * 3600 + dt.minute * 60 + dt.second, dt.hour,
                            tool, target, nb, nr, tl, int(attack), scen.get(eid, "")])
                n_kept += 1
                counts["attack_kept"] += attack
            counts["read"] += n_read
            counts["kept"] += n_kept
            print(f"  {base:<11} read {n_read:>11,}  kept {n_kept:>10,}  ({time.time() - t1:,.0f}s)", flush=True)
    missing = set(EVENT_FILES) - found
    if missing:
        raise SystemExit(f"event files not found in {data}: {sorted(missing)}")
    with open(out + ".ldap.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["user", "snapshot", "role", "functional_unit", "department"])
        for uid, v in sorted(ldap.items()):
            w.writerow([uid, *v])
    with open(out + ".insiders.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(insiders[0].keys()))
        w.writeheader()
        w.writerows(insiders)
    counts.update(users_ldap=len(ldap), insiders=len(insiders), malicious_events=len(mal_ids),
                  seconds=round(time.time() - t0))
    if counts["attack_kept"] < len(mal_ids):
        print(f"  note: {len(mal_ids) - counts['attack_kept']} answer-key events not found in the data",
              file=sys.stderr)
    print(f"done in {counts['seconds']:,}s -> {out}  ({os.path.getsize(out) / 1e6:,.1f} MB)")
    return counts


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data", required=True, help="r4.2.tar.bz2 or the extracted r4.2 folder")
    ap.add_argument("--answers", required=True, help="answers.tar.bz2 or the extracted answers folder")
    ap.add_argument("--out", default=os.path.join("data", "cert", "r42_events.csv.gz"))
    ap.add_argument("--keep", type=float, default=1 / 12, help="share of benign user-days kept")
    ap.add_argument("--dataset", default="4.2")
    a = ap.parse_args()
    prepare(a.data, a.answers, a.out, a.keep, a.dataset)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
