"""A tiny fake CERT r4.2 release, same file names, headers and answer-key layout,
so the adapter can be tested without the 1 GB archive. Values are random; only
the format is meant to match."""
from __future__ import annotations

import io
import os
import random
import tarfile
from datetime import datetime, timedelta

ROLES = ["Salesman", "ITAdmin", "Engineer"]
HOSTS = ["google.com", "dtaa.com", "msn.com", "yahoo.com", "bbc.co.uk"]


def _fmt(dt):
    return dt.strftime("%m/%d/%Y %H:%M:%S")


def build(root: str, n_users: int = 30, n_days: int = 20, seed: int = 0, as_tar: bool = True):
    rnd = random.Random(seed)
    users = [f"U{i:04d}" for i in range(n_users)]
    role = {u: ROLES[i % len(ROLES)] for i, u in enumerate(users)}
    insider = users[0]
    files = {k: [] for k in ("logon", "device", "file", "email", "http")}
    answer_lines, ctr = [], [0]

    def eid():
        ctr[0] += 1
        return "{%04d-%06d}" % (ctr[0] // 1000, ctr[0])

    start = datetime(2010, 1, 4)
    for d in range(n_days):
        day = start + timedelta(days=d)
        for u in users:
            pc = f"PC-{users.index(u):04d}"
            t = day + timedelta(hours=8, minutes=rnd.randint(0, 40))
            files["logon"].append([eid(), _fmt(t), u, pc, "Logon"])
            for _ in range(rnd.randint(5, 12)):
                t += timedelta(minutes=rnd.randint(2, 30))
                files["http"].append([eid(), _fmt(t), u, pc, "http://" + rnd.choice(HOSTS) + "/x/y",
                                      "word " * rnd.randint(3, 30)])
            t += timedelta(minutes=5)
            files["email"].append([eid(), _fmt(t), u, pc, f"a{rnd.randint(0,9)}@dtaa.com", "", "",
                                   f"{u}@dtaa.com", str(rnd.randint(10000, 40000)), "0", "hello " * 5])
            t += timedelta(hours=rnd.randint(6, 8))
            files["logon"].append([eid(), _fmt(t), u, pc, "Logoff"])
        if d >= n_days - 3:                       # insider: 3 malicious nights
            t = day + timedelta(hours=23, minutes=10)
            pc = "PC-0000"
            for kind, row in (("logon", [eid(), _fmt(t), insider, pc, "Logon"]),
                              ("device", [eid(), _fmt(t + timedelta(minutes=2)), insider, pc, "Connect"]),
                              ("http", [eid(), _fmt(t + timedelta(minutes=5)), insider, pc,
                                        "http://wikileaks.org/upload", "secret " * 400]),
                              ("device", [eid(), _fmt(t + timedelta(minutes=9)), insider, pc, "Disconnect"])):
                files[kind].append(row)
                answer_lines.append(",".join([kind] + row))

    headers = {
        "logon": "id,date,user,pc,activity", "device": "id,date,user,pc,activity",
        "file": "id,date,user,pc,filename,content",
        "email": "id,date,user,pc,to,cc,bcc,from,size,attachments,content",
        "http": None,                              # r4.2's http.csv has no header row
    }
    data = {}
    for k, rows in files.items():
        rows.sort(key=lambda r: datetime.strptime(r[1], "%m/%d/%Y %H:%M:%S"))
        body = "\n".join(",".join(r) for r in rows) + "\n"
        data[f"r4.2/{k}.csv"] = ((headers[k] + "\n") if headers[k] else "") + body
    data["r4.2/LDAP/2010-01.csv"] = "employee_name,user_id,email,role,projects,business_unit,functional_unit,department,team,supervisor\n" + \
        "\n".join(f"Name {u},{u},{u}@dtaa.com,{role[u]},,1,FU,Dept,Team,Boss" for u in users) + "\n"
    answers = {
        "answers/insiders.csv": "dataset,scenario,details,user,start,end\n"
                                f"4.2,1,r4.2-1-{insider}.csv,{insider},x,y\n"
                                "5.2,1,r5.2-1-ZZZ0000.csv,ZZZ0000,x,y\n",
        f"answers/r4.2-1/r4.2-1-{insider}.csv": "\n".join(answer_lines) + "\n",
    }
    os.makedirs(root, exist_ok=True)
    if as_tar:
        def _tar(path, members):
            with tarfile.open(path, "w:bz2") as tf:
                for name, text in members.items():
                    b = text.encode()
                    ti = tarfile.TarInfo(name)
                    ti.size = len(b)
                    tf.addfile(ti, io.BytesIO(b))
        _tar(os.path.join(root, "r4.2.tar.bz2"), data)
        _tar(os.path.join(root, "answers.tar.bz2"), answers)
        return os.path.join(root, "r4.2.tar.bz2"), os.path.join(root, "answers.tar.bz2"), insider
    for name, text in {**data, **answers}.items():
        p = os.path.join(root, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(text)
    return os.path.join(root, "r4.2"), os.path.join(root, "answers"), insider
