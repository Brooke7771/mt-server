# -*- coding: utf-8 -*-
"""
Сервер лицензий Majestic Tools (для Render + бесплатная база Postgres).

Хранит ключи, их доступы, сроки и привязку к железу. Отвечает программе,
что можно открыть. Админка (в самой программе) ходит сюда по мастер-токену.

Переменные окружения на Render:
  DATABASE_URL   - строка подключения к Postgres (из Supabase/Neon)
  ADMIN_SECRET   - длинная случайная строка; её же вписать в программу как мастер-ключ
                   (можно несколько через запятую - запасные мастер-ключи)
"""
import os
import re
import secrets
import datetime as dt

import psycopg
from flask import Flask, request, jsonify

ACCESSES = ["bot", "afk", "fish"]            # что бывает под ключом (готовка и ОЗУ всегда бесплатны)
app = Flask(__name__)

DB_URL = os.environ.get("DATABASE_URL", "")
ADMIN_SECRETS = [s.strip() for s in os.environ.get("ADMIN_SECRET", "").split(",") if s.strip()]


def db():
    return psycopg.connect(DB_URL, autocommit=True)


def init_db():
    with db() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                key         TEXT PRIMARY KEY,
                name        TEXT NOT NULL DEFAULT '',
                accesses    TEXT NOT NULL DEFAULT '',   -- через запятую
                max_devices INT  NOT NULL DEFAULT 1,
                expires     TIMESTAMPTZ,                -- NULL = бессрочный
                revoked     BOOLEAN NOT NULL DEFAULT FALSE,
                note        TEXT NOT NULL DEFAULT '',
                created     TIMESTAMPTZ NOT NULL DEFAULT now()
            )""")
        c.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                key       TEXT NOT NULL REFERENCES keys(key) ON DELETE CASCADE,
                hwid      TEXT NOT NULL,
                first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
                last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
                PRIMARY KEY (key, hwid)
            )""")


try:
    if DB_URL:
        init_db()
except Exception as e:
    print("init_db error:", e)


def now():
    return dt.datetime.now(dt.timezone.utc)


def row_to_key(r):
    return {"key": r[0], "name": r[1], "accesses": [a for a in r[2].split(",") if a],
            "max_devices": r[3], "expires": r[4].isoformat() if r[4] else None,
            "revoked": r[5], "note": r[6], "created": r[7].isoformat()}


def key_status(r):
    if r[5]:
        return "revoked"
    if r[4] and r[4] < now():
        return "expired"
    return "active"


def require_admin():
    tok = request.headers.get("X-Admin", "")
    return tok and tok in ADMIN_SECRETS


# ================================================================ для программы
@app.post("/api/check")
def check():
    """Программа шлёт {key, hwid}. Отвечает, что открыть."""
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip()
    hwid = (data.get("hwid") or "").strip()[:128]
    if not key or not hwid:
        return jsonify(ok=False, reason="no_key"), 200
    with db() as c:
        r = c.execute("SELECT key,name,accesses,max_devices,expires,revoked,note,created "
                      "FROM keys WHERE key=%s", (key,)).fetchone()
        if not r:
            return jsonify(ok=False, reason="not_found"), 200
        status = key_status(r)
        if status != "active":
            return jsonify(ok=False, reason=status, name=r[1]), 200
        devs = c.execute("SELECT hwid FROM devices WHERE key=%s", (key,)).fetchall()
        hwids = {d[0] for d in devs}
        if hwid not in hwids:
            if len(hwids) >= r[3]:
                return jsonify(ok=False, reason="device_limit", name=r[1]), 200
            c.execute("INSERT INTO devices(key,hwid) VALUES(%s,%s) "
                      "ON CONFLICT DO NOTHING", (key, hwid))
        c.execute("UPDATE devices SET last_seen=now() WHERE key=%s AND hwid=%s", (key, hwid))
    return jsonify(ok=True, name=r[1], accesses=[a for a in r[2].split(",") if a],
                   expires=r[4].isoformat() if r[4] else None), 200


# ================================================================ админка
@app.get("/api/admin/ping")
def admin_ping():
    return (jsonify(ok=True) if require_admin() else (jsonify(ok=False), 403))


@app.get("/api/admin/keys")
def admin_keys():
    if not require_admin():
        return jsonify(ok=False), 403
    with db() as c:
        rows = c.execute("SELECT key,name,accesses,max_devices,expires,revoked,note,created "
                         "FROM keys ORDER BY created DESC").fetchall()
        out = []
        for r in rows:
            k = row_to_key(r)
            k["status"] = key_status(r)
            devs = c.execute("SELECT hwid,first_seen,last_seen FROM devices WHERE key=%s "
                             "ORDER BY first_seen", (r[0],)).fetchall()
            k["devices"] = [{"hwid": d[0], "first_seen": d[1].isoformat(),
                             "last_seen": d[2].isoformat()} for d in devs]
            out.append(k)
    return jsonify(ok=True, keys=out)


def gen_key():
    raw = secrets.token_hex(10).upper()
    return "MJ-" + "-".join(raw[i:i + 5] for i in range(0, 20, 5))


@app.post("/api/admin/create")
def admin_create():
    if not require_admin():
        return jsonify(ok=False), 403
    d = request.get_json(silent=True) or {}
    accesses = ",".join(a for a in d.get("accesses", []) if a in ACCESSES)
    name = (d.get("name") or "").strip()[:80]
    note = (d.get("note") or "").strip()[:300]
    max_devices = max(1, min(20, int(d.get("max_devices", 1))))
    days = d.get("days")
    expires = None if not days else now() + dt.timedelta(days=int(days))
    key = gen_key()
    with db() as c:
        c.execute("INSERT INTO keys(key,name,accesses,max_devices,expires,note) "
                  "VALUES(%s,%s,%s,%s,%s,%s)", (key, name, accesses, max_devices, expires, note))
    return jsonify(ok=True, key=key)


@app.post("/api/admin/update")
def admin_update():
    if not require_admin():
        return jsonify(ok=False), 403
    d = request.get_json(silent=True) or {}
    key = (d.get("key") or "").strip()
    sets, vals = [], []
    if "name" in d:
        sets.append("name=%s"); vals.append((d["name"] or "")[:80])
    if "note" in d:
        sets.append("note=%s"); vals.append((d["note"] or "")[:300])
    if "accesses" in d:
        sets.append("accesses=%s"); vals.append(",".join(a for a in d["accesses"] if a in ACCESSES))
    if "max_devices" in d:
        sets.append("max_devices=%s"); vals.append(max(1, min(20, int(d["max_devices"]))))
    if "revoked" in d:
        sets.append("revoked=%s"); vals.append(bool(d["revoked"]))
    if "days" in d:                              # продлить от текущего момента
        sets.append("expires=%s")
        vals.append(None if d["days"] in (None, 0, "") else now() + dt.timedelta(days=int(d["days"])))
    if not sets:
        return jsonify(ok=False, reason="nothing"), 200
    vals.append(key)
    with db() as c:
        c.execute(f"UPDATE keys SET {', '.join(sets)} WHERE key=%s", vals)
    return jsonify(ok=True)


@app.post("/api/admin/unbind")
def admin_unbind():
    """Отвязать ключ от железа (одно устройство по hwid или все сразу)."""
    if not require_admin():
        return jsonify(ok=False), 403
    d = request.get_json(silent=True) or {}
    key = (d.get("key") or "").strip()
    hwid = d.get("hwid")
    with db() as c:
        if hwid:
            c.execute("DELETE FROM devices WHERE key=%s AND hwid=%s", (key, hwid))
        else:
            c.execute("DELETE FROM devices WHERE key=%s", (key,))
    return jsonify(ok=True)


@app.post("/api/admin/delete")
def admin_delete():
    if not require_admin():
        return jsonify(ok=False), 403
    key = ((request.get_json(silent=True) or {}).get("key") or "").strip()
    with db() as c:
        c.execute("DELETE FROM keys WHERE key=%s", (key,))
    return jsonify(ok=True)


@app.get("/")
def home():
    return "Majestic Tools license server is running.", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
