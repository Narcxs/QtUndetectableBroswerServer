#!/usr/bin/env python3
# Serveur de synchro v3.1 — comptes + equipes/partage/roles/cles enveloppees.
# (v3.0 : comptes, tokens, blobs scopes, quotas — comportement INCHANGE.)
# NE REMPLACE PAS la v2 (C:\chromium\cloud\sync_server.py), prod actuelle.
#
# ZERO-KNOWLEDGE : le mot de passe ne quitte JAMAIS le client.
#   client : data_key = scrypt(password, salt, n=16384, r=8, p=1)   (locale,
#            jamais transmise — chiffre les blobs et envelope les cles de profil)
#            verifier = scrypt(password, salt + b"|auth", ...)      (transmis)
#   serveur : stocke sha256(verifier) uniquement. Ni le mot de passe, ni les
#   data_key, ni les cles de profil en clair, ni les blobs ne sont lisibles ici
#   (profile_keys = cles ENVELOPPEES par la data_key de chaque utilisateur).
#
# STOCKAGE : blobs scopes par compte PROPRITAIRE du profil :
#   <store>/<account_id_owner>/profiles/<name>/v<N>.bin + latest.json
#   (mecanique v2 : retention 5, verrou indicatif). Un profil partage reste
#   chez son owner — la table profiles fait la jointure pour les membres.
#   DB SQLite : env SYNC_DB (defaut <store>/app.db), schema cree au demarrage
#   (CREATE TABLE IF NOT EXISTS : safe sur une DB v3.0 existante).
#
# CONFIG (env) : SYNC_HOST (defaut 127.0.0.1), SYNC_PORT (defaut 8799),
#   SYNC_STORE (defaut <dossier du script>/store), SYNC_DB.
#   COMPAT LEGACY : si SYNC_TOKEN est defini, ce token global reste accepte sur
#   les routes blobs avec le store GLOBAL v2 (<store>/<name>/...) — le temps de
#   migrer la prod. Les routes comptes/equipes exigent un vrai compte (403 en
#   legacy). Sans SYNC_TOKEN : comptes only.
#
# Dev : SYNC_PORT=8899 SYNC_STORE=/tmp/x python -u sync_server.py
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

HOST = os.environ.get("SYNC_HOST", "127.0.0.1")
PORT = int(os.environ.get("SYNC_PORT", "8799"))
STORE_DIR = Path(os.environ.get(
    "SYNC_STORE", str(Path(__file__).resolve().parent / "store")))
DB_PATH = Path(os.environ.get("SYNC_DB", str(STORE_DIR / "app.db")))
LEGACY_TOKEN = os.environ.get("SYNC_TOKEN", "")  # vide = comptes only
KEEP_VERSIONS = 5       # retention : 5 dernieres versions par profil
SESSION_DAYS = 30       # duree de vie d'un token de session

NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")           # anti path-traversal
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")  # validation basique

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  account_id      TEXT PRIMARY KEY,
  email           TEXT NOT NULL UNIQUE,
  display_name    TEXT,
  salt_b64        TEXT NOT NULL,        -- sel scrypt du client (pas secret)
  verifier_sha256 TEXT NOT NULL,        -- sha256(verifier) ; JAMAIS le mot de passe
  max_profiles    INTEGER NOT NULL DEFAULT 20,
  created_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,          -- 32 octets aleatoires en hex
  account_id TEXT NOT NULL REFERENCES users(account_id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS teams (
  team_id     TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  owner_id    TEXT NOT NULL REFERENCES users(account_id),
  max_members INTEGER NOT NULL DEFAULT 5,   -- sieges HORS owner
  created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS team_members (
  team_id  TEXT NOT NULL REFERENCES teams(team_id),
  user_id  TEXT NOT NULL REFERENCES users(account_id),
  role     TEXT NOT NULL CHECK(role IN ('admin','member')),
  added_at TEXT NOT NULL,
  UNIQUE(team_id, user_id)
);
-- record cree au 1er PUT d'un profil (ou au share) ; PK (owner_id, name)
CREATE TABLE IF NOT EXISTS profiles (
  name       TEXT NOT NULL,
  owner_id   TEXT NOT NULL REFERENCES users(account_id),
  team_id    TEXT REFERENCES teams(team_id),   -- NULL = prive (v3.0)
  created_at TEXT NOT NULL,
  PRIMARY KEY (owner_id, name)
);
-- cles de profil ENVELOPPEES (le serveur ne peut pas les dechiffrer)
CREATE TABLE IF NOT EXISTS profile_keys (
  team_id         TEXT NOT NULL,
  profile_name    TEXT NOT NULL,
  user_id         TEXT NOT NULL,
  wrapped_key_b64 TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  PRIMARY KEY (team_id, profile_name, user_id)
);
"""


def _now():
    return datetime.now(timezone.utc)


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db() as con:
        con.executescript(SCHEMA)


app = FastAPI(title="antidetect sync v3.1")

_locks = {}  # "scope/name" -> {"holder","since"} (memoire, indicatif)

_bearer = HTTPBearer(auto_error=False)


class Ctx:
    """Contexte de requete resolu : mode legacy (token global) ou compte."""

    def __init__(self, legacy, base, scope, account=None):
        self.legacy = legacy
        self.base = base          # dossier racine des profils de CE compte
        self.scope = scope        # "legacy" ou account_id
        self.account = account    # row sqlite (None en legacy)


def resolve(cred: HTTPAuthorizationCredentials = Depends(_bearer)) -> Ctx:
    """Exige Authorization: Bearer <token>. Token global SYNC_TOKEN (si defini)
    -> contexte legacy v2 (store global) ; sinon token de session -> compte."""
    if cred is None or cred.scheme.lower() != "bearer":
        raise HTTPException(401, "token Bearer manquant",
                            headers={"WWW-Authenticate": "Bearer"})
    tok = cred.credentials
    if LEGACY_TOKEN and hmac.compare_digest(tok, LEGACY_TOKEN):
        return Ctx(True, STORE_DIR, "legacy")
    with db() as con:
        row = con.execute(
            "SELECT u.account_id, u.email, u.display_name, u.max_profiles,"
            "       u.created_at, s.expires_at"
            " FROM sessions s JOIN users u ON u.account_id = s.account_id"
            " WHERE s.token = ?", (tok,)).fetchone()
    if row is None:
        raise HTTPException(401, "session inconnue",
                            headers={"WWW-Authenticate": "Bearer"})
    if datetime.fromisoformat(row["expires_at"]) < _now():
        raise HTTPException(401, "session expiree",
                            headers={"WWW-Authenticate": "Bearer"})
    return Ctx(False, STORE_DIR / row["account_id"] / "profiles",
               row["account_id"], row)


def require_account(ctx: Ctx) -> Ctx:
    """Les routes comptes/equipes n'ont pas de sens avec le token legacy."""
    if ctx.legacy:
        raise HTTPException(403, "mode legacy (SYNC_TOKEN) : pas de compte")
    return ctx


def _b64(s, field, lo, hi):
    """Decode du base64 strict ou 400 ; impose une taille brute dans [lo, hi]."""
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:
        raise HTTPException(400, f"{field}: base64 invalide")
    if not lo <= len(raw) <= hi:
        raise HTTPException(400, f"{field}: taille inattendue ({len(raw)} o)")
    return raw


def _check_name(name):
    if not NAME_RE.fullmatch(name):
        raise HTTPException(400, "nom de profil invalide")


def _profile_dir(base, name) -> Path:
    _check_name(name)
    return base / name


def _versions(d: Path):
    """Liste triee par numero : [(version, Path), ...]."""
    out = []
    if d.is_dir():
        for f in d.glob("v*.bin"):
            m = re.fullmatch(r"v(\d+)\.bin", f.name)
            if m:
                out.append((int(m.group(1)), f))
    out.sort(key=lambda t: t[0])
    return out


def resolve_profile(ctx: Ctx, name: str):
    """Resout le profil {name} pour l'appelant. Retourne
    (base_dir, role_effectif, profile_row|None) avec role dans
    'owner' | 'admin' | 'member'. Ordre :
      1. record profiles(me, name)            -> mon store, 'owner'
      2. pas de record mais mon dossier existe (donnees v3.0) -> idem
      3. record d'un AUTRE compte partage a une de mes equipes -> store de
         l'OWNER, mon role dans l'equipe ('admin'|'member')
      4. sinon -> mon store, 'owner', None (GET -> 404 ; PUT -> nouveau prive)
    """
    if ctx.legacy:
        return ctx.base, "owner", None
    me = ctx.account["account_id"]
    with db() as con:
        rec = con.execute("SELECT * FROM profiles WHERE owner_id = ?"
                          " AND name = ?", (me, name)).fetchone()
        if rec is not None:
            return ctx.base, "owner", rec
        if (ctx.base / name).is_dir():
            return ctx.base, "owner", None  # donnees pre-v3.1 sans record
        rec = con.execute(
            "SELECT p.*, m.role AS my_role FROM profiles p"
            " JOIN team_members m ON m.team_id = p.team_id AND m.user_id = ?"
            " WHERE p.name = ? AND p.team_id IS NOT NULL"
            " ORDER BY p.created_at LIMIT 1", (me, name)).fetchone()
        if rec is not None:
            return STORE_DIR / rec["owner_id"] / "profiles", rec["my_role"], rec
    return ctx.base, "owner", None


class RegisterIn(BaseModel):
    email: str
    salt_b64: str
    verifier_b64: str
    display_name: str | None = None


class LoginIn(BaseModel):
    email: str
    verifier_b64: str


class TeamIn(BaseModel):
    name: str


class MemberIn(BaseModel):
    email: str
    role: str


class ShareIn(BaseModel):
    team_id: str


class KeyIn(BaseModel):
    user_id: str
    wrapped_key_b64: str


# ---------------------------------------------------------------- auth / compte

@app.get("/health")
def health():
    return {"ok": True, "version": "3.1"}


@app.post("/auth/register", status_code=201)
def register(body: RegisterIn):
    email = body.email.strip().lower()
    if not EMAIL_RE.fullmatch(email):
        raise HTTPException(400, "email invalide")
    _b64(body.salt_b64, "salt_b64", 8, 64)
    verifier = _b64(body.verifier_b64, "verifier_b64", 16, 128)
    account_id = secrets.token_hex(16)
    try:
        with db() as con:
            con.execute(
                "INSERT INTO users (account_id, email, display_name, salt_b64,"
                " verifier_sha256, max_profiles, created_at)"
                " VALUES (?, ?, ?, ?, ?, 20, ?)",
                (account_id, email, body.display_name, body.salt_b64,
                 hashlib.sha256(verifier).hexdigest(), _now().isoformat()))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "email deja enregistre")
    print(f"[serveur] register {email} -> {account_id}", flush=True)
    return {"account_id": account_id}


@app.post("/auth/login")
def login(body: LoginIn):
    email = body.email.strip().lower()
    verifier = _b64(body.verifier_b64, "verifier_b64", 16, 128)
    digest = hashlib.sha256(verifier).hexdigest()
    with db() as con:
        row = con.execute("SELECT account_id, verifier_sha256 FROM users"
                          " WHERE email = ?", (email,)).fetchone()
    # message identique email inconnu / mauvais verifier (pas d'enumeration)
    if row is None or not hmac.compare_digest(row["verifier_sha256"], digest):
        raise HTTPException(401, "identifiants invalides")
    token = secrets.token_hex(32)
    exp = _now() + timedelta(days=SESSION_DAYS)
    with db() as con:
        con.execute("INSERT INTO sessions (token, account_id, created_at,"
                    " expires_at) VALUES (?, ?, ?, ?)",
                    (token, row["account_id"], _now().isoformat(),
                     exp.isoformat()))
        con.execute("DELETE FROM sessions WHERE expires_at < ?",
                    (_now().isoformat(),))  # menage paresseux
    print(f"[serveur] login {email}", flush=True)
    return {"token": token, "expires_at": exp.isoformat()}


@app.get("/auth/salt")
def auth_salt(email: str):
    """Sel scrypt du compte (PUBLIC : necessaire pour deriver verifier/data_key
    depuis une nouvelle machine). Ne revele que l'existence du compte —
    a proteger par rate-limit en prod."""
    with db() as con:
        row = con.execute("SELECT salt_b64 FROM users WHERE email = ?",
                          (email.strip().lower(),)).fetchone()
    if row is None:
        raise HTTPException(404, "compte inconnu")
    return {"salt_b64": row["salt_b64"]}


@app.get("/me")
def me(ctx: Ctx = Depends(resolve)):
    require_account(ctx)
    return {"email": ctx.account["email"],
            "display_name": ctx.account["display_name"],
            "max_profiles": ctx.account["max_profiles"],
            "created_at": ctx.account["created_at"]}


# ---------------------------------------------------------------- profils/blobs

@app.get("/profiles")
def list_profiles(ctx: Ctx = Depends(resolve)):
    """MES profils (derniere version/date/taille). Les profils partages avec
    moi sont sur /shared/profiles."""
    out = []
    if ctx.base.is_dir():
        for d in sorted(ctx.base.iterdir()):
            if not d.is_dir() or not NAME_RE.fullmatch(d.name):
                continue
            latest = d / "latest.json"
            if not latest.is_file():
                continue
            v = json.loads(latest.read_text(encoding="utf-8"))["version"]
            f = d / f"v{v}.bin"
            out.append({"name": d.name, "latest_version": v,
                        "size": f.stat().st_size if f.is_file() else 0,
                        "modified": datetime.fromtimestamp(
                            f.stat().st_mtime).isoformat()
                        if f.is_file() else None})
    return {"profiles": out}


@app.put("/profiles/{name}/blob")
async def put_blob(name: str, request: Request, ctx: Ctx = Depends(resolve)):
    """Ecriture : owner du profil OU admin de l'equipe liee. member = 403."""
    data = await request.body()
    if not data:
        raise HTTPException(400, "blob vide")
    _check_name(name)
    base, role, rec = resolve_profile(ctx, name)
    if role == "member":
        raise HTTPException(403, "profil partage en lecture seule : "
                                 "push reserve au owner et aux admins")
    d = base / name
    if not ctx.legacy and rec is None and not d.is_dir():
        # nouveau profil -> quota du compte (les profils existants passent)
        maxp = ctx.account["max_profiles"]
        current = sum(1 for p in ctx.base.iterdir()
                      if p.is_dir() and NAME_RE.fullmatch(p.name)) \
            if ctx.base.is_dir() else 0
        if current >= maxp:
            raise HTTPException(
                403, f"quota de profils atteint ({current}/{maxp}) : "
                     f"creation de '{name}' refusee")
    d.mkdir(parents=True, exist_ok=True)
    existing = _versions(d)
    version = existing[-1][0] + 1 if existing else 1
    (d / f"v{version}.bin").write_bytes(data)
    (d / "latest.json").write_text(json.dumps({"version": version}),
                                   encoding="utf-8")
    for v, f in _versions(d)[:-KEEP_VERSIONS]:  # retention
        f.unlink(missing_ok=True)
    if not ctx.legacy and rec is None:
        with db() as con:  # record du profil au 1er PUT
            con.execute("INSERT OR IGNORE INTO profiles (name, owner_id,"
                        " team_id, created_at) VALUES (?, ?, NULL, ?)",
                        (name, ctx.account["account_id"], _now().isoformat()))
    scope = rec["owner_id"] if rec is not None else ctx.scope
    print(f"[serveur] PUT {scope}/{name} -> v{version} ({len(data)} o)",
          flush=True)
    return {"version": version}


@app.get("/profiles/{name}/blob/latest")
def get_latest(name: str, ctx: Ctx = Depends(resolve)):
    """Lecture : owner, ou membre (admin|member) de l'equipe liee."""
    _check_name(name)
    base, _role, _rec = resolve_profile(ctx, name)
    d = base / name
    latest = d / "latest.json"
    if not latest.is_file():
        raise HTTPException(404, "aucune version pour ce profil")
    version = json.loads(latest.read_text(encoding="utf-8"))["version"]
    blob = d / f"v{version}.bin"
    if not blob.is_file():
        raise HTTPException(404, "blob de la derniere version introuvable")
    return {"version": version,
            "data": base64.b64encode(blob.read_bytes()).decode("ascii")}


@app.get("/profiles/{name}/versions")
def list_versions(name: str, ctx: Ctx = Depends(resolve)):
    _check_name(name)
    base, _role, _rec = resolve_profile(ctx, name)
    out = []
    for v, f in _versions(base / name):
        st = f.stat()
        out.append({"version": v, "size": st.st_size,
                    "modified": datetime.fromtimestamp(st.st_mtime).isoformat()})
    return {"versions": out}


def _lock_key(ctx: Ctx, name: str) -> str:
    _base, _role, rec = resolve_profile(ctx, name)
    scope = ("legacy" if ctx.legacy else
             (rec["owner_id"] if rec is not None else ctx.account["account_id"]))
    return f"{scope}/{name}"


@app.post("/profiles/{name}/lock")
def lock(name: str, holder: str = "inconnu", ctx: Ctx = Depends(resolve)):
    key = _lock_key(ctx, name)
    _locks[key] = {"holder": holder, "since": datetime.now().timestamp()}
    print(f"[serveur] LOCK {key} par {holder}", flush=True)
    return {"locked": True, "holder": holder}


@app.post("/profiles/{name}/unlock")
def unlock(name: str, ctx: Ctx = Depends(resolve)):
    key = _lock_key(ctx, name)
    _locks.pop(key, None)
    print(f"[serveur] UNLOCK {key}", flush=True)
    return {"locked": False}


@app.get("/profiles/{name}/lock")
def lock_state(name: str, ctx: Ctx = Depends(resolve)):
    key = _lock_key(ctx, name)
    info = _locks.get(key)
    if not info:
        return {"locked": False}
    return {"locked": True, "holder": info["holder"], "since": info["since"],
            "age_seconds": round(datetime.now().timestamp() - info["since"], 1)}


# ---------------------------------------------------------------- equipes

@app.post("/teams", status_code=201)
def create_team(body: TeamIn, ctx: Ctx = Depends(resolve)):
    require_account(ctx)
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "nom d'equipe vide")
    me = ctx.account["account_id"]
    team_id = secrets.token_hex(8)
    with db() as con:
        con.execute("INSERT INTO teams (team_id, name, owner_id, max_members,"
                    " created_at) VALUES (?, ?, ?, 5, ?)",
                    (team_id, name, me, _now().isoformat()))
        con.execute("INSERT INTO team_members (team_id, user_id, role,"
                    " added_at) VALUES (?, ?, 'admin', ?)",
                    (team_id, me, _now().isoformat()))  # owner = admin
    print(f"[serveur] team '{name}' ({team_id}) par {ctx.account['email']}",
          flush=True)
    return {"team_id": team_id, "name": name}


@app.get("/teams")
def my_teams(ctx: Ctx = Depends(resolve)):
    require_account(ctx)
    me = ctx.account["account_id"]
    out = []
    with db() as con:
        teams = con.execute(
            "SELECT t.* FROM teams t"
            " LEFT JOIN team_members m ON m.team_id = t.team_id"
            "   AND m.user_id = ?"
            " WHERE t.owner_id = ? OR m.user_id IS NOT NULL"
            " ORDER BY t.created_at", (me, me)).fetchall()
        for t in teams:
            members = con.execute(
                "SELECT m.user_id, u.email, m.role FROM team_members m"
                " JOIN users u ON u.account_id = m.user_id"
                " WHERE m.team_id = ? ORDER BY m.added_at",
                (t["team_id"],)).fetchall()
            out.append({"team_id": t["team_id"], "name": t["name"],
                        "is_owner": t["owner_id"] == me,
                        "max_members": t["max_members"],
                        "members": [dict(m) for m in members]})
    return {"teams": out}


@app.post("/teams/{team_id}/members", status_code=201)
def add_member(team_id: str, body: MemberIn, ctx: Ctx = Depends(resolve)):
    require_account(ctx)
    if body.role not in ("admin", "member"):
        raise HTTPException(400, "role invalide (admin|member)")
    email = body.email.strip().lower()
    me = ctx.account["account_id"]
    with db() as con:
        team = con.execute("SELECT * FROM teams WHERE team_id = ?",
                           (team_id,)).fetchone()
        if team is None:
            raise HTTPException(404, "equipe inconnue")
        if team["owner_id"] != me:
            raise HTTPException(403, "seul le owner de l'equipe gere les membres")
        user = con.execute("SELECT account_id FROM users WHERE email = ?",
                           (email,)).fetchone()
        if user is None:
            raise HTTPException(404, "aucun compte avec cet email")
        uid = user["account_id"]
        if con.execute("SELECT 1 FROM team_members WHERE team_id = ?"
                       " AND user_id = ?", (team_id, uid)).fetchone():
            raise HTTPException(409, "deja membre de l'equipe")
        seats = con.execute(
            "SELECT COUNT(*) AS c FROM team_members"
            " WHERE team_id = ? AND user_id != ?",
            (team_id, team["owner_id"])).fetchone()["c"]  # owner hors quota
        if seats >= team["max_members"]:
            raise HTTPException(403, f"quota de sieges atteint "
                                     f"({seats}/{team['max_members']})")
        con.execute("INSERT INTO team_members (team_id, user_id, role,"
                    " added_at) VALUES (?, ?, ?, ?)",
                    (team_id, uid, body.role, _now().isoformat()))
    print(f"[serveur] team {team_id} += {email} ({body.role})", flush=True)
    return {"team_id": team_id, "user_id": uid, "role": body.role}


@app.delete("/teams/{team_id}/members/{user_id}")
def del_member(team_id: str, user_id: str, ctx: Ctx = Depends(resolve)):
    require_account(ctx)
    me = ctx.account["account_id"]
    with db() as con:
        team = con.execute("SELECT * FROM teams WHERE team_id = ?",
                           (team_id,)).fetchone()
        if team is None:
            raise HTTPException(404, "equipe inconnue")
        if team["owner_id"] != me:
            raise HTTPException(403, "seul le owner de l'equipe gere les membres")
        if user_id == me:
            raise HTTPException(400, "le owner ne peut pas etre retire")
        cur = con.execute("DELETE FROM team_members WHERE team_id = ?"
                          " AND user_id = ?", (team_id, user_id))
        if cur.rowcount == 0:
            raise HTTPException(404, "pas membre de cette equipe")
    return {"removed": True, "user_id": user_id}


# ---------------------------------------------------------------- partage

@app.post("/profiles/{name}/share")
def share(name: str, body: ShareIn, ctx: Ctx = Depends(resolve)):
    """Lie le profil a une equipe. Owner du profil seul ; il doit etre owner
    ou membre de l'equipe cible. Cree le record si profil jamais pousse."""
    require_account(ctx)
    _check_name(name)
    me = ctx.account["account_id"]
    with db() as con:
        team = con.execute("SELECT * FROM teams WHERE team_id = ?",
                           (body.team_id,)).fetchone()
        if team is None:
            raise HTTPException(404, "equipe inconnue")
        member = con.execute("SELECT 1 FROM team_members WHERE team_id = ?"
                             " AND user_id = ?", (body.team_id, me)).fetchone()
        if member is None and team["owner_id"] != me:
            raise HTTPException(403, "je ne suis pas membre de cette equipe")
        rec = con.execute("SELECT 1 FROM profiles WHERE owner_id = ?"
                          " AND name = ?", (me, name)).fetchone()
        if rec is None:
            con.execute("INSERT INTO profiles (name, owner_id, team_id,"
                        " created_at) VALUES (?, ?, ?, ?)",
                        (name, me, body.team_id, _now().isoformat()))
        else:
            con.execute("UPDATE profiles SET team_id = ? WHERE owner_id = ?"
                        " AND name = ?", (body.team_id, me, name))
    print(f"[serveur] share {me}/{name} -> team {body.team_id}", flush=True)
    return {"shared": True, "team_id": body.team_id}


@app.post("/profiles/{name}/unshare")
def unshare(name: str, ctx: Ctx = Depends(resolve)):
    require_account(ctx)
    _check_name(name)
    me = ctx.account["account_id"]
    with db() as con:
        cur = con.execute("UPDATE profiles SET team_id = NULL"
                          " WHERE owner_id = ? AND name = ?", (me, name))
        if cur.rowcount == 0:
            raise HTTPException(404, "profil inconnu")
    print(f"[serveur] unshare {me}/{name}", flush=True)
    return {"shared": False}


@app.get("/shared/profiles")
def shared_with_me(ctx: Ctx = Depends(resolve)):
    """Profils partages avec moi via mes equipes (pas les miens)."""
    require_account(ctx)
    me = ctx.account["account_id"]
    with db() as con:
        rows = con.execute(
            "SELECT p.name, u.email AS owner_email, t.name AS team,"
            "       m.role AS effective_role"
            " FROM profiles p"
            " JOIN teams t ON t.team_id = p.team_id"
            " JOIN team_members m ON m.team_id = p.team_id AND m.user_id = ?"
            " JOIN users u ON u.account_id = p.owner_id"
            " WHERE p.team_id IS NOT NULL AND p.owner_id != ?"
            " ORDER BY t.name, p.name", (me, me)).fetchall()
    return {"profiles": [dict(r) for r in rows]}


# ---------------------------------------------------------------- cles enveloppees

def _visible_profile(con, me, name, need_admin=False):
    """Record du profil visible par moi (owner, ou membre de l'equipe liee).
    need_admin=True : seuls owner|admin matchent (pour ecrire une cle)."""
    cond = "p.owner_id = ? OR m.role = 'admin'" if need_admin \
        else "p.owner_id = ? OR m.user_id IS NOT NULL"
    return con.execute(
        "SELECT p.*, m.role AS my_role FROM profiles p"
        " LEFT JOIN team_members m ON m.team_id = p.team_id AND m.user_id = ?"
        f" WHERE p.name = ? AND ({cond})"
        " ORDER BY (p.owner_id = ?) DESC LIMIT 1",
        (me, name, me, me)).fetchone()


@app.post("/profiles/{name}/keys", status_code=201)
def put_key(name: str, body: KeyIn, ctx: Ctx = Depends(resolve)):
    """Stocke (upsert) la cle enveloppee d'un utilisateur pour ce profil.
    Appelant : owner du profil ou admin de l'equipe liee. Cible : owner ou
    membre de l'equipe. Le profil doit etre partage (cle indexee par team).
    Permission verifiee AVANT la validation du payload (member = 403)."""
    require_account(ctx)
    _check_name(name)
    me = ctx.account["account_id"]
    with db() as con:
        rec = _visible_profile(con, me, name, need_admin=True)
        if rec is None:
            raise HTTPException(403, "reserve au owner du profil et aux "
                                     "admins de l'equipe liee")
        wk = _b64(body.wrapped_key_b64, "wrapped_key_b64", 16, 8192)
        if rec["team_id"] is None:
            raise HTTPException(400, "profil non partage : partagez-le avant "
                                     "de deposer des cles")
        ok = body.user_id == rec["owner_id"] or con.execute(
            "SELECT 1 FROM team_members WHERE team_id = ? AND user_id = ?",
            (rec["team_id"], body.user_id)).fetchone()
        if not ok:
            raise HTTPException(400, "user_id sans acces a ce profil")
        con.execute(
            "INSERT INTO profile_keys (team_id, profile_name, user_id,"
            " wrapped_key_b64, updated_at) VALUES (?, ?, ?, ?, ?)"
            " ON CONFLICT(team_id, profile_name, user_id)"
            " DO UPDATE SET wrapped_key_b64 = excluded.wrapped_key_b64,"
            "             updated_at = excluded.updated_at",
            (rec["team_id"], name, body.user_id, body.wrapped_key_b64,
             _now().isoformat()))
    print(f"[serveur] key {name} pour {body.user_id} (par {me})", flush=True)
    return {"stored": True, "user_id": body.user_id}


@app.get("/profiles/{name}/key")
def get_key(name: str, ctx: Ctx = Depends(resolve)):
    """MA cle enveloppee pour ce profil (403 si pas d'acces, 404 si aucune)."""
    require_account(ctx)
    _check_name(name)
    me = ctx.account["account_id"]
    with db() as con:
        rec = _visible_profile(con, me, name)
        if rec is None:
            raise HTTPException(403, "pas d'acces a ce profil")
        row = con.execute(
            "SELECT wrapped_key_b64 FROM profile_keys"
            " WHERE team_id = ? AND profile_name = ? AND user_id = ?",
            (rec["team_id"], name, me)).fetchone()
    if row is None:
        raise HTTPException(404, "aucune cle enveloppee pour moi")
    return {"wrapped_key_b64": row["wrapped_key_b64"]}


init_db()  # schema cree a l'import (couvre aussi `uvicorn sync_server:app`)

if __name__ == "__main__":
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[serveur] sync v3.1 sur http://{HOST}:{PORT} "
          f"(store: {STORE_DIR}, db: {DB_PATH})"
          + (" + legacy SYNC_TOKEN actif" if LEGACY_TOKEN else ""), flush=True)
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
