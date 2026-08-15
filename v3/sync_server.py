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
        # Migration douce : colonne is_admin (1 = peut administrer le serveur).
        try:
            con.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
        except Exception:
            pass  # colonne déjà présente
        # Migration douce : abonnement à durée (NULL = illimité).
        try:
            con.execute("ALTER TABLE users ADD COLUMN plan_expires_at TEXT")
        except Exception:
            pass
        # Migration douce : teams = groupes de profils (remarque, règles JSON, builtin).
        for ddl in ("ALTER TABLE teams ADD COLUMN remark TEXT",
                    "ALTER TABLE teams ADD COLUMN rules TEXT",
                    "ALTER TABLE teams ADD COLUMN builtin INTEGER NOT NULL DEFAULT 0"):
            try:
                con.execute(ddl)
            except Exception:
                pass
        # Groupe natif « default » : les profils sans groupe y apparaissent.
        con.execute(
            "INSERT INTO teams (team_id, name, owner_id, max_members, created_at,"
            " remark, builtin) SELECT 'default', 'Default', '', 999999, ?,"
            " 'Groupe par défaut', 1 WHERE NOT EXISTS"
            " (SELECT 1 FROM teams WHERE team_id = 'default')",
            (_now().isoformat(),))


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
            "       u.created_at, u.is_admin, u.plan_expires_at, s.expires_at"
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


def require_admin(ctx: Ctx) -> Ctx:
    """Routes d'administration serveur : exige un compte marqué is_admin=1."""
    require_account(ctx)
    if not ctx.account["is_admin"]:
        raise HTTPException(403, "réservé aux administrateurs du serveur")
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
        row = con.execute("SELECT account_id, verifier_sha256, plan_expires_at"
                          " FROM users WHERE email = ?", (email,)).fetchone()
    # message identique email inconnu / mauvais verifier (pas d'enumeration)
    if row is None or not hmac.compare_digest(row["verifier_sha256"], digest):
        raise HTTPException(401, "identifiants invalides")
    # Abonnement expire : l'acces est bloque (message clair pour l'UI).
    if row["plan_expires_at"] and datetime.fromisoformat(
            row["plan_expires_at"]) < _now():
        raise HTTPException(403, "abonnement expiré — contactez votre fournisseur")
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
    return {"account_id": ctx.account["account_id"],
            "email": ctx.account["email"],
            "display_name": ctx.account["display_name"],
            "is_admin": bool(ctx.account["is_admin"]),
            "max_profiles": ctx.account["max_profiles"],
            "plan_expires_at": ctx.account["plan_expires_at"],
            "created_at": ctx.account["created_at"]}


@app.get("/admin/users")
def admin_users(ctx: Ctx = Depends(resolve)):
    """Liste tous les comptes du serveur (réservé aux is_admin)."""
    require_admin(ctx)
    with db() as con:
        users = [dict(r) for r in con.execute(
            "SELECT account_id, email, display_name, is_admin, max_profiles,"
            " plan_expires_at, created_at FROM users ORDER BY created_at")]
        for u in users:
            u["profiles"] = [r["name"] for r in con.execute(
                "SELECT name FROM profiles WHERE owner_id=?", (u["account_id"],))]
            u["teams"] = [dict(r) for r in con.execute(
                "SELECT t.name, t.team_id, tm.role FROM team_members tm "
                "JOIN teams t ON t.team_id = tm.team_id WHERE tm.user_id=?",
                (u["account_id"],))]
            del u["account_id"]  # pas d'id interne en sortie publique
    return {"users": users}


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


# ============================================================ ADMIN CRUD (v3.2)

class UserPatch(BaseModel):
    display_name: str | None = None
    max_profiles: int | None = None
    is_admin: bool | None = None
    plan_expires_at: str | None = None  # ISO ; "" = illimité


class ResetPasswordIn(BaseModel):
    salt_b64: str
    verifier_b64: str


class TeamPatch(BaseModel):
    name: str | None = None
    max_members: int | None = None
    remark: str | None = None
    rules: str | None = None  # JSON des règles globales du groupe (appliquées client-side)


class TeamCreate(BaseModel):
    name: str
    max_members: int = 5


def _user_by_email(con, email: str):
    row = con.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if row is None:
        raise HTTPException(404, "compte inconnu")
    return row


@app.patch("/admin/users/{email}")
def admin_user_patch(email: str, body: UserPatch, ctx: Ctx = Depends(resolve)):
    """Modifie un compte (display_name, quota max_profiles, flag admin)."""
    require_admin(ctx)
    with db() as con:
        u = _user_by_email(con, email)
        if body.display_name is not None:
            con.execute("UPDATE users SET display_name = ? WHERE account_id = ?",
                        (body.display_name, u["account_id"]))
        if body.max_profiles is not None:
            if body.max_profiles < 0:
                raise HTTPException(400, "max_profiles invalide")
            con.execute("UPDATE users SET max_profiles = ? WHERE account_id = ?",
                        (body.max_profiles, u["account_id"]))
        if body.is_admin is not None:
            con.execute("UPDATE users SET is_admin = ? WHERE account_id = ?",
                        (1 if body.is_admin else 0, u["account_id"]))
        if body.plan_expires_at is not None:
            con.execute("UPDATE users SET plan_expires_at = ? WHERE account_id = ?",
                        (body.plan_expires_at or None, u["account_id"]))
    print(f"[serveur] admin patch user {email} (par {ctx.account['email']})", flush=True)
    return {"updated": True, "email": email}


@app.post("/admin/users/{email}/reset-password")
def admin_reset_password(email: str, body: ResetPasswordIn,
                         ctx: Ctx = Depends(resolve)):
    """Réinitialise le mot de passe d'un compte (admin choisit le nouveau sel +
    verifier calculés localement). ⚠️ La data_key de l'ancien mot de passe est
    perdue : les données chiffrées propres au compte deviennent illisibles ;
    les clés enveloppées (contenus partagés) doivent être re-enveloppées."""
    require_admin(ctx)
    salt = _b64(body.salt_b64, "salt_b64", 16, 16)
    verifier = _b64(body.verifier_b64, "verifier_b64", 32, 128)
    digest = hashlib.sha256(verifier).hexdigest()
    with db() as con:
        u = _user_by_email(con, email)
        con.execute("UPDATE users SET salt_b64 = ?, verifier_sha256 = ?"
                    " WHERE account_id = ?",
                    (body.salt_b64, digest, u["account_id"]))
        con.execute("DELETE FROM sessions WHERE account_id = ?",
                    (u["account_id"],))  # force un nouveau login
    print(f"[serveur] admin reset-password {email} (par {ctx.account['email']})",
          flush=True)
    return {"reset": True, "email": email}


@app.delete("/admin/users/{email}")
def admin_user_delete(email: str, ctx: Ctx = Depends(resolve)):
    """Supprime un compte : sessions, memberships, clés, records profils.
    Les blobs restent sur disque (nettoyage manuel du store possible)."""
    require_admin(ctx)
    with db() as con:
        u = _user_by_email(con, email)
        if u["account_id"] == ctx.account["account_id"]:
            raise HTTPException(400, "impossible de se supprimer soi-même")
        con.execute("DELETE FROM sessions WHERE account_id = ?", (u["account_id"],))
        con.execute("DELETE FROM team_members WHERE user_id = ?", (u["account_id"],))
        con.execute("DELETE FROM profile_keys WHERE user_id = ?", (u["account_id"],))
        con.execute("UPDATE profiles SET team_id = NULL WHERE owner_id = ?",
                    (u["account_id"],))
        con.execute("DELETE FROM profiles WHERE owner_id = ?", (u["account_id"],))
        con.execute("DELETE FROM users WHERE account_id = ?", (u["account_id"],))
    print(f"[serveur] admin delete user {email} (par {ctx.account['email']})", flush=True)
    return {"deleted": True, "note": "compte supprimé ; blobs conservés sur disque"}


@app.get("/admin/teams")
def admin_teams(ctx: Ctx = Depends(resolve)):
    """Tous les groupes de profils du serveur (avec membres + profils inclus).
    Le groupe natif 'default' affiche aussi les profils sans groupe."""
    require_admin(ctx)
    with db() as con:
        teams = [dict(r) for r in con.execute(
            "SELECT team_id, name, remark, rules, builtin, max_members, created_at"
            " FROM teams ORDER BY builtin DESC, created_at")]
        orphan = [r["name"] for r in con.execute(
            "SELECT name FROM profiles WHERE team_id IS NULL")]
        for t in teams:
            t["members"] = [dict(r) for r in con.execute(
                "SELECT u.email, tm.role FROM team_members tm"
                " JOIN users u ON u.account_id = tm.user_id"
                " WHERE tm.team_id = ?", (t["team_id"],))]
            t["profiles"] = [r["name"] for r in con.execute(
                "SELECT name FROM profiles WHERE team_id = ?", (t["team_id"],))]
            if t["team_id"] == "default":
                t["profiles"] = t["profiles"] + orphan
    return {"teams": teams}


@app.post("/admin/teams", status_code=201)
def admin_team_create(body: TeamCreate, ctx: Ctx = Depends(resolve)):
    """Crée un groupe de profils (équipe) dont l'admin est owner."""
    require_admin(ctx)
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "nom requis")
    tid = secrets.token_hex(8)
    with db() as con:
        con.execute("INSERT INTO teams (team_id, name, owner_id, max_members,"
                    " created_at) VALUES (?, ?, ?, ?, ?)",
                    (tid, name, ctx.account["account_id"], body.max_members,
                     _now().isoformat()))
    print(f"[serveur] admin create team '{name}' ({tid})", flush=True)
    return {"team_id": tid, "name": name}


@app.patch("/admin/teams/{team_id}")
def admin_team_patch(team_id: str, body: TeamPatch, ctx: Ctx = Depends(resolve)):
    """Renomme une équipe / change son quota de sièges."""
    require_admin(ctx)
    with db() as con:
        if con.execute("SELECT 1 FROM teams WHERE team_id = ?",
                       (team_id,)).fetchone() is None:
            raise HTTPException(404, "équipe inconnue")
        if body.name is not None:
            con.execute("UPDATE teams SET name = ? WHERE team_id = ?",
                        (body.name.strip(), team_id))
        if body.max_members is not None:
            if body.max_members < 0:
                raise HTTPException(400, "max_members invalide")
            con.execute("UPDATE teams SET max_members = ? WHERE team_id = ?",
                        (body.max_members, team_id))
        if body.remark is not None:
            con.execute("UPDATE teams SET remark = ? WHERE team_id = ?",
                        (body.remark, team_id))
        if body.rules is not None:
            con.execute("UPDATE teams SET rules = ? WHERE team_id = ?",
                        (body.rules, team_id))
    return {"updated": True}


@app.delete("/admin/teams/{team_id}")
def admin_team_delete(team_id: str, ctx: Ctx = Depends(resolve)):
    """Supprime une équipe : membres, liens profils (unshare), clés."""
    require_admin(ctx)
    with db() as con:
        cur = con.execute("DELETE FROM teams WHERE team_id = ?", (team_id,))
        if cur.rowcount == 0:
            raise HTTPException(404, "équipe inconnue")
        con.execute("DELETE FROM team_members WHERE team_id = ?", (team_id,))
        con.execute("UPDATE profiles SET team_id = NULL WHERE team_id = ?",
                    (team_id,))
        con.execute("DELETE FROM profile_keys WHERE team_id = ?", (team_id,))
    print(f"[serveur] admin delete team {team_id} (par {ctx.account['email']})",
          flush=True)
    return {"deleted": True}


@app.post("/admin/teams/{team_id}/members", status_code=201)
def admin_member_add(team_id: str, body: MemberIn, ctx: Ctx = Depends(resolve)):
    """Ajoute un compte à une équipe (bypass owner — admin serveur)."""
    require_admin(ctx)
    if body.role not in ("admin", "member"):
        raise HTTPException(400, "role invalide (admin|member)")
    with db() as con:
        t = con.execute("SELECT * FROM teams WHERE team_id = ?",
                        (team_id,)).fetchone()
        if t is None:
            raise HTTPException(404, "équipe inconnue")
        u = _user_by_email(con, body.email)
        if u["account_id"] == t["owner_id"]:
            raise HTTPException(400, "l'owner est déjà admin de son équipe")
        if con.execute("SELECT 1 FROM team_members WHERE team_id = ?"
                       " AND user_id = ?",
                       (team_id, u["account_id"])).fetchone():
            raise HTTPException(409, "déjà membre")
        n = con.execute("SELECT COUNT(*) AS c FROM team_members tm"
                        " JOIN teams t2 ON t2.team_id = tm.team_id"
                        " WHERE tm.team_id = ? AND tm.user_id != t2.owner_id",
                        (team_id,)).fetchone()["c"]
        if n >= t["max_members"]:
            raise HTTPException(403, f"quota de sièges atteint ({n}/{t['max_members']})")
        con.execute("INSERT INTO team_members (team_id, user_id, role, added_at)"
                    " VALUES (?, ?, ?, ?)",
                    (team_id, u["account_id"], body.role, _now().isoformat()))
    return {"added": True, "email": body.email, "role": body.role}


@app.delete("/admin/teams/{team_id}/members/{email}")
def admin_member_remove(team_id: str, email: str, ctx: Ctx = Depends(resolve)):
    """Retire un compte d'une équipe (+ ses clés enveloppées de l'équipe)."""
    require_admin(ctx)
    with db() as con:
        u = _user_by_email(con, email)
        cur = con.execute("DELETE FROM team_members WHERE team_id = ?"
                          " AND user_id = ?", (team_id, u["account_id"]))
        if cur.rowcount == 0:
            raise HTTPException(404, "pas membre de cette équipe")
        con.execute("DELETE FROM profile_keys WHERE team_id = ? AND user_id = ?",
                    (team_id, u["account_id"]))
    return {"removed": True, "email": email}


@app.post("/admin/profiles/{name}/assign")
def admin_profile_assign(name: str, body: ShareIn, ctx: Ctx = Depends(resolve)):
    """Attribue un profil (n'importe quel owner) à une équipe — admin serveur."""
    require_admin(ctx)
    _check_name(name)
    with db() as con:
        if con.execute("SELECT 1 FROM teams WHERE team_id = ?",
                       (body.team_id,)).fetchone() is None:
            raise HTTPException(404, "équipe inconnue")
        rec = con.execute("SELECT owner_id FROM profiles WHERE name = ?"
                          " ORDER BY (owner_id = ?) DESC LIMIT 1",
                          (name, ctx.account["account_id"])).fetchone()
        if rec is None:
            con.execute("INSERT INTO profiles (name, owner_id, team_id, created_at)"
                        " VALUES (?, ?, ?, ?)",
                        (name, ctx.account["account_id"], body.team_id,
                         _now().isoformat()))
        else:
            con.execute("UPDATE profiles SET team_id = ? WHERE owner_id = ?"
                        " AND name = ?", (body.team_id, rec["owner_id"], name))
    print(f"[serveur] admin assign {name} -> team {body.team_id}", flush=True)
    return {"assigned": True, "profile": name, "team_id": body.team_id}


@app.post("/admin/profiles/{name}/unassign")
def admin_profile_unassign(name: str, body: ShareIn, ctx: Ctx = Depends(resolve)):
    """Retire un profil d'une équipe."""
    require_admin(ctx)
    _check_name(name)
    with db() as con:
        cur = con.execute("UPDATE profiles SET team_id = NULL WHERE name = ?"
                          " AND team_id = ?", (name, body.team_id))
        if cur.rowcount == 0:
            raise HTTPException(404, "profil non attribué à cette équipe")
    return {"assigned": False, "profile": name}


init_db()  # schema cree a l'import (couvre aussi `uvicorn sync_server:app`)

if __name__ == "__main__":
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[serveur] sync v3.1 sur http://{HOST}:{PORT} "
          f"(store: {STORE_DIR}, db: {DB_PATH})"
          + (" + legacy SYNC_TOKEN actif" if LEGACY_TOKEN else ""), flush=True)
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
