#!/usr/bin/env python3
# Serveur de synchro cloud v2 — FastAPI + uvicorn.
# v2 = v1 (comportement metier inchange) + securisation pour Internet :
#   - Auth Bearer OBLIGATOIRE sur tous les endpoints sauf /health.
#     Token = variable d'env SYNC_TOKEN ; REFUS DE DEMARRER si absente.
#   - Bind configurable : SYNC_HOST (defaut 127.0.0.1), SYNC_PORT (defaut 8799).
#   - Store configurable : SYNC_STORE (defaut <dossier du script>/store — en
#     local : C:\chromium\cloud\store ; sur le VPS : /var/lib/antidetect-sync/store).
#   - Noms de profil restreints a ^[a-zA-Z0-9_-]+$ (anti path-traversal).
# Stockage : <store>/<profil>/v<N>.bin + latest.json, retention 5 versions,
# verrou logique INDICATIF en memoire. Les blobs sont chiffres cote client
# (zero-knowledge) : le serveur ne stocke que des octets opaques.
#
# Local : SYNC_TOKEN=... python -u sync_server.py
# VPS   : voir vps/deploy.md (systemd + Caddy HTTPS).
import base64
import hmac
import json
import os
import re
import time
from datetime import datetime
from pathlib import Path

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

SYNC_TOKEN = os.environ.get("SYNC_TOKEN", "")
if not SYNC_TOKEN:
    raise SystemExit("[serveur] SYNC_TOKEN absente — refus de demarrer "
                     "(auth Bearer obligatoire sur tous les endpoints sauf /health)")

HOST = os.environ.get("SYNC_HOST", "127.0.0.1")
PORT = int(os.environ.get("SYNC_PORT", "8799"))
STORE_DIR = Path(os.environ.get(
    "SYNC_STORE", str(Path(__file__).resolve().parent / "store")))
KEEP_VERSIONS = 5  # retention : on ne garde que les 5 dernieres versions

app = FastAPI(title="antidetect sync v2")

_locks = {}  # nom profil -> {"holder": str, "since": timestamp} (memoire, indicatif)

NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")

_bearer = HTTPBearer(auto_error=False)


def require_token(cred: HTTPAuthorizationCredentials = Depends(_bearer)):
    """401 si le header Authorization: Bearer <token> est absent ou invalide.
    Comparaison en temps constant (compare_digest)."""
    ok = (cred is not None and cred.scheme.lower() == "bearer"
          and hmac.compare_digest(cred.credentials, SYNC_TOKEN))
    if not ok:
        raise HTTPException(401, "token Bearer manquant ou invalide",
                            headers={"WWW-Authenticate": "Bearer"})


AUTH = [Depends(require_token)]  # a appliquer sur toutes les routes sauf /health


def _profile_dir(name: str) -> Path:
    """Valide le nom (anti path-traversal) et retourne le dossier de stockage."""
    if not NAME_RE.fullmatch(name):
        raise HTTPException(400, "nom de profil invalide")
    return STORE_DIR / name


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


@app.get("/health")
def health():
    return {"ok": True}


@app.put("/profiles/{name}/blob", dependencies=AUTH)
async def put_blob(name: str, request: Request):
    data = await request.body()
    if not data:
        raise HTTPException(400, "blob vide")
    d = _profile_dir(name)
    d.mkdir(parents=True, exist_ok=True)
    existing = _versions(d)
    version = existing[-1][0] + 1 if existing else 1
    (d / f"v{version}.bin").write_bytes(data)
    (d / "latest.json").write_text(json.dumps({"version": version}),
                                   encoding="utf-8")
    for v, f in _versions(d)[:-KEEP_VERSIONS]:  # retention
        f.unlink(missing_ok=True)
    print(f"[serveur] PUT {name} -> v{version} ({len(data)} o)", flush=True)
    return {"version": version}


@app.get("/profiles/{name}/blob/latest", dependencies=AUTH)
def get_latest(name: str):
    d = _profile_dir(name)
    latest = d / "latest.json"
    if not latest.is_file():
        raise HTTPException(404, "aucune version pour ce profil")
    version = json.loads(latest.read_text(encoding="utf-8"))["version"]
    blob = d / f"v{version}.bin"
    if not blob.is_file():
        raise HTTPException(404, "blob de la derniere version introuvable")
    return {"version": version,
            "data": base64.b64encode(blob.read_bytes()).decode("ascii")}


@app.get("/profiles/{name}/versions", dependencies=AUTH)
def list_versions(name: str):
    d = _profile_dir(name)
    out = []
    for v, f in _versions(d):
        st = f.stat()
        out.append({"version": v, "size": st.st_size,
                    "modified": datetime.fromtimestamp(st.st_mtime).isoformat()})
    return {"versions": out}


@app.post("/profiles/{name}/lock", dependencies=AUTH)
def lock(name: str, holder: str = "inconnu"):
    _profile_dir(name)  # validation du nom
    _locks[name] = {"holder": holder, "since": time.time()}
    print(f"[serveur] LOCK {name} par {holder}", flush=True)
    return {"locked": True, "holder": holder}


@app.post("/profiles/{name}/unlock", dependencies=AUTH)
def unlock(name: str):
    _profile_dir(name)
    _locks.pop(name, None)
    print(f"[serveur] UNLOCK {name}", flush=True)
    return {"locked": False}


@app.get("/profiles/{name}/lock", dependencies=AUTH)
def lock_state(name: str):
    _profile_dir(name)
    info = _locks.get(name)
    if not info:
        return {"locked": False}
    return {"locked": True, "holder": info["holder"], "since": info["since"],
            "age_seconds": round(time.time() - info["since"], 1)}


if __name__ == "__main__":
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[serveur] sync v2 sur http://{HOST}:{PORT} (store: {STORE_DIR}) "
          f"— auth Bearer active", flush=True)
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
