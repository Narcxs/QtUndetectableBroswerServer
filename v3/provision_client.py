#!/usr/bin/env python3
# provision_client.py — crée/provisionne un compte client sur le serveur v3 :
# compte + équipe + ajout membre + partage du profil + clé enveloppée.
# Usage (env requises : ADMIN_PASSWORD) :
#   python provision_client.py <email_client> <mdp_client> <profil> [--team NOM] [--role member|admin]
import base64
import hashlib
import json
import os
import sys
import urllib.request
import urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADMIN_CFG = os.path.join(ROOT, "staging_config.json")
SCRYPT = dict(n=16384, r=8, p=1, dklen=32)


def req(method, url, token=None, payload=None):
    data = None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if payload is not None:
        data = json.dumps(payload).encode()
    r = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            body = resp.read().decode()
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"detail": body}


def derive(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, **SCRYPT)


def main():
    if len(sys.argv) < 4:
        print("usage: provision_client.py <email> <mdp> <profil> [--team NOM] [--role member|admin]")
        return 64
    email, password, profile = sys.argv[1:4]
    team_name = "client"
    role = "member"
    if "--team" in sys.argv:
        team_name = sys.argv[sys.argv.index("--team") + 1]
    if "--role" in sys.argv:
        role = sys.argv[sys.argv.index("--role") + 1]
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if not admin_password:
        print("env ADMIN_PASSWORD requise", file=sys.stderr)
        return 64

    cfg = json.load(open(ADMIN_CFG, encoding="utf-8"))
    server = cfg["server"].rstrip("/")
    admin_email = cfg["email"]
    admin_pw = admin_password.encode()

    # 1) Login admin (si le token du config est mort)
    st, salt_d = req("GET", f"{server}/auth/salt?email={admin_email}")
    admin_salt = base64.b64decode(salt_d["salt_b64"])
    admin_verifier = hashlib.scrypt(admin_pw, salt=admin_salt + b"|auth", **SCRYPT)
    st, r = req("POST", f"{server}/auth/login", payload={
        "email": admin_email, "verifier_b64": base64.b64encode(admin_verifier).decode()})
    if st != 200:
        print(f"login admin échoué ({st}): {r}")
        return 1
    admin_token = r["token"]
    admin_data_key = derive(admin_password, admin_salt)

    # 2) Compte client (register si besoin) + sel client
    client_salt = os.urandom(16)
    client_verifier = hashlib.scrypt(password.encode(), salt=client_salt + b"|auth", **SCRYPT)
    st, r = req("POST", f"{server}/auth/register", payload={
        "email": email,
        "salt_b64": base64.b64encode(client_salt).decode(),
        "verifier_b64": base64.b64encode(client_verifier).decode(),
        "display_name": email.split("@")[0]})
    if st == 409:
        st, salt_d = req("GET", f"{server}/auth/salt?email={email}")
        client_salt = base64.b64decode(salt_d["salt_b64"])
        print(f"[provision] compte existant réutilisé: {email}")
    elif st not in (200, 201):
        print(f"register échoué ({st}): {r}")
        return 1
    else:
        print(f"[provision] compte créé: {email}")
    client_id = r.get("account_id")  # présent dans la réponse register (201)
    client_data_key = derive(password, client_salt)

    # Login client -> token (+ account_id via /me, v3.1+)
    client_verifier = hashlib.scrypt(password.encode(), salt=client_salt + b"|auth", **SCRYPT)
    st, r = req("POST", f"{server}/auth/login", payload={
        "email": email, "verifier_b64": base64.b64encode(client_verifier).decode()})
    if st != 200:
        print(f"login client échoué ({st}): {r}")
        return 1
    client_token = r["token"]
    if not client_id:
        st, me = req("GET", f"{server}/me", token=client_token)
        client_id = me.get("account_id")

    # 3) Équipe (réutilise la 1ʳᵉ équipe de l'admin, ou la crée)
    st, teams = req("GET", f"{server}/teams", token=admin_token)
    team = None
    for t in (teams.get("teams") or teams if isinstance(teams, list) else []):
        team = t
        break
    if team is None:
        st, team = req("POST", f"{server}/teams", token=admin_token,
                       payload={"name": team_name})
        print(f"[provision] équipe créée: {team_name} ({team.get('team_id')})")
    team_id = team.get("team_id") or team.get("id")

    # 4) Ajout du membre
    st, r = req("POST", f"{server}/teams/{team_id}/members", token=admin_token,
                payload={"email": email, "role": role})
    if st not in (200, 201, 409):
        print(f"ajout membre échoué ({st}): {r}")
        return 1
    print(f"[provision] {email} ajouté à l'équipe (role={role})")

    # 5) Partage du profil
    st, r = req("POST", f"{server}/profiles/{profile}/share", token=admin_token,
                payload={"team_id": team_id})
    if st not in (200, 201):
        print(f"partage échoué ({st}): {r}")
        return 1
    print(f"[provision] profil '{profile}' partagé")

    # 6) Clé du profil enveloppée pour le client
    from Crypto.Cipher import AES
    nonce = os.urandom(12)
    ct, tag = AES.new(client_data_key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(
        admin_data_key)
    wrapped = base64.b64encode(nonce + ct + tag).decode()
    st, r = req("POST", f"{server}/profiles/{profile}/keys", token=admin_token,
                payload={"user_id": client_id, "wrapped_key_b64": wrapped})
    if st not in (200, 201):
        print(f"clé enveloppée échouée ({st}): {r}")
        return 1
    print(f"[provision] clé enveloppée déposée pour {email}")

    print(json.dumps({"ok": True, "client_email": email, "team_id": team_id,
                      "profile": profile, "role": role}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
