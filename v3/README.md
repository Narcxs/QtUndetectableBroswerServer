# Sync server v3.1 — comptes + équipes (dev)

Backend multi-utilisateurs : comptes + blobs scopés (v3.0), puis équipes,
partage de profils, rôles admin/member et clés enveloppées (v3.1).
Zero-knowledge : le serveur ne voit jamais le mot de passe, les data_keys,
ni le contenu des blobs ou des clés (enveloppées côté client).
**Ne remplace pas la v2** (`C:\chromium\cloud\sync_server.py`, prod actuelle).

## Lancement dev

```bash
# venv python (fastapi/uvicorn déjà installés dedans)
SYNC_PORT=8899 SYNC_STORE=C:/Temp/sync-v3 \
  C:/chromium/venv/Scripts/python.exe -u C:/chromium/cloud/v3/sync_server.py
```

Variables d'env : `SYNC_HOST` (défaut `127.0.0.1`), `SYNC_PORT` (défaut `8799`),
`SYNC_STORE` (défaut `<script>/store`), `SYNC_DB` (défaut `<store>/app.db`),
`SYNC_TOKEN` (optionnel — voir « mode legacy »).

## Flux client (zero-knowledge)

Le mot de passe ne quitte jamais le client. Dérivation côté client :

```python
import base64, hashlib, os
salt = os.urandom(16)
data_key = hashlib.scrypt(pw.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
# data_key : RESTE LOCALE — chiffre les blobs de profil et enveloppe les clés
# de profil (wrapped_key) ; jamais transmise.
verifier = hashlib.scrypt(pw.encode(), salt=salt + b"|auth",
                          n=16384, r=8, p=1, dklen=32)
# register : POST /auth/register {email, salt_b64, verifier_b64, display_name?}
# login    : POST /auth/login    {email, verifier_b64}  -> {token, expires_at}
# Le serveur ne stocke que sha256(verifier).
```

Ensuite : `Authorization: Bearer <token>` sur toutes les routes métier.

## Endpoints

| Route | Accès | Rôle |
|---|---|---|
| `GET /health` | public | `{"ok": true, "version": "3.1"}` |
| `POST /auth/register` | public | 201 `{account_id}` ; 409 si email pris |
| `POST /auth/login` | public | `{token, expires_at}` (30 j) ; 401 sinon |
| `GET /auth/salt?email=...` | public | `{"salt_b64"}` du compte (nouvelle machine) ; 404 si inconnu |
| `GET /me` | compte | infos du compte |
| `GET /profiles` | compte | MES profils (dernière version/date/taille) |
| `PUT /profiles/{name}/blob` | owner du profil ou **admin** de l'équipe liée | nouvelle version ; 403 member ; 403 au-delà de `max_profiles` (défaut 20) |
| `GET .../blob/latest`, `.../versions` | owner ou membre de l'équipe liée | lecture ; 404 si rien/pas d'accès |
| `POST/GET .../lock`, `POST .../unlock` | idem lecture | verrou **indicatif** en mémoire |
| `POST /teams` | compte | crée l'équipe (owner ajouté admin) → `{team_id}` |
| `GET /teams` | compte | mes équipes + membres (email, role) |
| `POST /teams/{id}/members` | owner de l'équipe | `{email, role}` ; 404 email inconnu ; 409 déjà membre ; 403 sièges (`max_members`, **hors owner**) |
| `DELETE /teams/{id}/members/{user_id}` | owner de l'équipe | retire un membre (le owner n'est pas retirable) |
| `POST /profiles/{name}/share` | owner du profil (et membre de l'équipe cible) | lie le profil à l'équipe ; crée le record si besoin |
| `POST /profiles/{name}/unshare` | owner du profil | délie (redevient privé) |
| `GET /shared/profiles` | compte | profils partagés avec moi `[{name, owner_email, team, effective_role}]` |
| `POST /profiles/{name}/keys` | owner du profil ou admin de l'équipe liée | upsert `{user_id, wrapped_key_b64}` (cible = owner ou membre de l'équipe) |
| `GET /profiles/{name}/key` | owner ou membre de l'équipe liée | MA wrapped_key ; 404 si aucune ; 403 si pas d'accès |

Blobs : `<store>/<account_id_OWNER>/profiles/<name>/v<N>.bin` + `latest.json`
(un profil partagé reste physiquement chez son owner ; la table `profiles`
fait la jointure). Rétention 5 versions. Noms : `^[a-zA-Z0-9_-]+$`.

## Règles d'accès (résumé tranché)

- Profil **non partagé** (`team_id NULL`) : privé à l'owner, 404 pour tous les
  autres (comportement v3.0 inchangé).
- Profil **partagé** : lecture = owner + tous les membres de l'équipe ;
  écriture (PUT) = owner + **admins** seulement ; member = read-only (403).
- L'owner d'une équipe est ajouté comme membre `admin` à la création, mais ne
  consomme **pas** de siège (`max_members` compte les membres hors owner).
- Résolution d'un profil par nom : MON record → mon dossier (données pré-v3.1)
  → record partagé à une de mes équipes → sinon privé à moi (404 en lecture).

## Mode legacy (migration prod v2)

Si `SYNC_TOKEN` est défini au démarrage, ce token global reste accepté sur les
routes blobs avec le **store global v2** (`<store>/<name>/...`) : les anciens
clients v2 continuent de fonctionner le temps de la migration. Les routes
comptes/équipes répondent 403 avec le token legacy. Sans `SYNC_TOKEN` :
comptes uniquement.

## Limites v3.1

- Verrous en mémoire (perdus au redémarrage) — indicatifs, comme v2.
- Quota profils = nombre de dossiers du compte dans le store.
- Collision de nom possible si DEUX owners partagent un profil du même nom à la
  même équipe : le premier (par `created_at`) gagne — à trancher en v3.2
  (refus au share, ou adressage par owner).
- `GET versions` sur un profil inexistant/inaccessible → `200 {"versions":[]}`
  (pas 404) — ne fuite aucune donnée, codé ainsi depuis la v2.
- SQLite mono-process (1 worker uvicorn). Multi-instance → Postgres plus tard.
- Login à protéger par HTTPS en prod (verifier = équivalent mot de passe côté
  auth) + rate-limit à ajouter.
- Pas de suppression de compte/équipe, pas de logout (sessions 30 j), pas de
  révocation de clé enveloppée (upsert/remplacement seulement).
