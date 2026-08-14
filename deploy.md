# Déploiement VPS — serveur de synchro antidetect (cloud v2)

Objectif : `https://sync.ton-domaine` qui sert la synchro des profils, chiffrée
zero-knowledge côté client, authentifiée par token Bearer. Durée : ~30 min.

Contenu de ce dossier (`cloud\vps\`) :

| Fichier | Rôle |
|---|---|
| `sync_server.py` | Le serveur (v2, auth Bearer). Copie de `C:\chromium\cloud\sync_server.py` |
| `requirements.txt` | Deps python épinglées (fastapi, uvicorn) |
| `antidetect-sync.service` | Unité systemd |
| `Caddyfile` | Reverse proxy HTTPS auto (Let's Encrypt) |
| `deploy.md` | Ce guide |

---

## 1. VPS + DNS

1. Crée un VPS **Ubuntu 24.04** chez Hetzner (CX22 ~4 €/mois) ou Contabo — 1 vCPU /
   2 Go RAM suffisent largement (le serveur ne fait que stocker des blobs).
2. Note l'IPv4 du VPS. Chez ton registrar, crée un enregistrement **DNS de type A** :
   `sync.ton-domaine` → IPv4 du VPS. Attends la propagation :
   `dig +short sync.ton-domaine` doit répondre l'IP.
3. Connecte-toi : `ssh root@<IP>` (les commandes ci-dessous sont à faire sur le VPS).

## 2. Paquets

```bash
apt update && apt upgrade -y
apt install -y python3-venv caddy ufw
```

(Si `caddy` est introuvable — dépôt Ubuntu modifié — utilise le dépôt officiel :
https://caddyserver.com/docs/install#debian-ubuntu-raspbian)

Pare-feu (SSH + HTTP/HTTPS pour Caddy, rien d'autre — le 8799 reste interne) :

```bash
ufw allow OpenSSH
ufw allow 80,443/tcp
ufw --force enable
```

## 3. Utilisateur dédié + dossiers

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin syncsrv
mkdir -p /opt/antidetect-sync /var/lib/antidetect-sync/store
chown -R syncsrv:syncsrv /var/lib/antidetect-sync
```

## 4. Copie des fichiers

Depuis ta machine Windows (Git Bash) :

```bash
scp C:/chromium/cloud/vps/{sync_server.py,requirements.txt,antidetect-sync.service,Caddyfile} root@<IP>:/tmp/
```

Sur le VPS :

```bash
mv /tmp/sync_server.py /tmp/requirements.txt /opt/antidetect-sync/
# antidetect-sync.service et Caddyfile restent dans /tmp jusqu'aux étapes 6-7
```

## 5. Environnement python

```bash
python3 -m venv /opt/antidetect-sync/venv
/opt/antidetect-sync/venv/bin/pip install -r /opt/antidetect-sync/requirements.txt
```

## 6. Token + fichier d'environnement

```bash
openssl rand -hex 32        # <- ton SYNC_TOKEN, garde-le (il ira aussi côté client)
```

Crée `/etc/antidetect-sync.env` (remplace les valeurs) :

```bash
cat > /etc/antidetect-sync.env <<'EOF'
SYNC_TOKEN=COLLE_ICI_LE_HEX_DE_64_CARACTERES
SYNC_HOST=127.0.0.1
SYNC_PORT=8799
SYNC_STORE=/var/lib/antidetect-sync/store
EOF
chmod 600 /etc/antidetect-sync.env
```

⚠️ `SYNC_HOST=127.0.0.1` est volontaire : Caddy (étape 7) termine le TLS et
reverse-proxy vers ce port. N'expose jamais 8799 directement.

## 7. systemd + Caddy

```bash
cp /tmp/antidetect-sync.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now antidetect-sync
systemctl status antidetect-sync     # active (running) attendu
journalctl -u antidetect-sync -n 5   # "[serveur] sync v2 ... auth Bearer active"
```

Édite le domaine dans le Caddyfile (`sync.EXEMPLE.COM` → `sync.ton-domaine`) puis :

```bash
cp /tmp/Caddyfile /etc/caddy/Caddyfile
$EDITOR /etc/caddy/Caddyfile         # remplace sync.EXEMPLE.COM
systemctl reload caddy               # le certificat LE est obtenu en ~10 s
```

## 8. Test final (depuis le VPS ou ta machine)

```bash
TOK=$(grep '^SYNC_TOKEN=' /etc/antidetect-sync.env | cut -d= -f2)
curl -s https://sync.ton-domaine/health
#   {"ok":true}                                  <- /health : pas d'auth, normal
curl -s -o /dev/null -w '%{http_code}\n' https://sync.ton-domaine/profiles/test/versions
#   401                                          <- sans token : refusé
curl -s -H "Authorization: Bearer $TOK" https://sync.ton-domaine/profiles/test/versions
#   {"versions":[]}                              <- avec token : OK
```

## 9. Côté client (Windows)

Crée `C:\chromium\sync_config.json` :

```json
{"server": "https://sync.ton-domaine", "token": "LE_MEME_HEX_QUE_SYNC_TOKEN"}
```

Tout profil avec `"sync": true` dans son JSON passera désormais par le VPS
(`[sync] pulled vN` / `[sync] pushed vN` dans la sortie du lanceur). Sans
`sync_config.json`, le client retombe sur `http://127.0.0.1:8799` sans token
(comportement v1 local).

---

## Checklist de vérification

- [ ] `dig +short sync.ton-domaine` répond l'IP du VPS
- [ ] `ufw status` : 22, 80, 443 ouverts (8799 absent = interne seulement)
- [ ] `systemctl status antidetect-sync` → active (running), restart on-failure actif
- [ ] `journalctl -u antidetect-sync` → `sync v2 sur http://127.0.0.1:8799 ... auth Bearer active`
- [ ] `curl https://sync.ton-domaine/health` → `{"ok":true}` **sans** avertissement certificat
- [ ] `/profiles/x/versions` → **401** sans token, **200** avec
- [ ] Depuis Windows : lancement d'un profil `sync:true` → `[sync] pulled/pushed`
- [ ] `ls /var/lib/antidetect-sync/store/<profil>/` → `v1.bin`, `latest.json`…

## Notes d'exploitation

- **Zero-knowledge** : le serveur ne peut pas lire les blobs. La passphrase
  (`C:\chromium\sync_key.txt`) est la SEULE clé — sauvegarde-la ; si tu la perds,
  tous les blobs du store sont définitivement illisibles.
- **Backup** : `tar czf sync-backup.tgz /var/lib/antidetect-sync/store` suffit.
- **Rétention** : 5 dernières versions par profil (les plus vieilles sont supprimées).
- **Verrou** : `/lock` est indicatif (pas de refus de download) — v1.
- **Mise à jour** : remplacer `/opt/antidetect-sync/sync_server.py`, puis
  `systemctl restart antidetect-sync`.
- **Regénérer le token** : nouveau `openssl rand -hex 32` dans
  `/etc/antidetect-sync.env` + `systemctl restart antidetect-sync` + mettre à jour
  `sync_config.json` sur chaque client (l'ancien token = 401 partout).
