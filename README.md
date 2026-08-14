# Antidetect Sync Server

Serveur de synchronisation des profils pour le fork QtUndetectableBroswer
(repo principal : https://github.com/Narcxs/QtUndetectableBroswer).

Stockage opaque de blobs de profils **chiffrés côté client** (zero-knowledge :
le serveur ne peut pas lire les cookies/sessions). Auth Bearer obligatoire.

## Contenu

- `sync_server.py` — API FastAPI : upload/download de blobs par profil,
  versioning (5 dernières versions), verrous indicatifs
- `requirements.txt` — fastapi + uvicorn (épinglés)
- `antidetect-sync.service` — unité systemd durcie
- `Caddyfile` — reverse proxy HTTPS auto (Let's Encrypt)
- **`deploy.md`** — guide de déploiement VPS complet (~30 min, ~5 €/mois)

## Déploiement

Suivre `deploy.md`. En résumé : VPS Ubuntu → venv python → `pip install -r
requirements.txt` → `SYNC_TOKEN` dans `/etc/antidetect-sync.env` → systemd →
Caddy pour le HTTPS. Config client : `sync_config.json` côté lanceur
(`{"server": "https://sync.votredomaine", "token": "..."}`).

⚠️ Repo à garder **privé**.
