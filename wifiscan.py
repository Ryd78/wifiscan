#!/usr/bin/env python3
"""wifiscan - scanne le réseau local (le tien) et liste les appareils connectés.

Usage légal uniquement : ce script doit être utilisé sur un réseau dont tu es
propriétaire ou administrateur, ou avec l'autorisation explicite de son
propriétaire. Scanner un réseau qui n'est pas le tien sans autorisation peut
être illégal selon ta juridiction.

Fonctionnement :
  1. Détecte ta propre adresse IP et le sous-réseau local.
  2. Envoie des requêtes ARP à chaque adresse du sous-réseau (scapy) pour
     voir qui répond : c'est la méthode standard pour lister les appareils
     d'un réseau local, bien plus fiable qu'un ping.
  3. Pour chaque appareil trouvé, identifie le fabricant à partir des 3
     premiers octets de l'adresse MAC (OUI = Organizationally Unique
     Identifier), via la base locale de nmap si présente, sinon une
     estimation par mots-clés.
  4. Optionnel (--os, nécessite root + nmap) : tente de deviner le système
     d'exploitation de chaque appareil.
"""
import argparse
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys

__version__ = "1.0.0"

GREEN, RED, YELLOW, CYAN, BOLD, RESET = (
    "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[1m", "\033[0m"
)

NMAP_MAC_PREFIXES_PATHS = [
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
]

# Mots-clés -> catégorie d'appareil, utilisés quand on a trouvé un fabricant
# mais qu'on veut une étiquette plus parlante que le nom brut du fabricant.
CATEGORY_HINTS = [
    (re.compile(r"apple", re.I), "Apple (iPhone/iPad/Mac)"),
    (re.compile(r"samsung", re.I), "Samsung (mobile/TV)"),
    (re.compile(r"huawei", re.I), "Huawei"),
    (re.compile(r"xiaomi", re.I), "Xiaomi"),
    (re.compile(r"raspberry\s*pi", re.I), "Raspberry Pi"),
    (re.compile(r"espressif", re.I), "ESP32/ESP8266 (IoT)"),
    (re.compile(r"amazon", re.I), "Amazon (Echo/Fire TV)"),
    (re.compile(r"google", re.I), "Google (Chromecast/Nest)"),
    (re.compile(r"sonos", re.I), "Sonos (enceinte connectée)"),
    (re.compile(r"intel|realtek|tp-link|netgear|d-link|asus|belkin", re.I), "Carte réseau / routeur"),
    (re.compile(r"microsoft", re.I), "Microsoft (PC/Xbox)"),
    (re.compile(r"sony", re.I), "Sony (PlayStation/TV)"),
    (re.compile(r"nintendo", re.I), "Nintendo (Switch)"),
    (re.compile(r"hewlett|hp inc", re.I), "HP (imprimante/PC)"),
]


def run(cmd):
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return res.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def require_root():
    if os.geteuid() != 0:
        print(f"{RED}Ce script doit être lancé en root (sudo) pour envoyer des requêtes ARP.{RESET}")
        sys.exit(1)


def detect_local_network(iface=None):
    """Détecte l'IP locale, l'interface et le sous-réseau au format CIDR."""
    out = run(["ip", "-o", "-4", "addr", "show"])
    candidates = []
    for line in out.splitlines():
        parts = line.split()
        try:
            idx = parts.index("inet")
        except ValueError:
            continue
        cidr = parts[idx + 1]
        name = parts[1]
        if name == "lo":
            continue
        candidates.append((name, cidr))

    if iface:
        candidates = [c for c in candidates if c[0] == iface]

    if not candidates:
        return None, None

    name, cidr = candidates[0]
    net = ipaddress.ip_network(cidr, strict=False)
    return name, net


def load_mac_vendor_db():
    """Charge la base locale de nmap (préfixe MAC -> fabricant), si présente."""
    for path in NMAP_MAC_PREFIXES_PATHS:
        if os.path.isfile(path):
            db = {}
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        prefix, _, vendor = line.partition(" ")
                        if prefix:
                            db[prefix.upper()] = vendor.strip()
                return db
            except OSError:
                continue
    return {}


def vendor_for_mac(mac, db):
    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    vendor = db.get(prefix)
    return vendor or "Fabricant inconnu"


def category_for_vendor(vendor):
    for pattern, label in CATEGORY_HINTS:
        if pattern.search(vendor):
            return label
    return vendor


def arp_scan(network, iface, timeout=3):
    """Scan ARP du sous-réseau avec scapy. Renvoie une liste de dicts."""
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError:
        print(f"{RED}Le module scapy est requis : sudo apt install python3-scapy{RESET}")
        sys.exit(1)

    arp = ARP(pdst=str(network))
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    kwargs = {"timeout": timeout, "verbose": False}
    if iface:
        kwargs["iface"] = iface

    answered, _ = srp(packet, **kwargs)

    devices = []
    for _, received in answered:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    return devices


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def os_guess(ip):
    """Devine l'OS d'un appareil avec nmap -O (nécessite root + nmap)."""
    if not shutil.which("nmap"):
        return None
    out = run(["nmap", "-O", "--osscan-guess", ip])
    m = re.search(r"OS details: (.+)", out)
    if m:
        return m.group(1).strip()
    m = re.search(r"Aggressive OS guesses: (.+)", out)
    if m:
        return m.group(1).split(",")[0].strip()
    return None


def scan(iface=None, timeout=3, guess_os=False):
    name, network = detect_local_network(iface)
    if not network:
        print(f"{RED}Impossible de détecter une interface réseau active.{RESET}")
        sys.exit(1)

    print(f"{BOLD}Interface :{RESET} {name}    {BOLD}Réseau :{RESET} {network}")
    print("Scan en cours (quelques secondes)...\n")

    vendor_db = load_mac_vendor_db()
    devices = arp_scan(network, name, timeout=timeout)

    results = []
    for d in devices:
        vendor = vendor_for_mac(d["mac"], vendor_db)
        entry = {
            "ip": d["ip"],
            "mac": d["mac"],
            "vendor": vendor,
            "type": category_for_vendor(vendor),
            "hostname": resolve_hostname(d["ip"]),
        }
        if guess_os:
            entry["os"] = os_guess(d["ip"])
        results.append(entry)

    results.sort(key=lambda e: tuple(int(p) for p in e["ip"].split(".")))
    return name, network, results


def report(name, network, results):
    print(f"{BOLD}{len(results)} appareil(s) trouvé(s) sur {network}{RESET}\n")
    for e in results:
        host = f" ({e['hostname']})" if e.get("hostname") else ""
        print(f"{CYAN}{e['ip']:<15}{RESET}{host}")
        print(f"   MAC    : {e['mac']}")
        print(f"   Type   : {e['type']}")
        if e.get("os"):
            print(f"   OS     : {e['os']}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Scanne ton propre réseau Wi-Fi/local et liste les appareils connectés."
    )
    parser.add_argument("-i", "--iface", help="interface à utiliser (ex: wlan0)")
    parser.add_argument("-t", "--timeout", type=int, default=3, help="délai du scan ARP en secondes (défaut: 3)")
    parser.add_argument("--os", action="store_true", help="tente de deviner l'OS de chaque appareil (plus lent)")
    parser.add_argument("--json", action="store_true", help="sortie JSON")
    parser.add_argument("--version", action="version", version=f"wifiscan {__version__}")
    args = parser.parse_args()

    if sys.platform != "linux":
        print("wifiscan est conçu pour Linux.", file=sys.stderr)
        return 1

    require_root()

    name, network, results = scan(iface=args.iface, timeout=args.timeout, guess_os=args.os)

    if args.json:
        print(json.dumps({"interface": name, "network": str(network), "devices": results}, indent=2, ensure_ascii=False))
    else:
        report(name, network, results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
