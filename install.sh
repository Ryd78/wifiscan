#!/usr/bin/env bash
# Installe les dépendances et la commande `wifiscan`
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Installation des dépendances (scapy, nmap)..."
sudo apt update -qq
sudo apt install -y python3-scapy nmap

chmod +x "$DIR/wifiscan.py"
sudo ln -sf "$DIR/wifiscan.py" /usr/local/bin/wifiscan

echo "Installé. Lance : sudo wifiscan"
