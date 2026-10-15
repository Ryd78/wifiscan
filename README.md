# wifiscan

Scanne **ton propre réseau Wi-Fi/local** et liste les appareils connectés :
adresse IP, adresse MAC, fabricant/type d'appareil deviné à partir de la MAC,
nom d'hôte (si résolvable), et en option une estimation du système
d'exploitation.

## ⚠️ Usage légal uniquement

N'utilise ce script que sur un réseau dont tu es **propriétaire ou
administrateur** (ta box, ton point d'accès de test), ou avec
l'**autorisation explicite** du responsable du réseau. Scanner un réseau qui
ne t'appartient pas sans autorisation peut être illégal selon ta
juridiction.

## Comment ça marche

1. Détecte ton adresse IP locale et le sous-réseau (ex: `192.168.1.0/24`).
2. Envoie des requêtes ARP à chaque adresse du sous-réseau et écoute les
   réponses : c'est la méthode standard pour lister les appareils d'un
   réseau local.
3. Identifie le fabricant de chaque appareil à partir des 3 premiers octets
   de son adresse MAC (base locale de nmap), puis en déduit une étiquette de
   type d'appareil (téléphone Apple, Raspberry Pi, imprimante HP, etc.).
4. Avec `--os`, tente en plus de deviner le système d'exploitation via
   `nmap -O` (plus lent, nécessite nmap).

## Installation

```bash
git clone https://github.com/<ton-pseudo>/wifiscan.git
cd wifiscan
./install.sh
```

## Utilisation

```bash
sudo wifiscan                  # scan simple
sudo wifiscan --os             # + estimation de l'OS (plus lent)
sudo wifiscan -i wlan0         # forcer une interface précise
sudo wifiscan --json           # sortie JSON
```

Le scan ARP nécessite les droits root.

## Licence

MIT
