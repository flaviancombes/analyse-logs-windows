import sys
import time
from collections import defaultdict
from colorama import Fore, Style, init

init(autoreset=True)

# -----------------------------
# arguments
# -----------------------------
if len(sys.argv) != 3 or sys.argv[2] not in ["détaillé", "synthèse"]:
    print("Usage : python analyse_logs.py <fichier_log> [détaillé|synthèse]")
    sys.exit(1)

LOG_FILE = sys.argv[1]
MODE = sys.argv[2]

print("Analyseur de logs démarré 🚀")
print(f"Fichier analysé : {LOG_FILE}")
print(f"Mode sélectionné : {MODE.upper()}\n")

# Petite barre de chargement (cosmétique)
print("Analyse des logs en cours ", end="", flush=True)
for _ in range(20):
    print("█", end="", flush=True)
    time.sleep(0.04)
print("\n")

# -----------------------------
# Mappings lisibles
# -----------------------------
LOGON_TYPE_MAP = {
    "2": "Connexion locale",
    "3": "Accès réseau (SMB / scan)",
    "10": "Connexion RDP"
}

STATUS_MAP = {
    "0xc000006d": "Mot de passe incorrect",
    "0xc0000064": "Utilisateur inexistant",
    "0xc0000234": "Compte verrouillé"
}

# -----------------------------
# Structure de stockage
# -----------------------------
attempts = defaultdict(lambda: {
    "total": 0,
    "ports": defaultdict(int),
    "users": defaultdict(int),
    "logon_types": defaultdict(int),
    "auth_packages": defaultdict(int),
    "status_codes": defaultdict(int),
    "events": []
})

# -----------------------------
# Lecture du fichier de logs
# -----------------------------
try:
    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            if "FAILED_LOGIN" not in line:
                continue

            try:
                parts = line.strip().split()
                datetime_ = parts[0]

                data = {}
                for p in parts[2:]:
                    if "=" in p:
                        k, v = p.split("=", 1)
                        data[k] = v

                ip_port = data.get("IP", "UNKNOWN:UNKNOWN")
                ip, port = ip_port.split(":") if ":" in ip_port else (ip_port, "UNKNOWN")

                user = data.get("User", "UNKNOWN")
                logon_type = data.get("LogonType", "UNKNOWN")
                auth = data.get("Auth", "UNKNOWN")
                status = data.get("Status", "UNKNOWN")

                attempts[ip]["total"] += 1
                attempts[ip]["ports"][port] += 1
                attempts[ip]["users"][user] += 1
                attempts[ip]["logon_types"][logon_type] += 1
                attempts[ip]["auth_packages"][auth] += 1
                attempts[ip]["status_codes"][status] += 1

                attempts[ip]["events"].append({
                    "datetime": datetime_,
                    "port": port,
                    "user": user,
                    "logon_type": logon_type,
                    "auth": auth,
                    "status": status
                })

            except Exception:
                continue  # Ignorer les lignes mal formées
except FileNotFoundError:
    print(Fore.RED + f"❌ Fichier '{LOG_FILE}' introuvable.")
    sys.exit(1)

# -----------------------------
# Tri des événements internes par date 
# -----------------------------
for data in attempts.values():
    data["events"].sort(key=lambda e: e["datetime"], reverse=True)

# -----------------------------
# Fonctions d'analyse
# -----------------------------
def detect_scenario(data):
    if "10" in data["logon_types"]:
        return "Tentative RDP"
    if len(data["users"]) >= 3:
        return "Password spraying"
    if "3" in data["logon_types"] and data["total"] >= 10:
        return "Brute force réseau"
    return "Activité suspecte"

def calculate_risk(data):
    score = 0
    if data["total"] >= 5:
        score += 30
    if len(data["users"]) >= 3:
        score += 20
    if "10" in data["logon_types"]:
        score += 20
    if "NTLM" in data["auth_packages"]:
        score += 10
    if len(data["ports"]) >= 5:
        score += 10
    return min(score, 100)

# -----------------------------
# Préparer la liste triée par score décroissant
# -----------------------------
ip_list = []
for ip, data in attempts.items():
    score = calculate_risk(data)
    ip_list.append((ip, data, score))

ip_list.sort(key=lambda x: x[2], reverse=True)  # tri décroissant

# -----------------------------
# AFFICHAGE DES RÉSULTATS
# -----------------------------
for ip, data, score in ip_list:
    scenario = detect_scenario(data)
    ip_label = f"{ip} (LOCALHOST)" if ip == "127.0.0.1" else ip

    # -------------------------
    # MODE DÉTAILLÉ
    # -------------------------
    if MODE == "détaillé":
        print(Fore.RED + "🔴 ALERTE SÉCURITÉ\n")
        print(f"IP source        : {ip_label}")
        print(f"Gravité estimée  : {score}/100")
        print(f"Scénario détecté : {scenario}")
        print(f"Tentatives       : {data['total']}")

        for lt in data["logon_types"]:
            print(f"Type d'accès     : {LOGON_TYPE_MAP.get(lt, lt)}")

        for status in data["status_codes"]:
            print(f"Cause principale : {STATUS_MAP.get(status, status)}")

        print(f"Comptes ciblés   : {', '.join(data['users'].keys())}")
        print(f"Authentification : {', '.join(data['auth_packages'].keys())}")

        print("\nConseils SOC L1 :")
        print("- Vérifier si l’IP est interne ou externe")
        print("- Vérifier l’utilisation normale des comptes ciblés")
        print("- Escalader si répétitif ou externe\n")

        print("Dernières tentatives :")
        for event in data["events"][:3]:
            print(
                f"  {event['datetime']} | "
                f"user={event['user']} | "
                f"port={event['port']}"
            )

        print("\n" + "-" * 60 + "\n")

    # -------------------------
    # MODE SYNTHÈSE 
    # -------------------------
    else:
        logon_summary = ','.join(LOGON_TYPE_MAP.get(lt, lt) for lt in data["logon_types"])
        users_count = len(data["users"])
        ports_count = len(data["ports"])

        print(
            f"{ip_label:<18} | "
            f"Score={score:<3} | "
            f"{scenario:<22} | "
            f"Users={users_count:<2} | "
            f"Ports={ports_count:<2} | "
            f"Logons={logon_summary:<25} | "
            f"Attempts={data['total']}"
        )

print(Fore.GREEN + "\nAnalyse terminée ✅")
