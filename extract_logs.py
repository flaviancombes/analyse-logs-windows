import sys
import subprocess
import xml.etree.ElementTree as ET

# -----------------------------
# arguments
# -----------------------------
if len(sys.argv) != 2:
    print("Usage : python extract_logs.py <nom_fichier_sortie>")
    sys.exit(1)

OUTPUT_FILE = sys.argv[1]

print("📥 Extraction des logs Windows (XML + namespace)...")

cmd = [
    "wevtutil",
    "qe",
    "Security",
    "/q:*[System[(EventID=4625)]]",
    "/f:xml",
    "/rd:true",
    "/c:50"
]

result = subprocess.run(
    cmd,
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="ignore"
)

if not result.stdout.strip():
    print("❌ Aucun log récupéré (lance PowerShell en ADMIN)")
    exit()

# Ajout d'une racine XML
xml_data = "<Events>" + result.stdout + "</Events>"
root = ET.fromstring(xml_data)

# Namespace Windows
ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

entries = []

for event in root.findall("e:Event", ns):
    # Date
    date = event.find("e:System/e:TimeCreated", ns)
    date = date.attrib.get("SystemTime") if date is not None else "UNKNOWN_DATE"

    # Valeurs par défaut
    ip = port = "UNKNOWN"
    username = domain = "UNKNOWN"
    logon_type = "UNKNOWN"
    auth_package = "UNKNOWN"
    status = substatus = "UNKNOWN"

    for data in event.findall(".//e:Data", ns):
        name = data.attrib.get("Name")
        value = data.text

        if not value or value == "-":
            continue

        if name == "IpAddress":
            ip = value
        elif name == "IpPort":
            port = value
        elif name == "TargetUserName":
            username = value
        elif name == "TargetDomainName":
            domain = value
        elif name == "LogonType":
            logon_type = value
        elif name == "AuthenticationPackageName":
            auth_package = value
        elif name == "Status":
            status = value
        elif name == "SubStatus":
            substatus = value

    entries.append(
        f"{date} FAILED_LOGIN "
        f"User={domain}\\{username} "
        f"LogonType={logon_type} "
        f"Auth={auth_package} "
        f"IP={ip}:{port} "
        f"Status={status} SubStatus={substatus}"
    )

# Écriture dans le fichier de sortie
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    for e in entries:
        f.write(e + "\n")

print(f"✅ {len(entries)} entrées générées dans '{OUTPUT_FILE}'")
