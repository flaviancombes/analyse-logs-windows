# Analyseur de tentatives de connexion Windows (SOC L1)

##  Objectif du projet

Ce projet permet d’extraire, normaliser et analyser les échecs d’authentification Windows (EventID 4625) dans une logique **SOC niveau L1**.  
Il aide à identifier des comportements suspects comme les **brute force**, **password spraying**, **tentatives RDP**, ou **scans SMB** à partir des logs Windows.

---

##  Contenu du projet

| Fichier | Description |
|---------|-------------|
| `extract_logs.py` | Extrait les événements Windows depuis le journal de sécurité et les normalise dans un format lisible par l’analyseur. |
| `analyse_logs.py` | Analyse les logs extraits, calcule un score de gravité et affiche des scénarios compréhensibles selon deux modes : `détaillé` ou `synthèse`. |
| `example_logs/auth_sample.log` | Logs d’exemple générés pour tester l’analyseur. |

---

##  Format des logs normalisés

Chaque entrée de log ressemble à ceci :

2025-12-31T15:57:10.8385607Z FAILED_LOGIN User=UNKNOWN\UNKNOWN LogonType=2 Auth=Negotiate IP=127.0.0.1:0 Status=0xc000006d SubStatus=0xc0000380

2025-12-31T14:51:09.5097897Z FAILED_LOGIN User=UNKNOWN\guest LogonType=3 Auth=NTLM IP=192.168.1.142:53744 Status=0xc000006d SubStatus=0xc0000064


- **Date** : date de la tentative
- **Etat** : echec de la tentative
- **User** : compte ciblé  
- **LogonType** : type de connexion (locale, RDP, SMB…)  
- **Auth** : méthode d’authentification (NTLM, Negotiate…)  
- **IP:Port** : adresse IP et port source  
- **Status/SubStatus** : codes d’erreur Windows

---

##  Utilisation

Ouverture du shell en tant qu'administrateur

### Extraction des logs


python extract_logs.py <nom_fichier_log>


<nom_fichier_log> : nom du fichier de sortie pour les logs normalisés (ex : auth2.log).

**Exemple** : python extract_logs.py auth2.log


### Analyse des logs

#### Deux modes disponibles :

détaillé : affichage complet avec conseils SOC L1

synthèse : résumé par IP avec score de gravité et scénario

python analyse_logs.py <fichier_log> [détaillé|synthèse]


<fichier_log> : fichier normalisé généré par extract_logs.py

**Exemple** :

python analyse_logs.py auth2.log détaillé

python analyse_logs.py auth2.log synthèse

## Limites connues :

- L’analyse se base uniquement sur les échecs de connexion Windows (**EventID 4625**) et ne prend pas en compte les connexions réussies ou les actions effectuées après une connexion.
- L’outil analyse des fichiers de logs existants et ne fonctionne pas en temps réel.
- La prise en charge des adresses **IPv6 est limitée** : le format IP/port peut entraîner une analyse moins précise pour les adresses IPv6 voir ne pas fonctionner.
- Le score de gravité repose sur des règles simples (nombre de tentatives, comptes ciblés, type de connexion) et sert à aider à la priorisation, sans remplacer un outil SOC ou un SIEM complet.


