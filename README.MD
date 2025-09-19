# Network Filtering Experiment

**Système de filtrage réseau expérimental pour comparer les approches séquentielle vs parallèle**

Projet de Master en Génie Informatique - DONFACK PASCAL ARTHUR MONTGOMERY  
Encadreurs : Dr HYPPOLITE MICHEL TAPAMO KENFACK & Dr DJOB MVONDO

---

## 🎯 Objectif du Projet

Ce projet vise à résoudre un problème concret dans la sécurité réseau : **la latence excessive causée par l'empilement de filtres réseau** (IPS, WAF, Firewalls).

### Le Problème
Quand on empile plusieurs filtres de sécurité réseau :
```
Client → IPS → WAF → Firewall → Serveur
```

**Résultat :** Un paquet peut traverser toute la chaîne avant d'être rejeté à la fin, gaspillant des ressources CPU et réseau.

### Notre Solution
Créer un **filtreur unifié** qui :
- Récupère les règles de tous les filtres existants
- Les applique **tôt** dans la chaîne pour rejeter les paquets malveillants avant qu'ils traversent tout
- Compare deux approches : **séquentielle** vs **parallèle/hybride**

---

## 🏗️ Architecture Technique

### Vue d'ensemble
```
Paquets réseau → NFQUEUE → Tiger-Fox → DROP/ACCEPT
                     ↓
                [Rule Engine]
                     ↓
            [Séquentiel | Hybride]
```

### Composants Principaux

#### 1. **NFQUEUE** - Interface Réseau
- Mécanisme Linux qui intercepte les paquets via iptables
- Permet de décider en temps réel : DROP ou ACCEPT
- Interface entre le kernel Linux et notre application Python

#### 2. **Rule Engine** - Moteur de Règles
- **Mode Séquentiel** : Vérifie les règles une par une (L3 → L4 → L7)
- **Mode Hybride** : Vérifie toutes les couches en parallèle avec des threads

#### 3. **Parser de Paquets**
- Analyse les paquets réseau pour extraire :
  - **Layer 3** : IP source/destination, protocole
  - **Layer 4** : Ports TCP/UDP, flags
  - **Layer 7** : HTTP (URI, headers, méthodes)

#### 4. **Système de Métriques**
- Mesure en temps réel : latence, throughput, CPU
- Compare les performances entre les deux modes

---

## 📁 Structure du Projet

```
tiger-foxx-experiment-filtering/
├── README.md                    # Ce fichier
├── config.yaml                 # Configuration du système
├── main.py                     # Point d'entrée principal
├── requirements.txt            # Dépendances Python
├── engine/
│   ├── __init__.py
│   ├── metrics.py              # Collecte de métriques
│   ├── packet_handler.py       # Gestion NFQUEUE
│   ├── packet_parser.py        # Analyse des paquets
│   └── rule_engine.py          # Moteur de règles
└── rules/
    ├── example_rules.json      # Règles d'exemple
    └── rule_loader.py          # Chargement des règles
```

---

## 🔧 Installation et Configuration

### Prérequis Système
- **Linux** (Ubuntu 20.04+ recommandé)
- **Python 3.8+**
- **Droits root** (requis pour NFQUEUE)

### 1. Installer les Dépendances
```bash
# Installer les outils système
sudo apt update
sudo apt install python3-pip iptables-dev libnetfilter-queue-dev

# Cloner le projet
git clone <votre-repo>
cd tiger-foxx-experiment-filtering

# Installer les dépendances Python
sudo pip install -r requirements.txt
```

### 2. Configurer iptables
```bash
# Rediriger le trafic HTTP vers NFQUEUE
sudo iptables -I INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0

# Ou pour tout le trafic (attention !)
sudo iptables -I INPUT -j NFQUEUE --queue-num 0
```

### 3. Configuration du Système
Modifier `config.yaml` selon vos besoins :
```yaml
engine:
  mode: "sequential"     # "sequential" ou "hybrid"
  queue_num: 0          # Numéro de queue NFQUEUE
  
performance:
  enable_metrics: true  # Activer la collecte de métriques
  metric_interval: 1.0  # Intervalle en secondes

rules:
  file: "rules/example_rules.json"  # Fichier de règles
```

---

## 🚀 Utilisation

### Lancement Basique
```bash
# Mode séquentiel
sudo python main.py --mode sequential

# Mode hybride (parallèle)
sudo python main.py --mode hybrid

# Avec logs détaillés
sudo python main.py --mode sequential --verbose
```

### Options Avancées
```bash
# Utiliser un fichier de règles personnalisé
sudo python main.py --rules mes_regles.json

# Changer le numéro de queue
sudo python main.py --queue 1

# Afficher l'aide
python main.py --help
```

### Arrêt du Système
```bash
# Ctrl+C pour arrêter le système
# Puis nettoyer iptables :
sudo iptables -D INPUT -j NFQUEUE --queue-num 0
```

---

## 📊 Tests et Évaluation

### 1. Générer du Trafic de Test

#### Avec wrk (HTTP)
```bash
# Installer wrk
sudo apt install wrk

# Test de charge basique
wrk -t4 -c100 -d30s http://target-server/

# Test avec attaques simulées
wrk -t4 -c100 -d30s -s attack.lua http://target-server/
```

#### Avec Scapy (Couches L3/L4)
```python
# Script Python pour générer des paquets L3/L4
from scapy.all import *

# Envoyer des paquets TCP
send(IP(dst="192.168.1.100")/TCP(dport=22), count=100)

# Simuler une attaque depuis une IP bloquée
send(IP(src="192.42.116.1", dst="192.168.1.100")/TCP(dport=80))
```

### 2. Analyser les Résultats

Le système affiche automatiquement :
```
TIGER-FOX FILTERING PERFORMANCE SUMMARY
========================================
Mode: SEQUENTIAL
Total Packets Processed: 1,247
Packets Dropped: 156 (12.5%)
Packets Accepted: 1,091 (87.5%)
Avg Decision Time: 0.245 ms
P99 Decision Time: 1.230 ms
CPU Usage: 15.4%
Memory Usage: 45.2 MB

Top Rules by Hits:
  block_sqli_attempts: 89 hits, 0.156ms avg
  block_scanner_ua: 34 hits, 0.089ms avg
```

---

## 📖 Comprendre les Règles

### Format des Règles
Les règles sont définies en JSON et organisées par couche OSI :

```json
{
  "rules": [
    {
      "id": "block_tor_ips",           // Identifiant unique
      "layer": 3,                     // Couche OSI (3=IP, 4=TCP/UDP, 7=HTTP)
      "type": "ip_src_in",            // Type de vérification
      "values": ["192.42.116.0/24"],  // Valeurs à vérifier
      "action": "drop"                // Action : "drop" ou "accept"
    }
  ]
}
```

### Types de Règles Supportés

#### Layer 3 (IP)
- `ip_src_in` : IP source dans une liste/CIDR
- `ip_dst_in` : IP destination dans une liste/CIDR
- `ip_src_country` : Pays de l'IP source (CN, RU, etc.)

#### Layer 4 (TCP/UDP)
- `tcp_dst_port` : Port TCP de destination
- `udp_dst_port` : Port UDP de destination
- `tcp_flags` : Flags TCP spécifiques

#### Layer 7 (Application)
- `http_uri_regex` : Regex sur l'URI HTTP
- `http_header_contains` : Contenu des headers HTTP
- `http_method` : Méthode HTTP (GET, POST, etc.)

### Exemples de Règles

```json
{
  "rules": [
    // Bloquer les IPs Tor
    {
      "id": "block_tor",
      "layer": 3,
      "type": "ip_src_in",
      "values": ["192.42.116.0/24", "199.87.154.0/24"],
      "action": "drop"
    },
    
    // Bloquer SSH
    {
      "id": "block_ssh",
      "layer": 4,
      "type": "tcp_dst_port",
      "values": [22],
      "action": "drop"
    },
    
    // Détecter SQLi
    {
      "id": "detect_sqli",
      "layer": 7,
      "type": "http_uri_regex",
      "values": ["(?i)(union|select).*from"],
      "action": "drop"
    }
  ]
}
```

---

## 🔬 Modes de Fonctionnement Détaillés

### Mode Séquentiel
```
Paquet arrive → L3 rules → L4 rules → L7 rules → Décision
                  ↓          ↓          ↓
                DROP?      DROP?      DROP?
```

**Avantages :**
- Simple et prévisible
- Consommation mémoire faible
- Débogage facile

**Inconvénients :**
- Plus lent pour beaucoup de règles
- N'utilise pas le multicœur

### Mode Hybride (Parallèle)
```
Paquet arrive → [L3 rules] → Décision
                [L4 rules] ↗
                [L7 rules] ↗
                (en parallèle)
```

**Avantages :**
- Utilise plusieurs cœurs CPU
- Plus rapide avec beaucoup de règles
- Première règle qui match gagne

**Inconvénients :**
- Plus complexe
- Consommation mémoire plus élevée
- Overhead des threads

---

## 📈 Métriques et Monitoring

### Métriques Collectées
- **Latence** : Temps de décision par paquet (P50, P95, P99)
- **Throughput** : Paquets traités par seconde
- **CPU** : Utilisation processeur (user/system)
- **Mémoire** : Consommation RSS et VMS
- **Règles** : Fréquence d'activation par règle

### Exportation des Données
```bash
# Les métriques sont automatiquement exportées en JSON
# Fichier : metrics_export_YYYYMMDD_HHMMSS.json
```

### Visualisation
```python
# Script pour analyser les résultats
import json
import matplotlib.pyplot as plt

# Charger les métriques
with open('metrics_export.json', 'r') as f:
    data = json.load(f)

# Créer des graphiques
plt.plot(data['time_series']['packets_per_second'])
plt.title('Throughput over time')
plt.show()
```

---

## 🛠️ Développement et Extension

### Ajouter un Nouveau Type de Règle

1. **Modifier `rule_engine.py`** :
```python
elif rule.type == 'mon_nouveau_type':
    # Votre logique ici
    return ma_condition
```

2. **Ajouter dans `example_rules.json`** :
```json
{
  "id": "ma_regle",
  "layer": 7,
  "type": "mon_nouveau_type",
  "values": ["valeur1", "valeur2"],
  "action": "drop"
}
```

### Optimisations Possibles
- **Cache intelligent** : Mettre en cache les décisions récentes
- **Pre-filtering** : Règles rapides en premier
- **Regex compilation** : Compiler les regex à l'avance
- **Memory pooling** : Réutiliser les objets

---

## 🐛 Dépannage

### Problèmes Courants

#### "Permission denied" en lançant le script
```bash
# Solution : Utiliser sudo
sudo python main.py
```

#### "No packets received"
```bash
# Vérifier les règles iptables
sudo iptables -L -n

# Générer du trafic de test
curl http://localhost/test
```

#### "Import error: netfilterqueue"
```bash
# Installer les dépendances système
sudo apt install libnetfilter-queue-dev
pip install netfilterqueue
```

#### Performances dégradées
```bash
# Réduire le nombre de règles
# Ou optimiser les règles regex
# Ou augmenter max_workers dans config
```

### Logs de Debug
```bash
# Activer les logs détaillés
sudo python main.py --verbose

# Surveiller les logs système
sudo tail -f /var/log/syslog | grep tiger-fox
```

---

## 📚 Références et Documentation

### Documentation Technique
- [Netfilter/iptables](https://netfilter.org/documentation/)
- [NFQUEUE](https://netfilter.org/projects/libnetfilter_queue/)
- [Scapy Documentation](https://scapy.readthedocs.io/)

### Articles de Recherche
- Roesch, M. "Snort - Lightweight Intrusion Detection for Networks"
- ModSecurity Documentation
- OWASP Core Rule Set

### Ressources CloudLab
- [CloudLab Portal](https://www.cloudlab.us/)
- [CloudLab Documentation](https://docs.cloudlab.us/)

---

## 🤝 Contribution

### Structure des Commits
```
[COMPONENT] Description courte

Description détaillée si nécessaire

Exemples :
[ENGINE] Optimize regex compilation for L7 rules
[METRICS] Add P99 latency calculation
[DOCS] Update installation instructions
```

### Tests
```bash
# Avant de commit, tester :
sudo python main.py --mode sequential --verbose
sudo python main.py --mode hybrid --verbose

# Vérifier que les métriques sont correctes
```

---

## 📞 Support et Contact

**Auteur :** DONFACK PASCAL ARTHUR MONTGOMERY (Tiger Fox)  
**Email :** [votre-email]  
**Projet :** Master en Génie Informatique  
**Institution :** [Votre université]

### Issues et Questions
- Créer une issue GitHub pour les bugs
- Utiliser les discussions pour les questions
- Lire d'abord ce README et la documentation

---

## 📄 License

Ce projet est développé dans le cadre d'un projet de recherche académique.
Utilisation libre pour la recherche et l'éducation.

---

## 🎯 Prochaines Étapes

### Version Actuelle (v1.0)
- [x] Moteur séquentiel
- [x] Moteur hybride
- [x] Interface NFQUEUE
- [x] Métriques basiques

### Prochaines Versions
- [ ] Migration vers C pour les performances
- [ ] Support eBPF/XDP
- [ ] Interface web de monitoring
- [ ] Support des règles Suricata natives
- [ ] Support ModSecurity natif
- [ ] Perspectives quantiques (recherche théorique)

---

**Happy Filtering! 🚀**
