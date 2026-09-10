# port-scanner

Deux outils Python de sécurité réseau développés dans le cadre de mon apprentissage en génie informatique (UQTR) :

1. **`port_scanner.py`** — Scanner de ports TCP qui identifie les services actifs sur une plage de ports et génère un rapport.
2. **`log_analyzer.py`** — Analyseur de logs réseau qui détecte les adresses IP à comportement anormal et génère des alertes horodatées.

## Structure du dépôt

```
port-scanner/
├── port_scanner.py       # Scanner de ports TCP
├── log_analyzer.py       # Analyseur de logs réseau
├── sample.log            # Log d'exemple pour tester
├── .gitignore
└── README.md
```

## 1. Scanner de ports (`port_scanner.py`)

Effectue un **TCP connect scan** : pour chaque port de la plage donnée, le script tente d'établir une connexion TCP complète. Si elle réussit, le port est considéré ouvert. Le script :

- identifie le service probable via une table des ports connus (22 → SSH, 80 → HTTP, 443 → HTTPS, etc.) ;
- tente de récupérer une bannière de service (par exemple la version d'un serveur) ;
- utilise plusieurs threads pour scanner rapidement ;
- génère un rapport texte horodaté.

### Utilisation

```
py port_scanner.py --host 127.0.0.1 --start-port 1 --end-port 1024
```

### Arguments

| Argument       | Défaut         | Description                                    |
|----------------|----------------|--------------------------------------------------|
| `--host`       | `127.0.0.1`    | Adresse IP à scanner                            |
| `--start-port` | `1`            | Port de départ                                  |
| `--end-port`   | `1024`         | Port de fin                                     |
| `--timeout`    | `0.5`          | Timeout de connexion (secondes)                 |
| `--threads`    | `100`          | Nombre de threads simultanés                    |
| `--output`     | auto-généré    | Chemin du fichier de rapport                    |



## 2. Analyseur de logs (`log_analyzer.py`)

Lit un fichier de logs réseau et détecte deux types d'activité anormale :

1. **Taux élevé de requêtes** (`TAUX_ELEVE`) : une IP dépasse un seuil de requêtes dans une fenêtre de temps glissante (utile pour repérer du brute-force ou du DoS).
2. **Volume anormal** (`VOLUME_ANORMAL`) : une IP fait un nombre total de requêtes qui s'écarte statistiquement (z-score) de la moyenne des autres IPs du fichier (utile pour repérer un scan ou un crawler agressif).

Le script attend des lignes au format : `AAAA-MM-JJ HH:MM:SS IP action` (ex: `2026-08-31 09:05:00 203.0.113.55 POST /login`).

### Utilisation

```
py log_analyzer.py --log sample.log --window 10 --threshold 8 --zscore 1.5
```

### Arguments

| Argument      | Défaut        | Description                                                    |
|----------------|---------------|--------------------------------------------------------------------|
| `--log`       | *(requis)*    | Chemin vers le fichier de log à analyser                         |
| `--window`    | `60`          | Fenêtre de temps (secondes) pour la détection de taux élevé      |
| `--threshold` | `20`          | Nombre de requêtes dans la fenêtre pour déclencher une alerte    |
| `--zscore`    | `2.0`         | Seuil de z-score pour l'anomalie de volume                       |
| `--output`    | `alerts.log`  | Fichier de sortie des alertes                                    |



## Comment tester

### Tester `log_analyzer.py`

Le fichier `sample.log` fourni contient une rafale de requêtes d'une même IP (`203.0.113.55`), simulant une tentative de brute-force sur `/login`.

```
py log_analyzer.py --log sample.log --window 10 --threshold 8
```

Résultat attendu : une alerte `TAUX_ELEVE` signalant `203.0.113.55`.

### Tester `port_scanner.py`

Le moyen le plus simple de vérifier la détection de port ouvert est de démarrer un petit serveur local, puis de le scanner :

```
# Terminal 1 : démarrer un serveur HTTP de test sur le port 8000
py -m http.server 8000

# Terminal 2 : scanner ce port
py port_scanner.py --host 127.0.0.1 --start-port 7990 --end-port 8010
```

Résultat attendu : le port 8000 apparaît comme `OUVERT` dans le rapport.

On peut aussi scanner directement sa propre machine sans serveur de test :

```
py port_scanner.py --host 127.0.0.1 --start-port 1 --end-port 1024
```


## Avertissement légal et éthique

Le scan de ports sur des systèmes qui ne vous appartiennent pas et pour lesquels vous n'avez pas d'autorisation explicite peut être illégal, même à des fins d'apprentissage. Ce projet est destiné à être utilisé :

- sur `127.0.0.1` / `localhost` ;
- sur votre propre réseau local (ordinateurs, routeur que vous possédez) ;
- sur des machines virtuelles ou environnements de laboratoire dédiés à l'apprentissage de la sécurité (ex. TryHackMe, Hack The Box).


## Auteur

**Fulbert Agossou**
Étudiant en génie électrique concentration génie informatique — Université du Québec à Trois-Rivières (UQTR)