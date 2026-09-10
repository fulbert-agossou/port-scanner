#!/usr/bin/env python3
"""
log_analyzer.py - Analyseur de logs reseau : detection d'IPs a activite anormale
Auteur : Fulbert Agossou
"""

import re
import argparse
import datetime
import statistics
from collections import defaultdict
# --- Expressions regulieres pour reconnaitre deux formats de logs courants ---

# Format simple : "2026-08-31 10:15:32 192.168.1.10 GET /login"
SIMPLE_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
)

# Format Apache/Nginx "Combined Log Format" :
# 192.168.1.10 - - [31/Aug/2026:10:15:32 +0000] "GET /login HTTP/1.1" 200 512
APACHE_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?\[(?P<timestamp>[^\]]+)\]'
)

def parse_simple_timestamp(ts):
    return datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")


def parse_apache_timestamp(ts):
    # Ex: "31/Aug/2026:10:15:32 +0000" -> on retire le fuseau horaire avant parsing
    ts_clean = ts.split(" ")[0]
    return datetime.datetime.strptime(ts_clean, "%d/%b/%Y:%H:%M:%S")

def parse_log_line(line):
    """
    Essaie d'extraire (ip, timestamp) d'une ligne de log en testant les deux
    formats connus. Retourne None si aucun format ne correspond.
    """
    match = SIMPLE_PATTERN.search(line)
    if match:
        try:
            return match.group("ip"), parse_simple_timestamp(match.group("timestamp"))
        except ValueError:
            pass

    match = APACHE_PATTERN.search(line)
    if match:
        try:
            return match.group("ip"), parse_apache_timestamp(match.group("timestamp"))
        except ValueError:
            pass

    return None

def load_events(log_path):
    """
    Lit le fichier de log ligne par ligne, extrait les evenements (ip, timestamp)
    valides, et les retourne tries chronologiquement. Retourne aussi le nombre
    de lignes qui n'ont pas pu etre interpretees.
    """
    events = []
    skipped = 0
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parsed = parse_log_line(line)
            if parsed:
                events.append(parsed)
            else:
                skipped += 1
    events.sort(key=lambda e: e[1])
    return events, skipped

def detect_rate_anomalies(events, window_seconds, threshold):
    """
    Detecte les IPs qui depassent 'threshold' requetes dans une fenetre
    glissante de 'window_seconds' secondes (technique de fenetre glissante
    a deux pointeurs, efficace car chaque timestamp n'est visite qu'une
    fois par pointeur).
    """
    alerts = []
    ip_timestamps = defaultdict(list)
    for ip, ts in events:
        ip_timestamps[ip].append(ts)

    for ip, timestamps in ip_timestamps.items():
        timestamps.sort()
        window_start_idx = 0
        for i, current_ts in enumerate(timestamps):
            while (current_ts - timestamps[window_start_idx]).total_seconds() > window_seconds:
                window_start_idx += 1
            count_in_window = i - window_start_idx + 1
            if count_in_window >= threshold:
                alerts.append({
                    "type": "TAUX_ELEVE",
                    "ip": ip,
                    "timestamp": current_ts,
                    "detail": f"{count_in_window} requetes en {window_seconds}s (seuil: {threshold})",
                })
                break
    return alerts

def detect_statistical_anomalies(events, z_threshold=2.0):
    """
    Detecte les IPs dont le volume total de requetes s'ecarte significativement
    de la moyenne des autres IPs (z-score >= seuil), ce qui peut indiquer un
    scan, un crawler agressif ou une activite inhabituelle.
    """
    alerts = []
    counts = defaultdict(int)
    for ip, _ in events:
        counts[ip] += 1

    if len(counts) < 2:
        return alerts

    values = list(counts.values())
    mean = statistics.mean(values)
    stdev = statistics.stdev(values)

    if stdev == 0:
        return alerts

    for ip, count in counts.items():
        z_score = (count - mean) / stdev
        if z_score >= z_threshold:
            alerts.append({
                "type": "VOLUME_ANORMAL",
                "ip": ip,
                "timestamp": datetime.datetime.now(),
                "detail": f"{count} requetes au total (moyenne: {mean:.1f}, z-score: {z_score:.2f})",
            })
    return alerts

def write_alerts(alerts, output_path):
    """Ecrit toutes les alertes, triees chronologiquement, dans un fichier texte."""
    alerts.sort(key=lambda a: a["timestamp"])
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("RAPPORT D'ALERTES - ANALYSE DE LOGS\n")
        f.write("=" * 60 + "\n")
        f.write(f"Genere le : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Nombre d'alertes : {len(alerts)}\n")
        f.write("-" * 60 + "\n")
        if not alerts:
            f.write("Aucune anomalie detectee.\n")
        for alert in alerts:
            ts_str = alert["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{ts_str}] [{alert['type']}] IP: {alert['ip']} - {alert['detail']}\n")
        f.write("=" * 60 + "\n")


def parse_args():
    parser = argparse.ArgumentParser(description="Analyseur de logs reseau")
    parser.add_argument("--log", required=True,
                         help="Chemin vers le fichier de log a analyser")
    parser.add_argument("--window", type=int, default=60,
                         help="Fenetre de temps en secondes pour la detection de taux (defaut: 60)")
    parser.add_argument("--threshold", type=int, default=20,
                         help="Nombre de requetes dans la fenetre pour declencher une alerte (defaut: 20)")
    parser.add_argument("--zscore", type=float, default=2.0,
                         help="Seuil de z-score pour l'anomalie statistique (defaut: 2.0)")
    parser.add_argument("--output", default="alerts.log",
                         help="Fichier de sortie des alertes (defaut: alerts.log)")
    return parser.parse_args()

def main():
    args = parse_args()

    print(f"Lecture du fichier de log : {args.log}")
    events, skipped = load_events(args.log)
    print(f"{len(events)} evenements charges, {skipped} lignes ignorees (format non reconnu).")

    if not events:
        print("Aucun evenement valide trouve. Verifiez le format du fichier de log.")
        return

    rate_alerts = detect_rate_anomalies(events, args.window, args.threshold)
    stat_alerts = detect_statistical_anomalies(events, args.zscore)
    all_alerts = rate_alerts + stat_alerts

    write_alerts(all_alerts, args.output)

    print(f"\n{len(all_alerts)} alerte(s) generee(s) :")
    for alert in sorted(all_alerts, key=lambda a: a["timestamp"]):
        print(f"  [{alert['type']}] {alert['ip']} - {alert['detail']}")

    print(f"\nRapport d'alertes enregistre dans : {args.output}")


if __name__ == "__main__":
    main()