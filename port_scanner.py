#!/usr/bin/env python3
"""
port_scanner.py - Scanner de ports TCP avec identification de services
Auteur : Fulbert Agossou
"""

import socket
import argparse
import sys
import datetime
import concurrent.futures
import threading
# Dictionnaire des ports connus -> noms de services courants
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    27017: "MongoDB",
}
# Verrou pour eviter que plusieurs threads n'ecrivent en meme temps dans la console
print_lock = threading.Lock()
def identify_service(port):
    """Retourne le nom du service connu pour un port donne, ou 'Inconnu'."""
    return COMMON_PORTS.get(port, "Inconnu")
def grab_banner(sock):
    """
    Tente de lire quelques octets envoyes par le service (souvent une version
    ou un message de bienvenue). Beaucoup de services n'envoient rien tant
    qu'on ne leur parle pas : dans ce cas on retourne None sans planter.
    """
    try:
        sock.settimeout(1)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner if banner else None
    except Exception:
        return None

def scan_port(host, port, timeout):
    """
    Tente une connexion TCP complete (connect scan) sur (host, port).
    Retourne un dict decrivant le port s'il est ouvert, sinon None.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = None
    try:
        conn_result = sock.connect_ex((host, port))
        if conn_result == 0:
            service = identify_service(port)
            banner = grab_banner(sock)
            result = {"port": port, "service": service, "banner": banner}
            with print_lock:
                extra = f" | banniere: {banner}" if banner else ""
                print(f"[+] Port {port:5d} OUVERT  -> {service}{extra}")
    except socket.error:
        pass
    finally:
        sock.close()
    return result




def scan_range(host, start_port, end_port, timeout, max_workers):
    """
    Scanne tous les ports de start_port a end_port en parallele grace a un
    ThreadPoolExecutor (le scan reseau est majoritairement en attente I/O,
    les threads sont donc efficaces ici).
    """
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout): port
            for port in range(start_port, end_port + 1)
        }
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)
    open_ports.sort(key=lambda r: r["port"])
    return open_ports
def generate_report(host, start_port, end_port, open_ports, elapsed, output_path):
    """Construit le texte du rapport et l'ecrit dans un fichier."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []
    lines.append("=" * 60)
    lines.append("RAPPORT DE SCAN DE PORTS")
    lines.append("=" * 60)
    lines.append(f"Date          : {timestamp}")
    lines.append(f"Cible         : {host}")
    lines.append(f"Plage scannee : {start_port}-{end_port}")
    lines.append(f"Duree         : {elapsed:.2f} secondes")
    lines.append(f"Ports ouverts : {len(open_ports)}")
    lines.append("-" * 60)

    if open_ports:
        for r in open_ports:
            line = f"Port {r['port']:5d} | Service: {r['service']:10s}"
            if r["banner"]:
                line += f" | Banniere: {r['banner']}"
            lines.append(line)
    else:
        lines.append("Aucun port ouvert detecte dans cette plage.")

    lines.append("=" * 60)

    report_text = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text + "\n")
    return report_text

def parse_args():
    parser = argparse.ArgumentParser(
        description="Scanner de ports TCP avec identification de services"
    )
    parser.add_argument("--host", default="127.0.0.1",
                         help="Adresse IP a scanner (defaut: 127.0.0.1)")
    parser.add_argument("--start-port", type=int, default=1,
                         help="Port de depart (defaut: 1)")
    parser.add_argument("--end-port", type=int, default=1024,
                         help="Port de fin (defaut: 1024)")
    parser.add_argument("--timeout", type=float, default=0.5,
                         help="Timeout de connexion en secondes (defaut: 0.5)")
    parser.add_argument("--threads", type=int, default=100,
                         help="Nombre de threads simultanes (defaut: 100)")
    parser.add_argument("--output", default=None,
                         help="Chemin du fichier rapport (defaut: report_<host>_<date>.txt)")
    return parser.parse_args()

def main():
    args = parse_args()

    if args.start_port < 1 or args.end_port > 65535 or args.start_port > args.end_port:
        print("Erreur : plage de ports invalide (1-65535, start-port <= end-port).")
        sys.exit(1)

    print(f"Scan de {args.host} sur les ports {args.start_port}-{args.end_port}...\n")

    start_time = datetime.datetime.now()
    open_ports = scan_range(args.host, args.start_port, args.end_port, args.timeout, args.threads)
    elapsed = (datetime.datetime.now() - start_time).total_seconds()

    if args.output:
        output_path = args.output
    else:
        date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"report_{args.host}_{date_str}.txt"

    report = generate_report(args.host, args.start_port, args.end_port, open_ports, elapsed, output_path)
    print("\n" + report)
    print(f"\nRapport enregistre dans : {output_path}")


if __name__ == "__main__":
    main()