#!/usr/bin/env python3

import os
import sys
import argparse
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw

# Konfiguracja sygnatur
SUSPICIOUS_PORTS = {4444, 1337, 6667, 9999}
ATTACK_SIGNATURES = [
    b"UNION SELECT",
    b"' OR '1'='1",
    b"<script>",
    b"../",
    b"etc/passwd",
    b"cmd.exe"
]

def parse_arguments():
    parser = argparse.ArgumentParser(description="Automatyczny analizator plików PCAP/PCAPNG dla celów informatyki śledczej.")
    parser.add_argument("-f", "--file", required=True, help="Ścieżka do analizowanego pliku .pcap/.pcapng")
    parser.add_argument("-o", "--output", default="raport.txt", help="Nazwa pliku raportu wyjściowego (domyślnie: forensic_report.txt)")
    return parser.parse_args()

def analyze_pcap(file_path):
    print(f" > Wczytywanie pliku: {file_path}...")
    try:
        packets = rdpcap(file_path)
    except Exception as e:
        print(f"Błąd podczas wczytywania pliku: {e}")
        sys.exit(1)

    stats = {
        "total_packets": len(packets),
        "protocols": Counter(),
        "alerts": []
    }

    print(f" > Rozpoczęto analizę {len(packets)} pakietów...")

    for idx, pkt in enumerate(packets):
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            if pkt.haslayer(TCP):
                stats["protocols"]["TCP"] += 1
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport

                if dport in SUSPICIOUS_PORTS or sport in SUSPICIOUS_PORTS:
                    alert = f"TCP: Podejrzany port w użyciu (Port: {dport if dport in SUSPICIOUS_PORTS else sport}) | {src_ip} -> {dst_ip}"
                    stats["alerts"].append(alert)

                if pkt.haslayer(Raw):
                    payload = pkt[Raw].load
                    for sig in ATTACK_SIGNATURES:
                        if sig in payload:
                            alert = f"WEB: Wykryto sygnaturę ataku '{sig.decode(errors='ignore')}' w pakiecie #{idx} | {src_ip} -> {dst_ip}"
                            stats["alerts"].append(alert)

            elif pkt.haslayer(UDP):
                stats["protocols"]["UDP"] += 1
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                if dport in SUSPICIOUS_PORTS or sport in SUSPICIOUS_PORTS:
                    alert = f"UDP: Podejrzany port w użyciu (Port: {dport if dport in SUSPICIOUS_PORTS else sport}) | {src_ip} -> {dst_ip}"
                    stats["alerts"].append(alert)

            elif pkt.haslayer(ICMP):
                stats["protocols"]["ICMP"] += 1
        else:
            stats["protocols"]["Inne"] += 1

    return stats

def generate_report(stats, output_path, source_file):
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"Analizowany plik źródłowy: {source_file}\n")
            f.write(f"Łączna liczba przeanalizowanych pakietów: {stats['total_packets']}\n\n")

            f.write("Statystyki protokołów\n")
            for proto, count in stats["protocols"].items():
                f.write(f" - {proto}: {count}\n")
            f.write("\n")

            f.write("Wykryte anomalie i alerty")
            if not stats["alerts"]:
                f.write("\nNie wykryto znanych sygnatur ataków ani podejrzanych portów.\n")
            else:
                f.write(f": {len(stats['alerts'])}\n")
                for alert in stats["alerts"]:
                    f.write(f"{alert}\n")

            f.write("\n")
        print(f"Raport został zapisany w pliku: {output_path}")
    except Exception as e:
        print(f"Błąd podczas zapisu raportu: {e}")

def main():
    args = parse_arguments()

    if not os.path.exists(args.file):
        print(f"Błąd: Plik '{args.file}' nie istnieje.")
        sys.exit(1)

    stats = analyze_pcap(args.file)
    generate_report(stats, args.output, args.file)

if __name__ == "__main__":
    main()
