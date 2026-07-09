# Skrypt do wstępnej analizy pakietów PCAP / PCAPNG

analizepcap.py to automatyczne narzędzie do analizy plików .pcap oraz .pcapng, stworzone z myślą o wstępnej analizie ruchu sieciowego. Skrypt identyfikuje podejrzane porty oraz wykrywa sygnatury typowych ataków w warstwie aplikacji.

## Funkcjonalności
1. Wczytywanie plików .pcap / .pcapng
2. Zliczanie pakietów według protokołów: TCP, UDP, ICMP, inne
3. Wykrywanie podejrzanych portów: 4444, 1337, 6667, 9999
4. Rozpoznawanie sygnatur ataków:
- UNION SELECT (SQL Injection)
- ' OR '1'='1 (SQL Injection)
- <script> (XSS)
- ../ (Path Traversal)
- etc/passwd (Path Traversal)
- cmd.exe (Command Injection)
5. Generowanie raportu tekstowego

## Wymagania

1. Python 3.6 lub nowszy
2. Biblioteka scapy

## Użycie

```bash
python3 analizepcap.py -f ścieżka/do/pliku.pcap [-o nazwa_raportu.txt]
```

Przykład użycia i raportu:
```bash
python3 analizepcap.py -f capture.pcapng -o raport.txt
```

Przykładowy raport
```
Analizowany plik źródłowy: /home/mg/Dokumenty/Spy/capture.pcapng
Łączna liczba przeanalizowanych pakietów: 7621

Statystyki protokołów
 - TCP: 3192
 - UDP: 4428
 - Inne: 1

Wykryte anomalie i alerty: 1
WEB: Wykryto sygnaturę ataku '../' w pakiecie #7471 | 81.26.0.18 -> 10.100.0.234
```
...

## Uwagi

1. Skrypt analizuje tylko pierwsze ładunki (Raw) pakietów TCP – nie obsługuje fragmentacji ani strumieniowania.
2. Sygnatury są sprawdzane dosłownie (case‑sensitive) – mogą wystąpić wyniki fałszywie dodatnie.
3. Narzędzie przeznaczone jest do wstępnej, automatycznej analizy – nie zastępuje dogłębnego śledztwa.
