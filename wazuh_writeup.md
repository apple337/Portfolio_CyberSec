# Wazuh SIEM Lab – Writeup Portfolio
**Autor:** apple337  
**Platforma:** Kurs Cybersecurity – Lekcja 12: Monitoring i SIEM  
**Narzędzia:** Wazuh 4.14.2, Ubuntu 24.04 LTS, Windows 11, Sysmon v15.15  
**Data wykonania:** styczeń–luty 2026  

---

## Środowisko laboratoryjne

| Element | Wartość |
|---|---|
| Wazuh Manager | 48.209.8.17 |
| Agent Ubuntu | Dave (ID 013), Ubuntu 24.04.3 LTS, IP 192.168.1.36 |
| Agent Windows | winDave, Windows 11 |
| Agent referencyjny | PrzemyslawK (ID 001) – analizowany w zadaniach |
| Wersja agenta | Wazuh v4.14.2 |

---

## Zadanie 1 – Instalacja agenta Wazuh na Ubuntu Server

### Cel
Zainstalowanie i uruchomienie agenta Wazuh na maszynie Ubuntu Server, podłączenie do centralnego managera SIEM.

### Krok 1 – Weryfikacja połączenia z Internetem

```bash
ping -c 3 8.8.8.8
```

Wynik: 3 pakiety wysłane, 3 odebrane, 0% packet loss, czas ~11 ms.  
Połączenie z Internetem potwierdzone.

### Krok 2 – Dodanie repozytorium Wazuh

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
```

Pobrano klucz GPG Wazuh i dodano repozytorium do systemu APT.  
Po `apt update` pobrano 67,2 kB metadanych paczek, w tym nowe wpisy z repozytorium Wazuh.

### Krok 3 – Instalacja agenta

```bash
WAZUH_MANAGER='48.209.8.17' WAZUH_AGENT_NAME='Dave' apt install wazuh-agent
```

Wynik: pobranie 13,1 MB archiwum, instalacja 48,5 MB na dysku, zakończona sukcesem.

### Krok 4 – Uruchomienie usługi

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
sudo systemctl status wazuh-agent
```

Status: **active (running)** od 30 stycznia 2026 12:54:19 UTC.  
Uruchomione procesy: wazuh-execd, wazuh-agentd, wazuh-syscheckd, wazuh-logcollector, wazuh-modulesd.

### Krok 5 – Health Monitoring agenta

**Agents Overview**  
W momencie wykonywania zadania w systemie było 24 agentów łącznie, z czego **tylko 4 aktywne** (20 rozłączonych).  
Systemy operacyjne: ubuntu (18 agentów), windows (6 agentów).

**IT Hygiene – Inventory**  
- Zainstalowane pakiety: cloud-init, ssh-import-id, ubuntu-drivers-common, ubuntu-pro-client, ufw
- Pamięć RAM: 1,9 GB, użycie 20%
- CPU: Intel Core i3-8100 @ 3.60 GHz (2 rdzenie)
- Docelowy port komunikacji: **1514** (Wazuh Manager)
- Porty źródłowe: 53 (DNS), 2222, 68 (DHCP), 37663

**Security Configuration Assessment (SCA)**  
- Benchmark: CIS Ubuntu Linux 24.04 LTS v1.0.0
- Wynik: **53%** (129 passed / 114 failed / 36 not applicable)
- Przykładowe zdane testy: wyłączenie zbędnych modułów kernela (cramfs, freevxfs, hfs, overlayfs, squashfs)
- Przykładowe niezdane testy: moduł afs nie jest wyłączony

**Vulnerability Detection**  
| Severity | Liczba |
|---|---|
| Critical | 3 |
| High | 372 |
| Medium | 846 |
| Low | 33 |
| Pending | 619 |

Top 5 podatnych paczek: linux-image-6.8.0-90-generic (1769), curl (7), libcurl3t64-gnutls (7), libcurl4i64 (7), amd64-microcode (5)

---

## Zadanie 2 – Analiza Security Dashboard

### Odpowiedzi na pytania

**1. Pięć różnych typów alertów wykrytych w systemie:**

| Typ alertu | Opis |
|---|---|
| SSH authentication | Nieudane próby logowania SSH, ataki brute force |
| PAM authentication | Błędy uwierzytelniania użytkowników przez PAM |
| File Integrity Monitoring (FIM) | Zmiany sumy kontrolnej plików systemowych |
| CIS Compliance | Niespełnione wymagania benchmarku CIS Ubuntu |
| System login | Poprawne logowania użytkowników do systemu |

**2. Najczęstszy typ alertu na Ubuntu Server:**  
Najczęściej generowane alerty to zdarzenia PAM (uwierzytelnianie) oraz alerty compliance CIS Ubuntu Linux, związane z weryfikacją konfiguracji bezpieczeństwa i próbami logowania użytkowników.

**3. Alert o najwyższym poziomie severity:**  
Najwyższy zaobserwowany poziom to `rule.level = 7` – alerty "Integrity checksum changed" (Rule ID 550). W badanym okresie nie wystąpiły zdarzenia o poziomie 12+, co wskazuje na brak incydentów krytycznych wymagających natychmiastowej reakcji.

> **Wniosek:** Brak alertów krytycznych (level 12+) nie oznacza braku zagrożeń – liczne zdarzenia poziomu 10 (SSH brute force) świadczą o aktywnej próbie włamania.

---

## Zadanie 3 – Threat Hunting (poziom medium)

### Krok 1 – Analiza podejrzanej aktywności SSH

**Filtr: Rule ID 5712 – SSH brute force (nieistniejący użytkownik)**  
Łącznie: **150 trafień** dla agenta PrzemyslawK (ID 001)

| Parametr | Wartość |
|---|---|
| Dominujące źródłowe IP | 192.168.50.96 |
| Poziom alertu | 10 (High) |
| Wzorzec czasowy | 27–28 stycznia 2026, godziny nocne i wczesnoporanne |

**Analiza wzorca ataku:**
- Pierwsza próba: 27 stycznia 2026 o 11:18 (seria 10 zdarzeń)
- Przerwa ~6 godzin
- Wznowienie 27 stycznia o ~17:00, kontynuacja do 28 stycznia do 07:10
- Próby powtarzają się co kilka sekund/minut nieprzerwanie przez noc

**Filtr: Rule ID 5551 – PAM: wielokrotne nieudane logowania**  
Łącznie: **10 trafień** w dniu 27 stycznia 2026 o godzinie 11:18  
Odstępy: setne części sekundy między próbami → wskazuje na automatyczny skrypt

**Wnioski – Threat Assessment:**  
Obserwowany wzorzec jednoznacznie wskazuje na **automatyczny atak brute force SSH** z adresu IP 192.168.50.96.  
Atakujący próbuje logowania na nieistniejące konta użytkowników w regularnych, krótkich odstępach czasu.  
Charakter ataku: najprawdopodobniej **skryptowany credential stuffing lub dictionary attack**.  
Rekomendacja: zablokowanie IP 192.168.50.96 na firewallu, wdrożenie fail2ban, zmiana portu SSH z 22 na niestandardowy.

### Krok 2 – Analiza Sudo / Privilege Escalation

Przeszukano zdarzenia z filtrem na słowo kluczowe "sshd" i "sudo".  
Zaobserwowane typy zdarzeń na agencie PrzemyslawK:

| Rule ID | Opis | Poziom |
|---|---|---|
| 40101 | System user successfully logged to the system | 12 |
| 2502 | syslog: User missed the password more than once | 10 |
| 5710 | sshd: Attempt to login using a non-existent user | 5 |
| 5503 | PAM: User login failed | 5 |
| 5760 | sshd: authentication failed | 5 |

**Wniosek:**  
Agent najczęściej generuje zdarzenia związane z nieudanymi próbami SSH (logowania do nieistniejących kont) i błędami PAM. Nie zaobserwowano udanych prób sudo od nieautoryzowanych użytkowników. Alerty PAM potwierdzają zautomatyzowane próby ataku brute force.

### Krok 3 – File Integrity Monitoring (FIM)

**Filtr:** Rule description "file modified" → Rule 550 "Integrity checksum changed"

| Timestamp | Plik | Rule | Poziom |
|---|---|---|---|
| Jan 29 11:18:44 | /usr/bin/c_rehash | 550 | 7 |
| Jan 29 11:18:43 | /usr/bin/openssl | 550 | 7 |
| Jan 29 11:18:43 | /etc/ld.so.cache | 550 | 7 |
| Jan 28 11:18:37 | /usr/bin/screen | 550 | 7 |
| Jan 28 11:18:36 | /etc/shells | 550 | 7 |

**Wnioski:**
- Zmodyfikowane pliki należą do katalogów `/etc` (konfiguracja systemowa) i `/usr/bin` (binaria systemowe)
- Wszystkie zmiany miały miejsce o godzinie **11:18** – charakterystyczne dla harmonogramu aktualizacji
- Pliki openssl, c_rehash, screen → prawdopodobna aktualizacja pakietów systemowych przez APT
- Brak wskazań na złośliwą modyfikację – wzorzec zgodny z rutynowymi aktualizacjami

> **Wniosek bezpieczeństwa:** Modyfikacje plików w `/etc` i `/usr/bin` zawsze wymagają weryfikacji kontekstu. W tym przypadku wzorzec (spójny timestamp, paczki systemowe) wskazuje na aktualizację, nie kompromitację. W prawdziwym SOC każda zmiana /etc/shells byłaby priorytetem do zbadania – dodanie nowej powłoki to klasyczna technika persistence.

---

## Zadanie 4 – Advanced Integration: Windows + Sysmon (poziom senior)

### Cel
Instalacja agenta Wazuh na Windows 11 VM, integracja z Sysmonem, analiza zdarzeń detekcji.

### Krok 1 – Instalacja agenta Wazuh na Windows 11

```powershell
# Pobranie instalatora (PowerShell jako Administrator)
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.2-1.msi `
  -OutFile $env:tmp\wazuh-agent

# Cicha instalacja z podłączeniem do managera
msiexec.exe /i $env:tmp\wazuh-agent /q `
  WAZUH_MANAGER='48.209.8.17' `
  WAZUH_AGENT_NAME='winDave'

# Uruchomienie usługi
NET START Wazuh
```

Wynik: "The Wazuh service was started successfully."

**Weryfikacja połączenia** (ossec.log):
```
wazuh-agent INFO (4102): Connected to the server [48.209.8.27]:1514/tcp
wazuh-agent INFO: Agent is now online
sca: INFO: Evaluation finished for policy CIS Win11 Enterprise
wazuh-agent INFO (6012): Real-time file integrity monitoring started
```

### Krok 2 – Instalacja i konfiguracja Sysmon

```powershell
# Instalacja z plikiem konfiguracyjnym (na Desktop\Sysmon)
.\Sysmon64.exe -accepteula -i .\sysmonconfig.xml
```

Wynik instalacji:
- Sysmon v15.15 (Mark Russinovich / Thomas Garnier, Microsoft)
- Configuration file validated (schema version 4.90)
- SysmonDrv installed i uruchomiony
- Sysmon64 started – usługa widoczna w Services.msc jako "System Monitor service"

### Krok 3 – Detection Analysis: Sysmon Events w Wazuh

Po integracji Sysmon z agentem winDave wygenerowane zostały następujące zdarzenia:

| Rule ID | Opis | Poziom | Interpretacja |
|---|---|---|---|
| 92031 | Discovery activity executed | 3 | Sysmon wykrył działania rekonesansowe (enumeracja systemu) |
| 92033 | Discovery activity spawned via PowerShell | 3 | Rekonesans wywołany przez PowerShell |
| 92205 | PowerShell created executable in Windows root folder | 9 | PowerShell zapisał plik .exe w katalogu systemowym |
| 92021 | PowerShell used to delete files/directories | 3 | PowerShell usunął pliki lub katalogi |

Łącznie: **24 zdarzenia** w przedziale Feb 2, 2026 @ 23:44–23:48

**Wnioski – Sysmon Integration:**  
Integracja Sysmon z Wazuh działa poprawnie – zdarzenia z Sysmon Event Log są odbierane i korelowane przez managera w czasie rzeczywistym.

Wykryte zachowania (Rule 92205 – level 9) mogą wskazywać na podejrzaną aktywność: PowerShell tworzący pliki wykonywalne w katalogu root to technika **T1059.001** (MITRE ATT&CK: PowerShell). W środowisku produkcyjnym wymagałoby to natychmiastowego śledztwa.

MITRE ATT&CK tactics widoczne na dashboardzie agenta:
- Defense Evasion
- Initial Access
- Persistence
- Privilege Escalation

---

## Podsumowanie

| Zadanie | Poziom | Status |
|---|---|---|
| Instalacja agenta Wazuh na Ubuntu | Junior | ✅ Wykonane |
| Analiza Security Dashboard | Junior | ✅ Wykonane |
| Threat Hunting (SSH brute force, FIM, Sudo) | Medium | ✅ Wykonane |
| Windows 11 + Sysmon + Wazuh Integration | Senior | ✅ Wykonane |

**Kluczowe wnioski z laboratorium:**

1. **SSH Brute Force** – IP 192.168.50.96 przeprowadził zautomatyzowany atak na agenta PrzemyslawK (150+ prób). Automatyczne alerty Wazuh (rule.level=10) umożliwiają szybką reakcję.

2. **Vulnerability Management** – System Ubuntu z 3 podatnościami krytycznymi i 372 wysokimi wymaga pilnego patchowania, szczególnie kernela (linux-image) i bibliotek curl/libcurl.

3. **SCA Score 53%** – Ponad połowa kontrolek CIS nie jest spełniona na domyślnej instalacji Ubuntu. W środowisku produkcyjnym wymagana jest hardening zgodnie z CIS Benchmark.

4. **Sysmon + Wazuh** – Integracja znacząco zwiększa widoczność na endpoincie Windows, umożliwiając detekcję technik ATT&CK niewidocznych w standardowych logach Windows (np. tworzenie plików przez PowerShell).

---

*Writeup przygotowany jako element portfolio dla roli Junior SOC Analyst / Junior Penetration Tester.*
