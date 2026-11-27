# NetTrace Pro 0.8.0

Desktopová aplikace pro diagnostiku a dlouhodobé sledování síťového připojení. Zachovává původní ICMP/TCP monitoring, traceroute heatmapu, historii, CSV/PDF export a Ookla Speedtest; projekt je nově rozdělen do samostatných modulů.

## Nové a upravené funkce

- **Modulární struktura:** `main.py` je pouze vstupní bod; GUI, databáze, síťové sondy, analýza tras, exporty, procesy, LAN discovery a e-mailová upozornění jsou oddělené moduly.
- **LAN discovery:** skenování uživatelem zadané privátní podsítě v CIDR zápisu (max. 512 adres), ping a reverzní DNS; MAC adresa se doplní pouze pokud je dostupná v lokální ARP cache Windows. Výsledky se ukládají do SQLite.
- **TCP port check:** ověření vybraných portů na zadaném hostu.
- **Historie:** dostupnost vypočítaná z uložených monitorovacích vzorků, časové přehledy a týdenní/měsíční agregace.
- **E-mailová upozornění:** volitelné SMTP/STARTTLS upozornění na výpadek, obnovení spojení a překročení prahů. Heslo se ukládá přes systémový keyring, nikoli do konfiguračního souboru.
- **Bez blikajících konzolí:** příkazy `ping`, `tracert`, `arp` a Ookla CLI se ve Windows spouštějí s `CREATE_NO_WINDOW` a `STARTF_USESHOWWINDOW`; EXE je sestavené v režimu `--windowed`.
- **Databáze:** původní tabulky a historie zůstávají zachované; nové tabulky se vytvářejí automaticky.

## Spuštění ze zdrojového kódu

Požadavky: Windows 10/11, Python 3.10 nebo novější.

```powershell
python -m pip install -r requirements.txt
python main.py
```

## Sestavení EXE

V PowerShellu v adresáři projektu:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build_windows.ps1
```

Výsledný soubor bude `dist\NetTracePro.exe`. Build vyžaduje internet pro instalaci balíčků. Pokud je přiložen `speedtest.exe`, přibalí se do EXE.

## Poznámky k přesnosti a bezpečnosti

- LAN discovery je best-effort: zařízení mohou blokovat ICMP, hostname nemusí být dostupný a MAC adresa se nemusí objevit v ARP cache. Nejde o garantovaný inventář celé sítě.
- Z ARP/ping údajů nelze určit fyzické propojení switchů a zařízení; aplikace proto nevykresluje smyšlenou fyzickou topologii.
- Skenování je omezeno na privátní podsítě do 512 adres. Používej jej pouze v síti, kterou smíš spravovat.
- „Availability“ je odhad z měření, která aplikace skutečně uložila. Doby, kdy aplikace neběžela nebo monitoring nebyl spuštěný, nelze zpětně dopočítat.
- Úspěšné TCP spojení potvrzuje pouze dostupnost portu z daného počítače, nikoli bezpečnost služby.
- Pro e-mailová upozornění je nutné nastavit SMTP server, odesílatele, příjemce a přihlašovací údaje. Heslo vyžaduje podporovaný systémový keyring.
- Windows firewall, antivir nebo oprávnění mohou ovlivnit výsledky síťových testů.

## Datové umístění

Historie je ukládána do `%USERPROFILE%\.nettrace_pro\history.sqlite3`. Nastavení aplikace používá Qt `QSettings`.

<img width="1282" height="1004" alt="NetTrace-Pro_0 8 0" src="https://github.com/user-attachments/assets/46c683cf-93e2-4fc2-bfe2-6bcfb537c1ae" />

