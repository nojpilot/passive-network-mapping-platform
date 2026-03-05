# Workflow platformy pro pasivní mapování sítě

Dokument popisuje, jak z pasivních dat (PCAP, NetFlow/IPFIX, Zeek/Suricata logy) sestavit přehled hostů, služeb, vztahů a kritičnosti prvků v síti. Aktivní skenování ani validace nejsou součástí rozsahu.

## 1. Účel a rozsah

- automaticky zmapovat síť z dostupných pasivních zdrojů,
- vyrobit inventář hostů/služeb, fingerprinty a graf závislostí,
- odhadnout role a kritičnost uzlů,
- generovat konzistentní výstupy vhodné pro další analýzu nebo report.

## 2. Vstupy a předpoklady

- `PCAP` – ideální zdroj pro hlubší fingerprinting (hlavičky, bannery).
- `NetFlow`/`IPFIX` – agregované flows ze SPAN/TAP nebo exportérů.
- Volitelné `Zeek`/`Suricata` logy (`dns`, `http`, `ssl`, `ssh`, `conn`) pro rychlou extrakci metadat.
- Přesný adresní/organizační rozsah musí být znám už při ingestu, aby bylo možné filtrovat mimo-doménová data.
- Testovací dataset: `Cyber Czech` NetFlow vzorek (https://zenodo.org/records/3746129) pro ověření pipeline bez vlastních dat.

## 3. Přehled pipeline

1. **Ingest** – převod hrubých dat na jednotné flow + metadata.
2. **Normalizace** – mapování na JSON schéma inspirované CRUSOE.
3. **Inventarizace** – identifikace aktivních IP, portů, služeb a směrů.
4. **Fingerprinting** – OS/TLS/SSH otisky, doplňkové signály (SNI, ALPN, DNS).
5. **Graf vztahů** – stavba orientovaného grafu služeb a závislostí.
6. **Kritičnost** – heuristiky nad grafem, rolemi a objemy.
7. **Export** – machine-readable JSON + lidsky čitelný PDF report.

## 4. Podrobné fáze

### 4.1 Ingest dat

- **Cíl:** sjednotit různé formáty do interní reprezentace flows + protokolových metadat.
- **Postup:**
  - `PCAP` → `Zeek` nebo `Arkime`: získáme flows, hlavičky, bannery.
  - `NetFlow`/`IPFIX` → `nfdump` nebo `SiLK`: agregované sledy komunikací.
- **Výstup:** časově seřazené flows s referencí na rozhraní, směrování a dostupná pole.

### 4.2 Normalizace & datový model

- **Cíl:** mít jednotné JSON schéma (Host, System, Network, Detection and Response, Access Control, Mission, Threat) podle CRUSOE.
- **Kroky:** mapování polí na standard, doplnění chybějících hodnot (např. jednotné označení rozhraní, směru, role).
- **Výstup:** normalizované entity připravené k inventarizaci a analýze.

### 4.3 Inventarizace hostů a služeb

- **Cíl:** rozpoznat „živé“ adresy, používané porty/služby a základní charakteristiky (DNS/DHCP provoz, směry, objemy).
- **Kroky:** filtr dle definovaného adresního/domenového rozsahu, seskupení podle IP a portů, výpočet statistik (směr, počet toků, datový objem).
- **Výstup:** katalog hostů a jejich služeb, včetně indikátorů pro další heuristiky. Prakticky řešeno příkazem `inventory`, který přečte `flows.jsonl` a vytvoří přehledné `hosts.jsonl` (IP → MAC/hostname/DHCP údaje + seznam nabízených a používaných portů).

### 4.4 Fingerprinting

- **OS:** `p0f` nad PCAP (hlavičky TCP/IP).
- **TLS:** `JA3/JA3S/JA4` z TLS ClientHello/ServerHello; doplnit `SNI`, (`ALPN`).
- **SSH:** `HASSH` z parametrů počáteční výměny klíčů (algoritmy KEX, šifry, MAC).
- **CPE export:** mapovat detekované služby/otisky na CPE 2.3 identifikátory a ukládat je do výstupního JSONu, aby šly strojově řadit a porovnávat.
- **Poznámky:** šifrování a randomizace klientů způsobují variabilní otisky, proto kombinovat více signálů, používat časová okna, prahy výskytu a počítat s kolizemi.

### 4.5 Komunikační vztahy a závislosti

- **Cíl:** postavit směrovaný graf, kde uzel = IP/role/služba, hrana = klient → server.
- **Funkce:** detekce rolí (`DNS`, `DHCP`, `AD`, `mail`), multihosting (`SNI`, `Host` hlavička), funkční závislosti časovou korelací (např. klient nejprve DNS → následně TLS).
- **Výstup:** graf s anotacemi, připravený pro heuristiky kritičnosti.
- **Implementace:** znovupoužít Python prototyp (https://is.muni.cz/th/t0dn4/) postavený na metodě z článku https://ieeexplore.ieee.org/document/10575713; doprovodná data na https://zenodo.org/records/10548434 (NetworkX, role, vazby). Kód je přibalen v `data/prototype/link-prediction` (MIT licence), spouští se wrapperem `scripts/prototype_runner.py` (potřebuje Python ≤3.11 + PyTorch/torch_geometric).

### 4.6 Vyhodnocení kritičnosti

- **Základ:** centrálnost v grafu, počet závislých služeb, objem/unikátnost komunikace, role hosta, kombinace s fingerprinty.
- **Integrovaný nástroj:** pro výpočet kritičnosti využít existující nástroj z diplomky studenta (https://is.muni.cz/th/tba1i/), napojený na náš graf a CPE identifikátory; pipeline mu poskytne `hosts.jsonl`, hrany a role, výstup se vrátí jako priorizovaný seznam.
- **Výstup:** seřazený seznam kritických uzlů včetně metrik a textového zdůvodnění; v JSONu připojit referenci na použité metody/nástroj.

### 4.7 Výstupy a reporty

- Machine-readable `JSON` podle sjednoceného schématu.
- Jedním příkazem generovaný report: `export` vytvoří `summary.json` + `report.md`, volitelně `report.pdf` (vyžaduje `pandoc`). Obsah: přehled sítě, seznam hostů/služeb, graf závislostí, fingerprinty/CPE, top kritické uzly. (Volitelně lze doplnit tabulku doména ↔ IP (Passive DNS)).

## 5. Orchestrace (one-shot pipeline)

```
ingest(pcap|netflow)
  → normalize(unified_model)
  → enrich(fingerprints + passive DNS)
  → analyze(graph + roles + criticality)
  → export(json + pdf_report)
```

## 6. Omezení a rizika

- Pasivní přístup nezachytí nevyužité nebo spící služby.
- Šifrování omezuje bannery i část fingerprintingu; některé funkce nejsou dostupné při ingestu pouze z NetFlow.
- Fingerprinty se u moderních klientů mění (update knihoven, náhodné pořadí ciphers); nutné pracovat s časem a prahy.

## 7. Kritéria úspěchu (demo scénář)

1. Správně identifikovaní hosté a služby z dostupných dat.
2. Graf komunikací s detekovanými rolěmi.
3. Top 5 kritických uzlů s uvedenými metrikami.
4. Export sjednoceného `JSON` + `PDF` reportu.

## 8. Otevřené otázky / TODO

- [ ] Zadefinovat přesný adresní nebo doménový rozsah, aby bylo jasné, co filtrovat už při ingestu.
- [ ] Ujasnit si, které volby budou řízené přes CLI flagy/konfiguraci a jak se projeví ve všech krocích pipeline.
- [ ] Rozhodnout, co se stane s toky mimo sledované subnety (zahodit, archivovat, označit?).
- [ ] Popsat strategii pro případy, kdy je k dispozici pouze NetFlow (které funkce fingerprintingu jsou tím pádem vypnuté).
- [ ] Potvrdit, zda bude PCAP k dispozici pro `p0f`, a specifikovat jak se bude získávat (SPAN interface, capture window, rotace souborů).
- [ ] Ověřit CPE mapování fingerprintů (převod z JA3/HASSH/SNI na CPE 2.3) a sjednotit to v exportu.
- [ ] Zaintegrovat Python prototyp z práce (https://is.muni.cz/auth/th/t0dn4/, data/implementace: https://zenodo.org/records/10548434) – primárně graf a role, využívá `NetworkX`.
- [ ] Navázat pipeline na nástroj pro kritičnost (https://is.muni.cz/auth/th/tba1i/) a sjednotit vstupní/výstupní formát.
- [ ] Předpřipravit CI test nad datasetem `Cyber Czech` pro rychlý smoke test ingestu → exportu.
