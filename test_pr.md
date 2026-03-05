# Rychlé příklady použití CLI

## 1) Kompletní průchod na ukázkovém PCAP (Windows 10 idle traffic)

```
# Ingest: Zeek + nfdump (pouze PCAP)
python main.py ingest \
  --pcap data/cesnet-idle-os-traffic/windows__windows-10__10.0.9045.429/2025-02-05__vagrant__gusztavvargadr_windows-10/traffic.pcap \
  --output data/demo_ingested

# Normalize: převod na flows.jsonl
python main.py normalize \
  --input data/demo_ingested \
  --output data/demo_normalized

# Inventory: hosts.jsonl (role + základní služby)
python main.py inventory \
  --flows data/demo_normalized \
  --output data/demo_inventory

# Enrich: JA3/JA3S/HASSH/SNI/DNS z flows + p0f OS z PCAP
python main.py enrich \
  --flows data/demo_normalized \
  --pcap data/cesnet-idle-os-traffic/windows__windows-10__10.0.9045.429/2025-02-05__vagrant__gusztavvargadr_windows-10/traffic.pcap \
  --output data/demo_enriched

# Analyze: graf host → služba (využívá roles z inventory a os_guesses z enrich)
python main.py analyze \
  --flows data/demo_normalized \
  --hosts data/demo_inventory/hosts.jsonl \
  --enriched-hosts data/demo_enriched/enriched_hosts.jsonl \
  --min-flows 2 \
  --output data/demo_graph
```

Rychla kontrola, že enrich přidal OS guessy: `jq 'select(.os_guesses) | .ip,.os_guesses' data/demo_enriched/enriched_hosts.jsonl | head`

## 2) Jen enrich+analyze nad hotovými flows

Pokud už máš `flows.jsonl` (např. `data/test_bookworm_normalized/flows.jsonl`) a PCAP:

```
python main.py enrich \
  --flows data/test_bookworm_normalized \
  --pcap data/cesnet-idle-os-traffic/linux__debian__12-bookworm/2025-02-05__vagrant__debian_bookworm64/traffic.pcap \
  --output data/test_bookworm_enriched

python main.py analyze \
  --flows data/test_bookworm_normalized \
  --hosts data/test_bookworm_inventory/hosts.jsonl \
  --enriched-hosts data/test_bookworm_enriched/enriched_hosts.jsonl \
  --output data/test_bookworm_graph
```
