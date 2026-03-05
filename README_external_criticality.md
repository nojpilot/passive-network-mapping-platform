## Externí nástroj pro kritičnost – integrační rozhraní

`main.py criticality` už umí volat externí nástroj (`--external-cmd`). Tady je shrnutí, jaký payload posíláme a co očekáváme zpět, abychom mohli integrovat nástroj z diplomky (https://is.muni.cz/auth/th/tba1i/).

### Vstup (stdin)

- JSON objekt `{ "nodes": [...], "edges": [...] }`
- Uzly: převzaté z `graph.json`, typicky:
  ```json
  {
    "id": "10.0.0.5",
    "type": "host",
    "roles": ["dns_server"],
    "os": "Windows",
    "cpe": ["cpe:2.3:a:isc:bind:9:*:*:*:*:*:*:*"]
  }
  ```
- Hrany: výstup z analyze:
  ```json
  {
    "src": "10.0.0.10",
    "dst": "10.0.0.5:53/udp",
    "flows": 42,
    "bytes": 12345,
    "sni": ["example.com"],
    "dns_qnames": ["example.com"],
    "first_seen": 1.0,
    "last_seen": 2.0
  }
  ```

Pro ladění lze payload uložit na disk: `main.py criticality --dump-input data/run/cyber_czech/criticality/criticality_input.json ...`

### Výstup (stdout)

- JSON s listem výsledků nebo objekt se `results`/`scores`. Každá položka by měla mít:
  ```json
  {
    "id": "10.0.0.5",
    "score": 0.87,
    "explanation": "betweenness=0.42, dns role, 120 clients"
  }
  ```
- Pole `id` je povinné; `score` číselné. Další pole se propíší do `metrics`.

### Příklad spuštění

```
# vytvoř payload a spusť interní heuristiku + uložený vstup
.venv/bin/python main.py criticality \
  --graph data/run/cyber_czech/graph \
  --hosts data/run/cyber_czech/enriched/enriched_hosts.jsonl \
  --output data/run/cyber_czech/criticality \
  --dump-input data/run/cyber_czech/criticality/criticality_input.json

# volání externího nástroje (cmd čte stdin, vrací JSON)
.venv/bin/python main.py criticality \
  --graph data/run/cyber_czech/graph \
  --hosts data/run/cyber_czech/enriched/enriched_hosts.jsonl \
  --output data/run/cyber_czech/criticality_external \
  --external-cmd "/path/to/external_tool --arg1 foo" \
  --dump-input data/run/cyber_czech/criticality_external/input.json

# využití stubu (scripts/external_criticality_stub.py) pro ověření integrace
.venv/bin/python main.py criticality \
  --graph data/run/cyber_czech/graph \
  --hosts data/run/cyber_czech/enriched/enriched_hosts.jsonl \
  --output data/run/cyber_czech/criticality_stub \
  --external-cmd ".venv/bin/python scripts/external_criticality_stub.py" \
  --dump-input data/run/cyber_czech/criticality_stub/input.json
```

### Poznámky

- Pokud externí nástroj vrátí neparsovatelný JSON, fallbackne se interní heuristika.
- U velkých grafů se betweenness počítá na vzorku (k=256) kvůli rychlosti; externí nástroj může použít vlastní metriky.
