# External Criticality Tool Interface

`main.py criticality` can call an external ranking tool through
`--external-cmd`. This document defines the JSON contract used by the CLI.

The interface is intentionally small: the pipeline sends the graph and enriched
host metadata on stdin, and expects host or node scores on stdout. This makes it
possible to connect research prototypes without coupling their dependencies to
the main project.

## Input

The external command receives one JSON object on stdin:

```json
{
  "nodes": [],
  "edges": []
}
```

Nodes are derived from `graph.json` and enriched host records:

```json
{
  "id": "10.0.0.5",
  "type": "host",
  "roles": ["dns_server"],
  "os": "Windows",
  "cpe": ["cpe:2.3:a:isc:bind:9:*:*:*:*:*:*:*"]
}
```

Edges are derived from the analysis output:

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

For debugging, save the exact payload with `--dump-input`:

```bash
.venv/bin/python main.py criticality \
  --graph data/run/cyber_czech/graph \
  --hosts data/run/cyber_czech/enriched/enriched_hosts.jsonl \
  --output data/run/cyber_czech/criticality \
  --dump-input data/run/cyber_czech/criticality/criticality_input.json
```

## Output

The external command should print JSON to stdout. Both forms are accepted:

```json
[
  {
    "id": "10.0.0.5",
    "score": 0.87,
    "explanation": "betweenness=0.42, dns role, 120 clients"
  }
]
```

```json
{
  "results": [
    {
      "id": "10.0.0.5",
      "score": 0.87
    }
  ]
}
```

`id` is required and must match a node identifier. `score` must be numeric.
Additional fields are preserved in the output metrics where possible.

## Examples

Run the built-in heuristic and save the external-tool input:

```bash
.venv/bin/python main.py criticality \
  --graph data/run/cyber_czech/graph \
  --hosts data/run/cyber_czech/enriched/enriched_hosts.jsonl \
  --output data/run/cyber_czech/criticality \
  --dump-input data/run/cyber_czech/criticality/criticality_input.json
```

Call an external tool:

```bash
.venv/bin/python main.py criticality \
  --graph data/run/cyber_czech/graph \
  --hosts data/run/cyber_czech/enriched/enriched_hosts.jsonl \
  --output data/run/cyber_czech/criticality_external \
  --external-cmd "/path/to/external_tool --arg1 foo" \
  --dump-input data/run/cyber_czech/criticality_external/input.json
```

Verify the integration with the repository stub:

```bash
.venv/bin/python main.py criticality \
  --graph data/run/cyber_czech/graph \
  --hosts data/run/cyber_czech/enriched/enriched_hosts.jsonl \
  --output data/run/cyber_czech/criticality_stub \
  --external-cmd ".venv/bin/python scripts/external_criticality_stub.py" \
  --dump-input data/run/cyber_czech/criticality_stub/input.json
```

## Notes

- If the external command fails or returns invalid JSON, the CLI falls back to
  the built-in heuristic.
- For large graphs, sampled betweenness is used by the internal heuristic for
  speed. External tools may use their own metrics.
