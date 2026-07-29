# External Criticality Tool Interface

`main.py criticality` can call an external ranking tool through
`--external-cmd`. This document defines the JSON contract used by the CLI.

The interface is intentionally small: the pipeline sends the observed
host-to-service graph and enriched host metadata on stdin, and expects host or
node scores on stdout. This makes it possible to connect research prototypes
without coupling their dependencies to the main project.

There is no built-in `--rules rules.yaml` option. If an organization needs
business-impact rules or its own weights, its external command is responsible
for loading that configuration and returning the resulting scores.

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
  "in_scope": true,
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
python main.py criticality \
  --graph data/run/demo/graph \
  --hosts data/run/demo/enriched/enriched_hosts.jsonl \
  --output data/run/demo/criticality \
  --dump-input data/run/demo/criticality/criticality_input.json
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

`id` is required and must match an eligible node identifier. Nodes explicitly
marked `in_scope: false`, their service nodes, and incident edges are removed
from the external payload. Scores must be finite numeric values; duplicate or
unknown identifiers, non-finite values, malformed JSON, and an empty result are
rejected. Additional fields are preserved in the output metrics where possible.

The external tool must decide how to interpret the graph. In particular,
service nodes have identifiers such as `10.0.0.5:53/udp`; their `ip` field links
them to the corresponding host. Traffic `bytes` represent observed volume and
must not be passed to shortest-path algorithms as a distance unless they are
first transformed into a justified distance measure.

## Examples

Run the built-in heuristic and save the external-tool input:

```bash
python main.py criticality \
  --graph data/run/demo/graph \
  --hosts data/run/demo/enriched/enriched_hosts.jsonl \
  --output data/run/demo/criticality \
  --dump-input data/run/demo/criticality/criticality_input.json
```

Call an external tool:

```bash
python main.py criticality \
  --graph data/run/demo/graph \
  --hosts data/run/demo/enriched/enriched_hosts.jsonl \
  --output data/run/demo/criticality_external \
  --external-cmd "/path/to/external_tool --arg1 foo" \
  --external-timeout 60 \
  --dump-input data/run/demo/criticality_external/input.json
```

Verify the integration with the repository example:

```bash
python main.py criticality \
  --graph data/run/demo/graph \
  --hosts data/run/demo/enriched/enriched_hosts.jsonl \
  --output data/run/demo/criticality_stub \
  --external-cmd "python scripts/external_criticality_stub.py" \
  --dump-input data/run/demo/criticality_stub/input.json
```

`scripts/external_criticality_stub.py` is only a transport example. It projects
service destinations back to their host IPs and returns normalized undirected
host degree. It does not reproduce the built-in multi-signal heuristic and is
not an example of business-criticality rules.

## Built-in resource policy

The built-in scorer uses exact unweighted betweenness when its conservative
work estimate `nodes * (nodes + edges)` is at most 10,000,000. This estimate
reflects one graph traversal and per-node initialization for every source.
Consequently, sparse CESNET-sized graphs are evaluated exactly instead of
being approximated solely because their node count exceeds 2,000.

Above that boundary, the scorer uses at most 64 deterministically selected
sources (`seed=42`) when `k * (nodes + edges)` is at most 10,000,000. It skips
betweenness when even that sampled computation exceeds the safety limit. The
selected mode, sample size, work estimates, limits, and seed are recorded in
each internal result's `provenance.betweenness_plan`.

## Notes

- If the external command fails, times out, or violates the JSON contract, the
  criticality stage fails. It does not silently fall back to the built-in
  heuristic.
- The built-in score measures structural prominence in observed communication,
  not business impact or a proven functional dependency.
- The framework validates external identifiers and score syntax and records
  results as `method: external`; it cannot validate the external method's
  business assumptions or scientific validity.
