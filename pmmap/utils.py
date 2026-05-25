import os, csv, glob, json
from ipaddress import ip_address, ip_network
from typing import Iterable

# The config file is optional; CLI flags take precedence over config.yaml defaults.

def _load_yaml_safe(path: str):
    try:
        import yaml
        with open(path) as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        return {}

class NetFilter:
    def __init__(self, include_cidrs=None, exclude_cidrs=None, drop_outside=False):
        cfg = _load_yaml_safe('config.yaml') or {}
        network_cfg = cfg.get('network') or {}
        filters_cfg = cfg.get('filters') or {}
        include = include_cidrs if include_cidrs else network_cfg.get('include_cidrs', [])
        exclude = exclude_cidrs if exclude_cidrs else network_cfg.get('exclude_cidrs', [])
        self.include = [ip_network(c) for c in include]
        self.exclude = [ip_network(c) for c in exclude]
        self.drop_outside = drop_outside or filters_cfg.get('drop_outside_ranges', False)

    def in_ranges(self, ip: str) -> bool:
        # True means the address is allowed; false means it can be dropped.
        try:
            addr = ip_address(ip)
        except Exception:
            return False
        if self.exclude and any(addr in n for n in self.exclude):
            return False
        if self.include:
            inside = any(addr in n for n in self.include)
            return inside
        # If include ranges are not defined, keep the address unless exclusions matched.
        return True

# Find all CSV files in the directory tree.

def iter_csv(input_dir: str):
    for path in glob.glob(os.path.join(input_dir, '**', '*.csv'), recursive=True):
        with open(path, newline='') as f:
            try:
                reader = csv.DictReader(f)
            except Exception:
                continue
            yield os.path.basename(path).lower(), reader

# Write JSON Lines.

def write_jsonl(path: str, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as fw:
        for r in records:
            fw.write(json.dumps(r) + '\n')

# Iterate over nfdump JSON exports.

def iter_nfdump_json(input_dir: str):
    pattern = os.path.join(input_dir, '**', '*.json')
    for path in glob.glob(pattern, recursive=True):
        if os.path.basename(path) == 'flows.jsonl':
            continue

        # Prefer streamed JSON Lines for larger files, for example Cyber Czech.
        size_bytes = 0
        try:
            size_bytes = os.path.getsize(path)
        except OSError:
            size_bytes = 0
        stream_only = size_bytes > 50 * 1024 * 1024  # 50 MB

        if stream_only:
            for entry in iter_json_lines_file(path):
                yield path, entry
            continue

        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except OSError:
            continue
        if not content.strip():
            continue
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            data = None
        if data is not None:
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        yield path, entry
            elif isinstance(data, dict):
                if any(k in data for k in ('sa', 'srcip', 'src', 'ts', 'da', 'dstip', 'dst')):
                    yield path, data
                else:
                    flows = None
                    for candidate in ('flows', 'records', 'data'):
                        candidate_val = data.get(candidate)
                        if isinstance(candidate_val, list):
                            flows = candidate_val
                            break
                    if flows:
                        for entry in flows:
                            if isinstance(entry, dict):
                                yield path, entry
            continue
        # Fallback to JSON Lines, one object per line.
        for entry in iter_json_lines(content.splitlines()):
            yield path, entry


def iter_json_lines_file(path: str) -> Iterable[dict]:
    """Stream JSON Lines from disk, one object per line, tolerating trailing commas."""
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                stripped = line.strip().rstrip(',').strip()
                if not stripped or stripped in ('[', ']'):
                    continue
                try:
                    entry = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                if isinstance(entry, dict):
                    yield entry
    except OSError:
        return


def iter_json_lines(lines: Iterable[str]) -> Iterable[dict]:
    """Stream JSON Lines from a string sequence, one object per line."""
    for raw in lines:
        stripped = raw.strip().rstrip(',').strip()
        if not stripped or stripped in ('[', ']'):
            continue
        try:
            entry = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict):
            yield entry

# Iterate over Zeek TSV logs, for example conn.log or dns.log.

def iter_zeek_log(input_dir: str, log_name: str):
    pattern = os.path.join(input_dir, '**', f'{log_name}.log')
    for path in glob.glob(pattern, recursive=True):
        separator = '\t'
        empty_field = '(empty)'
        unset_field = '-'
        fields = None
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            for raw_line in fh:
                line = raw_line.rstrip('\n')
                if not line:
                    continue
                if line.startswith('#'):
                    parts = line.strip().split()
                    if not parts:
                        continue
                    directive = parts[0][1:]
                    if directive == 'separator' and len(parts) > 1:
                        token = parts[1]
                        try:
                            separator = token.encode('utf-8').decode('unicode_escape')
                        except Exception:
                            separator = '\t'
                    elif directive == 'empty_field' and len(parts) > 1:
                        empty_field = parts[1]
                    elif directive == 'unset_field' and len(parts) > 1:
                        unset_field = parts[1]
                    elif directive == 'fields':
                        remainder = line[7:]  # strip '#fields'
                        remainder = remainder.lstrip()
                        if separator:
                            fields = remainder.split(separator)
                        else:
                            fields = parts[1:]
                    continue
                if not fields:
                    continue
                values = line.split(separator)
                if len(values) != len(fields):
                    continue
                row = {}
                for key, value in zip(fields, values):
                    if value == unset_field or value == '':
                        row[key] = None
                    elif value == empty_field:
                        row[key] = ''
                    else:
                        row[key] = value
                yield path, row
