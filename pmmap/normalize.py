"""Convert Zeek/nfdump outputs into unified Flow objects."""

import os
import glob
import datetime
import json
from collections import Counter
from .schema import Flow
from .utils import NetFilter, iter_csv, iter_zeek_log, iter_nfdump_json, write_jsonl

# Convert nfdump CSV rows to unified Flow dictionaries.

_NUM = { 'ts','sp','dp','pkt','byt','td' }

_DEF_MAP = {
    # CSV headers mapped to internal fields.
    'ts': 'ts',
    'sa': 'src_ip',
    'sp': 'src_port',
    'da': 'dst_ip',
    'dp': 'dst_port',
    'pr': 'proto',
    'pkt': 'pkts',
    'byt': 'bytes',
    'td': 'duration',
    # Fallback names for alternative exporter headers.
    'time': 'ts',
    'srcip': 'src_ip',
    'src': 'src_ip',
    'srcport': 'src_port',
    'src_port': 'src_port',
    'dstip': 'dst_ip',
    'dst': 'dst_ip',
    'dstport': 'dst_port',
    'dst_port': 'dst_port',
    'src_ip': 'src_ip',
    'dst_ip': 'dst_ip',
    'proto': 'proto',
    'packets': 'pkts',
    'pkts': 'pkts',
    'bytes': 'bytes',
    'duration': 'duration',
    'first': 'ts',
    'start': 'ts',
    'ibyt': 'bytes',
    'obyt': 'bytes',
    'ipkt': 'pkts',
    'opkt': 'pkts',
    'in_bytes': 'bytes',
    'out_bytes': 'bytes',
    'in_packets': 'pkts',
    'out_packets': 'pkts',
    # Common IPFIX exporter field names.
    'sourceipv4address': 'src_ip',
    'destinationipv4address': 'dst_ip',
    'sourceipv6address': 'src_ip',
    'destinationipv6address': 'dst_ip',
    'sourcetransportport': 'src_port',
    'destinationtransportport': 'dst_port',
    'protocolidentifier': 'proto',
    'octetdeltacount': 'bytes',
    'octetdeltacount_rev': 'bytes',
    'packetdeltacount': 'pkts',
    'packetdeltacount_rev': 'pkts',
    'flowstartmilliseconds': 'ts',
    'flowendmilliseconds': 'duration',  # used for duration after post-processing
    'flowendmilliseconds_rev': 'duration',
    'biflowstartmilliseconds': 'ts',
    'biflowendmilliseconds': 'duration',
    'biflowendmilliseconds_rev': 'duration',
    'timestamp': 'ts',
}

def _to_int(v, default=0):
    try:
        return int(float(v))
    except Exception:
        return default

def _to_float(v, default=0.0):
    try:
        return float(v)
    except Exception:
        return default

def _map_row(r: dict):
    """Map generic nfdump CSV/JSON row onto Flow fields."""
    out = {}
    start_ts = None
    end_ts = None
    forward_bytes = 0
    reverse_bytes = 0
    forward_pkts = 0
    reverse_pkts = 0
    has_forward_bytes = False
    has_reverse_bytes = False
    has_forward_pkts = False
    has_reverse_pkts = False
    has_ambiguous_bidirectional_counters = False
    for k, v in r.items():
        if v is None or v == '':
            continue
        key_norm = k.strip().lower()
        if key_norm in {
            'flowstartmilliseconds', 'biflowstartmilliseconds', 'timestamp',
            'flowstart', 'flowstarttime', 'flowstartmicroseconds', 'flowstartnanoseconds',
            'flowstartmilliseconds_rev', 'biflowstartmilliseconds_rev',
        }:
            ts_val = _parse_timestamp(v)
            if ts_val is not None:
                start_ts = ts_val if start_ts is None else min(start_ts, ts_val)
            continue
        if key_norm in {
            'flowendmilliseconds', 'biflowendmilliseconds', 'flowend',
            'flowendtime', 'flowendmicroseconds', 'flowendnanoseconds',
            'flowendmilliseconds_rev', 'biflowendmilliseconds_rev',
        }:
            ts_val = _parse_timestamp(v)
            if ts_val is not None:
                end_ts = ts_val if end_ts is None else max(end_ts, ts_val)
            continue

        if key_norm in {
            'byt',
            'bytes',
            'octetdeltacount',
        }:
            forward_bytes += _to_int(v)
            has_forward_bytes = True
        elif key_norm in {'octetdeltacount_rev'}:
            reverse_bytes += _to_int(v)
            has_reverse_bytes = True
        if key_norm in {
            'pkt',
            'packets',
            'pkts',
            'packetdeltacount',
        }:
            forward_pkts += _to_int(v)
            has_forward_pkts = True
        elif key_norm in {'packetdeltacount_rev'}:
            reverse_pkts += _to_int(v)
            has_reverse_pkts = True
        if key_norm in {
            'ibyt',
            'obyt',
            'in_bytes',
            'out_bytes',
            'ipkt',
            'opkt',
            'in_packets',
            'out_packets',
        }:
            has_ambiguous_bidirectional_counters = True

        key = _DEF_MAP.get(key_norm)
        if not key:
            continue
        if key in {'src_port','dst_port'}:
            out[key] = _to_int(v)
        elif key == 'pkts':
            value = _to_int(v)
            out[key] = value + out.get(key, 0)
        elif key == 'bytes':
            value = _to_int(v)
            out[key] = value + out.get(key, 0)
        elif key == 'ts':
            ts_val = _parse_timestamp(v)
            if ts_val is not None:
                out[key] = ts_val
        elif key == 'duration':
            # If this is a flow-end timestamp, calculate the duration later.
            out[key] = _to_float(v)
        elif key in {'proto','src_ip','dst_ip'}:
            if key == 'proto':
                proto_val = _normalize_proto_value(v)
                if proto_val:
                    out[key] = proto_val
            else:
                out[key] = str(v)
    if 'ts' not in out and start_ts is not None:
        out['ts'] = start_ts
    if 'duration' not in out and start_ts is not None and end_ts is not None:
        duration_val = end_ts - start_ts
        out['duration'] = duration_val if duration_val >= 0 else 0.0
    if has_forward_bytes:
        out['bytes_src_to_dst'] = forward_bytes
    if has_reverse_bytes:
        out['bytes_dst_to_src'] = reverse_bytes
    if has_forward_pkts:
        out['pkts_src_to_dst'] = forward_pkts
    if has_reverse_pkts:
        out['pkts_dst_to_src'] = reverse_pkts
    if has_ambiguous_bidirectional_counters:
        out['traffic_directionality'] = 'bidirectional_total'
    elif has_reverse_bytes or has_reverse_pkts:
        out['traffic_directionality'] = 'bidirectional_split'
    elif has_forward_bytes or has_forward_pkts:
        out['traffic_directionality'] = 'source_to_destination'
    return out


def _normalize_epoch(value: float) -> float:
    """Normalize timestamp to seconds (handles ms/us/ns epochs)."""
    if value >= 1e17:
        return value / 1e9  # nanoseconds to seconds
    if value >= 1e14:
        return value / 1e6  # microseconds to seconds
    if value >= 1e11:
        return value / 1e3  # milliseconds to seconds
    return value


def _parse_timestamp(value):
    """Parse timestamps in either epoch or common datetime formats."""
    if value in (None, '', '-'):
        return None
    if isinstance(value, (int, float)):
        return _normalize_epoch(float(value))
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return _normalize_epoch(float(text))
        except ValueError:
            # attempt to parse common datetime formats used by nfdump
            for fmt in ('%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S'):
                try:
                    dt = datetime.datetime.strptime(text, fmt)
                    return dt.timestamp()
                except ValueError:
                    continue
    return None


def _normalize_proto_value(value) -> str | None:
    """Normalize proto string or protocol number to lower-case text."""
    if value in (None, '', '-'):
        return None
    mapping = {
        6: 'tcp',
        17: 'udp',
        1: 'icmp',
    }
    try:
        num = int(value)
        if num in mapping:
            return mapping[num]
        # Keep unknown protocol numbers as numeric strings.
        return str(num)
    except Exception:
        pass
    try:
        return str(value).lower()
    except Exception:
        return None


def _map_common_zeek_fields(r: dict, default_proto: str | None = None):
    """Extract shared Zeek fields (ip/ports/ts/traffic) for flow creation."""
    out = {
        # Zeek's id.orig_* fields identify the connection originator rather
        # than merely an arbitrary exporter direction.
        'src_is_initiator': True,
        'orientation_source': 'zeek_orig_resp',
    }
    ts = r.get('ts')
    if ts not in (None, '', '-'):
        try:
            out['ts'] = float(ts)
        except Exception:
            pass
    uid = r.get('uid')
    if uid not in (None, '', '-'):
        out['uid'] = uid
    src_ip = r.get('id.orig_h')
    if src_ip:
        out['src_ip'] = src_ip
    dst_ip = r.get('id.resp_h')
    if dst_ip:
        out['dst_ip'] = dst_ip
    src_port = r.get('id.orig_p')
    if src_port not in (None, '', '-'):
        out['src_port'] = _to_int(src_port)
    dst_port = r.get('id.resp_p')
    if dst_port not in (None, '', '-'):
        out['dst_port'] = _to_int(dst_port)
    proto = r.get('proto')
    norm_proto = _normalize_proto_value(proto)
    if norm_proto:
        out['proto'] = norm_proto
    elif default_proto:
        out['proto'] = default_proto
    duration = r.get('duration')
    if duration not in (None, '', '-'):
        try:
            out['duration'] = float(duration)
        except Exception:
            pass
    forward_bytes = sum(
        _to_int(r.get(key))
        for key in ('orig_bytes', 'request_bytes')
        if r.get(key) not in (None, '', '-')
    )
    reverse_bytes = sum(
        _to_int(r.get(key))
        for key in ('resp_bytes', 'response_bytes')
        if r.get(key) not in (None, '', '-')
    )
    has_forward_bytes = any(
        r.get(key) not in (None, '', '-')
        for key in ('orig_bytes', 'request_bytes')
    )
    has_reverse_bytes = any(
        r.get(key) not in (None, '', '-')
        for key in ('resp_bytes', 'response_bytes')
    )
    if has_forward_bytes:
        out['bytes_src_to_dst'] = forward_bytes
    if has_reverse_bytes:
        out['bytes_dst_to_src'] = reverse_bytes
    if has_forward_bytes or has_reverse_bytes:
        out['bytes'] = forward_bytes + reverse_bytes

    forward_pkts = _to_int(r.get('orig_pkts'))
    reverse_pkts = _to_int(r.get('resp_pkts'))
    has_forward_pkts = r.get('orig_pkts') not in (None, '', '-')
    has_reverse_pkts = r.get('resp_pkts') not in (None, '', '-')
    if has_forward_pkts:
        out['pkts_src_to_dst'] = forward_pkts
    if has_reverse_pkts:
        out['pkts_dst_to_src'] = reverse_pkts
    if has_forward_pkts or has_reverse_pkts:
        out['pkts'] = forward_pkts + reverse_pkts
    if (
        has_forward_bytes
        or has_reverse_bytes
        or has_forward_pkts
        or has_reverse_pkts
    ):
        out['traffic_directionality'] = 'bidirectional_split'
    return out


def _map_zeek_conn_row(r: dict):
    """Normalize conn.log rows (Zeek) into Flow-like records."""
    out = _map_common_zeek_fields(r)
    # conn.log always contains bytes; use zero if the shared helper did not collect any.
    out.setdefault('bytes', 0)
    conn_state = r.get('conn_state')
    if conn_state not in (None, '', '-'):
        normalized_state = str(conn_state).upper()
        out['connection_state'] = normalized_state
        out['service_response_observed'] = normalized_state in {
            'SF',
            'S1',
            'S2',
            'S3',
            'RSTO',
            'RSTR',
        }
    return out


def _map_zeek_dns_row(r: dict):
    """Normalize dns.log rows with qname info."""
    out = _map_common_zeek_fields(r, default_proto='udp')
    query = r.get('query')
    if query:
        out['dns_qname'] = query
    return out


def _map_zeek_ssl_row(r: dict):
    """Normalize ssl.log rows with TLS fingerprint metadata."""
    out = _map_common_zeek_fields(r, default_proto='tcp')
    sni = r.get('server_name')
    if sni:
        out['sni'] = sni
    ja3 = r.get('ja3')
    if ja3:
        out['ja3'] = ja3
    ja3s = r.get('ja3s')
    if ja3s:
        out['ja3s'] = ja3s
    return out


def _map_zeek_ssh_row(r: dict):
    """Normalize ssh.log rows into Flow-like records with HASSH."""
    out = _map_common_zeek_fields(r, default_proto='tcp')
    hassh_client = r.get('hassh')
    hassh_server = r.get('hasshServer') or r.get('hassh_server')
    if hassh_client:
        out['hassh'] = hassh_client
    if hassh_server:
        out['hassh_server'] = hassh_server
    return out


def _map_zeek_dhcp_row(r: dict):
    """Normalize dhcp.log rows (lease metadata) to attach to flows."""
    out = {
        'src_is_initiator': True,
        'orientation_source': 'zeek_dhcp_client_server',
    }
    ts = r.get('ts')
    if ts not in (None, '', '-'):
        try:
            out['ts'] = float(ts)
        except Exception:
            pass
    client_addr = r.get('client_addr')
    server_addr = r.get('server_addr')
    if client_addr:
        out['src_ip'] = client_addr
    if server_addr:
        out['dst_ip'] = server_addr
    out['proto'] = 'udp'
    out['src_port'] = 68
    out['dst_port'] = 67
    uids = r.get('uids')
    if isinstance(uids, str):
        first_uid = uids.split(',')[0]
    elif isinstance(uids, (list, tuple, set)):
        first_uid = next(iter(uids), None)
    else:
        first_uid = None
    if first_uid and first_uid not in ('-', ''):
        out['uid'] = first_uid
    mac = r.get('mac')
    if mac and mac not in ('-', ''):
        out['dhcp_mac'] = mac
    host_name = r.get('host_name')
    if host_name and host_name not in ('-', ''):
        out['dhcp_host_name'] = host_name
    fqdn = r.get('client_fqdn')
    if fqdn and fqdn not in ('-', ''):
        out['dhcp_fqdn'] = fqdn
    domain = r.get('domain')
    if domain and domain not in ('-', ''):
        out['dhcp_domain'] = domain
    requested = r.get('requested_addr')
    if requested and requested not in ('-', ''):
        out['dhcp_requested_ip'] = requested
    assigned = r.get('assigned_addr')
    if assigned and assigned not in ('-', ''):
        out['dhcp_assigned_ip'] = assigned
    lease = r.get('lease_time')
    if lease not in (None, '', '-'):
        try:
            out['dhcp_lease_time'] = float(lease)
        except Exception:
            pass
    msg_types = r.get('msg_types')
    if msg_types and msg_types not in ('-', ''):
        if isinstance(msg_types, str):
            parsed = [token for token in msg_types.split(',') if token]
        elif isinstance(msg_types, (list, tuple)):
            parsed = list(msg_types)
        else:
            parsed = None
        if parsed:
            out['dhcp_msg_types'] = parsed
    duration = r.get('duration')
    if duration not in (None, '', '-'):
        try:
            out['duration'] = float(duration)
        except Exception:
            pass
    return out

def run(input_dir: str, out_dir: str, net_cfg: dict | None = None):
    """Normalize all supported inputs within input_dir into flows.jsonl."""
    if not os.path.isdir(input_dir):
        raise FileNotFoundError(f"Input directory '{input_dir}' does not exist.")

    supported_patterns = (
        '**/*.csv',
        '**/*.json',
        '**/conn.log',
        '**/dns.log',
        '**/ssl.log',
        '**/ssh.log',
        '**/dhcp.log',
    )
    has_supported_inputs = any(
        glob.glob(os.path.join(input_dir, pattern), recursive=True)
        for pattern in supported_patterns
    )
    if not has_supported_inputs:
        raise FileNotFoundError(
            f"No supported inputs were found in input directory '{input_dir}' "
            "(CSV/JSON/Zeek logs)."
        )

    nf = NetFilter(
        include_cidrs=(net_cfg or {}).get('include_cidrs'),
        exclude_cidrs=(net_cfg or {}).get('exclude_cidrs'),
        drop_outside=(net_cfg or {}).get('drop_outside'),
    )

    out_path = os.path.join(out_dir, 'flows.jsonl')
    records = []
    uid_index: dict[str, dict] = {}
    quality = {
        'input_records_seen': 0,
        'records_by_source': Counter(),
        'missing_required_fields': 0,
        'filtered_excluded': 0,
        'filtered_outside_scope': 0,
        'invalid_records': 0,
        'merged_uid_records': 0,
        'validation_errors': Counter(),
    }

    def _append_flow(rec: dict, source_kind: str):
        quality['input_records_seen'] += 1
        quality['records_by_source'][source_kind] += 1
        if not rec:
            quality['missing_required_fields'] += 1
            return
        src_ip = rec.get('src_ip')
        dst_ip = rec.get('dst_ip')
        proto = rec.get('proto')
        if not src_ip or not dst_ip or not proto:
            quality['missing_required_fields'] += 1
            return
        # Explicit exclusions are stronger than monitored-boundary filtering:
        # records touching an excluded range are always omitted.
        if nf.is_excluded(src_ip) or nf.is_excluded(dst_ip):
            quality['filtered_excluded'] += 1
            return
        src_ok = nf.in_ranges(src_ip)
        dst_ok = nf.in_ranges(dst_ip)
        # A monitored-range filter should retain boundary communication.  Drop
        # only flows for which neither endpoint belongs to the requested scope.
        if not src_ok and not dst_ok and nf.drop_outside:
            quality['filtered_outside_scope'] += 1
            return
        uid = rec.get('uid') or None
        try:
            flow = Flow(**{
                'ts': rec.get('ts', 0.0),
                'src_ip': src_ip,
                'src_port': int(rec.get('src_port', 0)),
                'dst_ip': dst_ip,
                'dst_port': int(rec.get('dst_port', 0)),
                'proto': proto,
                'bytes': int(rec.get('bytes', 0)),
                'pkts': int(rec.get('pkts', 0)),
                'bytes_src_to_dst': rec.get('bytes_src_to_dst'),
                'bytes_dst_to_src': rec.get('bytes_dst_to_src'),
                'pkts_src_to_dst': rec.get('pkts_src_to_dst'),
                'pkts_dst_to_src': rec.get('pkts_dst_to_src'),
                'traffic_directionality': rec.get('traffic_directionality'),
                'duration': rec.get('duration'),
                'uid': uid,
                'src_in_scope': src_ok,
                'dst_in_scope': dst_ok,
                'src_is_initiator': rec.get('src_is_initiator'),
                'orientation_source': rec.get('orientation_source'),
                'connection_state': rec.get('connection_state'),
                'service_response_observed': rec.get(
                    'service_response_observed'
                ),
                'dns_qname': rec.get('dns_qname'),
                'sni': rec.get('sni'),
                'ja3': rec.get('ja3'),
                'ja3s': rec.get('ja3s'),
                'hassh': rec.get('hassh'),
                'hassh_server': rec.get('hassh_server'),
                'dhcp_mac': rec.get('dhcp_mac'),
                'dhcp_host_name': rec.get('dhcp_host_name'),
                'dhcp_fqdn': rec.get('dhcp_fqdn'),
                'dhcp_domain': rec.get('dhcp_domain'),
                'dhcp_requested_ip': rec.get('dhcp_requested_ip'),
                'dhcp_assigned_ip': rec.get('dhcp_assigned_ip'),
                'dhcp_lease_time': rec.get('dhcp_lease_time'),
                'dhcp_msg_types': rec.get('dhcp_msg_types'),
            })
            flow_dict = flow.model_dump()
            if uid:
                existing = uid_index.get(uid)
                if existing:
                    # Fill missing or optional fields from later Zeek rows with the same uid.
                    for key in (
                        'dns_qname',
                        'sni',
                        'ja3',
                        'ja3s',
                        'hassh',
                        'hassh_server',
                        'dhcp_mac',
                        'dhcp_host_name',
                        'dhcp_fqdn',
                        'dhcp_domain',
                        'dhcp_requested_ip',
                        'dhcp_assigned_ip',
                        'dhcp_lease_time',
                        'dhcp_msg_types',
                    ):
                        value = flow_dict.get(key)
                        if value:
                            existing[key] = value
                    # Fill quantitative fields when they are missing.
                    for key in ('ts', 'src_port', 'dst_port'):
                        value = flow_dict.get(key)
                        if value and not existing.get(key):
                            existing[key] = value
                    for key in ('bytes', 'pkts'):
                        value = flow_dict.get(key)
                        if value and existing.get(key) in (None, 0):
                            existing[key] = value
                    for key in (
                        'bytes_src_to_dst',
                        'bytes_dst_to_src',
                        'pkts_src_to_dst',
                        'pkts_dst_to_src',
                        'traffic_directionality',
                        'connection_state',
                        'service_response_observed',
                    ):
                        value = flow_dict.get(key)
                        if value is not None and existing.get(key) is None:
                            existing[key] = value
                    duration_val = flow_dict.get('duration')
                    if duration_val is not None and (existing.get('duration') is None or existing.get('duration') == 0):
                        existing['duration'] = duration_val
                    quality['merged_uid_records'] += 1
                    return
                records.append(flow_dict)
                uid_index[uid] = records[-1]
                return
            records.append(flow_dict)
        except Exception as exc:
            quality['invalid_records'] += 1
            if hasattr(exc, 'errors'):
                try:
                    for error in exc.errors():
                        location = '.'.join(str(part) for part in error.get('loc', ())) or 'record'
                        error_type = str(error.get('type') or type(exc).__name__)
                        quality['validation_errors'][f'{location}:{error_type}'] += 1
                except Exception:
                    quality['validation_errors'][type(exc).__name__] += 1
            else:
                quality['validation_errors'][type(exc).__name__] += 1
            return

    for name, reader in iter_csv(input_dir):
        # Expect nfdump CSV headers with at least ts, sa, da, pr, and related fields.
        for r in reader:
            rec = _map_row(r)
            _append_flow(rec, 'csv')

    for path, obj in iter_nfdump_json(input_dir):
        rec = _map_row(obj)
        _append_flow(rec, 'nfdump_json')

    for path, row in iter_zeek_log(input_dir, 'conn'):
        rec = _map_zeek_conn_row(row)
        _append_flow(rec, 'zeek_conn')

    for path, row in iter_zeek_log(input_dir, 'dns'):
        rec = _map_zeek_dns_row(row)
        _append_flow(rec, 'zeek_dns')

    for path, row in iter_zeek_log(input_dir, 'ssl'):
        rec = _map_zeek_ssl_row(row)
        _append_flow(rec, 'zeek_ssl')

    for path, row in iter_zeek_log(input_dir, 'ssh'):
        rec = _map_zeek_ssh_row(row)
        _append_flow(rec, 'zeek_ssh')

    for path, row in iter_zeek_log(input_dir, 'dhcp'):
        rec = _map_zeek_dhcp_row(row)
        _append_flow(rec, 'zeek_dhcp')

    write_jsonl(out_path, records)
    quality_payload = {
        'input_records_seen': quality['input_records_seen'],
        'accepted_flows': len(records),
        'records_by_source': dict(sorted(quality['records_by_source'].items())),
        'missing_required_fields': quality['missing_required_fields'],
        'filtered_excluded': quality['filtered_excluded'],
        'filtered_outside_scope': quality['filtered_outside_scope'],
        'invalid_records': quality['invalid_records'],
        'merged_uid_records': quality['merged_uid_records'],
        'validation_errors': dict(sorted(quality['validation_errors'].items())),
        'network_scope': {
            'include_cidrs': [str(network) for network in nf.include],
            'exclude_cidrs': [str(network) for network in nf.exclude],
            'drop_outside': bool(nf.drop_outside),
        },
    }
    stats_path = os.path.join(out_dir, 'normalization_stats.json')
    with open(stats_path, 'w', encoding='utf-8') as stats_file:
        json.dump(quality_payload, stats_file, ensure_ascii=False, indent=2)
        stats_file.write('\n')
    if not records:
        raise ValueError(
            f"No valid flow records were produced. Data-quality details -> {stats_path}"
        )
    print(
        f"Wrote {len(records)} flows -> {out_path} "
        f"(data-quality statistics -> {stats_path})"
    )


def run_normalized(input_file: str, out_dir: str, net_cfg: dict | None = None):
    """Validate and scope-filter an existing canonical flows.jsonl file."""
    if not os.path.isfile(input_file):
        raise FileNotFoundError(
            f"Normalized flows file '{input_file}' does not exist."
        )

    nf = NetFilter(
        include_cidrs=(net_cfg or {}).get('include_cidrs'),
        exclude_cidrs=(net_cfg or {}).get('exclude_cidrs'),
        drop_outside=(net_cfg or {}).get('drop_outside'),
    )
    records: list[dict] = []
    quality = {
        'input_records_seen': 0,
        'records_by_source': Counter(),
        'missing_required_fields': 0,
        'filtered_excluded': 0,
        'filtered_outside_scope': 0,
        'invalid_records': 0,
        'merged_uid_records': 0,
        'validation_errors': Counter(),
    }

    with open(input_file, 'r', encoding='utf-8', errors='replace') as source:
        for line in source:
            if not line.strip():
                continue
            quality['input_records_seen'] += 1
            quality['records_by_source']['normalized_jsonl'] += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                quality['invalid_records'] += 1
                quality['validation_errors']['record:json_invalid'] += 1
                continue
            if not isinstance(record, dict):
                quality['invalid_records'] += 1
                quality['validation_errors']['record:not_object'] += 1
                continue

            src_ip = record.get('src_ip')
            dst_ip = record.get('dst_ip')
            proto = record.get('proto')
            if not src_ip or not dst_ip or not proto:
                quality['missing_required_fields'] += 1
                continue
            if nf.is_excluded(src_ip) or nf.is_excluded(dst_ip):
                quality['filtered_excluded'] += 1
                continue
            src_ok = nf.in_ranges(src_ip)
            dst_ok = nf.in_ranges(dst_ip)
            if not src_ok and not dst_ok and nf.drop_outside:
                quality['filtered_outside_scope'] += 1
                continue

            try:
                flow = Flow(
                    **{
                        **record,
                        'src_in_scope': src_ok,
                        'dst_in_scope': dst_ok,
                    }
                )
            except Exception as exc:
                quality['invalid_records'] += 1
                if hasattr(exc, 'errors'):
                    try:
                        for error in exc.errors():
                            location = '.'.join(
                                str(part) for part in error.get('loc', ())
                            ) or 'record'
                            error_type = str(
                                error.get('type') or type(exc).__name__
                            )
                            quality['validation_errors'][
                                f'{location}:{error_type}'
                            ] += 1
                    except Exception:
                        quality['validation_errors'][type(exc).__name__] += 1
                else:
                    quality['validation_errors'][type(exc).__name__] += 1
                continue
            records.append(flow.model_dump())

    out_path = os.path.join(out_dir, 'flows.jsonl')
    write_jsonl(out_path, records)
    quality_payload = {
        'input_records_seen': quality['input_records_seen'],
        'accepted_flows': len(records),
        'records_by_source': dict(sorted(quality['records_by_source'].items())),
        'missing_required_fields': quality['missing_required_fields'],
        'filtered_excluded': quality['filtered_excluded'],
        'filtered_outside_scope': quality['filtered_outside_scope'],
        'invalid_records': quality['invalid_records'],
        'merged_uid_records': quality['merged_uid_records'],
        'validation_errors': dict(sorted(quality['validation_errors'].items())),
        'network_scope': {
            'include_cidrs': [str(network) for network in nf.include],
            'exclude_cidrs': [str(network) for network in nf.exclude],
            'drop_outside': bool(nf.drop_outside),
        },
    }
    stats_path = os.path.join(out_dir, 'normalization_stats.json')
    with open(stats_path, 'w', encoding='utf-8') as stats_file:
        json.dump(quality_payload, stats_file, ensure_ascii=False, indent=2)
        stats_file.write('\n')
    if not records:
        raise ValueError(
            f"No valid flow records were produced. Data-quality details -> {stats_path}"
        )
    print(
        f"Validated {len(records)} normalized flows -> {out_path} "
        f"(data-quality statistics -> {stats_path})"
    )
