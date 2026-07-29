import click
from pmmap import pipeline

# Shared filtering flags for thesis network-scope constraints.
NETFLAGS = [
    click.option('--include-cidrs', multiple=True, help='CIDR ranges to include, usually internal address ranges.'),
    click.option('--exclude-cidrs', multiple=True, help='CIDR ranges to exclude.'),
    click.option(
        '--drop-outside',
        is_flag=True,
        default=None,
        help='Drop records when neither endpoint is in the configured include ranges.',
    ),
]


@click.group()
def cli():
    pass


@cli.command(name='run')
@click.option('--input', 'input_path', type=click.Path(exists=True),
              help='Preprocessed CSV/JSON/Zeek-log file or directory.')
@click.option('--flows', 'flows_path', type=click.Path(exists=True),
              help='Already-normalized flows.jsonl file or its containing directory.')
@click.option('--pcap', 'pcap_inputs', type=click.Path(exists=True), multiple=True,
              help='Raw PCAP/PCAPNG files or directories to process with Zeek.')
@click.option('--netflow', 'netflow_inputs', type=click.Path(exists=True), multiple=True,
              help='Raw NetFlow/IPFIX files or directories to process with nfdump.')
@click.option('--output', type=str, required=True,
              help='Run directory containing all stage outputs and run_manifest.json.')
@NETFLAGS[0]
@NETFLAGS[1]
@NETFLAGS[2]
@click.option('--zeek-bin', default='zeek', show_default=True, help='Zeek binary.')
@click.option('--zeek-script', 'zeek_scripts', multiple=True, help='Optional Zeek scripts.')
@click.option('--nfdump-bin', default='nfdump', show_default=True, help='nfdump binary.')
@click.option('--netflow-format', type=click.Choice(['csv', 'json']), default='csv',
              show_default=True, help='nfdump output format.')
@click.option('--p0f-bin', default='p0f', show_default=True,
              help='p0f binary for optional passive OS fingerprinting.')
@click.option('--cpe-map', 'cpe_map_path', type=click.Path(exists=True, dir_okay=False),
              help='Optional fingerprint-to-CPE mapping. No sample map is loaded implicitly.')
@click.option('--min-flows', type=click.IntRange(min=1), default=1, show_default=True,
              help='Minimum flow count required for a graph edge.')
@click.option('--external-cmd', type=str,
              help='Optional external criticality command.')
@click.option('--external-timeout', type=click.FloatRange(min=0.1), default=60.0,
              show_default=True, help='External criticality timeout in seconds.')
@click.option('--title', default='Passive Network Mapping Report', show_default=True,
              help='Report title.')
@click.option('--pdf/--no-pdf', default=False, show_default=True,
              help='Attempt PDF generation with Pandoc.')
@click.option('--top-k', type=click.IntRange(min=1), default=10, show_default=True,
              help='Number of records in report leader tables.')
@click.option('--hash-inputs/--no-hash-inputs', default=True, show_default=True,
              help='Record SHA-256 hashes of source inputs in the run manifest.')
def run_workflow(
    input_path,
    flows_path,
    pcap_inputs,
    netflow_inputs,
    output,
    include_cidrs,
    exclude_cidrs,
    drop_outside,
    zeek_bin,
    zeek_scripts,
    nfdump_bin,
    netflow_format,
    p0f_bin,
    cpe_map_path,
    min_flows,
    external_cmd,
    external_timeout,
    title,
    pdf,
    top_k,
    hash_inputs,
):
    """Run the full mapping workflow from one selected input mode."""
    try:
        pipeline.run_all(
            out_dir=output,
            input_path=input_path,
            flows_path=flows_path,
            pcap_inputs=pcap_inputs,
            netflow_inputs=netflow_inputs,
            include_cidrs=include_cidrs or None,
            exclude_cidrs=exclude_cidrs or None,
            drop_outside=drop_outside,
            zeek_bin=zeek_bin,
            zeek_scripts=zeek_scripts,
            nfdump_bin=nfdump_bin,
            netflow_format=netflow_format,
            p0f_bin=p0f_bin,
            cpe_map_path=cpe_map_path,
            min_flows=min_flows,
            external_cmd=external_cmd,
            external_timeout=external_timeout,
            title=title,
            pdf=pdf,
            top_k=top_k,
            hash_inputs=hash_inputs,
        )
    except Exception as exc:
        raise click.ClickException(f"Workflow failed: {exc}") from exc


@cli.command(name='normalize')
@click.option('--input', type=str, required=True, help='Input directory with nfdump CSV files, for example data/raw.')
@click.option('--output', type=str, required=True, help='Output directory for flows.jsonl, for example data/normalized.')
@NETFLAGS[0]
@NETFLAGS[1]
@NETFLAGS[2]
def normalize(input, output, include_cidrs, exclude_cidrs, drop_outside):
    """Convert nfdump CSV files to flows.jsonl (JSON Lines)."""
    try:
        pipeline.normalize(
            input_dir=input,
            out_dir=output,
            include_cidrs=include_cidrs,
            exclude_cidrs=exclude_cidrs,
            drop_outside=drop_outside,
        )
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc


@cli.command(name='ingest')
@click.option('--pcap', 'pcap_inputs', type=click.Path(exists=True), multiple=True,
              help='PCAP/PCAPNG files or directories.')
@click.option('--netflow', 'netflow_inputs', type=click.Path(exists=True), multiple=True,
              help='NetFlow/IPFIX files or directories, for example nfcapd.*.')
@click.option('--output', type=str, required=True, help='Target directory for outputs (zeek/, nfdump/).')
@click.option('--zeek-bin', default='zeek', show_default=True, help='Zeek binary.')
@click.option('--zeek-script', 'zeek_scripts', multiple=True,
              help='Optional Zeek scripts. By default, Zeek runs local.')
@click.option('--nfdump-bin', default='nfdump', show_default=True, help='nfdump binary.')
@click.option('--netflow-format', type=click.Choice(['csv', 'json']), default='csv', show_default=True,
              help='nfdump output format.')
def ingest(pcap_inputs, netflow_inputs, output, zeek_bin, zeek_scripts, nfdump_bin, netflow_format):
    """Run Zeek/nfdump ingest according to the workflow."""
    try:
        pipeline.ingest(
            out_dir=output,
            pcap_inputs=pcap_inputs,
            netflow_inputs=netflow_inputs,
            zeek_bin=zeek_bin,
            zeek_scripts=zeek_scripts,
            nfdump_bin=nfdump_bin,
            netflow_format=netflow_format,
        )
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc


@cli.command(name='inventory')
@click.option('--flows', type=str, required=True,
              help='Path to flows.jsonl or to a directory containing it.')
@click.option('--output', type=str, required=True,
              help='Output directory for hosts.jsonl.')
def inventory(flows, output):
    """Group normalized flows into hosts.jsonl."""
    try:
        pipeline.inventory(flows_path=flows, out_dir=output)
    except FileNotFoundError as exc:
        raise click.ClickException(str(exc)) from exc
    except Exception as exc:
        raise click.ClickException(f"Inventory failed: {exc}") from exc


@cli.command(name='enrich')
@click.option('--flows', type=str, required=True,
              help='Path to flows.jsonl for fingerprint aggregation.')
@click.option('--output', type=str, required=True,
              help='Output directory for enriched_hosts.jsonl.')
@click.option('--pcap', 'pcap_inputs', type=click.Path(exists=True), multiple=True,
              help='Optional PCAP/PCAPNG files or directories for p0f OS fingerprinting.')
@click.option('--p0f-bin', default='p0f', show_default=True,
              help='p0f binary for passive OS fingerprinting.')
@click.option('--cpe-map', 'cpe_map_path', type=str,
              help='Optional YAML/JSON mapping from fingerprints to CPE 2.3 identifiers.')
def enrich(flows, output, pcap_inputs, p0f_bin, cpe_map_path):
    """Aggregate JA3/JA3S/HASSH/SNI/DNS, CPE mapping, and optional p0f OS guesses."""
    try:
        pipeline.enrich(
            flows_path=flows,
            out_dir=output,
            pcap_inputs=pcap_inputs,
            p0f_bin=p0f_bin,
            cpe_map_path=cpe_map_path,
        )
    except Exception as exc:
        raise click.ClickException(f"Enrich failed: {exc}") from exc


@cli.command(name='analyze')
@click.option('--flows', type=str, required=True,
              help='Path to flows.jsonl.')
@click.option('--output', type=str, required=True,
              help='Output directory for graph.json and edges.jsonl.')
@click.option('--hosts', type=str, required=False,
              help='Optional hosts.jsonl from inventory for role and OS metadata.')
@click.option('--enriched-hosts', type=str, required=False,
              help='Optional enriched_hosts.jsonl with fingerprints and OS metadata.')
@click.option('--min-flows', type=int, default=1, show_default=True,
              help='Minimum number of flows required to keep an edge in the graph.')
def analyze(flows, output, hosts, enriched_hosts, min_flows):
    """Build an observed host-to-service communication graph."""
    try:
        pipeline.analyze(
            flows_path=flows,
            out_dir=output,
            hosts_path=hosts,
            enriched_hosts_path=enriched_hosts,
            min_flows=min_flows,
        )
    except Exception as exc:
        raise click.ClickException(f"Analyze failed: {exc}") from exc


@cli.command(name='criticality')
@click.option('--graph', type=str, required=True,
              help='Path to graph.json produced by analyze.')
@click.option('--output', type=str, required=True, help='Output directory for criticality results.')
@click.option('--hosts', type=str, required=False,
              help='Optional enriched_hosts.jsonl with additional CPE, role, and OS metadata.')
@click.option('--external-cmd', type=str, required=False,
              help='External criticality tool. It reads JSON from stdin and returns JSON on stdout.')
@click.option('--dump-input', 'dump_input_path', type=str, required=False,
              help='Path for saving the JSON payload sent to the external tool.')
@click.option('--external-timeout', type=click.FloatRange(min=0.1), default=60.0,
              show_default=True, help='External criticality timeout in seconds.')
def criticality(
    graph,
    output,
    hosts,
    external_cmd,
    dump_input_path,
    external_timeout,
):
    """Rank nodes by criticality using the built-in heuristic or an external tool."""
    try:
        pipeline.criticality(
            graph_path=graph,
            out_dir=output,
            hosts_path=hosts,
            external_cmd=external_cmd,
            dump_input_path=dump_input_path,
            external_timeout=external_timeout,
        )
    except Exception as exc:
        raise click.ClickException(f"Criticality failed: {exc}") from exc


@cli.command(name='export')
@click.option('--hosts', type=str, required=True, help='hosts.jsonl from inventory.')
@click.option('--graph', type=str, required=True, help='graph.json from analyze.')
@click.option('--criticality', type=str, required=False, help='criticality.jsonl from the criticality step.')
@click.option('--output', type=str, required=True, help='Output directory for summary.json and report.md.')
@click.option('--title', type=str, default='Passive Network Mapping Report', show_default=True,
              help='Report title.')
@click.option('--pdf', is_flag=True, help='Generate PDF when pandoc is available.')
@click.option('--enriched', type=str, required=False, help='Optional enriched_hosts.jsonl for fingerprint/CPE overview.')
@click.option('--top-k', type=int, default=10, show_default=True, help='Number of rows in top tables.')
@click.option('--figures-manifest', type=str, required=False,
              help='Optional JSON figure manifest to include in the report.')
def export(hosts, graph, criticality, output, title, pdf, enriched, top_k, figures_manifest):
    """Generate summary JSON, Markdown, and optionally PDF from pipeline outputs."""
    try:
        pipeline.export(
            hosts_path=hosts,
            graph_path=graph,
            criticality_path=criticality,
            out_dir=output,
            title=title,
            pdf=pdf,
            enriched_path=enriched,
            top_k=top_k,
            figures_manifest_path=figures_manifest,
        )
    except Exception as exc:
        raise click.ClickException(f"Export failed: {exc}") from exc


if __name__ == '__main__':
    cli()
