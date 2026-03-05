import click
from pmmap import pipeline

# Společné flagy pro filtrování dle požadavku vedoucího
NETFLAGS = [
    click.option('--include-cidrs', multiple=True, help='Seznam CIDR (interní adresní rozsahy).'),
    click.option('--exclude-cidrs', multiple=True, help='Seznam CIDR k vyloučení.'),
    click.option('--drop-outside', is_flag=True, help='Vynechat záznamy, které nespadají do definovaných rozsahů.'),
]

@click.group()
def cli():
    pass

@cli.command(name='normalize')
@click.option('--input', type=str, required=True, help='Vstupní složka s nfdump CSV (např. data/raw).')
@click.option('--output', type=str, required=True, help='Výstupní složka pro flows.jsonl (např. data/normalized).')
@NETFLAGS[0]
@NETFLAGS[1]
@NETFLAGS[2]
def normalize(input, output, include_cidrs, exclude_cidrs, drop_outside):
    """Převeď nfdump CSV → flows.jsonl (JSON Lines)."""
    pipeline.normalize(
        input_dir=input,
        out_dir=output,
        include_cidrs=include_cidrs,
        exclude_cidrs=exclude_cidrs,
        drop_outside=drop_outside,
    )


@cli.command(name='ingest')
@click.option('--pcap', 'pcap_inputs', type=click.Path(exists=True), multiple=True,
              help='PCAP/PCAPNG soubory nebo složky se stopami.')
@click.option('--netflow', 'netflow_inputs', type=click.Path(exists=True), multiple=True,
              help='NetFlow/IPFIX soubory nebo složky (např. nfcapd.*).')
@click.option('--output', type=str, required=True, help='Cílová složka pro výstupy (zeek/, nfdump/).')
@click.option('--zeek-bin', default='zeek', show_default=True, help='Binárka Zeek.')
@click.option('--zeek-script', 'zeek_scripts', multiple=True,
              help='Volitelné Zeek skripty (defaultně se spouští local).')
@click.option('--nfdump-bin', default='nfdump', show_default=True, help='Binárka nfdump.')
@click.option('--netflow-format', type=click.Choice(['csv', 'json']), default='csv', show_default=True,
              help='Formát výstupu z nfdump.')
def ingest(pcap_inputs, netflow_inputs, output, zeek_bin, zeek_scripts, nfdump_bin, netflow_format):
    """Spusť Zeek/nfdump ingest podle návrhu workflow."""
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
              help='Cesta k flows.jsonl souboru (nebo složce, kde je uložen).')
@click.option('--output', type=str, required=True,
              help='Složka, kam se uloží hosts.jsonl.')
def inventory(flows, output):
    """Seskup výstup normalize → hosts.jsonl."""
    try:
        pipeline.inventory(flows_path=flows, out_dir=output)
    except FileNotFoundError as exc:
        raise click.ClickException(str(exc)) from exc
    except Exception as exc:
        raise click.ClickException(f"Inventarizace selhala: {exc}") from exc


@cli.command(name='enrich')
@click.option('--flows', type=str, required=True,
              help='Cesta k flows.jsonl (normalize) pro fingerprint agregaci.')
@click.option('--output', type=str, required=True,
              help='Složka, kam se uloží enriched_hosts.jsonl.')
@click.option('--pcap', 'pcap_inputs', type=click.Path(exists=True), multiple=True,
              help='PCAP/PCAPNG soubory/složky pro p0f OS fingerprinting (volitelné).')
@click.option('--p0f-bin', default='p0f', show_default=True,
              help='Binárka p0f pro pasivní fingerprinting OS.')
@click.option('--cpe-map', 'cpe_map_path', type=str,
              help='Cesta k YAML/JSON mapování fingerprint → CPE 2.3 (volitelné).')
def enrich(flows, output, pcap_inputs, p0f_bin, cpe_map_path):
    """Agreguj JA3/JA3S/HASSH/SNI/DNS + CPE mapování a volitelný p0f OS guess do enriched_hosts.jsonl."""
    try:
        pipeline.enrich(
            flows_path=flows,
            out_dir=output,
            pcap_inputs=pcap_inputs,
            p0f_bin=p0f_bin,
            cpe_map_path=cpe_map_path,
        )
    except Exception as exc:
        raise click.ClickException(f"Enrich selhal: {exc}") from exc


@cli.command(name='analyze')
@click.option('--flows', type=str, required=True,
              help='Cesta k flows.jsonl (normalize).')
@click.option('--output', type=str, required=True,
              help='Složka, kam se uloží graf (graph.json, edges.jsonl).')
@click.option('--hosts', type=str, required=False,
              help='Volitelný hosts.jsonl z inventáře pro role/OS.')
@click.option('--enriched-hosts', type=str, required=False,
              help='Volitelné enriched_hosts.jsonl s fingerprinty/OS.')
@click.option('--min-flows', type=int, default=1, show_default=True,
              help='Minimální počet toků pro ponechání hrany v grafu.')
def analyze(flows, output, hosts, enriched_hosts, min_flows):
    """Vytvoř graf závislostí host → služba + role a hostname signály."""
    try:
        pipeline.analyze(
            flows_path=flows,
            out_dir=output,
            hosts_path=hosts,
            enriched_hosts_path=enriched_hosts,
            min_flows=min_flows,
        )
    except Exception as exc:
        raise click.ClickException(f"Analyze selhalo: {exc}") from exc


@cli.command(name='criticality')
@click.option('--graph', type=str, required=True,
              help='Cesta k graph.json (výstup analyze).')
@click.option('--output', type=str, required=True,
              help='Složka pro criticality výstup.')
@click.option('--hosts', type=str, required=False,
              help='Volitelný enriched_hosts.jsonl pro další metadata (CPE/role/OS).')
@click.option('--external-cmd', type=str, required=False,
              help='Externí nástroj pro kritičnost (čte JSON na stdin, vrací JSON na stdout).')
@click.option('--dump-input', 'dump_input_path', type=str, required=False,
              help='Cesta pro uložení JSON payloadu pro externí nástroj.')
def criticality(graph, output, hosts, external_cmd, dump_input_path):
    """Seřaď uzly podle kritičnosti (interní heuristiky nebo externí nástroj)."""
    try:
        pipeline.criticality(
            graph_path=graph,
            out_dir=output,
            hosts_path=hosts,
            external_cmd=external_cmd,
            dump_input_path=dump_input_path,
        )
    except Exception as exc:
        raise click.ClickException(f"Criticality selhalo: {exc}") from exc


@cli.command(name='export')
@click.option('--hosts', type=str, required=True, help='hosts.jsonl z inventory.')
@click.option('--graph', type=str, required=True, help='graph.json z analyze.')
@click.option('--criticality', type=str, required=False, help='criticality.jsonl z criticality kroku.')
@click.option('--output', type=str, required=True, help='Složka pro report (summary.json, report.md).')
@click.option('--title', type=str, default='Passive Network Mapping Report', show_default=True,
              help='Titulek reportu.')
@click.option('--pdf', is_flag=True, help='Pokud je pandoc dostupný, vygeneruj i PDF.')
@click.option('--enriched', type=str, required=False, help='Volitelné enriched_hosts.jsonl pro fingerprint/CPE přehled.')
@click.option('--top-k', type=int, default=10, show_default=True, help='Počet položek v TOP tabulkách.')
@click.option('--figures-manifest', type=str, required=False,
              help='Volitelný JSON manifest obrázků pro vložení do reportu.')
def export(hosts, graph, criticality, output, title, pdf, enriched, top_k, figures_manifest):
    """Vygeneruj summary JSON, Markdown (a volitelně PDF) z výsledků pipeline."""
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
        raise click.ClickException(f"Export selhal: {exc}") from exc

if __name__ == '__main__':
    cli()
