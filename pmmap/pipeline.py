"""Notebook-friendly wrappers around pipeline stages."""

from __future__ import annotations

from typing import Iterable, Sequence

from . import analyze as analyze_module
from . import criticality as criticality_module
from . import enrich as enrich_module
from . import export as export_module
from . import ingest as ingest_module
from . import inventory as inventory_module
from . import normalize as normalize_module
from . import workflow as workflow_module


def ingest(
    out_dir: str,
    pcap_inputs: Iterable[str] | None = None,
    netflow_inputs: Iterable[str] | None = None,
    zeek_bin: str = "zeek",
    zeek_scripts: Iterable[str] | None = None,
    nfdump_bin: str = "nfdump",
    netflow_format: str = "csv",
):
    """Run Zeek/nfdump ingest step (optional for raw PCAP/NetFlow inputs)."""
    ingest_module.run(
        out_dir=out_dir,
        pcap_inputs=pcap_inputs,
        netflow_inputs=netflow_inputs,
        zeek_bin=zeek_bin,
        zeek_scripts=zeek_scripts,
        nfdump_bin=nfdump_bin,
        netflow_format=netflow_format,
    )


def normalize(
    input_dir: str,
    out_dir: str,
    include_cidrs: Sequence[str] | None = None,
    exclude_cidrs: Sequence[str] | None = None,
    drop_outside: bool | None = None,
):
    """Normalize nfdump/Zeek outputs into flows.jsonl."""
    net_cfg = {
        "include_cidrs": list(include_cidrs) if include_cidrs else None,
        "exclude_cidrs": list(exclude_cidrs) if exclude_cidrs else None,
        "drop_outside": drop_outside,
    }
    normalize_module.run(input_dir=input_dir, out_dir=out_dir, net_cfg=net_cfg)


def inventory(flows_path: str, out_dir: str):
    """Build hosts.jsonl inventory from flows."""
    inventory_module.run(flows_path=flows_path, out_dir=out_dir)


def enrich(
    flows_path: str,
    out_dir: str,
    pcap_inputs: Iterable[str] | None = None,
    p0f_bin: str = "p0f",
    cpe_map_path: str | None = None,
):
    """Aggregate fingerprints and optional p0f OS guesses into enriched_hosts.jsonl."""
    enrich_module.run(
        flows_path=flows_path,
        out_dir=out_dir,
        pcap_inputs=pcap_inputs,
        p0f_bin=p0f_bin,
        cpe_map_path=cpe_map_path,
    )


def analyze(
    flows_path: str,
    out_dir: str,
    hosts_path: str | None = None,
    enriched_hosts_path: str | None = None,
    min_flows: int = 1,
):
    """Build host-service graph from flows (graph.json, edges.jsonl)."""
    analyze_module.run(
        flows_path=flows_path,
        out_dir=out_dir,
        hosts_path=hosts_path,
        enriched_hosts_path=enriched_hosts_path,
        min_flows=min_flows,
    )


def criticality(
    graph_path: str,
    out_dir: str,
    hosts_path: str | None = None,
    external_cmd: str | None = None,
    dump_input_path: str | None = None,
    external_timeout: float = 60.0,
):
    """Compute criticality scores (internal or external tool)."""
    criticality_module.run(
        graph_path=graph_path,
        out_dir=out_dir,
        hosts_path=hosts_path,
        external_cmd=external_cmd,
        dump_input_path=dump_input_path,
        external_timeout=external_timeout,
    )


def export(
    hosts_path: str,
    graph_path: str,
    out_dir: str,
    criticality_path: str | None = None,
    title: str = "Passive Network Mapping Report",
    pdf: bool = False,
    enriched_path: str | None = None,
    top_k: int = 10,
    figures_manifest_path: str | None = None,
    regenerate_figures: bool = True,
):
    """Generate markdown/PDF summary report from pipeline outputs and optional figures."""
    export_module.run(
        hosts_path=hosts_path,
        graph_path=graph_path,
        criticality_path=criticality_path,
        out_dir=out_dir,
        title=title,
        pdf=pdf,
        enriched_path=enriched_path,
        top_k=top_k,
        figures_manifest_path=figures_manifest_path,
        regenerate_figures=regenerate_figures,
    )


def run_all(
    out_dir: str,
    *,
    input_path: str | None = None,
    flows_path: str | None = None,
    pcap_inputs: Sequence[str] | None = None,
    netflow_inputs: Sequence[str] | None = None,
    include_cidrs: Sequence[str] | None = None,
    exclude_cidrs: Sequence[str] | None = None,
    drop_outside: bool | None = None,
    zeek_bin: str = "zeek",
    zeek_scripts: Sequence[str] | None = None,
    nfdump_bin: str = "nfdump",
    netflow_format: str = "csv",
    p0f_bin: str = "p0f",
    cpe_map_path: str | None = None,
    min_flows: int = 1,
    external_cmd: str | None = None,
    external_timeout: float = 60.0,
    title: str = "Passive Network Mapping Report",
    pdf: bool = False,
    top_k: int = 10,
    hash_inputs: bool = True,
):
    """Run the complete workflow and write a reproducibility manifest."""
    return workflow_module.run(
        out_dir=out_dir,
        input_path=input_path,
        flows_path=flows_path,
        pcap_inputs=pcap_inputs,
        netflow_inputs=netflow_inputs,
        include_cidrs=include_cidrs,
        exclude_cidrs=exclude_cidrs,
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
