"""Utilities for mapping passive fingerprints to CPE 2.3 hypotheses.

The mapping is deliberately limited to protocol fingerprints.  Hostnames such
as TLS SNI values describe a contacted or served name, but they are not
evidence that either endpoint runs the product named by that hostname.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Iterable

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional dependency fallback
    yaml = None


SUPPORTED_CPE_SECTIONS = ("ja3", "ja3s", "hassh")
_ENTRY_FIELDS = frozenset({"cpe", "value", "confidence", "provenance"})
_CPE_COMPONENT = r"(?:[^:\\\s]|\\.)+"
_CPE_23_PATTERN = re.compile(
    rf"^cpe:2\.3:[aho]:{_CPE_COMPONENT}(?::{_CPE_COMPONENT}){{9}}$"
)


class CPEMapValidationError(ValueError):
    """Raised when an explicitly supplied fingerprint-to-CPE map is invalid."""


def _validate_cpe_23(value: object, location: str) -> None:
    if not isinstance(value, str) or not _CPE_23_PATTERN.fullmatch(value):
        raise CPEMapValidationError(
            f"CPE mapping entry '{location}' contains invalid CPE 2.3 value "
            f"{value!r}; expected the 13-component formatted-string form "
            "'cpe:2.3:<a|o|h>:vendor:product:version:update:edition:"
            "language:sw_edition:target_sw:target_hw:other'."
        )


def _validate_mapping_entry(raw: object, location: str) -> None:
    payload = raw
    if isinstance(raw, dict):
        unknown_fields = sorted(
            (field for field in raw if field not in _ENTRY_FIELDS),
            key=str,
        )
        if unknown_fields:
            raise CPEMapValidationError(
                f"CPE mapping entry '{location}' has unsupported field(s): "
                + ", ".join(repr(field) for field in unknown_fields)
                + ". Allowed fields are: cpe, value, confidence, provenance."
            )
        value_fields = [field for field in ("cpe", "value") if field in raw]
        if len(value_fields) != 1:
            raise CPEMapValidationError(
                f"CPE mapping entry '{location}' must contain exactly one of "
                "'cpe' or 'value'."
            )
        payload = raw[value_fields[0]]

    if isinstance(payload, str):
        values = [payload]
    elif isinstance(payload, list) and payload:
        values = payload
        if not all(isinstance(value, str) for value in values):
            raise CPEMapValidationError(
                f"CPE mapping entry '{location}' must contain only CPE 2.3 strings."
            )
    else:
        raise CPEMapValidationError(
            f"CPE mapping entry '{location}' must be a CPE 2.3 string, a "
            "non-empty list of CPE 2.3 strings, or an object containing "
            "exactly one of 'cpe' or 'value'."
        )

    for value in values:
        _validate_cpe_23(value, location)


def _validate_mapping(mapping: object, source: str) -> dict:
    if not isinstance(mapping, dict) or not mapping:
        raise CPEMapValidationError(
            f"CPE mapping '{source}' must contain a top-level object with at "
            f"least one supported section: {', '.join(SUPPORTED_CPE_SECTIONS)}."
        )

    unsupported = sorted(
        (section for section in mapping if section not in SUPPORTED_CPE_SECTIONS),
        key=str,
    )
    if unsupported:
        raise CPEMapValidationError(
            f"CPE mapping '{source}' has unsupported section(s): "
            + ", ".join(repr(section) for section in unsupported)
            + f". Supported sections are: {', '.join(SUPPORTED_CPE_SECTIONS)}."
        )

    for section, entries in mapping.items():
        if not isinstance(entries, dict) or not entries:
            raise CPEMapValidationError(
                f"CPE mapping section '{section}' must be a non-empty object "
                "of fingerprint-to-CPE entries."
            )
        for evidence, entry in entries.items():
            if not isinstance(evidence, str) or not evidence.strip():
                raise CPEMapValidationError(
                    f"CPE mapping section '{section}' contains an empty or "
                    "non-string fingerprint key."
                )
            _validate_mapping_entry(entry, f"{section}.{evidence}")
    return mapping


def _extract_cpe_values(raw) -> list[str]:
    """Normalize mapping values to a list of CPE strings."""
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, (list, tuple, set)):
        out: list[str] = []
        for item in raw:
            out.extend(_extract_cpe_values(item))
        return out
    if isinstance(raw, dict):
        if 'cpe' in raw:
            return _extract_cpe_values(raw['cpe'])
        if 'value' in raw:
            return _extract_cpe_values(raw['value'])
    return []


def _mapping_metadata(raw) -> tuple[object, object]:
    """Return optional confidence/provenance supplied by a mapping entry."""
    if not isinstance(raw, dict):
        return "unrated", None
    return raw.get("confidence", "unrated"), raw.get("provenance")


class CPEMapper:
    """Best-effort mapper of JA3/JA3S/HASSH fingerprints to CPE 2.3 IDs."""

    def __init__(
        self,
        mapping: dict | None = None,
        source: str | None = None,
        source_sha256: str | None = None,
    ):
        self.mapping = mapping or {}
        self.source = source or "in-memory mapping"
        self.source_sha256 = source_sha256

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> "CPEMapper":
        if not path:
            raise ValueError("An explicit CPE mapping file path is required.")
        resolved_path = os.path.realpath(
            os.path.abspath(os.path.expanduser(os.fspath(path)))
        )
        if not os.path.isfile(resolved_path):
            raise FileNotFoundError(
                f"CPE mapping file '{resolved_path}' does not exist or is not a file."
            )
        try:
            with open(resolved_path, "rb") as fh:
                raw = fh.read()
        except OSError as exc:
            raise OSError(
                f"Could not read CPE mapping file '{resolved_path}': {exc}"
            ) from exc

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CPEMapValidationError(
                f"CPE mapping file '{resolved_path}' must be UTF-8 encoded."
            ) from exc

        if resolved_path.lower().endswith((".yaml", ".yml")):
            if yaml is None:
                raise RuntimeError(
                    "PyYAML is required to load a YAML CPE mapping file."
                )
            try:
                mapping = yaml.safe_load(text)
            except Exception as exc:
                raise CPEMapValidationError(
                    f"CPE mapping file '{resolved_path}' could not be parsed: {exc}"
                ) from exc
        else:
            try:
                mapping = json.loads(text)
            except json.JSONDecodeError as exc:
                raise CPEMapValidationError(
                    f"CPE mapping file '{resolved_path}' could not be parsed: {exc}"
                ) from exc

        validated_mapping = _validate_mapping(mapping, resolved_path)
        return cls(
            validated_mapping,
            source=resolved_path,
            source_sha256=hashlib.sha256(raw).hexdigest(),
        )

    def _direct_entry(self, section: str, evidence: str):
        values = self.mapping.get(section) or {}
        return values.get(evidence) if isinstance(values, dict) else None

    def match(self, kind: str, evidence: str) -> list[str]:
        """Return list of CPE strings for given fingerprint kind and evidence value."""
        if not evidence:
            return []
        if kind in SUPPORTED_CPE_SECTIONS:
            return _extract_cpe_values(self._direct_entry(kind, evidence))
        return []

    def match_hypotheses(self, kind: str, evidence: str) -> list[dict]:
        """Return CPE hypotheses plus mapping-supplied confidence metadata."""
        if not evidence or kind not in SUPPORTED_CPE_SECTIONS:
            return []
        entry = self._direct_entry(kind, evidence)
        confidence, entry_provenance = _mapping_metadata(entry)
        return [
            {
                'cpe': cpe,
                'confidence': confidence,
                'mapping_entry_provenance': entry_provenance,
            }
            for cpe in _extract_cpe_values(entry)
        ]


def map_host_fingerprints(
    mapper: CPEMapper,
    ja3: Iterable[str] | None = None,
    ja3s: Iterable[str] | None = None,
    hassh: Iterable[str] | None = None,
    sni_values: Iterable[str] | None = None,
    hassh_server: Iterable[str] | None = None,
) -> list[dict]:
    """Map endpoint-specific fingerprints to conservative CPE hypotheses.

    ``sni_values`` remains accepted for API compatibility, but is intentionally
    ignored: an SNI hostname is not host-product evidence.
    """
    if mapper is None:
        return []
    del sni_values

    results: dict[tuple[str, str, str, str], dict] = {}
    evidence_groups = (
        ('ja3', 'client', ja3 or []),
        ('ja3s', 'server', ja3s or []),
        ('hassh', 'client', hassh or []),
        ('hassh', 'server', hassh_server or []),
    )
    for source, endpoint_role, values in evidence_groups:
        for value in values:
            for match in mapper.match_hypotheses(source, value):
                cpe = match['cpe']
                provenance = {
                    'method': 'configured_fingerprint_lookup',
                    'mapping_source': mapper.source,
                }
                if mapper.source_sha256:
                    provenance['mapping_sha256'] = mapper.source_sha256
                if match.get('mapping_entry_provenance') is not None:
                    provenance['mapping_entry'] = match['mapping_entry_provenance']
                key = (cpe, source, value, endpoint_role)
                results[key] = {
                    'cpe': cpe,
                    'source': source,
                    'evidence': value,
                    'endpoint_role': endpoint_role,
                    'confidence': match.get('confidence', 'unrated'),
                    'provenance': provenance,
                }

    return [
        results[key]
        for key in sorted(results, key=lambda item: (item[0], item[1], item[2], item[3]))
    ]
