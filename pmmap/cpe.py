"""Utilities for mapping passive fingerprints to CPE 2.3 identifiers."""

from __future__ import annotations

import json
import os
import re
from typing import Iterable

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional dependency fallback
    yaml = None


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


class CPEMapper:
    """Best-effort mapper of fingerprints (JA3/JA3S/HASSH/SNI) to CPE 2.3 IDs."""

    def __init__(self, mapping: dict | None = None):
        self.mapping = mapping or {}
        self._sni_exact = {
            key.lower(): val for key, val in (self.mapping.get('sni', {}).get('exact') or {}).items()
        }
        self._sni_regex: list[tuple[re.Pattern, list[str]]] = []
        for rule in self.mapping.get('sni', {}).get('regex', []) or []:
            pattern = rule.get('pattern') if isinstance(rule, dict) else None
            cpe = _extract_cpe_values(rule.get('cpe') if isinstance(rule, dict) else None)
            if not pattern or not cpe:
                continue
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
            except re.error:
                continue
            self._sni_regex.append((compiled, cpe))

    @classmethod
    def from_file(cls, path: str | None) -> "CPEMapper":
        if not path or not os.path.isfile(path):
            return cls({})
        mapping = {}
        try:
            if path.endswith(('.yaml', '.yml')) and yaml:
                with open(path, 'r', encoding='utf-8') as fh:
                    mapping = yaml.safe_load(fh) or {}
            else:
                with open(path, 'r', encoding='utf-8') as fh:
                    mapping = json.load(fh)
        except Exception:
            mapping = {}
        if not isinstance(mapping, dict):
            mapping = {}
        return cls(mapping)

    def _match_direct(self, section: str, evidence: str) -> list[str]:
        values = self.mapping.get(section) or {}
        entry = values.get(evidence) if isinstance(values, dict) else None
        return _extract_cpe_values(entry)

    def _match_sni(self, evidence: str) -> list[str]:
        evid_lower = evidence.lower()
        exact_match = self._sni_exact.get(evid_lower)
        if exact_match:
            return _extract_cpe_values(exact_match)
        matches: list[str] = []
        for pattern, cpe_values in self._sni_regex:
            if pattern.search(evidence):
                matches.extend(cpe_values)
        return matches

    def match(self, kind: str, evidence: str) -> list[str]:
        """Return list of CPE strings for given fingerprint kind and evidence value."""
        if not evidence:
            return []
        if kind in ('ja3', 'ja3s', 'hassh'):
            return self._match_direct(kind, evidence)
        if kind == 'sni':
            return self._match_sni(evidence)
        return []


def map_host_fingerprints(
    mapper: CPEMapper,
    ja3: Iterable[str] | None = None,
    ja3s: Iterable[str] | None = None,
    hassh: Iterable[str] | None = None,
    sni_values: Iterable[str] | None = None,
) -> list[dict]:
    """Map multiple fingerprint collections to CPE entries (deduplicated)."""
    if mapper is None:
        return []
    results: set[tuple[str, str, str]] = set()

    for value in ja3 or []:
        for cpe in mapper.match('ja3', value):
            results.add((cpe, 'ja3', value))
    for value in ja3s or []:
        for cpe in mapper.match('ja3s', value):
            results.add((cpe, 'ja3s', value))
    for value in hassh or []:
        for cpe in mapper.match('hassh', value):
            results.add((cpe, 'hassh', value))
    for value in sni_values or []:
        for cpe in mapper.match('sni', value):
            results.add((cpe, 'sni', value))

    return [
        {'cpe': cpe, 'source': source, 'evidence': evidence}
        for (cpe, source, evidence) in sorted(results, key=lambda item: (item[0], item[1], item[2]))
    ]
