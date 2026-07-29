"""Infer logical client and service endpoints without rewriting raw flow direction.

Normalized flows retain the observed ``src_*``/``dst_*`` orientation because it
is still meaningful for byte and packet accounting.  Consumers that need
client/server semantics should use :func:`infer_endpoints` instead of assuming
that every destination port is an offered service.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Any, Mapping


# Linux commonly starts ephemeral allocations at 32768.  Treating this whole
# range as "definitely ephemeral" would be too strong because IANA registered
# ports extend to 49151, so evidence in the lower part receives medium
# confidence and the IANA dynamic/private range receives high confidence.
_LIKELY_EPHEMERAL_START = 32768
_IANA_EPHEMERAL_START = 49152


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_proto(value: Any) -> str:
    if value is None:
        return ""
    return str(value).lower()


def _parse_optional_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes"}:
            return True
        if normalized in {"false", "0", "no"}:
            return False
    return None


def _known_service(
    proto: str,
    port: int,
    service_map: Mapping[tuple[str, int], str] | None,
) -> bool:
    if not proto or not 0 < port <= 65535:
        return False
    if service_map and (proto, port) in service_map:
        return True
    try:
        socket.getservbyport(port, proto)
        return True
    except OSError:
        return False


def _ephemeral_confidence(port: int) -> str:
    return "high" if port >= _IANA_EPHEMERAL_START else "medium"


@dataclass(frozen=True)
class EndpointInference:
    """Logical endpoint roles derived from one normalized flow.

    ``client_ip`` and ``server_ip`` are ``None`` when the available evidence is
    insufficient to claim client/server roles.  ``reversed`` indicates that the
    inferred client-to-server orientation is opposite to the observed
    source-to-destination record.
    """

    client_ip: str | None
    client_port: int | None
    server_ip: str | None
    server_port: int | None
    proto: str
    method: str
    confidence: str
    reversed: bool
    response_observed: bool | None = None

    @property
    def service_identified(self) -> bool:
        return bool(self.server_ip and self.server_port and self.proto)

    @property
    def service_observed(self) -> bool:
        """Whether evidence supports reporting the endpoint as a service."""
        return self.service_identified and self.response_observed is not False


def infer_endpoints(
    record: Mapping[str, Any],
    service_map: Mapping[tuple[str, int], str] | None = None,
) -> EndpointInference:
    """Infer logical client/service endpoints from explicit or port evidence.

    Explicit initiator metadata (currently emitted for Zeek originator and
    responder fields) takes precedence.  Without it, inference is intentionally
    conservative: a known service port must be paired with a likely ephemeral
    port.  Ambiguous pairs return no logical endpoint roles so downstream code
    cannot accidentally report an arbitrary high destination port as an
    offered service.
    """

    src_ip = record.get("src_ip")
    dst_ip = record.get("dst_ip")
    src_port = _to_int(record.get("src_port"))
    dst_port = _to_int(record.get("dst_port"))
    proto = _normalize_proto(record.get("proto"))

    if not src_ip or not dst_ip or not proto:
        return EndpointInference(
            client_ip=None,
            client_port=None,
            server_ip=None,
            server_port=None,
            proto=proto,
            method="missing_endpoint_data",
            confidence="none",
            reversed=False,
        )

    src_is_initiator = _parse_optional_bool(record.get("src_is_initiator"))
    response_observed = _parse_optional_bool(
        record.get("service_response_observed")
    )
    if src_is_initiator is not None:
        source = str(record.get("orientation_source") or "explicit_initiator_flag")
        if src_is_initiator:
            return EndpointInference(
                client_ip=str(src_ip),
                client_port=src_port,
                server_ip=str(dst_ip),
                server_port=dst_port if dst_port > 0 else None,
                proto=proto,
                method=source,
                confidence="high",
                reversed=False,
                response_observed=response_observed,
            )
        return EndpointInference(
            client_ip=str(dst_ip),
            client_port=dst_port,
            server_ip=str(src_ip),
            server_port=src_port if src_port > 0 else None,
            proto=proto,
            method=source,
            confidence="high",
            reversed=True,
            response_observed=response_observed,
        )

    src_known = _known_service(proto, src_port, service_map)
    dst_known = _known_service(proto, dst_port, service_map)
    src_ephemeral = src_port >= _LIKELY_EPHEMERAL_START
    dst_ephemeral = dst_port >= _LIKELY_EPHEMERAL_START

    # A low/registered known service paired with a high client port is strong
    # enough even if the bundled service database happens to name the high port.
    if dst_known and src_ephemeral and dst_port < _LIKELY_EPHEMERAL_START:
        return EndpointInference(
            client_ip=str(src_ip),
            client_port=src_port,
            server_ip=str(dst_ip),
            server_port=dst_port,
            proto=proto,
            method="known_service_vs_ephemeral",
            confidence=_ephemeral_confidence(src_port),
            reversed=False,
        )
    if src_known and dst_ephemeral and src_port < _LIKELY_EPHEMERAL_START:
        return EndpointInference(
            client_ip=str(dst_ip),
            client_port=dst_port,
            server_ip=str(src_ip),
            server_port=src_port,
            proto=proto,
            method="known_service_vs_ephemeral",
            confidence=_ephemeral_confidence(dst_port),
            reversed=True,
        )

    return EndpointInference(
        client_ip=None,
        client_port=None,
        server_ip=None,
        server_port=None,
        proto=proto,
        method="ambiguous_ports",
        confidence="none",
        reversed=False,
    )
