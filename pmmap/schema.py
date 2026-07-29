from ipaddress import ip_address
from typing import Optional, List

from pydantic import BaseModel, Field, field_validator


class Flow(BaseModel):
    ts: float = Field(ge=0)
    src_ip: str
    src_port: int = Field(ge=0, le=65535)
    dst_ip: str
    dst_port: int = Field(ge=0, le=65535)
    proto: str
    bytes: int = Field(ge=0)
    pkts: int = Field(ge=0)
    bytes_src_to_dst: Optional[int] = Field(default=None, ge=0)
    bytes_dst_to_src: Optional[int] = Field(default=None, ge=0)
    pkts_src_to_dst: Optional[int] = Field(default=None, ge=0)
    pkts_dst_to_src: Optional[int] = Field(default=None, ge=0)
    traffic_directionality: Optional[str] = None
    duration: float | None = Field(default=None, ge=0)
    uid: Optional[str] = None
    src_in_scope: Optional[bool] = None
    dst_in_scope: Optional[bool] = None
    src_is_initiator: Optional[bool] = None
    orientation_source: Optional[str] = None
    connection_state: Optional[str] = None
    service_response_observed: Optional[bool] = None
    dns_qname: Optional[str] = None
    sni: Optional[str] = None
    ja3: Optional[str] = None
    ja3s: Optional[str] = None
    hassh: Optional[str] = None
    hassh_server: Optional[str] = None
    dhcp_mac: Optional[str] = None
    dhcp_host_name: Optional[str] = None
    dhcp_fqdn: Optional[str] = None
    dhcp_domain: Optional[str] = None
    dhcp_requested_ip: Optional[str] = None
    dhcp_assigned_ip: Optional[str] = None
    dhcp_lease_time: Optional[float] = None
    dhcp_msg_types: Optional[List[str]] = None

    @field_validator('src_ip', 'dst_ip')
    @classmethod
    def validate_ip_address(cls, value: str) -> str:
        """Validate addresses while retaining the JSON-compatible string type."""
        return str(ip_address(value))

    @field_validator('proto')
    @classmethod
    def normalize_protocol(cls, value: str) -> str:
        normalized = str(value).strip().lower()
        if not normalized:
            raise ValueError('protocol must not be empty')
        return normalized
