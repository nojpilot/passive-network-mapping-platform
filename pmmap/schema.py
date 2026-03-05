from pydantic import BaseModel
from typing import Optional, List


class Flow(BaseModel):
    ts: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    bytes: int
    pkts: int
    duration: float | None = None
    uid: Optional[str] = None
    dns_qname: Optional[str] = None
    sni: Optional[str] = None
    ja3: Optional[str] = None
    ja3s: Optional[str] = None
    hassh: Optional[str] = None
    dhcp_mac: Optional[str] = None
    dhcp_host_name: Optional[str] = None
    dhcp_fqdn: Optional[str] = None
    dhcp_domain: Optional[str] = None
    dhcp_requested_ip: Optional[str] = None
    dhcp_assigned_ip: Optional[str] = None
    dhcp_lease_time: Optional[float] = None
    dhcp_msg_types: Optional[List[str]] = None
   
