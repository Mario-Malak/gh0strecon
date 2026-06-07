from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class DNSRecord:
    subdomain: str
    ips: List[str] = field(default_factory=list)
    resolved: bool = False
    error: Optional[str] = None


@dataclass
class PortRecord:
    ip: str
    port: int
    protocol: str
    state: str
    service: str
    version: str
    extra: Optional[str] = None


@dataclass
class ServiceRecord:
    ip: str
    port: int
    service: str
    version: str


@dataclass
class MsfModule:
    name: str
    rank: str
    description: str


@dataclass
class MsfResult:
    service: str
    modules: List[MsfModule] = field(default_factory=list)


@dataclass
class ReconResult:
    domain: str
    subdomains: List[str] = field(default_factory=list)
    dns_records: List[DNSRecord] = field(default_factory=list)
    unique_ips: List[str] = field(default_factory=list)
    port_records: List[PortRecord] = field(default_factory=list)
    service_records: List[ServiceRecord] = field(default_factory=list)
    msf_results: List[MsfResult] = field(default_factory=list)
