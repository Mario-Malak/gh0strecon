import logging
from typing import List

from core.models import PortRecord, ServiceRecord

logger = logging.getLogger(__name__)


_SERVICE_ALIASES = {
    "http-alt": "http",
    "https-alt": "https",
    "microsoft-ds": "smb",
    "netbios-ssn": "smb",
    "ms-wbt-server": "rdp",
    "domain": "dns",
}


def _normalize_service(name: str) -> str:
    return _SERVICE_ALIASES.get(name.lower(), name.lower())


def parse_port_records(port_records: List[PortRecord]) -> List[ServiceRecord]:
    
    services: List[ServiceRecord] = []
    seen: set[tuple] = set()

    for record in port_records:
        service_name = _normalize_service(record.service) if record.service else "unknown"
        key = (record.ip, record.port, service_name)

        if key in seen:
            continue
        seen.add(key)

        services.append(
            ServiceRecord(
                ip=record.ip,
                port=record.port,
                service=service_name,
                version=record.version or "",
            )
        )

    logger.info("Parsed %d unique service records", len(services))
    return services
