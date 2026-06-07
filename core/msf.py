import logging
import re
import subprocess
from typing import List, Optional

from core.models import MsfModule, MsfResult, ServiceRecord

logger = logging.getLogger(__name__)


_MSF_LINE_RE = re.compile(
    r"^\s*\d+\s+"
    r"([\w/\.\-]+)\s+"         
    r"[\d\-\.]+\s+"             
    r"(\w+)\s+"                 
    r"(?:Yes|No)\s+"            
    r"(.+?)\s*$"                
)


def _run_msf_search(service_query: str, timeout: int) -> str:

    cmd = [
        "msfconsole",
        "-q",
        "-x",
        f"search {service_query}; exit",
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout
    except FileNotFoundError:
        logger.warning("msfconsole not found — skipping MSF intelligence")
        return ""
    except subprocess.TimeoutExpired:
        logger.warning("msfconsole timed out for query: %s", service_query)
        return ""
    except Exception as exc:
        logger.error("MSF search error for %s: %s", service_query, exc)
        return ""


def _parse_msf_output(raw: str) -> List[MsfModule]:

    modules: List[MsfModule] = []
    for line in raw.splitlines():
        match = _MSF_LINE_RE.match(line)
        if match:
            name, rank, description = match.groups()
            modules.append(MsfModule(name=name, rank=rank, description=description.strip()))
    return modules


def _build_search_query(service: str, version: Optional[str] = None) -> str:

    if version:
        product = version.split()[0]  # use first word of version string
        return f"{service} {product}"
    return service


def lookup_service(service: str, version: str = "", timeout: int = 30) -> MsfResult:
    
    query = _build_search_query(service, version)
    logger.info("MSF search: %s", query)
    raw = _run_msf_search(query, timeout)

    modules = _parse_msf_output(raw)
    result = MsfResult(service=f"{service} {version}".strip(), modules=modules)
    logger.info("MSF found %d modules for '%s'", len(modules), query)
    return result


def lookup_all_services(
    service_records: List[ServiceRecord],
    enabled_services: List[str],
    timeout: int = 30,
) -> List[MsfResult]:
    
    # Collect unique (service, version) pairs
    seen: set[str] = set()
    results: List[MsfResult] = []

    for rec in service_records:
        if rec.service not in enabled_services:
            continue
        key = f"{rec.service}:{rec.version}"
        if key in seen:
            continue
        seen.add(key)
        results.append(lookup_service(rec.service, rec.version, timeout))

    logger.info("MSF lookups complete: %d queries performed", len(results))
    return results
