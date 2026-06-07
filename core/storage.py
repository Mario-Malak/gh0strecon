import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any, List

from core.models import ReconResult

logger = logging.getLogger(__name__)


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    logger.debug("Wrote %s", path)


def _write_text(path: Path, lines: List[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    logger.debug("Wrote %s", path)


def init_output_dir(base_dir: str, domain: str) -> Path:
    """Create and return the output directory for this domain."""
    output_dir = Path(base_dir) / domain
    output_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Output directory: %s", output_dir)
    return output_dir


def save_subdomains(output_dir: Path, subdomains: List[str]) -> None:
    _write_text(output_dir / "subdomains.txt", subdomains)
    logger.info("Saved %d subdomains", len(subdomains))


def save_dns(output_dir: Path, dns_records: list) -> None:
    _write_json(output_dir / "dns.json", [asdict(r) for r in dns_records])
    logger.info("Saved %d DNS records", len(dns_records))


def save_ips(output_dir: Path, ips: List[str]) -> None:
    _write_json(output_dir / "ips.json", ips)
    logger.info("Saved %d unique IPs", len(ips))


def save_ports(output_dir: Path, port_records: list) -> None:
    _write_json(output_dir / "ports.json", [asdict(r) for r in port_records])
    logger.info("Saved %d port records", len(port_records))


def save_services(output_dir: Path, service_records: list) -> None:
    _write_json(output_dir / "services.json", [asdict(r) for r in service_records])
    logger.info("Saved %d service records", len(service_records))


def save_msf(output_dir: Path, msf_results: list) -> None:
    _write_json(output_dir / "msf.json", [asdict(r) for r in msf_results])
    logger.info("Saved %d MSF results", len(msf_results))


def save_all(result: ReconResult, base_dir: str) -> Path:
    
    output_dir = init_output_dir(base_dir, result.domain)
    save_subdomains(output_dir, result.subdomains)
    save_dns(output_dir, result.dns_records)
    save_ips(output_dir, result.unique_ips)
    save_ports(output_dir, result.port_records)
    save_services(output_dir, result.service_records)
    save_msf(output_dir, result.msf_results)
    logger.info("All results saved to %s", output_dir)
    return output_dir
