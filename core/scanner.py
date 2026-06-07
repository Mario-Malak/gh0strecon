import logging
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List

from core.models import PortRecord

logger = logging.getLogger(__name__)


def _parse_nmap_xml(xml_path: str) -> List[PortRecord]:

    records: List[PortRecord] = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        logger.error("Failed to parse Nmap XML: %s", exc)
        return records

    for host in root.findall("host"):

        addr_elem = host.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr", "")

        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            port_id = int(port_elem.get("portid", 0))
            protocol = port_elem.get("protocol", "tcp")

            service_elem = port_elem.find("service")
            service_name = ""
            version = ""
            extra = ""
            if service_elem is not None:
                service_name = service_elem.get("name", "")
                product = service_elem.get("product", "")
                ver = service_elem.get("version", "")
                extra_info = service_elem.get("extrainfo", "")
                version = " ".join(filter(None, [product, ver])).strip()
                extra = extra_info

            records.append(
                PortRecord(
                    ip=ip,
                    port=port_id,
                    protocol=protocol,
                    state="open",
                    service=service_name,
                    version=version,
                    extra=extra or None,
                )
            )

    logger.debug("Parsed %d open ports from %s", len(records), xml_path)
    return records


def scan_ip(
    ip: str,
    nmap_args: str = "-T4 -F --open",
    top_ports: int = 100,
    timeout: int = 300,
) -> List[PortRecord]:
    
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_out = tmp.name

    try:
        top_ports_args = [] if "--top-ports" in nmap_args else ["--top-ports", str(top_ports)]
        cmd = ["nmap"] + nmap_args.split() + top_ports_args + ["-oX", xml_out, ip]
        logger.info("Scanning %s: %s", ip, " ".join(cmd))

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode != 0:
            logger.warning("Nmap non-zero exit for %s: %s", ip, result.stderr.strip())

        records = _parse_nmap_xml(xml_out)
        logger.info("IP %s: %d open ports found", ip, len(records))
        return records

    except FileNotFoundError:
        logger.error("nmap not found — install nmap and ensure it's in PATH")
        return []
    except subprocess.TimeoutExpired:
        logger.warning("Nmap timed out for %s", ip)
        return []
    except Exception as exc:
        logger.error("Unexpected scanner error for %s: %s", ip, exc)
        return []
    finally:
        Path(xml_out).unlink(missing_ok=True)
