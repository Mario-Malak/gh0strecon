#!/usr/bin/env python3
import argparse
import logging
import sys
import time
from pathlib import Path

import yaml

from core.dedupe import extract_unique_ips
from core.dns import resolve_subdomains
from core.enum import enumerate_subdomains
from core.graph import generate_graph
from core.models import ReconResult
from core.msf import lookup_all_services
from core.parser import parse_port_records
from core.scanner import scan_ip
from core.scheduler import ScanScheduler, ScanTask, make_scan_mode_config
from core.storage import save_all


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def load_config(path: str) -> dict:
    config_path = Path(path)
    if not config_path.exists():
        logging.warning("Config file not found: %s — using defaults", path)
        return {}
    with config_path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Modular reconnaissance automation platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py example.com
  python main.py example.com --mode normal
  python main.py example.com --mode slow --config myconfig.yaml
        """,
    )
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument(
        "--mode",
        choices=["fast", "normal", "slow"],
        default=None,
        help="Scan mode (overrides config.yaml)",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to config YAML file (default: config.yaml)",
    )
    parser.add_argument(
        "--no-msf",
        action="store_true",
        help="Skip Metasploit intelligence lookups",
    )
    return parser.parse_args()


def run_pipeline(domain: str, config: dict, scan_mode: str, run_msf: bool) -> None:
    logger = logging.getLogger("main")
    start_time = time.time()

    result = ReconResult(domain=domain)

    # ── 1. Subdomain Enumeration ──────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("STAGE 1 — Subdomain Enumeration")
    logger.info("=" * 60)
    enum_cfg = config.get("enumeration", {})
    result.subdomains = enumerate_subdomains(
        domain=domain,
        tools=enum_cfg.get("tools", ["subfinder", "assetfinder", "amass"]),
        timeout=enum_cfg.get("timeout", 120),
    )
    logger.info("Subdomains collected: %d", len(result.subdomains))

    # ── 2. DNS Resolution ─────────────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("STAGE 2 — DNS Resolution")
    logger.info("=" * 60)
    dns_cfg = config.get("dns", {})
    result.dns_records = resolve_subdomains(
        subdomains=result.subdomains,
        timeout=dns_cfg.get("timeout", 5),
        max_workers=dns_cfg.get("max_workers", 50),
    )

    # ── 3. IP Deduplication ───────────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("STAGE 3 — IP Deduplication")
    logger.info("=" * 60)
    result.unique_ips = extract_unique_ips(result.dns_records)
    logger.info("Unique IPs for scanning: %d", len(result.unique_ips))

    # ── 4 + 5. Scheduled Port Scanning ───────────────────────────────────────
    logger.info("=" * 60)
    logger.info("STAGE 4+5 — Scheduled Port Scanning (mode: %s)", scan_mode)
    logger.info("=" * 60)
    scanner_cfg = config.get("scanner", {})
    mode_cfg = make_scan_mode_config(scan_mode, config)
    nmap_args = mode_cfg["nmap_args"]
    top_ports = mode_cfg["top_ports"]

    tasks = [
        ScanTask(
            task_id=f"scan::{ip}",
            fn=scan_ip,
            kwargs={
                "ip": ip,
                "nmap_args": nmap_args,
                "top_ports": top_ports,
            },
        )
        for ip in result.unique_ips
    ]

    with ScanScheduler(
        max_workers=scanner_cfg.get("max_workers", 10),
        retry_attempts=scanner_cfg.get("retry_attempts", 2),
        retry_delay=float(scanner_cfg.get("retry_delay", 3)),
        rate_limit_delay=0.1,
    ) as scheduler:
        completed_tasks = scheduler.submit_tasks(tasks)

    for task in completed_tasks:
        if task.success and task.result:
            result.port_records.extend(task.result)

    logger.info("Total open ports discovered: %d", len(result.port_records))

    # ── 6. Service Parsing ────────────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("STAGE 6 — Service Parsing")
    logger.info("=" * 60)
    result.service_records = parse_port_records(result.port_records)

    # ── 7. Metasploit Intelligence ────────────────────────────────────────────
    if run_msf:
        logger.info("=" * 60)
        logger.info("STAGE 7 — Metasploit Intelligence")
        logger.info("=" * 60)
        msf_cfg = config.get("metasploit", {})
        if msf_cfg.get("enabled", True):
            result.msf_results = lookup_all_services(
                service_records=result.service_records,
                enabled_services=msf_cfg.get("search_services", []),
                timeout=msf_cfg.get("timeout", 30),
            )
        else:
            logger.info("MSF disabled in config")
    else:
        logger.info("MSF lookups skipped (--no-msf)")

    # ── 8. Storage ────────────────────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("STAGE 8 — Saving Results")
    logger.info("=" * 60)
    output_dir = save_all(result, base_dir=config.get("recon", {}).get("output_dir", "results"))

    # ── 9. Graph Generation ───────────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("STAGE 9 — Generating Graph")
    logger.info("=" * 60)
    graph_cfg = config.get("graph", {})
    graph_path = generate_graph(
        result=result,
        output_dir=output_dir,
        layout=graph_cfg.get("layout", "cose"),
    )

    # ── Summary ───────────────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    logger.info("=" * 60)
    logger.info("RECON COMPLETE — %.1fs", elapsed)
    logger.info("=" * 60)
    logger.info("  Domain      : %s", domain)
    logger.info("  Subdomains  : %d", len(result.subdomains))
    logger.info("  Resolved    : %d", sum(1 for r in result.dns_records if r.resolved))
    logger.info("  Unique IPs  : %d", len(result.unique_ips))
    logger.info("  Open Ports  : %d", len(result.port_records))
    logger.info("  Services    : %d", len(result.service_records))
    logger.info("  MSF results : %d", len(result.msf_results))
    logger.info("  Output dir  : %s", output_dir)
    logger.info("  Graph       : %s", graph_path)
    logger.info("=" * 60)


def main() -> None:
    args = parse_args()
    config = load_config(args.config)

    log_level = config.get("recon", {}).get("log_level", "INFO")
    setup_logging(log_level)

    scan_mode = args.mode or config.get("scanner", {}).get("mode", "fast")
    run_msf = not args.no_msf

    run_pipeline(
        domain=args.domain,
        config=config,
        scan_mode=scan_mode,
        run_msf=run_msf,
    )


if __name__ == "__main__":
    main()
