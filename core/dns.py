import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

import dns.resolver
import dns.exception

from core.models import DNSRecord

logger = logging.getLogger(__name__)


def _resolve_single(subdomain: str, timeout: int) -> DNSRecord:

    record = DNSRecord(subdomain=subdomain)

   
    resolver = dns.resolver.Resolver()
    resolver.lifetime = float(timeout)   # total time budget per query
    resolver.timeout  = float(timeout)   # per-nameserver attempt timeout

    try:
        ips: set[str] = set()

        # Resolve A records (IPv4)
        try:
            for rdata in resolver.resolve(subdomain, "A"):
                ips.add(rdata.address)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass  

        # Resolve AAAA records (IPv6)
        try:
            for rdata in resolver.resolve(subdomain, "AAAA"):
                ips.add(rdata.address)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass

        record.ips = sorted(ips)
        record.resolved = bool(ips)

        if ips:
            logger.debug("%s -> %s", subdomain, sorted(ips))
        else:
            logger.debug("%s: no A/AAAA records found", subdomain)

    except dns.resolver.NXDOMAIN:
        record.error = "NXDOMAIN"
        logger.debug("DNS NXDOMAIN for %s", subdomain)
    except dns.exception.Timeout:
        record.error = f"Timeout after {timeout}s"
        logger.debug("DNS timeout for %s", subdomain)
    except dns.resolver.NoNameservers:
        record.error = "No nameservers available"
        logger.warning("No nameservers for %s", subdomain)
    except Exception as exc:
        record.error = str(exc)
        logger.warning("Unexpected DNS error for %s: %s", subdomain, exc)

    return record


def resolve_subdomains(
    subdomains: List[str],
    timeout: int = 5,
    max_workers: int = 50,
) -> List[DNSRecord]:

    records: List[DNSRecord] = []
    logger.info("Resolving %d subdomains (workers=%d)", len(subdomains), max_workers)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_resolve_single, sub, timeout): sub
            for sub in subdomains
        }
        for future in as_completed(futures):
            try:
                records.append(future.result())
            except Exception as exc:
                sub = futures[future]
                logger.error("Future error for %s: %s", sub, exc)

    resolved = sum(1 for r in records if r.resolved)
    logger.info("DNS resolution complete: %d/%d resolved", resolved, len(records))
    return records
