import logging
from typing import List

from core.models import DNSRecord  # used by extract_unique_ips

logger = logging.getLogger(__name__)


def dedupe_strings(items: List[str]) -> List[str]:

    result = sorted(set(items))
    logger.debug("dedupe_strings: %d -> %d items", len(items), len(result))
    return result


def extract_unique_ips(dns_records: List[DNSRecord]) -> List[str]:
    
    all_ips: set[str] = set()
    for record in dns_records:
        if record.resolved:
            all_ips.update(record.ips)

    result = sorted(all_ips)
    logger.info("Unique IPs extracted: %d", len(result))
    return result


