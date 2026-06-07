import logging
import subprocess
from typing import List

from core.dedupe import dedupe_strings

logger = logging.getLogger(__name__)


def _run_tool(tool: str, domain: str, timeout: int) -> List[str]:

    commands = {
        "subfinder": ["subfinder", "-d", domain, "-silent"],
        "assetfinder": ["assetfinder", "--subs-only", domain],
        "amass": ["amass", "enum", "-passive", "-d", domain],
    }

    cmd = commands.get(tool)
    if not cmd:
        logger.warning("Unknown tool: %s", tool)
        return []

    try:
        logger.info("Running %s for %s", tool, domain)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0 and result.stderr:
            logger.debug("%s stderr: %s", tool, result.stderr.strip())
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        logger.info("%s returned %d results", tool, len(lines))
        return lines
    except FileNotFoundError:
        logger.warning("Tool not found: %s (skipping)", tool)
        return []
    except subprocess.TimeoutExpired:
        logger.warning("%s timed out after %ds", tool, timeout)
        return []
    except Exception as exc:
        logger.error("Unexpected error running %s: %s", tool, exc)
        return []


def _normalize(subdomain: str, domain: str) -> str | None:

    normalized = subdomain.lower().rstrip(".")
    if not normalized.endswith(domain.lower()):
        return None
    return normalized


def enumerate_subdomains(domain: str, tools: List[str], timeout: int) -> List[str]:
    
    raw: List[str] = []
    for tool in tools:
        raw.extend(_run_tool(tool, domain, timeout))


    normalized = [_normalize(e, domain) for e in raw]
    filtered = [n for n in normalized if n] + [domain.lower()]
    result = dedupe_strings(filtered)
    logger.info("Total unique subdomains after deduplication: %d", len(result))
    return result
