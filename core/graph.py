import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from core.models import ReconResult

logger = logging.getLogger(__name__)

# Node/edge type colors
_COLORS = {
    "domain":    {"bg": "#e63946", "fg": "#ffffff"},
    "subdomain": {"bg": "#457b9d", "fg": "#ffffff"},
    "ip":        {"bg": "#2d6a4f", "fg": "#ffffff"},
    "port":      {"bg": "#f4a261", "fg": "#1a1a2e"},
    "service":   {"bg": "#9b5de5", "fg": "#ffffff"},
}


def _node_id(prefix: str, value: str) -> str:
    return f"{prefix}::{value}"


def build_graph_data(result: ReconResult) -> Dict[str, List[Dict[str, Any]]]:

    nodes: List[Dict] = []
    edges: List[Dict] = []
    seen_nodes: set[str] = set()
    seen_edges: set[tuple] = set()

    def add_node(nid: str, label: str, ntype: str, meta: Dict[str, Any] = {}) -> None:
        if nid not in seen_nodes:
            seen_nodes.add(nid)
            nodes.append({
                "data": {
                    "id": nid,
                    "label": label,
                    "type": ntype,
                    "meta": meta,
                    "color": _COLORS.get(ntype, {}).get("bg", "#888"),
                    "fontColor": _COLORS.get(ntype, {}).get("fg", "#fff"),
                }
            })

    def add_edge(source: str, target: str, label: str) -> None:
        key = (source, target, label)
        if key not in seen_edges:
            seen_edges.add(key)
            edges.append({
                "data": {
                    "id": f"{source}--{label}--{target}",
                    "source": source,
                    "target": target,
                    "label": label,
                }
            })


    domain_nid = _node_id("domain", result.domain)
    add_node(domain_nid, result.domain, "domain", {"domain": result.domain})


    for dns_rec in result.dns_records:
        sub_nid = _node_id("subdomain", dns_rec.subdomain)
        add_node(sub_nid, dns_rec.subdomain, "subdomain", {
            "subdomain": dns_rec.subdomain,
            "resolved": dns_rec.resolved,
            "ips": dns_rec.ips,
        })
        add_edge(domain_nid, sub_nid, "resolves_to")


        for ip in dns_rec.ips:
            ip_nid = _node_id("ip", ip)
            add_node(ip_nid, ip, "ip", {"ip": ip})
            add_edge(sub_nid, ip_nid, "resolves_to")


    msf_by_service: Dict[str, List[str]] = {}
    for msf_result in result.msf_results:
        key = msf_result.service
        msf_by_service[key] = [m.name for m in msf_result.modules[:5]]  # top 5


    for svc in result.service_records:
        ip_nid = _node_id("ip", svc.ip)
        port_label = f":{svc.port}"
        port_nid = _node_id("port", f"{svc.ip}:{svc.port}")
        add_node(port_nid, port_label, "port", {
            "ip": svc.ip,
            "port": svc.port,
            "service": svc.service,
            "version": svc.version,
        })
        add_edge(ip_nid, port_nid, "exposes")

        if svc.service and svc.service != "unknown":
            svc_label = f"{svc.service} {svc.version}".strip()
            svc_nid = _node_id("service", f"{svc.ip}:{svc.port}:{svc.service}")


            msf_key = f"{svc.service} {svc.version}".strip()
            msf_modules = msf_by_service.get(msf_key, msf_by_service.get(svc.service, []))

            add_node(svc_nid, svc_label, "service", {
                "service": svc.service,
                "version": svc.version,
                "msf_modules": msf_modules,
            })
            add_edge(port_nid, svc_nid, "runs")

    return {"nodes": nodes, "edges": edges}


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Recon Graph — {domain}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: 'Courier New', monospace;
    background: #0d0d0f;
    color: #e0e0e0;
    height: 100vh;
    display: flex;
    flex-direction: column;
  }}

  header {{
    background: #111117;
    border-bottom: 1px solid #e63946;
    padding: 12px 20px;
    display: flex;
    align-items: center;
    gap: 16px;
    flex-shrink: 0;
  }}

  header h1 {{
    font-size: 1rem;
    font-weight: 600;
    color: #e63946;
    letter-spacing: 0.1em;
    text-transform: uppercase;
  }}

  .stats {{
    display: flex;
    gap: 20px;
    margin-left: auto;
    font-size: 0.75rem;
    color: #888;
  }}

  .stat span {{ color: #e0e0e0; font-weight: 600; }}

  .legend {{
    display: flex;
    gap: 12px;
    font-size: 0.7rem;
    flex-wrap: wrap;
  }}

  .legend-item {{
    display: flex;
    align-items: center;
    gap: 5px;
  }}

  .legend-dot {{
    width: 10px;
    height: 10px;
    border-radius: 50%;
    flex-shrink: 0;
  }}

  #main {{
    display: flex;
    flex: 1;
    min-height: 0;
  }}

  #cy {{
    flex: 1;
    background: #0d0d0f;
  }}

  #panel {{
    width: 300px;
    background: #111117;
    border-left: 1px solid #222230;
    padding: 16px;
    overflow-y: auto;
    flex-shrink: 0;
    font-size: 0.8rem;
  }}

  #panel h2 {{
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: #555;
    margin-bottom: 12px;
    border-bottom: 1px solid #222230;
    padding-bottom: 8px;
  }}

  #panel-content .empty {{
    color: #444;
    font-style: italic;
  }}

  .meta-row {{
    display: flex;
    gap: 8px;
    margin-bottom: 6px;
    line-height: 1.5;
  }}

  .meta-key {{
    color: #666;
    min-width: 80px;
    flex-shrink: 0;
  }}

  .meta-val {{
    color: #c8e6c9;
    word-break: break-all;
  }}

  .node-type-badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    font-weight: 700;
    margin-bottom: 10px;
  }}

  .msf-module {{
    background: #1a1a2e;
    border: 1px solid #9b5de5;
    border-radius: 3px;
    padding: 4px 8px;
    margin-bottom: 4px;
    font-size: 0.7rem;
    color: #ce93d8;
    word-break: break-all;
  }}

  .msf-header {{
    color: #9b5de5;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin: 10px 0 6px;
  }}

  .controls {{
    display: flex;
    gap: 8px;
    padding: 8px 16px;
    background: #111117;
    border-top: 1px solid #222230;
    flex-shrink: 0;
  }}

  button {{
    background: #1a1a2e;
    border: 1px solid #333350;
    color: #aaa;
    padding: 5px 12px;
    border-radius: 3px;
    cursor: pointer;
    font-family: inherit;
    font-size: 0.75rem;
    transition: all 0.15s;
  }}

  button:hover {{
    border-color: #e63946;
    color: #e63946;
  }}

  .filter-group {{
    display: flex;
    gap: 4px;
    margin-left: auto;
    align-items: center;
  }}

  .filter-btn {{
    border-radius: 3px;
    padding: 4px 10px;
    font-size: 0.7rem;
  }}

  .filter-btn.active {{
    border-color: currentColor;
    color: inherit;
  }}

  input[type=text] {{
    background: #1a1a2e;
    border: 1px solid #333350;
    color: #ddd;
    padding: 4px 10px;
    border-radius: 3px;
    font-family: inherit;
    font-size: 0.75rem;
    width: 180px;
  }}

  input[type=text]:focus {{
    outline: none;
    border-color: #457b9d;
  }}
</style>
</head>
<body>

<header>
  <h1>⬡ RECON :: {domain}</h1>
  <div class="legend">
    <div class="legend-item"><div class="legend-dot" style="background:#e63946"></div>domain</div>
    <div class="legend-item"><div class="legend-dot" style="background:#457b9d"></div>subdomain</div>
    <div class="legend-item"><div class="legend-dot" style="background:#2d6a4f"></div>ip</div>
    <div class="legend-item"><div class="legend-dot" style="background:#f4a261"></div>port</div>
    <div class="legend-item"><div class="legend-dot" style="background:#9b5de5"></div>service</div>
  </div>
  <div class="stats">
    <div>subdomains <span id="stat-sub">0</span></div>
    <div>ips <span id="stat-ip">0</span></div>
    <div>ports <span id="stat-port">0</span></div>
    <div>services <span id="stat-svc">0</span></div>
  </div>
</header>

<div id="main">
  <div id="cy"></div>
  <div id="panel">
    <h2>Node Inspector</h2>
    <div id="panel-content"><div class="empty">Click a node to inspect it.</div></div>
  </div>
</div>

<div class="controls">
  <button onclick="cy.fit()">Fit All</button>
  <button onclick="cy.reset()">Reset Zoom</button>
  <button onclick="runLayout()">Re-layout</button>
  <input type="text" id="search" placeholder="Search nodes..." oninput="filterNodes(this.value)"/>
  <div class="filter-group">
    <button class="filter-btn" style="color:#457b9d" onclick="toggleFilter('subdomain')">Subdomains</button>
    <button class="filter-btn" style="color:#2d6a4f" onclick="toggleFilter('ip')">IPs</button>
    <button class="filter-btn" style="color:#f4a261" onclick="toggleFilter('port')">Ports</button>
    <button class="filter-btn" style="color:#9b5de5" onclick="toggleFilter('service')">Services</button>
  </div>
</div>

<script>
const elements = {elements_json};

const cy = cytoscape({{
  container: document.getElementById('cy'),
  elements: elements,
  style: [
    {{
      selector: 'node',
      style: {{
        'background-color': 'data(color)',
        'color': 'data(fontColor)',
        'label': 'data(label)',
        'text-valign': 'center',
        'text-halign': 'center',
        'font-size': '9px',
        'font-family': 'Courier New, monospace',
        'width': 'label',
        'height': 'label',
        'padding': '8px',
        'shape': 'roundrectangle',
        'border-width': 0,
        'text-wrap': 'ellipsis',
        'text-max-width': '120px',
        'min-width': '30px',
        'min-height': '20px',
      }}
    }},
    {{
      selector: 'node[type="domain"]',
      style: {{
        'font-size': '12px',
        'font-weight': 'bold',
        'shape': 'hexagon',
        'width': '60px',
        'height': '60px',
        'padding': '12px',
      }}
    }},
    {{
      selector: 'node[type="ip"]',
      style: {{ 'shape': 'ellipse' }}
    }},
    {{
      selector: 'node[type="port"]',
      style: {{ 'shape': 'diamond', 'width': '40px', 'height': '40px' }}
    }},
    {{
      selector: 'edge',
      style: {{
        'width': 1,
        'line-color': '#2a2a3a',
        'target-arrow-color': '#2a2a3a',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'font-size': '7px',
        'font-family': 'Courier New, monospace',
        'color': '#444',
        'label': 'data(label)',
        'text-rotation': 'autorotate',
      }}
    }},
    {{
      selector: ':selected',
      style: {{
        'border-width': 2,
        'border-color': '#ffffff',
        'border-opacity': 0.8,
      }}
    }},
    {{
      selector: '.highlighted',
      style: {{
        'border-width': 2,
        'border-color': '#e63946',
        'border-opacity': 1,
      }}
    }},
    {{
      selector: '.faded',
      style: {{
        'opacity': 0.15,
      }}
    }},
  ],
  layout: {{
    name: '{layout}',
    animate: true,
    animationDuration: 600,
    randomize: false,
    componentSpacing: 80,
    nodeRepulsion: 8000,
    gravity: 0.25,
    idealEdgeLength: 80,
    edgeElasticity: 0.5,
    nestingFactor: 1.2,
    numIter: 1000,
    coolingFactor: 0.99,
  }}
}});

// Update stats
document.getElementById('stat-sub').textContent = cy.nodes('[type="subdomain"]').length;
document.getElementById('stat-ip').textContent = cy.nodes('[type="ip"]').length;
document.getElementById('stat-port').textContent = cy.nodes('[type="port"]').length;
document.getElementById('stat-svc').textContent = cy.nodes('[type="service"]').length;

// Node click handler
cy.on('tap', 'node', function(evt) {{
  const node = evt.target;
  const data = node.data();
  const meta = data.meta || {{}};
  const panel = document.getElementById('panel-content');

  const typeColors = {{
    domain: '#e63946', subdomain: '#457b9d',
    ip: '#2d6a4f', port: '#f4a261', service: '#9b5de5'
  }};
  const color = typeColors[data.type] || '#888';

  let html = `<div class="node-type-badge" style="background:${{color}}">${{data.type}}</div>`;
  html += `<div class="meta-row"><span class="meta-key">label</span><span class="meta-val">${{data.label}}</span></div>`;

  for (const [k, v] of Object.entries(meta)) {{
    if (k === 'msf_modules') continue;
    if (Array.isArray(v)) {{
      html += `<div class="meta-row"><span class="meta-key">${{k}}</span><span class="meta-val">${{v.join(', ') || '—'}}</span></div>`;
    }} else {{
      html += `<div class="meta-row"><span class="meta-key">${{k}}</span><span class="meta-val">${{v === '' ? '—' : v}}</span></div>`;
    }}
  }}

  if (meta.msf_modules && meta.msf_modules.length > 0) {{
    html += `<div class="msf-header">⚡ MSF Modules (${{meta.msf_modules.length}})</div>`;
    for (const mod of meta.msf_modules) {{
      html += `<div class="msf-module">${{mod}}</div>`;
    }}
  }}

  panel.innerHTML = html;

  // Highlight neighbors
  cy.elements().removeClass('highlighted faded');
  node.addClass('highlighted');
  node.neighborhood().addClass('highlighted');
  cy.elements().not(node).not(node.neighborhood()).addClass('faded');
}});

cy.on('tap', function(evt) {{
  if (evt.target === cy) {{
    cy.elements().removeClass('highlighted faded');
    document.getElementById('panel-content').innerHTML = '<div class="empty">Click a node to inspect it.</div>';
  }}
}});

function runLayout() {{
  cy.layout({{ name: '{layout}', animate: true, animationDuration: 500 }}).run();
}}

function filterNodes(query) {{
  if (!query) {{
    cy.elements().removeClass('highlighted faded');
    return;
  }}
  const q = query.toLowerCase();
  const matched = cy.nodes().filter(n => n.data('label').toLowerCase().includes(q));
  cy.elements().addClass('faded');
  matched.removeClass('faded').addClass('highlighted');
  matched.connectedEdges().removeClass('faded');
}}

const hiddenTypes = new Set();
function toggleFilter(type) {{
  const nodes = cy.nodes(`[type="${{type}}"]`);
  if (hiddenTypes.has(type)) {{
    nodes.show();
    hiddenTypes.delete(type);
  }} else {{
    nodes.hide();
    hiddenTypes.add(type);
  }}
}}
</script>
</body>
</html>"""


def generate_graph(result: ReconResult, output_dir: Path, layout: str = "cose") -> Path:
   
    graph_data = build_graph_data(result)
    elements_json = json.dumps(
        graph_data["nodes"] + graph_data["edges"],
        indent=2,
    )

    html = _HTML_TEMPLATE.format(
        domain=result.domain,
        elements_json=elements_json,
        layout=layout,
    )

    out_path = output_dir / "graph.html"
    out_path.write_text(html, encoding="utf-8")
    logger.info(
        "Graph generated: %s (%d nodes, %d edges)",
        out_path,
        len(graph_data["nodes"]),
        len(graph_data["edges"]),
    )
    return out_path
