"""Report generation for scan results."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Template

from .models import ScanResult, Severity

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AIProbe Security Report - {{ scan.scan_id }}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0f172a; color: #e2e8f0; line-height: 1.6; }
  .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
  h1 { font-size: 28px; color: #60a5fa; margin-bottom: 8px; }
  h2 { font-size: 20px; color: #94a3b8; margin: 32px 0 16px; border-bottom: 1px solid #334155; padding-bottom: 8px; }
  h3 { font-size: 16px; color: #e2e8f0; margin: 16px 0 8px; }
  .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 32px;
            padding: 24px; background: #1e293b; border-radius: 12px; border: 1px solid #334155; }
  .score-badge { font-size: 48px; font-weight: 700; }
  .score-low { color: #22c55e; }
  .score-med { color: #eab308; }
  .score-high { color: #ef4444; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin: 24px 0; }
  .stat { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 16px; text-align: center; }
  .stat-value { font-size: 32px; font-weight: 700; }
  .stat-label { font-size: 13px; color: #94a3b8; margin-top: 4px; }
  .critical { color: #ef4444; }
  .high { color: #f97316; }
  .medium { color: #eab308; }
  .low { color: #60a5fa; }
  .info { color: #94a3b8; }
  table { width: 100%; border-collapse: collapse; margin: 16px 0; }
  th { background: #1e293b; color: #94a3b8; text-align: left; padding: 12px; font-size: 13px;
       text-transform: uppercase; letter-spacing: 0.5px; }
  td { padding: 12px; border-bottom: 1px solid #1e293b; font-size: 14px; }
  tr:hover { background: #1e293b40; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 12px;
           font-weight: 600; text-transform: uppercase; }
  .badge-critical { background: #ef444420; color: #ef4444; border: 1px solid #ef444440; }
  .badge-high { background: #f9731620; color: #f97316; border: 1px solid #f9731640; }
  .badge-medium { background: #eab30820; color: #eab308; border: 1px solid #eab30840; }
  .badge-low { background: #60a5fa20; color: #60a5fa; border: 1px solid #60a5fa40; }
  .badge-info { background: #94a3b820; color: #94a3b8; border: 1px solid #94a3b840; }
  .finding { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; margin: 12px 0; }
  .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
  .finding-title { font-weight: 600; font-size: 15px; }
  .finding-detail { margin: 8px 0; font-size: 14px; color: #94a3b8; }
  .finding-detail strong { color: #e2e8f0; }
  .code-block { background: #0f172a; border: 1px solid #334155; border-radius: 6px;
                padding: 12px; font-family: 'JetBrains Mono', monospace; font-size: 13px;
                white-space: pre-wrap; word-break: break-all; margin: 8px 0; max-height: 200px; overflow-y: auto; }
  .meta { display: flex; gap: 24px; color: #64748b; font-size: 13px; margin-top: 8px; }
  footer { margin-top: 48px; padding-top: 24px; border-top: 1px solid #334155; color: #475569; font-size: 13px; text-align: center; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1>AIProbe Security Report</h1>
      <div class="meta">
        <span>Scan ID: {{ scan.scan_id }}</span>
        <span>Target: {{ scan.target }}</span>
        <span>Duration: {{ "%.1f"|format(scan.duration_seconds) }}s</span>
        <span>{{ scan.timestamp[:19] }}Z</span>
      </div>
    </div>
    <div class="score-badge {{ score_class }}">{{ "%.0f"|format(scan.overall_risk_score) }}</div>
  </div>

  <div class="stats">
    <div class="stat"><div class="stat-value">{{ scan.total_findings }}</div><div class="stat-label">Total Findings</div></div>
    <div class="stat"><div class="stat-value critical">{{ scan.critical_findings }}</div><div class="stat-label">Critical</div></div>
    <div class="stat"><div class="stat-value high">{{ scan.high_findings }}</div><div class="stat-label">High</div></div>
    <div class="stat"><div class="stat-value medium">{{ scan.medium_findings }}</div><div class="stat-label">Medium</div></div>
    <div class="stat"><div class="stat-value low">{{ scan.low_findings }}</div><div class="stat-label">Low</div></div>
  </div>

  <h2>Module Results</h2>
  <table>
    <thead><tr><th>Module</th><th>Category</th><th>Score</th><th>Critical</th><th>High</th><th>Total</th><th>Duration</th></tr></thead>
    <tbody>
    {% for r in scan.results %}
    <tr>
      <td>{{ r.module }}</td>
      <td>{{ r.category }}</td>
      <td><strong>{{ "%.0f"|format(r.risk_score) }}</strong></td>
      <td class="critical">{{ r.critical_count }}</td>
      <td class="high">{{ r.high_count }}</td>
      <td>{{ r.findings|length }}</td>
      <td>{{ "%.1f"|format(r.duration_seconds) }}s</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>

  <h2>Detailed Findings</h2>
  {% for r in scan.results %}
  {% for f in r.findings %}
  <div class="finding">
    <div class="finding-header">
      <span class="finding-title">{{ f.title }}</span>
      <span class="badge badge-{{ f.severity.value }}">{{ f.severity.value }}</span>
    </div>
    <div class="finding-detail">{{ f.description }}</div>
    {% if f.attack_payload %}
    <h3>Attack Payload</h3>
    <div class="code-block">{{ f.attack_payload }}</div>
    {% endif %}
    {% if f.model_response %}
    <h3>Model Response</h3>
    <div class="code-block">{{ f.model_response }}</div>
    {% endif %}
    {% if f.evidence %}
    <div class="finding-detail"><strong>Evidence:</strong> {{ f.evidence }}</div>
    {% endif %}
    {% if f.remediation %}
    <div class="finding-detail"><strong>Remediation:</strong> {{ f.remediation }}</div>
    {% endif %}
    {% if f.owasp_mapping %}
    <div class="finding-detail"><strong>OWASP:</strong> {{ f.owasp_mapping }}</div>
    {% endif %}
  </div>
  {% endfor %}
  {% endfor %}

  <footer>
    Generated by AIProbe v1.0.0 | {{ scan.timestamp[:19] }}Z
  </footer>
</div>
</body>
</html>"""


class Reporter:
    """Generates JSON and HTML reports from scan results."""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def save_json(self, scan: ScanResult) -> str:
        path = os.path.join(self.output_dir, f"{scan.scan_id}.json")
        with open(path, "w") as f:
            json.dump(scan.to_dict(), f, indent=2, default=str)
        return path

    def save_html(self, scan: ScanResult) -> str:
        scan.compute_aggregates()
        score = scan.overall_risk_score
        score_class = "score-low" if score < 30 else "score-med" if score < 60 else "score-high"

        template = Template(HTML_TEMPLATE)
        html = template.render(scan=scan, score_class=score_class)

        path = os.path.join(self.output_dir, f"{scan.scan_id}.html")
        with open(path, "w") as f:
            f.write(html)
        return path

    def generate(self, scan: ScanResult, fmt: str = "both") -> list[str]:
        paths = []
        if fmt in ("json", "both"):
            paths.append(self.save_json(scan))
        if fmt in ("html", "both"):
            paths.append(self.save_html(scan))
        return paths
