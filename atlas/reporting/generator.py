"""
ATLAS Report Generator

Generates HTML and JSON vulnerability reports.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

from jinja2 import Template

from atlas.core.state_manager import ScanState
from atlas.persistence.models import Finding, ReconResult
from atlas.utils.logger import get_logger
from atlas.utils.config import get_config

logger = get_logger(__name__)


class ReportGenerator:
    """
    Generates vulnerability assessment reports.
    
    Supports HTML and JSON output formats.
    """
    
    def __init__(self):
        self._config = get_config()
        self._reports_dir = self._config.data_dir / "reports"
        self._reports_dir.mkdir(parents=True, exist_ok=True)
    
    async def generate(self, scan_state: ScanState, format: str = "html") -> str:
        """
        Generate report from scan state.
        
        Args:
            scan_state: Current scan state
            format: Output format ('html' or 'json')
            
        Returns:
            Path to generated report
        """
        report_data = self._prepare_data(scan_state)
        
        if format == "json":
            return self._generate_json(report_data, scan_state.scan_id)
        else:
            return self._generate_html(report_data, scan_state.scan_id)
    
    async def generate_from_data(
        self,
        scan_id: str,
        target: str,
        findings: List[Finding],
        recon_results: List[ReconResult],
        format: str = "html"
    ) -> str:
        """
        Generate report from database data.
        
        Args:
            scan_id: Scan identifier
            target: Target URL
            findings: List of findings
            recon_results: Reconnaissance results
            format: Output format
            
        Returns:
            Path to generated report
        """
        # Build report data
        services = {}
        for r in recon_results:
            services[r.port] = {
                "service": r.service,
                "version": r.version,
                "protocol": r.protocol
            }
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
        
        report_data = {
            "scan_id": scan_id,
            "target": target,
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_findings": len(findings),
                "severity_counts": severity_counts,
                "ports_discovered": len(recon_results)
            },
            "recon": {
                "ports": [r.port for r in recon_results],
                "services": services
            },
            "findings": [f.to_dict() for f in findings]
        }
        
        if format == "json":
            return self._generate_json(report_data, scan_id)
        else:
            return self._generate_html(report_data, scan_id)
    
    def _prepare_data(self, state: ScanState) -> Dict[str, Any]:
        """Prepare report data from scan state"""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for finding in state.findings:
            sev = finding.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        return {
            "scan_id": state.scan_id,
            "target": state.target,
            "generated_at": datetime.utcnow().isoformat(),
            "completed_at": state.updated_at.isoformat(),
            "summary": {
                "total_findings": len(state.findings),
                "severity_counts": severity_counts,
                "checks_executed": len(state.executed_checks),
                "ports_discovered": len(state.open_ports)
            },
            "recon": {
                "ports": state.open_ports,
                "services": state.services,
                "fingerprint": state.target_fingerprint
            },
            "findings": state.findings
        }
    
    def _generate_json(self, data: Dict[str, Any], scan_id: str) -> str:
        """Generate JSON report"""
        report_path = self._reports_dir / f"{scan_id}.json"
        
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        
        logger.info(f"Generated JSON report: {report_path}")
        return str(report_path)
    
    def _generate_html(self, data: Dict[str, Any], scan_id: str) -> str:
        """Generate HTML report"""
        report_path = self._reports_dir / f"{scan_id}.html"
        
        html_content = self._html_template.render(
            report=data,
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        )
        
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        logger.info(f"Generated HTML report: {report_path}")
        return str(report_path)
    
    @property
    def _html_template(self) -> Template:
        """HTML report template"""
        return Template('''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ATLAS Security Report - {{ report.scan_id }}</title>
    <style>
        :root {
            --bg: #0d1117;
            --bg-card: #161b22;
            --text: #e6edf3;
            --text-muted: #8b949e;
            --border: #30363d;
            --critical: #f85149;
            --high: #f0883e;
            --medium: #d29922;
            --low: #3fb950;
            --info: #58a6ff;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 40px;
        }
        .container { max-width: 1000px; margin: 0 auto; }
        .header {
            text-align: center;
            padding: 40px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 40px;
        }
        .logo { font-size: 2.5rem; color: var(--info); margin-bottom: 10px; }
        h1 { font-size: 1.5rem; font-weight: 400; color: var(--text-muted); }
        .meta { margin-top: 20px; font-size: 0.9rem; color: var(--text-muted); }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 16px;
            margin-bottom: 40px;
        }
        .summary-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }
        .summary-value { font-size: 2rem; font-weight: 700; }
        .summary-label { font-size: 0.85rem; color: var(--text-muted); }
        .critical .summary-value { color: var(--critical); }
        .high .summary-value { color: var(--high); }
        .medium .summary-value { color: var(--medium); }
        .low .summary-value { color: var(--low); }
        .info .summary-value { color: var(--info); }
        .section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
        }
        .section h2 {
            font-size: 1.2rem;
            margin-bottom: 20px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border);
        }
        .finding {
            background: var(--bg);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 16px;
            border-left: 4px solid;
        }
        .finding.severity-critical { border-color: var(--critical); }
        .finding.severity-high { border-color: var(--high); }
        .finding.severity-medium { border-color: var(--medium); }
        .finding.severity-low { border-color: var(--low); }
        .finding.severity-info { border-color: var(--info); }
        .finding-header { display: flex; justify-content: space-between; margin-bottom: 12px; }
        .finding-title { font-weight: 600; font-size: 1.1rem; }
        .badge {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-critical { background: rgba(248,81,73,0.2); color: var(--critical); }
        .badge-high { background: rgba(240,136,62,0.2); color: var(--high); }
        .badge-medium { background: rgba(210,153,34,0.2); color: var(--medium); }
        .badge-low { background: rgba(63,185,80,0.2); color: var(--low); }
        .badge-info { background: rgba(88,166,255,0.2); color: var(--info); }
        .finding-section { margin-top: 16px; }
        .finding-section-title { font-weight: 500; color: var(--text-muted); font-size: 0.85rem; margin-bottom: 8px; }
        .evidence {
            background: var(--bg-card);
            padding: 12px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 0.85rem;
            overflow-x: auto;
            white-space: pre-wrap;
        }
        .services-list { display: flex; flex-wrap: wrap; gap: 8px; }
        .service-tag {
            background: var(--bg);
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 0.85rem;
        }
        .footer {
            text-align: center;
            padding: 40px;
            color: var(--text-muted);
            font-size: 0.85rem;
        }
        .owasp-tag { color: var(--info); font-size: 0.85rem; }
        @media print {
            body { background: white; color: black; }
            .finding { page-break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">⚡ ATLAS</div>
            <h1>Security Assessment Report</h1>
            <div class="meta">
                <p><strong>Target:</strong> {{ report.target }}</p>
                <p><strong>Scan ID:</strong> {{ report.scan_id }}</p>
                <p><strong>Generated:</strong> {{ generated_at }}</p>
            </div>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <div class="summary-value">{{ report.summary.total_findings }}</div>
                <div class="summary-label">Total Findings</div>
            </div>
            <div class="summary-card critical">
                <div class="summary-value">{{ report.summary.severity_counts.critical or 0 }}</div>
                <div class="summary-label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="summary-value">{{ report.summary.severity_counts.high or 0 }}</div>
                <div class="summary-label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="summary-value">{{ report.summary.severity_counts.medium or 0 }}</div>
                <div class="summary-label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="summary-value">{{ report.summary.severity_counts.low or 0 }}</div>
                <div class="summary-label">Low</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Reconnaissance Results</h2>
            <p style="margin-bottom: 16px;">Discovered {{ report.recon.ports|length }} open ports</p>
            {% if report.recon.fingerprint %}
            <p style="margin-bottom: 16px; color: var(--low);">
                🎯 Target Identified: <strong>{{ report.recon.fingerprint }}</strong>
            </p>
            {% endif %}
            <div class="services-list">
                {% for port, svc in report.recon.services.items() %}
                <div class="service-tag">
                    <strong>{{ port }}</strong>/{{ svc.protocol or 'tcp' }} - {{ svc.service or 'unknown' }}
                    {% if svc.version %}({{ svc.version }}){% endif %}
                </div>
                {% endfor %}
            </div>
        </div>
        
        <div class="section">
            <h2>Vulnerability Findings</h2>
            {% if report.findings %}
                {% for finding in report.findings %}
                <div class="finding severity-{{ finding.severity }}">
                    <div class="finding-header">
                        <div class="finding-title">{{ finding.title }}</div>
                        <span class="badge badge-{{ finding.severity }}">{{ finding.severity }}</span>
                    </div>
                    
                    {% if finding.owasp_category %}
                    <div class="owasp-tag">{{ finding.owasp_category }}</div>
                    {% endif %}
                    
                    <div class="finding-section">
                        <div class="finding-section-title">Description</div>
                        <p>{{ finding.description }}</p>
                    </div>
                    
                    {% if finding.evidence %}
                    <div class="finding-section">
                        <div class="finding-section-title">Evidence</div>
                        <div class="evidence">{{ finding.evidence }}</div>
                    </div>
                    {% endif %}
                    
                    {% if finding.url %}
                    <div class="finding-section">
                        <div class="finding-section-title">Affected URL</div>
                        <p>{{ finding.url }}</p>
                    </div>
                    {% endif %}
                    
                    {% if finding.remediation %}
                    <div class="finding-section">
                        <div class="finding-section-title">Remediation</div>
                        <p>{{ finding.remediation }}</p>
                    </div>
                    {% endif %}
                </div>
                {% endfor %}
            {% else %}
                <p style="color: var(--low); text-align: center; padding: 40px;">
                    ✓ No vulnerabilities found
                </p>
            {% endif %}
        </div>
        
        <div class="footer">
            <p>Generated by ATLAS - Automated Threat and Lifecycle Assessment System</p>
            <p>For educational and research purposes only</p>
        </div>
    </div>
</body>
</html>''')
