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
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500&family=Orbitron:wght@600;700;800&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0a0e1a;
            --bg-card: #0f1419;
            --bg-darker: #050810;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
            --border: #1e293b;
            --primary: #00ff88;
            --secondary: #00d4ff;
            --critical: #ff4757;
            --high: #ff6b6b;
            --medium: #ffd43b;
            --low: #51cf66;
            --info: #00d4ff;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 40px;
            position: relative;
        }
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image: linear-gradient(var(--primary) 1px, transparent 1px),
                linear-gradient(90deg, var(--primary) 1px, transparent 1px);
            background-size: 60px 60px;
            opacity: 0.02;
            pointer-events: none;
            z-index: 0;
        }
        .container { max-width: 1000px; margin: 0 auto; position: relative; z-index: 1; }
        .header {
            text-align: center;
            padding: 50px;
            background: linear-gradient(145deg, var(--bg-card), var(--bg-darker));
            border: 1px solid var(--border);
            border-radius: 16px;
            margin-bottom: 40px;
            position: relative;
        }
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--primary), var(--secondary));
            border-radius: 16px 16px 0 0;
        }
        .logo {
            font-family: 'Orbitron', monospace;
            font-size: 3rem;
            font-weight: 800;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: 4px;
            margin-bottom: 10px;
        }
        h1 {
            font-family: 'Fira Code', monospace;
            font-size: 1.2rem;
            font-weight: 400;
            color: var(--text-muted);
        }
        .meta { margin-top: 24px; font-family: 'Fira Code', monospace; font-size: 0.85rem; color: var(--text-muted); }
        .meta p { margin-bottom: 6px; }
        .meta strong { color: var(--primary); }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 16px;
            margin-bottom: 40px;
        }
        .summary-card {
            background: linear-gradient(145deg, var(--bg-card), var(--bg-darker));
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px 16px;
            text-align: center;
            transition: all 0.3s;
        }
        .summary-card:hover {
            border-color: var(--primary);
            box-shadow: 0 0 30px rgba(0, 255, 136, 0.15);
            transform: translateY(-3px);
        }
        .summary-value { font-family: 'Orbitron', monospace; font-size: 2.2rem; font-weight: 700; }
        .summary-label { font-family: 'Fira Code', monospace; font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; margin-top: 8px; }
        .critical .summary-value { color: var(--critical); text-shadow: 0 0 20px rgba(255, 71, 87, 0.5); }
        .high .summary-value { color: var(--high); text-shadow: 0 0 20px rgba(255, 107, 107, 0.5); }
        .medium .summary-value { color: var(--medium); text-shadow: 0 0 20px rgba(255, 212, 59, 0.5); }
        .low .summary-value { color: var(--low); text-shadow: 0 0 20px rgba(81, 207, 102, 0.5); }
        .info .summary-value { color: var(--info); text-shadow: 0 0 20px rgba(0, 212, 255, 0.5); }
        .section {
            background: linear-gradient(145deg, var(--bg-card), var(--bg-darker));
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 28px;
            margin-bottom: 24px;
            position: relative;
        }
        .section::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, var(--primary), var(--secondary));
            border-radius: 12px 12px 0 0;
            opacity: 0;
            transition: opacity 0.3s;
        }
        .section:hover::before { opacity: 1; }
        .section h2 {
            font-family: 'Orbitron', monospace;
            font-size: 1.1rem;
            color: var(--primary);
            margin-bottom: 20px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border);
            letter-spacing: 1px;
        }
        .finding {
            background: var(--bg);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 16px;
            border-left: 4px solid;
            transition: all 0.3s;
        }
        .finding:hover {
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.3);
        }
        .finding.severity-critical { border-color: var(--critical); }
        .finding.severity-high { border-color: var(--high); }
        .finding.severity-medium { border-color: var(--medium); }
        .finding.severity-low { border-color: var(--low); }
        .finding.severity-info { border-color: var(--info); }
        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
        .finding-title { font-weight: 600; font-size: 1.1rem; }
        .badge {
            padding: 6px 14px;
            border-radius: 20px;
            font-family: 'Fira Code', monospace;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .badge-critical { background: rgba(255, 71, 87, 0.15); color: var(--critical); border: 1px solid rgba(255, 71, 87, 0.3); }
        .badge-high { background: rgba(255, 107, 107, 0.15); color: var(--high); border: 1px solid rgba(255, 107, 107, 0.3); }
        .badge-medium { background: rgba(255, 212, 59, 0.15); color: var(--medium); border: 1px solid rgba(255, 212, 59, 0.3); }
        .badge-low { background: rgba(81, 207, 102, 0.15); color: var(--low); border: 1px solid rgba(81, 207, 102, 0.3); }
        .badge-info { background: rgba(0, 212, 255, 0.15); color: var(--info); border: 1px solid rgba(0, 212, 255, 0.3); }
        .finding-section { margin-top: 16px; }
        .finding-section-title { font-family: 'Fira Code', monospace; font-weight: 500; color: var(--primary); font-size: 0.8rem; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 1px; }
        .evidence {
            background: var(--bg-darker);
            padding: 16px;
            border-radius: 8px;
            font-family: 'Fira Code', monospace;
            font-size: 0.85rem;
            overflow-x: auto;
            white-space: pre-wrap;
            border: 1px solid var(--border);
            color: var(--secondary);
        }
        .services-list { display: flex; flex-wrap: wrap; gap: 10px; }
        .service-tag {
            background: var(--bg);
            padding: 10px 16px;
            border-radius: 8px;
            font-family: 'Fira Code', monospace;
            font-size: 0.85rem;
            border: 1px solid var(--border);
            transition: all 0.3s;
        }
        .service-tag:hover {
            border-color: var(--primary);
            box-shadow: 0 0 15px rgba(0, 255, 136, 0.2);
        }
        .service-tag strong { color: var(--primary); }
        .footer {
            text-align: center;
            padding: 40px;
            color: var(--text-muted);
            font-family: 'Fira Code', monospace;
            font-size: 0.8rem;
        }
        .footer p:first-child { color: var(--primary); margin-bottom: 8px; }
        .owasp-tag { color: var(--secondary); font-family: 'Fira Code', monospace; font-size: 0.8rem; }
        @media (max-width: 768px) {
            .summary-grid { grid-template-columns: repeat(3, 1fr); }
            body { padding: 20px; }
            .header { padding: 30px 20px; }
        }
        @media print {
            body { background: white; color: black; }
            body::before { display: none; }
            .finding { page-break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">ATLAS</div>
            <h1>// Security Assessment Report</h1>
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
            <div class="summary-card info">
                <div class="summary-value">{{ report.summary.severity_counts.info or 0 }}</div>
                <div class="summary-label">Info</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Reconnaissance Results</h2>
            <p style="margin-bottom: 16px; color: var(--text-muted);">Discovered {{ report.recon.ports|length }} open ports</p>
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
                <p style="color: var(--low); text-align: center; padding: 40px; font-family: 'Fira Code', monospace;">
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

