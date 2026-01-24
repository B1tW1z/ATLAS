"""
ATLAS Command-Line Interface

Provides CLI commands for vulnerability assessment.
"""

import asyncio
import sys
from typing import Optional, List
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import print as rprint

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from atlas.core.engine import ATLASEngine
from atlas.persistence.database import Database
from atlas.utils.logger import get_logger
from atlas.presets import list_presets, get_preset, PresetTarget, VulnerabilityInfo

logger = get_logger(__name__)
console = Console()
app = typer.Typer(
    name="atlas",
    help="ATLAS - Advanced Testing Lab for Application Security",
    add_completion=False
)


def print_banner():
    """Print ATLAS banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║     █████╗ ████████╗██╗      █████╗ ███████╗              ║
    ║    ██╔══██╗╚══██╔══╝██║     ██╔══██╗██╔════╝              ║
    ║    ███████║   ██║   ██║     ███████║███████╗              ║
    ║    ██╔══██║   ██║   ██║     ██╔══██║╚════██║              ║
    ║    ██║  ██║   ██║   ███████╗██║  ██║███████║              ║
    ║    ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝              ║
    ║                                                           ║
    ║    Advanced Testing Lab for Application Security          ║
    ║    v1.0.0 | Educational Use Only                          ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL or IP address"),
    auto: bool = typer.Option(False, "--auto", "-a", help="Auto-select all applicable checks"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output report path"),
    format: str = typer.Option("html", "--format", "-f", help="Report format (html/json)")
):
    """
    Start a new vulnerability assessment scan.
    
    Example:
        atlas scan http://localhost:3000
        atlas scan http://juice-shop:3000 --auto
    """
    print_banner()
    
    console.print(f"\n[bold green]Starting scan for target:[/] {target}\n")
    
    # Initialize
    db = Database()
    engine = ATLASEngine(database=db)
    
    async def run_scan():
        # Start scan
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            # Initialize
            task = progress.add_task("Initializing scan...", total=None)
            state = await engine.start_scan(target)
            console.print(f"[dim]Scan ID: {state.scan_id}[/]")
            
            # Reconnaissance
            progress.update(task, description="Running reconnaissance...")
            recon_results = await engine.run_reconnaissance()
            
            progress.update(task, description="Reconnaissance complete!")
        
        # Display recon results
        display_recon_results(recon_results)
        
        # Get available checks
        checks = engine.get_available_checks()
        
        if not checks:
            console.print("[yellow]No applicable checks found for this target[/]")
            return
        
        # Display and select checks
        display_available_checks(checks)
        
        if auto:
            selected = [c["id"] for c in checks]
            console.print(f"\n[bold]Auto-selecting all {len(selected)} checks[/]")
        else:
            selected = prompt_check_selection(checks)
        
        if not selected:
            console.print("[yellow]No checks selected. Exiting.[/]")
            return
        
        engine.select_checks(selected)
        
        # Execute checks
        console.print(f"\n[bold cyan]Executing {len(selected)} vulnerability checks...[/]\n")
        
        findings = await engine.execute_checks()
        
        # Display findings
        display_findings(findings)
        
        # Generate report
        if output or findings:
            console.print("\n[bold]Generating report...[/]")
            report_path = await engine.generate_report(format=format)
            console.print(f"[green]Report saved to: {report_path}[/]")
        
        console.print("\n[bold green]Scan complete![/]")
    
    # Run async
    asyncio.run(run_scan())


@app.command()
def resume(
    scan_id: str = typer.Argument(..., help="Scan ID to resume")
):
    """
    Resume a previously interrupted scan.
    
    Example:
        atlas resume abc123
    """
    print_banner()
    
    db = Database()
    engine = ATLASEngine(database=db)
    
    async def do_resume():
        state = await engine.resume_scan(scan_id)
        
        if not state:
            console.print(f"[red]Scan {scan_id} not found[/]")
            return
        
        console.print(f"[green]Resumed scan: {scan_id}[/]")
        console.print(f"Target: {state.target}")
        console.print(f"Phase: {state.phase.name}")
        
        progress = engine.get_progress()
        console.print(f"Progress: {progress['completed_checks']}/{progress['total_checks']} checks")
    
    asyncio.run(do_resume())


@app.command(name="list")
def list_scans(
    limit: int = typer.Option(10, "--limit", "-n", help="Number of scans to show")
):
    """
    List recent scan sessions.
    
    Example:
        atlas list
        atlas list -n 20
    """
    db = Database()
    sessions = db.list_scan_sessions(limit=limit)
    
    if not sessions:
        console.print("[yellow]No scan sessions found[/]")
        return
    
    table = Table(title="Recent Scans")
    table.add_column("ID", style="cyan")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Phase")
    table.add_column("Created")
    
    for session in sessions:
        table.add_row(
            session.id,
            session.target[:40] + "..." if len(session.target) > 40 else session.target,
            session.status,
            session.phase,
            session.created_at.strftime("%Y-%m-%d %H:%M")
        )
    
    console.print(table)


@app.command()
def report(
    scan_id: str = typer.Argument(..., help="Scan ID to generate report for"),
    format: str = typer.Option("html", "--format", "-f", help="Report format"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output path")
):
    """
    Generate report for a completed scan.
    
    Example:
        atlas report abc123
        atlas report abc123 -f json -o ./report.json
    """
    db = Database()
    
    session = db.get_scan_session(scan_id)
    if not session:
        console.print(f"[red]Scan {scan_id} not found[/]")
        return
    
    findings = db.get_findings(scan_id)
    console.print(f"Found {len(findings)} findings for scan {scan_id}")
    
    # TODO: Generate report using ReportGenerator
    console.print("[yellow]Report generation - use the full scan workflow[/]")


@app.command()
def checks():
    """
    List all available vulnerability checks.
    """
    from atlas.checks.registry import CheckRegistry
    
    registry = CheckRegistry()
    all_checks = registry.get_all_metadata()
    
    # Group by category
    by_category = {}
    for check in all_checks:
        cat = check["category"]
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(check)
    
    for category, checks in by_category.items():
        console.print(f"\n[bold cyan]{category}[/]")
        
        table = Table(show_header=True)
        table.add_column("ID")
        table.add_column("Name")
        table.add_column("Severity")
        table.add_column("OWASP")
        
        for check in checks:
            severity_color = {
                "critical": "red",
                "high": "orange3",
                "medium": "yellow",
                "low": "green",
                "info": "blue"
            }.get(check["severity"], "white")
            
            table.add_row(
                check["id"],
                check["name"],
                f"[{severity_color}]{check['severity'].upper()}[/]",
                check.get("owasp_category", "N/A")
            )
        
        console.print(table)


# Helper functions

def display_recon_results(results: dict):
    """Display reconnaissance results"""
    console.print("\n[bold cyan]═══ Reconnaissance Results ═══[/]\n")
    
    table = Table(title="Discovered Services")
    table.add_column("Port", style="cyan")
    table.add_column("Protocol")
    table.add_column("Service")
    table.add_column("Version")
    
    for port, info in results.get("services", {}).items():
        table.add_row(
            str(port),
            info.get("protocol", "tcp"),
            info.get("service", "unknown"),
            info.get("version", "")
        )
    
    console.print(table)
    
    if results.get("fingerprint"):
        console.print(f"\n[bold green]Target Identified:[/] {results['fingerprint']}")


def display_available_checks(checks: list):
    """Display available checks for selection"""
    console.print("\n[bold cyan]═══ Available Vulnerability Checks ═══[/]\n")
    
    # Group by category
    by_category = {}
    for check in checks:
        cat = check["category"]
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(check)
    
    idx = 1
    check_map = {}
    
    for category, cat_checks in by_category.items():
        console.print(f"\n[bold]{category}[/]")
        
        for check in cat_checks:
            check_map[idx] = check["id"]
            severity_color = {
                "critical": "red",
                "high": "orange3",
                "medium": "yellow",
                "low": "green",
                "info": "blue"
            }.get(check["severity"], "white")
            
            console.print(
                f"  [{idx}] {check['name']} "
                f"[{severity_color}]({check['severity'].upper()})[/]"
            )
            idx += 1
    
    return check_map


def prompt_check_selection(checks: list) -> list:
    """Prompt user to select checks"""
    console.print("\n[bold]Select checks to run:[/]")
    console.print("[dim]Enter numbers separated by commas, 'all' for all, or 'q' to quit[/]")
    
    check_ids = [c["id"] for c in checks]
    
    selection = typer.prompt("Selection")
    
    if selection.lower() == 'q':
        return []
    
    if selection.lower() == 'all':
        return check_ids
    
    try:
        indices = [int(x.strip()) for x in selection.split(",")]
        # Convert 1-indexed to 0-indexed
        return [check_ids[i-1] for i in indices if 0 < i <= len(check_ids)]
    except (ValueError, IndexError):
        console.print("[red]Invalid selection[/]")
        return []


def display_findings(findings: list):
    """Display vulnerability findings"""
    console.print("\n[bold cyan]═══ Vulnerability Findings ═══[/]\n")
    
    if not findings:
        console.print("[green]No vulnerabilities found![/]")
        return
    
    for i, finding in enumerate(findings, 1):
        severity = finding.get("severity", "info")
        severity_color = {
            "critical": "red",
            "high": "orange3",
            "medium": "yellow",
            "low": "green",
            "info": "blue"
        }.get(severity, "white")
        
        panel = Panel(
            f"[bold]{finding.get('title', 'Untitled')}[/]\n\n"
            f"[dim]Description:[/] {finding.get('description', 'N/A')}\n\n"
            f"[dim]Evidence:[/] {finding.get('evidence', 'N/A')[:200]}\n\n"
            f"[dim]Remediation:[/] {finding.get('remediation', 'N/A')[:200]}",
            title=f"[{severity_color}]Finding #{i} - {severity.upper()}[/]",
            border_style=severity_color
        )
        console.print(panel)


# ============================================================================
# DEMO MODE - Preset Vulnerable Targets
# ============================================================================

@app.command()
def demo(
    preset: Optional[str] = typer.Argument(None, help="Preset target (vulnbank, iotgoat)"),
    target_url: Optional[str] = typer.Option(None, "--url", "-u", help="Override default target URL")
):
    """
    Demo mode with preset vulnerable targets.
    
    Shows known vulnerabilities and guides you through testing.
    
    Examples:
        atlas demo                    # Interactive preset selection
        atlas demo vulnbank           # Use VulnBank preset
        atlas demo iotgoat -u http://192.168.1.1
    """
    print_banner()
    
    # List presets if none specified
    if not preset:
        console.print("\n[bold cyan]═══ Available Demo Targets ═══[/]\n")
        
        presets = list_presets()
        for i, p in enumerate(presets, 1):
            console.print(f"  [{i}] [bold]{p.name}[/]")
            console.print(f"      {p.description}")
            console.print(f"      [dim]Category:[/] {p.category.value}")
            console.print(f"      [dim]Vulnerabilities:[/] {len(p.vulnerabilities)}")
            console.print(f"      [dim]GitHub:[/] {p.github_url}")
            console.print()
        
        console.print("  [0] [bold]Custom Target[/]")
        console.print("      Scan a third-party target with generic checks\n")
        
        selection = Prompt.ask("Select target", choices=[str(i) for i in range(len(presets) + 1)])
        
        if selection == "0":
            # Custom target - use regular scan
            custom_url = Prompt.ask("Enter target URL")
            console.print("\n[yellow]Switching to standard scan mode...[/]\n")
            scan(custom_url, auto=False, output=None, format="html")
            return
        
        preset = presets[int(selection) - 1].id
    
    # Load preset
    target = get_preset(preset)
    if not target:
        console.print(f"[red]Preset '{preset}' not found[/]")
        console.print(f"[dim]Available: {', '.join([p.id for p in list_presets()])}[/]")
        return
    
    # Display preset info
    display_preset_info(target)
    
    # Get target URL
    url = target_url or target.default_url
    console.print(f"\n[bold]Target URL:[/] {url}")
    
    if not target_url:
        if Confirm.ask("Use a different URL?", default=False):
            url = Prompt.ask("Enter target URL", default=url)
    
    # Display vulnerabilities
    display_preset_vulnerabilities(target)
    
    # Let user select vulnerabilities to test
    selected_vulns = select_vulnerabilities(target)
    
    if not selected_vulns:
        console.print("[yellow]No vulnerabilities selected. Exiting.[/]")
        return
    
    # For each selected vulnerability, show command and wait
    for vuln in selected_vulns:
        run_guided_test(vuln, url)
    
    console.print("\n[bold green]Demo session complete![/]")


def display_preset_info(target: PresetTarget):
    """Display preset target information"""
    panel = Panel(
        f"[bold]{target.name}[/]\n\n"
        f"{target.description}\n\n"
        f"[dim]Category:[/] {target.category.value}\n"
        f"[dim]GitHub:[/] {target.github_url}\n"
        f"[dim]Vulnerabilities:[/] {len(target.vulnerabilities)}",
        title="[cyan]Demo Target[/]",
        border_style="cyan"
    )
    console.print(panel)
    
    # Setup instructions
    console.print("\n[bold]Setup Instructions:[/]")
    console.print(Panel(target.setup_instructions.strip(), border_style="dim"))


def display_preset_vulnerabilities(target: PresetTarget):
    """Display vulnerabilities grouped by category"""
    console.print("\n[bold cyan]═══ Known Vulnerabilities ═══[/]\n")
    
    by_cat = target.get_vulnerabilities_by_category()
    
    for category, vulns in by_cat.items():
        console.print(f"\n[bold]{category}[/]")
        
        for vuln in vulns:
            severity_color = {
                "critical": "red",
                "high": "orange3",
                "medium": "yellow",
                "low": "green",
                "info": "blue"
            }.get(vuln.severity, "white")
            
            console.print(
                f"  • {vuln.name} "
                f"[{severity_color}]({vuln.severity.upper()})[/]"
            )


def select_vulnerabilities(target: PresetTarget) -> List[VulnerabilityInfo]:
    """Let user select which vulnerabilities to test"""
    console.print("\n[bold]Select vulnerabilities to test:[/]")
    console.print("[dim]Enter numbers separated by commas, 'all' for all, or 'q' to quit[/]\n")
    
    # Number them
    idx = 1
    vuln_map = {}
    by_cat = target.get_vulnerabilities_by_category()
    
    for category, vulns in by_cat.items():
        console.print(f"[bold]{category}[/]")
        for vuln in vulns:
            vuln_map[idx] = vuln
            severity_color = {
                "critical": "red",
                "high": "orange3",
                "medium": "yellow",
                "low": "green",
                "info": "blue"
            }.get(vuln.severity, "white")
            console.print(
                f"  [{idx}] {vuln.name} [{severity_color}]({vuln.severity.upper()})[/]"
            )
            idx += 1
        console.print()
    
    selection = Prompt.ask("Selection")
    
    if selection.lower() == 'q':
        return []
    
    if selection.lower() == 'all':
        return list(vuln_map.values())
    
    try:
        indices = [int(x.strip()) for x in selection.split(",")]
        return [vuln_map[i] for i in indices if i in vuln_map]
    except (ValueError, KeyError):
        console.print("[red]Invalid selection[/]")
        return []


def run_guided_test(vuln: VulnerabilityInfo, target_url: str):
    """Run a guided test for a vulnerability"""
    severity_color = {
        "critical": "red",
        "high": "orange3",
        "medium": "yellow",
        "low": "green",
        "info": "blue"
    }.get(vuln.severity, "white")
    
    console.print(f"\n{'═' * 60}")
    console.print(f"\n[bold {severity_color}]Testing: {vuln.name}[/]")
    console.print(f"[dim]OWASP:[/] {vuln.owasp_category or 'N/A'}")
    console.print(f"[dim]CWE:[/] {vuln.cwe_id or 'N/A'}")
    console.print(f"\n[bold]Description:[/]")
    console.print(f"  {vuln.description}")
    
    if vuln.test_command:
        # Replace {target} placeholder
        command = vuln.test_command.replace("{target}", target_url)
        
        console.print(f"\n[bold]Suggested Test Command:[/]")
        console.print(Panel(command, border_style="green"))
        
        console.print("\n[dim]You can copy and run this command in another terminal.[/]")
    
    # Wait for user to proceed
    console.print()
    action = Prompt.ask(
        "Action",
        choices=["continue", "skip", "exit"],
        default="continue"
    )
    
    if action == "exit":
        raise typer.Exit()
    elif action == "skip":
        console.print("[yellow]Skipped[/]")
    else:
        # If we have an ATLAS check mapped, offer to run it
        if vuln.check_id:
            if Confirm.ask(f"Run ATLAS automated check '{vuln.check_id}'?", default=True):
                run_automated_check(vuln.check_id, target_url)
        else:
            console.print("[dim]No automated check available. Use manual testing.[/]")
            Prompt.ask("Press Enter when ready to continue", default="")


def run_automated_check(check_id: str, target_url: str):
    """Run an automated ATLAS check"""
    from atlas.checks.registry import CheckRegistry
    
    registry = CheckRegistry()
    check = registry.get_check(check_id)
    
    if not check:
        console.print(f"[yellow]Check '{check_id}' not found in registry[/]")
        return
    
    console.print(f"\n[bold]Running {check.metadata.name}...[/]")
    
    async def do_check():
        result = await check.execute(target_url, {"services": {}, "ports": []})
        return result
    
    try:
        result = asyncio.run(do_check())
        
        if result.is_vulnerable:
            console.print(f"\n[bold red]✗ VULNERABLE[/]")
            console.print(f"[dim]Evidence:[/] {result.evidence[:300] if result.evidence else 'N/A'}")
        else:
            console.print(f"\n[bold green]✓ Not vulnerable or inconclusive[/]")
            if result.error_message:
                console.print(f"[dim]Note:[/] {result.error_message}")
    except Exception as e:
        console.print(f"[red]Check failed: {e}[/]")


@app.command()
def presets():
    """
    List available demo preset targets.
    """
    print_banner()
    console.print("\n[bold cyan]═══ Demo Preset Targets ═══[/]\n")
    
    for preset in list_presets():
        console.print(f"[bold]{preset.id}[/]: {preset.name}")
        console.print(f"  {preset.description}")
        console.print(f"  [dim]Vulnerabilities: {len(preset.vulnerabilities)} | Category: {preset.category.value}[/]")
        console.print()


if __name__ == "__main__":
    app()

