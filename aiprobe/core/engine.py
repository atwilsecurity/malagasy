"""Test orchestration engine."""

from __future__ import annotations

import time
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from .config import ProbeConfig
from .llm_client import LLMClient
from .models import ScanResult, TestResult, TestStatus, Severity

console = Console()


class ProbeEngine:
    """Orchestrates all test modules and aggregates results."""

    def __init__(self, config: ProbeConfig):
        self.config = config
        self.client = LLMClient(config.llm)
        self.scan_result = ScanResult(target=config.llm.endpoint, provider=config.llm.provider)
        self._modules: list = []

    def register_modules(self):
        """Dynamically register enabled test modules."""
        if self.config.rag.enabled:
            from ..modules.rag import (
                KnowledgePoisoningModule,
                RetrievalManipulationModule,
                IndirectInjectionModule,
                CitationHallucinationModule,
                ContextOverflowModule,
            )
            self._modules.extend([
                KnowledgePoisoningModule(self.client, self.config),
                RetrievalManipulationModule(self.client, self.config),
                IndirectInjectionModule(self.client, self.config),
                CitationHallucinationModule(self.client, self.config),
                ContextOverflowModule(self.client, self.config),
            ])

        if self.config.agent.enabled:
            from ..modules.agent import (
                UnauthorizedToolModule,
                PrivilegeEscalationModule,
                ToolChainAbuseModule,
                AgentHijackingModule,
                ScopeCreepModule,
            )
            self._modules.extend([
                UnauthorizedToolModule(self.client, self.config),
                PrivilegeEscalationModule(self.client, self.config),
                ToolChainAbuseModule(self.client, self.config),
                AgentHijackingModule(self.client, self.config),
                ScopeCreepModule(self.client, self.config),
            ])

        if self.config.multimodal.enabled:
            from ..modules.multimodal import (
                ImageInjectionModule,
                CrossModalExploitModule,
                SteganographicModule,
                OCRBypassModule,
            )
            self._modules.extend([
                ImageInjectionModule(self.client, self.config),
                CrossModalExploitModule(self.client, self.config),
                SteganographicModule(self.client, self.config),
                OCRBypassModule(self.client, self.config),
            ])

    def run(self) -> ScanResult:
        """Execute all registered test modules."""
        start = time.time()
        self.register_modules()

        if not self._modules:
            console.print("[yellow]No test modules enabled. Check your configuration.[/yellow]")
            return self.scan_result

        console.print()
        console.rule("[bold blue]AIProbe Security Scan[/bold blue]")
        console.print(f"  Target:   [cyan]{self.config.llm.endpoint}[/cyan]")
        console.print(f"  Provider: [cyan]{self.config.llm.provider}[/cyan]")
        console.print(f"  Model:    [cyan]{self.config.llm.model}[/cyan]")
        console.print(f"  Modules:  [cyan]{len(self._modules)}[/cyan]")
        console.print(f"  Intensity:[cyan] {self.config.attack_intensity}[/cyan]")
        console.rule()
        console.print()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            overall = progress.add_task("[bold]Overall Progress", total=len(self._modules))

            for module in self._modules:
                mod_name = module.name
                progress.update(overall, description=f"[bold]{mod_name}")
                console.print(f"\n  [bold blue]▸[/bold blue] Running: [white]{mod_name}[/white]")

                try:
                    result = module.run()
                    self.scan_result.results.append(result)
                    self.scan_result.modules_run.append(mod_name)

                    # Print inline summary
                    findings = len(result.findings)
                    crits = result.critical_count
                    highs = result.high_count
                    status_icon = "✓" if findings == 0 else "✗"
                    status_color = "green" if findings == 0 else "red" if crits > 0 else "yellow"
                    console.print(
                        f"    [{status_color}]{status_icon}[/{status_color}] "
                        f"Score: [bold]{result.risk_score:.0f}[/bold]/100  "
                        f"Findings: {findings} "
                        f"([red]{crits} crit[/red], [yellow]{highs} high[/yellow])"
                    )

                except Exception as e:
                    console.print(f"    [red]✗ Error: {e}[/red]")
                    err_result = TestResult(
                        module=mod_name,
                        category=module.category,
                        status=TestStatus.ERROR,
                    )
                    self.scan_result.results.append(err_result)

                progress.advance(overall)

        self.scan_result.duration_seconds = time.time() - start
        self.scan_result.compute_aggregates()

        self._print_summary()
        return self.scan_result

    def _print_summary(self):
        """Print final scan summary table."""
        sr = self.scan_result
        console.print()
        console.rule("[bold blue]Scan Complete[/bold blue]")
        console.print()

        # Summary stats
        score_color = "green" if sr.overall_risk_score < 30 else "yellow" if sr.overall_risk_score < 60 else "red"
        console.print(f"  Scan ID:       [cyan]{sr.scan_id}[/cyan]")
        console.print(f"  Duration:      [cyan]{sr.duration_seconds:.1f}s[/cyan]")
        console.print(f"  Risk Score:    [{score_color}][bold]{sr.overall_risk_score:.1f}[/bold]/100[/{score_color}]")
        console.print(f"  API Calls:     [cyan]{self.client.total_calls}[/cyan]")
        console.print(f"  Tokens Used:   [cyan]{self.client.total_tokens:,}[/cyan]")
        console.print()

        # Findings table
        table = Table(title="Findings Summary", show_header=True, header_style="bold white on blue")
        table.add_column("Module", style="white", min_width=30)
        table.add_column("Score", justify="center", min_width=8)
        table.add_column("Critical", justify="center", style="red")
        table.add_column("High", justify="center", style="yellow")
        table.add_column("Medium", justify="center", style="cyan")
        table.add_column("Low", justify="center", style="dim")

        for r in sr.results:
            sc = f"{r.risk_score:.0f}"
            crit = str(r.critical_count)
            high = str(r.high_count)
            med = str(sum(1 for f in r.findings if f.severity == Severity.MEDIUM))
            low = str(sum(1 for f in r.findings if f.severity == Severity.LOW))
            table.add_row(r.module, sc, crit, high, med, low)

        table.add_row(
            "[bold]TOTAL", f"[bold]{sr.overall_risk_score:.0f}",
            f"[bold red]{sr.critical_findings}", f"[bold yellow]{sr.high_findings}",
            f"[bold cyan]{sr.medium_findings}", f"[bold]{sr.low_findings}",
        )
        console.print(table)
        console.print()

    def cleanup(self):
        self.client.close()
