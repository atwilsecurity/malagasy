"""AIProbe CLI - AI Security Testing Framework."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click
from rich.console import Console

from .core.config import ProbeConfig
from .core.engine import ProbeEngine
from .core.reporter import Reporter

console = Console()

BANNER = """
[bold blue]
    _    ___ ____            _
   / \\  |_ _|  _ \\ _ __ ___ | |__   ___
  / _ \\  | || |_) | '__/ _ \\| '_ \\ / _ \\
 / ___ \\ | ||  __/| | | (_) | |_) |  __/
/_/   \\_\\___|_|   |_|  \\___/|_.__/ \\___|
[/bold blue]
[dim]AI Security Testing Framework v1.0.0[/dim]
[dim]RAG | Agent/Tool-Use | Multi-Modal Attack Testing[/dim]
"""


@click.group()
@click.version_option(version="1.0.0")
def main():
    """AIProbe - AI Security Testing Framework

    Tests AI/LLM models for RAG poisoning, agent/tool-use vulnerabilities,
    and multi-modal attack surfaces.
    """
    pass


@main.command()
@click.option("--endpoint", "-e", required=True, help="LLM API endpoint URL")
@click.option("--api-key", "-k", required=True, help="API key (or set AIPROBE_API_KEY)")
@click.option("--provider", "-p", default="azure_openai",
              type=click.Choice(["azure_openai", "openai", "anthropic", "custom"]),
              help="LLM provider")
@click.option("--model", "-m", default="gpt-4", help="Model name or deployment")
@click.option("--modules",
              type=click.Choice(["all", "rag", "agent", "multimodal", "consumption", "multiturn"]),
              default="all",
              help="Test modules to run. 'all' excludes 'consumption' (opt-in only).")
@click.option("--intensity", "-i", type=click.Choice(["low", "medium", "high"]),
              default="medium", help="Attack intensity")
@click.option("--output", "-o", default="./aiprobe_results", help="Output directory")
@click.option("--format", "fmt", type=click.Choice(["json", "html", "both"]),
              default="both", help="Report format")
@click.option("--config", "-c", type=click.Path(exists=True), default=None,
              help="Path to YAML config file")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def scan(endpoint, api_key, provider, model, modules, intensity, output, fmt, config, verbose):
    """Run a security scan against an LLM endpoint."""
    console.print(BANNER)

    # Build config
    if config:
        cfg = ProbeConfig.from_yaml(config)
    else:
        cfg = ProbeConfig()
        cfg.llm.endpoint = endpoint
        cfg.llm.api_key = api_key
        cfg.llm.provider = provider
        cfg.llm.model = model
        if provider == "azure_openai":
            cfg.llm.deployment_name = model

    cfg.attack_intensity = intensity
    cfg.output_dir = output
    cfg.report_format = fmt
    cfg.verbose = verbose

    # Enable/disable modules.
    # 'consumption' is opt-in only — not included in 'all', has to be selected explicitly.
    if modules == "rag":
        cfg.agent.enabled = False
        cfg.multimodal.enabled = False
        cfg.multiturn.enabled = False
    elif modules == "agent":
        cfg.rag.enabled = False
        cfg.multimodal.enabled = False
        cfg.multiturn.enabled = False
    elif modules == "multimodal":
        cfg.rag.enabled = False
        cfg.agent.enabled = False
        cfg.multiturn.enabled = False
    elif modules == "multiturn":
        cfg.rag.enabled = False
        cfg.agent.enabled = False
        cfg.multimodal.enabled = False
    elif modules == "consumption":
        cfg.rag.enabled = False
        cfg.agent.enabled = False
        cfg.multimodal.enabled = False
        cfg.multiturn.enabled = False
        cfg.consumption.enabled = True

    if cfg.consumption.enabled:
        cap_dollars = cfg.consumption.max_test_cost_usd
        rate = cfg.consumption.cost_per_1k_tokens
        console.print(
            "\n  [yellow]⚠ CONSUMPTION TESTS ENABLED[/yellow]\n"
            "  This category sends traffic engineered to consume tokens and "
            "[bold]costs real money[/bold] during the scan.\n"
            f"  Cost cap: [cyan]${cap_dollars:.2f}[/cyan] @ [cyan]${rate}/1K tokens[/cyan]. "
            f"Suite aborts when reached.\n"
            "  Override via ConsumptionConfig.max_test_cost_usd in your YAML.\n"
        )

    # Validate
    errors = cfg.validate_config()
    if errors:
        for err in errors:
            console.print(f"  [red]✗[/red] {err}")
        sys.exit(1)

    # Run scan
    engine = ProbeEngine(cfg)
    try:
        result = engine.run()
    finally:
        engine.cleanup()

    # Generate reports
    reporter = Reporter(output)
    paths = reporter.generate(result, fmt)

    console.print()
    for p in paths:
        console.print(f"  [green]✓[/green] Report saved: [cyan]{p}[/cyan]")
    console.print()


@main.command()
@click.option("--output", "-o", default="./aiprobe.yaml", help="Output config file path")
def init(output):
    """Generate a sample configuration file."""
    console.print(BANNER)

    cfg = ProbeConfig()
    cfg.llm.endpoint = "https://your-model.openai.azure.com"
    cfg.llm.api_key = "your-api-key-here"
    cfg.llm.model = "gpt-4"
    cfg.llm.deployment_name = "gpt-4"
    cfg.to_yaml(output)

    console.print(f"  [green]✓[/green] Config file created: [cyan]{output}[/cyan]")
    console.print(f"  [dim]Edit the file with your LLM endpoint and API key, then run:[/dim]")
    console.print(f"  [dim]  aiprobe scan --config {output}[/dim]")
    console.print()


@main.command()
def modules():
    """List all available test modules."""
    console.print(BANNER)

    from .modules.rag import (
        KnowledgePoisoningModule, RetrievalManipulationModule,
        IndirectInjectionModule, CitationHallucinationModule, ContextOverflowModule,
    )
    from .modules.agent import (
        UnauthorizedToolModule, PrivilegeEscalationModule,
        ToolChainAbuseModule, AgentHijackingModule, ScopeCreepModule,
    )
    from .modules.multimodal import (
        ImageInjectionModule, CrossModalExploitModule,
        SteganographicModule, OCRBypassModule,
    )
    from .modules.consumption import (
        OutputAmplificationModule, TokenFloodingModule,
        RecursiveReasoningModule, RateLimitProbeModule,
        WalletDrainSimulationModule,
    )
    from .modules.multiturn import (
        CrescendoJailbreakModule, RefusalErosionModule,
        PersonaDriftModule, ContextPoisoningChainModule,
        TrustBuildingExploitModule,
    )

    all_modules = [
        ("RAG Security", [
            KnowledgePoisoningModule, RetrievalManipulationModule,
            IndirectInjectionModule, CitationHallucinationModule, ContextOverflowModule,
        ]),
        ("Agent / Tool-Use", [
            UnauthorizedToolModule, PrivilegeEscalationModule,
            ToolChainAbuseModule, AgentHijackingModule, ScopeCreepModule,
        ]),
        ("Multi-Modal", [
            ImageInjectionModule, CrossModalExploitModule,
            SteganographicModule, OCRBypassModule,
        ]),
        ("Consumption (LLM10, opt-in)", [
            OutputAmplificationModule, TokenFloodingModule,
            RecursiveReasoningModule, RateLimitProbeModule,
            WalletDrainSimulationModule,
        ]),
        ("Multi-Turn / Long-Horizon", [
            CrescendoJailbreakModule, RefusalErosionModule,
            PersonaDriftModule, ContextPoisoningChainModule,
            TrustBuildingExploitModule,
        ]),
    ]

    for category, mods in all_modules:
        console.print(f"\n  [bold blue]{category}[/bold blue]")
        for mod in mods:
            console.print(f"    [cyan]•[/cyan] {mod.name}")
            console.print(f"      [dim]{mod.description}[/dim]")

    total = sum(len(mods) for _, mods in all_modules)
    console.print(f"\n  [dim]Total: {total} modules across {len(all_modules)} categories[/dim]\n")


if __name__ == "__main__":
    main()
