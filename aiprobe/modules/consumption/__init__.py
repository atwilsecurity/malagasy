"""OWASP LLM10 (Unbounded Consumption) test modules."""

from .output_amplification import OutputAmplificationModule
from .token_flooding import TokenFloodingModule
from .recursive_reasoning import RecursiveReasoningModule
from .rate_limit_probe import RateLimitProbeModule
from .wallet_drain_simulation import WalletDrainSimulationModule

__all__ = [
    "OutputAmplificationModule",
    "TokenFloodingModule",
    "RecursiveReasoningModule",
    "RateLimitProbeModule",
    "WalletDrainSimulationModule",
]
