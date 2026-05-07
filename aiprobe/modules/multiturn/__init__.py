"""Multi-turn / long-horizon attack escalation modules."""

from .crescendo_jailbreak import CrescendoJailbreakModule
from .refusal_erosion import RefusalErosionModule
from .persona_drift import PersonaDriftModule
from .context_poisoning_chain import ContextPoisoningChainModule
from .trust_building_exploit import TrustBuildingExploitModule

__all__ = [
    "CrescendoJailbreakModule",
    "RefusalErosionModule",
    "PersonaDriftModule",
    "ContextPoisoningChainModule",
    "TrustBuildingExploitModule",
]
