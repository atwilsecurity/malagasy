"""Agent/Tool-Use Security Testing Modules."""

from .unauthorized_tools import UnauthorizedToolModule
from .privilege_escalation import PrivilegeEscalationModule
from .tool_chain_abuse import ToolChainAbuseModule
from .agent_hijacking import AgentHijackingModule
from .scope_creep import ScopeCreepModule

__all__ = [
    "UnauthorizedToolModule",
    "PrivilegeEscalationModule",
    "ToolChainAbuseModule",
    "AgentHijackingModule",
    "ScopeCreepModule",
]
