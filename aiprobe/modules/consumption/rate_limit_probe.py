"""
Rate Limit Probe (OWASP LLM10 — Unbounded Consumption)

Bursts a small number of concurrent requests at the endpoint and checks
whether rate limiting kicks in. Absence of rate limiting is a finding.

OPERATIONALLY HAZARDOUS — bursting prod endpoints can trigger ops alerts.
This probe is gated behind ConsumptionConfig.rate_limit_probe_enabled (default
False) on top of the existing consumption opt-in.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..base import BaseModule
from ...core.models import AttackCategory, Severity


# Rate-limit signals across providers.
RATE_LIMIT_HTTP_STATUSES = {429, 503}
RATE_LIMIT_BODY_SIGNALS = [
    "rate limit", "rate_limit", "rate-limited", "too many requests",
    "quota exceeded", "throttled", "retry-after",
]


def _looks_rate_limited(response: dict, raw_text: str = "") -> bool:
    """Heuristic detection of rate-limit responses across providers."""
    if isinstance(response, dict):
        err = response.get("error", {})
        if isinstance(err, dict):
            code = str(err.get("code", "")).lower()
            msg = str(err.get("message", "")).lower()
            if "rate" in code or "rate" in msg or "throttl" in msg or "quota" in msg:
                return True
    if raw_text:
        low = raw_text.lower()
        return any(sig in low for sig in RATE_LIMIT_BODY_SIGNALS)
    return False


class RateLimitProbeModule(BaseModule):
    name = "Consumption: Rate Limit Probe"
    category = "consumption"
    description = (
        "Bursts concurrent requests to test whether the endpoint enforces "
        "rate limiting. OPERATIONALLY HAZARDOUS — separately gated."
    )

    def _default_category(self) -> AttackCategory:
        return AttackCategory.RATE_LIMIT_PROBE

    def execute(self):
        if not self.config.consumption.rate_limit_probe_enabled:
            self.add_finding(
                category=AttackCategory.RATE_LIMIT_PROBE,
                severity=Severity.INFO,
                title="Rate limit probe skipped (disabled)",
                description=(
                    "rate_limit_probe_enabled=False. Set it to True in "
                    "ConsumptionConfig only when you have authorization to "
                    "burst requests against the target endpoint."
                ),
            )
            return

        burst = self.config.consumption.rate_limit_burst_size
        window = self.config.consumption.rate_limit_burst_window_sec

        results: list[dict] = []
        start = time.time()

        def _send(i: int) -> dict:
            try:
                response = self.client.chat(
                    [{"role": "user", "content": f"Echo the number {i}."}],
                    temperature=0.0,
                    max_tokens=16,
                )
                text = self.client._extract_text(response)
                return {
                    "index": i,
                    "rate_limited": _looks_rate_limited(response, text),
                    "response_snippet": text[:120],
                }
            except Exception as e:
                msg = str(e)
                return {
                    "index": i,
                    "rate_limited": _looks_rate_limited({}, msg),
                    "error": msg[:200],
                }

        # Concurrent burst.
        with ThreadPoolExecutor(max_workers=burst) as pool:
            futures = [pool.submit(_send, i) for i in range(burst)]
            for fut in as_completed(futures):
                results.append(fut.result())

        elapsed = time.time() - start
        rate_limited_count = sum(1 for r in results if r.get("rate_limited"))
        completed_count = sum(1 for r in results if "error" not in r)

        # Finding: burst completed inside window with NO rate limiting.
        if rate_limited_count == 0 and elapsed <= window:
            self.add_finding(
                category=AttackCategory.RATE_LIMIT_PROBE,
                severity=Severity.HIGH,
                title=f"No rate limiting detected on {burst}-request burst",
                description=(
                    f"Sent {burst} concurrent requests within {elapsed:.1f}s. "
                    f"None were rate-limited. The endpoint accepts unbounded "
                    f"concurrent traffic, enabling cost-amplification and DoS-shaped "
                    f"attacks."
                ),
                attack_payload=f"<{burst} concurrent identical requests>",
                evidence=(
                    f"burst_size={burst}, window_sec={window}, elapsed={elapsed:.1f}s, "
                    f"completed={completed_count}, rate_limited={rate_limited_count}"
                ),
                remediation=(
                    "Enforce per-key rate limits at the API gateway (e.g. requests "
                    "per minute, tokens per minute). Return 429 with Retry-After "
                    "headers for clients that exceed the limit. Consider per-IP "
                    "limits for unauthenticated traffic."
                ),
                owasp_mapping="LLM10: Unbounded Consumption",
                risk_score=70.0,
            )
        elif rate_limited_count > 0:
            # Rate limiting works — info finding only.
            self.add_finding(
                category=AttackCategory.RATE_LIMIT_PROBE,
                severity=Severity.INFO,
                title=f"Rate limiting active ({rate_limited_count}/{burst})",
                description=(
                    f"{rate_limited_count} of {burst} concurrent requests were "
                    f"rate-limited. The endpoint defends against bursts."
                ),
                evidence=(
                    f"burst_size={burst}, elapsed={elapsed:.1f}s, "
                    f"rate_limited={rate_limited_count}"
                ),
            )
            self.mark_passed()
        else:
            # Took longer than the burst window — likely some implicit throttling.
            self.mark_passed()
