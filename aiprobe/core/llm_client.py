"""Unified LLM client supporting Azure OpenAI, OpenAI, and custom endpoints."""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any, Optional

import httpx

from .config import LLMConfig


class LLMClient:
    """Handles all LLM API interactions."""

    def __init__(self, config: LLMConfig):
        self.config = config
        self.total_calls = 0
        self.total_tokens = 0
        self._client = httpx.Client(timeout=config.timeout)

    def close(self):
        self._client.close()

    # ── Chat Completion ──────────────────────────────────────────

    def chat(
        self,
        messages: list[dict[str, Any]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        tools: Optional[list[dict]] = None,
        tool_choice: Optional[str] = None,
    ) -> dict[str, Any]:
        """Send a chat completion request. Returns the full API response."""
        temp = temperature if temperature is not None else self.config.temperature
        tokens = max_tokens or self.config.max_tokens

        if self.config.provider == "azure_openai":
            return self._azure_chat(messages, temp, tokens, tools, tool_choice)
        elif self.config.provider == "openai":
            return self._openai_chat(messages, temp, tokens, tools, tool_choice)
        elif self.config.provider == "anthropic":
            return self._anthropic_chat(messages, temp, tokens)
        else:
            return self._custom_chat(messages, temp, tokens, tools, tool_choice)

    def chat_text(self, messages: list[dict], **kwargs) -> str:
        """Convenience: return just the text content from a chat call."""
        resp = self.chat(messages, **kwargs)
        return self._extract_text(resp)

    # ── Vision ───────────────────────────────────────────────────

    def chat_with_image(
        self,
        text_prompt: str,
        image_path: Optional[str] = None,
        image_url: Optional[str] = None,
        image_base64: Optional[str] = None,
        system_prompt: str = "",
    ) -> dict[str, Any]:
        """Send a vision request with an image."""
        content = []

        if text_prompt:
            content.append({"type": "text", "text": text_prompt})

        if image_path:
            b64 = base64.b64encode(Path(image_path).read_bytes()).decode()
            ext = Path(image_path).suffix.lstrip(".").replace("jpg", "jpeg")
            content.append({
                "type": "image_url",
                "image_url": {"url": f"data:image/{ext};base64,{b64}"}
            })
        elif image_url:
            content.append({"type": "image_url", "image_url": {"url": image_url}})
        elif image_base64:
            content.append({
                "type": "image_url",
                "image_url": {"url": f"data:image/png;base64,{image_base64}"}
            })

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": content})

        return self.chat(messages)

    # ── Function / Tool Calling ──────────────────────────────────

    def chat_with_tools(
        self,
        messages: list[dict],
        tools: list[dict],
        tool_choice: str = "auto",
    ) -> dict[str, Any]:
        """Send a request with tool/function definitions."""
        return self.chat(messages, tools=tools, tool_choice=tool_choice)

    # ── Provider Implementations ─────────────────────────────────

    def _azure_chat(self, messages, temp, max_tokens, tools, tool_choice) -> dict:
        url = (
            f"{self.config.endpoint.rstrip('/')}/openai/deployments/"
            f"{self.config.deployment_name or self.config.model}/chat/completions"
            f"?api-version={self.config.api_version}"
        )
        headers = {"api-key": self.config.api_key, "Content-Type": "application/json"}
        body: dict[str, Any] = {
            "messages": messages,
            "temperature": temp,
            "max_tokens": max_tokens,
        }
        if tools:
            body["tools"] = tools
            if tool_choice:
                body["tool_choice"] = tool_choice

        resp = self._client.post(url, headers=headers, json=body)
        self.total_calls += 1
        data = resp.json()
        self.total_tokens += data.get("usage", {}).get("total_tokens", 0)
        return data

    def _openai_chat(self, messages, temp, max_tokens, tools, tool_choice) -> dict:
        url = f"{self.config.endpoint.rstrip('/')}/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
        body: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": temp,
            "max_tokens": max_tokens,
        }
        if tools:
            body["tools"] = tools
            if tool_choice:
                body["tool_choice"] = tool_choice

        resp = self._client.post(url, headers=headers, json=body)
        self.total_calls += 1
        data = resp.json()
        self.total_tokens += data.get("usage", {}).get("total_tokens", 0)
        return data

    def _anthropic_chat(self, messages, temp, max_tokens) -> dict:
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.config.api_key,
            "anthropic-version": "2024-01-01",
            "Content-Type": "application/json",
        }
        # Convert from OpenAI format
        system = ""
        conv_messages = []
        for m in messages:
            if m["role"] == "system":
                system = m["content"] if isinstance(m["content"], str) else ""
            else:
                conv_messages.append(m)

        body: dict[str, Any] = {
            "model": self.config.model,
            "messages": conv_messages,
            "temperature": temp,
            "max_tokens": max_tokens,
        }
        if system:
            body["system"] = system

        resp = self._client.post(url, headers=headers, json=body)
        self.total_calls += 1
        return resp.json()

    def _custom_chat(self, messages, temp, max_tokens, tools, tool_choice) -> dict:
        """Generic endpoint — assumes OpenAI-compatible API."""
        url = f"{self.config.endpoint.rstrip('/')}/v1/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        body: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": temp,
            "max_tokens": max_tokens,
        }
        if tools:
            body["tools"] = tools
            if tool_choice:
                body["tool_choice"] = tool_choice

        resp = self._client.post(url, headers=headers, json=body)
        self.total_calls += 1
        return resp.json()

    # ── Helpers ───────────────────────────────────────────────────

    def _extract_text(self, response: dict) -> str:
        """Extract text from various provider response formats."""
        # OpenAI / Azure format
        choices = response.get("choices", [])
        if choices:
            msg = choices[0].get("message", {})
            content = msg.get("content", "")
            if content:
                return content
            # Check for tool calls
            tool_calls = msg.get("tool_calls", [])
            if tool_calls:
                return json.dumps([tc.get("function", {}) for tc in tool_calls])

        # Anthropic format
        content_blocks = response.get("content", [])
        if isinstance(content_blocks, list):
            texts = [b.get("text", "") for b in content_blocks if b.get("type") == "text"]
            if texts:
                return " ".join(texts)

        return str(response)
