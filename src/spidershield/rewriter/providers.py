"""LLM provider abstraction -- supports Claude, OpenAI, Gemini."""

from __future__ import annotations

import os
from typing import Protocol


class LLMProvider(Protocol):
    """Common interface for LLM providers."""

    def complete(self, system: str, user: str, max_tokens: int = 500) -> str: ...


class AnthropicProvider:
    """Claude via Anthropic API."""

    def __init__(self, model: str = "claude-sonnet-4-20250514"):
        import anthropic  # type: ignore[import-untyped]

        self.client = anthropic.Anthropic()
        self.model = model

    def complete(self, system: str, user: str, max_tokens: int = 500) -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=0,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return response.content[0].text.strip()


class OpenAIProvider:
    """GPT models via OpenAI API."""

    def __init__(self, model: str = "gpt-4o"):
        import openai  # type: ignore[import-untyped]

        self.client = openai.OpenAI()
        self.model = model

    def complete(self, system: str, user: str, max_tokens: int = 500) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=0,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return (response.choices[0].message.content or "").strip()


class GeminiProvider:
    """Gemini via Google Generative AI API."""

    def __init__(self, model: str = "gemini-2.0-flash"):
        import google.generativeai as genai  # type: ignore[import-untyped]

        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(model)

    def complete(self, system: str, user: str, max_tokens: int = 500) -> str:
        import google.generativeai as genai  # type: ignore[import-untyped]

        response = self.model.generate_content(
            f"{system}\n\n---\n\n{user}",
            generation_config=genai.GenerationConfig(
                max_output_tokens=max_tokens,
                temperature=0,
            ),
        )
        return (response.text or "").strip()


def detect_provider(
    provider: str | None = None,
    model: str | None = None,
) -> LLMProvider | None:
    """Auto-detect or explicitly select an LLM provider.

    Detection order: explicit flag > ANTHROPIC_API_KEY > OPENAI_API_KEY > GEMINI_API_KEY.
    Returns None if no provider is available.
    """
    if provider == "claude":
        return AnthropicProvider(model or "claude-sonnet-4-20250514")
    if provider == "openai":
        return OpenAIProvider(model or "gpt-4o")
    if provider == "gemini":
        return GeminiProvider(model or "gemini-2.0-flash")

    # Auto-detect from environment
    if os.environ.get("ANTHROPIC_API_KEY"):
        return AnthropicProvider(model or "claude-sonnet-4-20250514")
    if os.environ.get("OPENAI_API_KEY"):
        return OpenAIProvider(model or "gpt-4o")
    if os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
        return GeminiProvider(model or "gemini-2.0-flash")

    return None
