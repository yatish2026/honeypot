"""LLM Prompt Engineering Vulnerability & Red-Teaming Module."""

from modules.prompt_shield.hardening import (
    HARDENING_STRATEGIES,
    DEFAULT_VULNERABLE_PROMPTS,
    apply_hardening,
    auto_harden_prompt,
    calculate_hardening_score,
    generate_canary_token
)
