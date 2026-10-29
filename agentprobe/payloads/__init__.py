"""Isolated canary test cases. Each registry call creates fresh markers."""

from agentprobe.payloads.registry import build_registry, fuzz_values, poison_metadata

__all__ = ["build_registry", "fuzz_values", "poison_metadata"]
