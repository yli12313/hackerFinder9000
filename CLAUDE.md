# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenSafety AI is a defensive AI gateway that proxies requests to LLM backends (OpenRouter or vLLM) while providing real-time threat detection for multi-stage "split-up" attacks. It implements an OpenAI-compatible API (`/v1/chat/completions`, `/v1/models`).

## Common Commands

```bash
# Install dependencies
uv sync --all-groups

# Run the server (development)
uv run python src/main.py

# Run tests
uv run --group test pytest

# Run a single test
uv run --group test pytest tests/test_my_math.py::TestSomeFunction::test_some_function_zero

# Lint and format (via pre-commit)
uv run pre-commit run --all-files

# Lint only
uv run --group test ruff check .

# Format only
uv run --group test ruff format .
```

## Architecture

### Core Components

**`src/main.py`** - FastAPI application entry point
- OpenAI-compatible API endpoints (`/v1/chat/completions`, `/v1/models`)
- Threat monitoring endpoints (`/threats/recent`, `/threats/campaigns`, `/threats/analyze`)
- Content fingerprinting endpoints (`/fingerprint`, `/fingerprint/compare`)
- Manages global instances: `request_tracker`, `threat_analyzer`, `http_client`

**`src/detection/`** - Threat detection engine
- `analyzer.py` - `ThreatAnalyzer`: Main analysis engine combining pattern matching, behavioral analysis, fingerprinting, and historical correlation. Produces `ThreatAssessment` with threat score, level, and recommended action.
- `tracker.py` - `RequestTracker`: High-performance request tracker with sliding windows indexed by IP, user, API key, content hash, and system prompt hash. Thread-safe with background cleanup.
- `patterns.py` - `SplitAttackDetector`: Pattern-based detection using regex for injection, exfiltration, jailbreak, and code patterns. Detects temporal and campaign patterns.
- `fingerprint.py` - `AdvancedFingerprinter`: Content fingerprinting using MinHash, SimHash, and LSH for similarity detection.

**`src/models/openai_compat.py`** - Pydantic models for OpenAI API compatibility

### Detection Flow

1. Request arrives at `/v1/chat/completions`
2. `TrackedRequest` created with metadata (IP, user, model, message count)
3. `ThreatAnalyzer.analyze()` runs pattern detection, behavioral analysis, fingerprinting
4. If `should_block()` returns true (based on score and threshold), request is rejected with 403
5. Otherwise, request is proxied to configured backend (vLLM or OpenRouter)
6. Request is tracked for future correlation

### Environment Variables

- `BACKEND_TYPE`: `vllm` (default) or `openrouter`
- `VLLM_BASE_URL`: vLLM server URL (default: `http://localhost:8001/v1`)
- `OPENROUTER_API_KEY`: API key for OpenRouter backend
- `BLOCKING_ENABLED`: Enable request blocking (default: `false`, monitoring mode)
- `BLOCKING_THRESHOLD`: Threat score threshold for blocking (default: `0.8`)

## Conventions

- Uses `uv` for dependency management
- Follows conventional commits (commitizen configured)
- Pre-commit hooks run ruff (lint + format) and pytest
- Python 3.12+ required
