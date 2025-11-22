"""
OpenSafety AI Corporation of America
Defensive AI Gateway with Split-Up Attack Detection

A high-performance API gateway that proxies requests to OpenRouter while
providing real-time threat detection for multi-stage split-up attacks.
"""

import json
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Optional

import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from detection.analyzer import (
    ThreatAnalyzer,
    ThreatAssessment,
)
from detection.tracker import (
    RequestTracker,
    TrackedRequest,
    create_request_id,
)
from models.openai_compat import (
    ChatCompletionChunk,
    ChatCompletionRequest,
    ChatCompletionResponse,
    Choice,
    ChoiceMessage,
    DeltaMessage,
    ErrorDetail,
    ErrorResponse,
    ModelInfo,
    ModelsResponse,
    StreamChoice,
    Usage,
)

load_dotenv()

# Backend Configuration
BACKEND_TYPE = os.getenv("BACKEND_TYPE", "vllm").lower()

# OpenRouter Configuration
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# vLLM Configuration
VLLM_BASE_URL = os.getenv("VLLM_BASE_URL", "http://localhost:8001/v1")
VLLM_API_KEY = os.getenv("VLLM_API_KEY", "")

# General Configuration
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "openai/gpt-4o-mini")
BLOCKING_ENABLED = os.getenv("BLOCKING_ENABLED", "false").lower() == "true"
BLOCKING_THRESHOLD = float(os.getenv("BLOCKING_THRESHOLD", "0.8"))


# Backend URL and Key Resolution
def get_backend_config():
    """Get backend URL and API key based on configured backend type."""
    if BACKEND_TYPE == "vllm":
        return VLLM_BASE_URL, VLLM_API_KEY
    elif BACKEND_TYPE == "openrouter":
        return OPENROUTER_BASE_URL, OPENROUTER_API_KEY
    else:
        raise ValueError(f"Unsupported backend type: {BACKEND_TYPE}")


# Global instances
request_tracker: Optional[RequestTracker] = None
threat_analyzer: Optional[ThreatAnalyzer] = None
http_client: Optional[httpx.AsyncClient] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle."""
    global request_tracker, threat_analyzer, http_client

    # Startup
    request_tracker = RequestTracker(
        window_size_seconds=600,  # 10 minute tracking window
        max_requests_per_key=5000,
    )
    threat_analyzer = ThreatAnalyzer(
        tracker=request_tracker,
        blocking_enabled=BLOCKING_ENABLED,
        blocking_threshold=BLOCKING_THRESHOLD,
    )
    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(120.0, connect=10.0),
        limits=httpx.Limits(max_connections=1000, max_keepalive_connections=100),
    )

    yield

    # Shutdown
    if http_client:
        await http_client.aclose()
    if request_tracker:
        request_tracker.shutdown()


app = FastAPI(
    title="OpenSafety AI Corporation of America",
    description="Defensive AI Gateway with Split-Up Attack Detection. "
    "Proxies requests to OpenRouter while detecting multi-stage cyberattacks.",
    version="0.3.0",
    lifespan=lifespan,
)

# CORS middleware for broad compatibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Dependency Injection
# ============================================================================


def get_client_ip(request: Request) -> str:
    """Extract client IP, respecting proxy headers."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def get_api_key(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Optional[str]:
    """Extract API key from headers."""
    if authorization and authorization.startswith("Bearer "):
        return authorization[7:]
    return x_api_key


# ============================================================================
# Health & Info Endpoints
# ============================================================================


@app.get("/")
async def root():
    """Root endpoint with service info."""
    return {
        "service": "OpenSafety AI Corporation of America",
        "version": "0.3.0",
        "status": "operational",
        "endpoints": {
            "chat": "/v1/chat/completions",
            "models": "/v1/models",
            "health": "/health",
            "stats": "/stats",
            "threats": "/threats/recent",
        },
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    backend_url, backend_key = get_backend_config()
    return {
        "status": "healthy",
        "service": "opensafety-ai",
        "timestamp": int(time.time()),
        "backend_type": BACKEND_TYPE,
        "backend_configured": bool(backend_key),
        "backend_url": backend_url,
        "blocking_enabled": BLOCKING_ENABLED,
    }


@app.get("/stats")
async def get_stats():
    """Get service statistics."""
    if not threat_analyzer:
        raise HTTPException(status_code=503, detail="Service not initialized")

    return {
        "service": "opensafety-ai",
        "timestamp": int(time.time()),
        **threat_analyzer.get_stats(),
    }


# ============================================================================
# OpenAI-Compatible API Endpoints
# ============================================================================


@app.get("/v1/models", response_model=ModelsResponse)
async def list_models(api_key: Optional[str] = Depends(get_api_key)):
    """
    List available models from the configured backend.
    Mirrors OpenAI /v1/models endpoint.
    """
    if not http_client:
        raise HTTPException(status_code=503, detail="Service not initialized")

    backend_url, default_backend_key = get_backend_config()
    key = api_key or default_backend_key

    if not key and BACKEND_TYPE == "openrouter":
        raise HTTPException(status_code=401, detail="API key required")

    try:
        headers = {}
        if key:
            headers["Authorization"] = f"Bearer {key}"

        response = await http_client.get(
            f"{backend_url}/models",
            headers=headers,
        )
        response.raise_for_status()
        data = response.json()

        # Transform to our model format
        models = []
        for model in data.get("data", []):
            models.append(
                ModelInfo(
                    id=model.get("id", ""),
                    created=model.get("created", 0),
                    owned_by=model.get("owned_by", BACKEND_TYPE),
                    context_length=model.get("context_length"),
                    pricing=model.get("pricing"),
                )
            )

        return ModelsResponse(data=models)

    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=str(e))  # noqa: B904
    except Exception as e:
        raise HTTPException(  # noqa: B904
            status_code=502, detail=f"{BACKEND_TYPE.title()} error: {str(e)}"
        )


@app.post("/v1/chat/completions")
async def chat_completions(
    request_body: ChatCompletionRequest,
    request: Request,
    api_key: Optional[str] = Depends(get_api_key),
):
    """
    OpenAI-compatible chat completions endpoint.

    Proxies to the configured backend while performing real-time threat analysis.
    Detects split-up attacks, prompt injection, and coordinated campaigns.
    """
    if not http_client or not threat_analyzer:
        raise HTTPException(status_code=503, detail="Service not initialized")

    backend_url, default_backend_key = get_backend_config()
    key = api_key or default_backend_key

    if not key and BACKEND_TYPE == "openrouter":
        raise HTTPException(
            status_code=401,
            detail=f"API key required. Set {BACKEND_TYPE.upper()}_API_KEY or pass via Authorization header.",  # noqa: E501
        )

    request_id = create_request_id()
    client_ip = get_client_ip(request)
    start_time = time.time()

    # Create tracked request
    tracked = TrackedRequest(
        request_id=request_id,
        timestamp=start_time,
        client_ip=client_ip,
        user_id=request_body.user,
        model=request_body.model or DEFAULT_MODEL,
        message_count=len(request_body.messages),
        total_content_length=sum(
            len(str(m.content)) for m in request_body.messages if m.content
        ),
        has_system_prompt=any(m.role.value == "system" for m in request_body.messages),
        has_tools=bool(request_body.tools),
        tool_count=len(request_body.tools) if request_body.tools else 0,
    )

    # Convert messages to dict format for analysis
    messages_dict = [m.model_dump(exclude_none=True) for m in request_body.messages]

    # Perform threat analysis
    assessment = threat_analyzer.analyze(
        request=tracked,
        messages=messages_dict,
        api_key=key,
    )

    # Check if request should be blocked
    if threat_analyzer.should_block(assessment):
        tracked.was_blocked = True
        request_tracker.track(tracked)

        return JSONResponse(
            status_code=403,
            content=ErrorResponse(
                error=ErrorDetail(
                    message=f"Request blocked: {assessment.summary}",
                    type="threat_detected",
                    code="blocked_by_opensafety",
                    param=None,
                )
            ).model_dump(),
            headers={
                "X-OpenSafety-Request-ID": request_id,
                "X-OpenSafety-Threat-Score": str(assessment.threat_score),
                "X-OpenSafety-Threat-Level": assessment.threat_level.value,
            },
        )

    # Prepare request for OpenRouter
    openrouter_payload = request_body.model_dump(exclude_none=True)

    # Ensure model is set
    if not openrouter_payload.get("model"):
        openrouter_payload["model"] = DEFAULT_MODEL

    headers = {
        "Content-Type": "application/json",
    }

    if key:
        headers["Authorization"] = f"Bearer {key}"

    if BACKEND_TYPE == "openrouter":
        headers.update(
            {
                "HTTP-Referer": request.headers.get("referer", "https://opensafety.ai"),
                "X-Title": "OpenSafety AI Gateway",
            }
        )

    # Handle streaming vs non-streaming
    if request_body.stream:
        return StreamingResponse(
            stream_chat_completion(
                openrouter_payload,
                headers,
                request_id,
                assessment,
                tracked,
                start_time,
            ),
            media_type="text/event-stream",
            headers={
                "X-OpenSafety-Request-ID": request_id,
                "X-OpenSafety-Threat-Score": str(assessment.threat_score),
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
            },
        )
    else:
        return await non_streaming_completion(
            openrouter_payload,
            headers,
            request_id,
            assessment,
            tracked,
            start_time,
        )


async def stream_chat_completion(
    payload: dict[str, Any],
    headers: dict[str, str],
    request_id: str,
    assessment: ThreatAssessment,
    tracked: TrackedRequest,
    start_time: float,
):
    """Stream chat completion from OpenRouter with SSE."""
    completion_id = f"chatcmpl-{uuid.uuid4().hex}"
    created = int(time.time())
    model = payload.get("model", DEFAULT_MODEL)

    try:
        backend_url, _ = get_backend_config()
        async with http_client.stream(
            "POST",
            f"{backend_url}/chat/completions",
            json=payload,
            headers=headers,
        ) as response:
            if response.status_code != 200:
                error_body = await response.aread()
                error_msg = error_body.decode() if error_body else "Unknown error"
                yield f"data: {json.dumps({'error': error_msg})}\n\n"
                return

            async for line in response.aiter_lines():
                if not line:
                    continue

                if line.startswith("data: "):
                    data = line[6:]

                    if data == "[DONE]":
                        yield "data: [DONE]\n\n"
                        break

                    try:
                        chunk_data = json.loads(data)

                        # Transform to our format with security headers
                        chunk = ChatCompletionChunk(
                            id=completion_id,
                            created=created,
                            model=model,
                            choices=[
                                StreamChoice(
                                    index=c.get("index", 0),
                                    delta=DeltaMessage(
                                        role=c.get("delta", {}).get("role"),
                                        content=c.get("delta", {}).get("content"),
                                        tool_calls=c.get("delta", {}).get("tool_calls"),
                                    ),
                                    finish_reason=c.get("finish_reason"),
                                )
                                for c in chunk_data.get("choices", [])
                            ],
                        )

                        yield f"data: {chunk.model_dump_json()}\n\n"

                    except json.JSONDecodeError:
                        continue

    except Exception as e:
        yield f"data: {json.dumps({'error': str(e)})}\n\n"

    finally:
        # Update tracked request
        tracked.response_time_ms = (time.time() - start_time) * 1000


async def non_streaming_completion(
    payload: dict[str, Any],
    headers: dict[str, str],
    request_id: str,
    assessment: ThreatAssessment,
    tracked: TrackedRequest,
    start_time: float,
) -> JSONResponse:
    """Handle non-streaming chat completion."""
    try:
        backend_url, _ = get_backend_config()
        response = await http_client.post(
            f"{backend_url}/chat/completions",
            json=payload,
            headers=headers,
        )

        elapsed_ms = (time.time() - start_time) * 1000
        tracked.response_time_ms = elapsed_ms

        if response.status_code != 200:
            error_data = (
                response.json() if response.content else {"error": "Unknown error"}
            )
            raise HTTPException(status_code=response.status_code, detail=error_data)

        data = response.json()

        # Transform response
        completion = ChatCompletionResponse(
            id=data.get("id", f"chatcmpl-{uuid.uuid4().hex}"),
            created=data.get("created", int(time.time())),
            model=data.get("model", payload.get("model")),
            choices=[
                Choice(
                    index=c.get("index", 0),
                    message=ChoiceMessage(
                        role="assistant",
                        content=c.get("message", {}).get("content"),
                        tool_calls=c.get("message", {}).get("tool_calls"),
                        function_call=c.get("message", {}).get("function_call"),
                    ),
                    finish_reason=c.get("finish_reason"),
                )
                for c in data.get("choices", [])
            ],
            usage=Usage(
                prompt_tokens=data.get("usage", {}).get("prompt_tokens", 0),
                completion_tokens=data.get("usage", {}).get("completion_tokens", 0),
                total_tokens=data.get("usage", {}).get("total_tokens", 0),
            ),
            x_opensafety_request_id=request_id,
            x_opensafety_threat_score=assessment.threat_score,
        )

        # Update tracked request with response info
        if completion.usage:
            tracked.response_tokens = completion.usage.completion_tokens

        return JSONResponse(
            content=completion.model_dump(exclude_none=True),
            headers={
                "X-OpenSafety-Request-ID": request_id,
                "X-OpenSafety-Threat-Score": str(assessment.threat_score),
                "X-OpenSafety-Threat-Level": assessment.threat_level.value,
                "X-Response-Time-Ms": str(int(elapsed_ms)),
            },
        )

    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=str(e))  # noqa: B904
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(  # noqa: B904
            status_code=502, detail=f"{BACKEND_TYPE.title()} error: {str(e)}"
        )


# ============================================================================
# Threat Monitoring Endpoints
# ============================================================================


class ThreatReportResponse(BaseModel):
    """Response model for threat reports."""

    request_id: str
    timestamp: float
    threat_score: float
    threat_level: str
    client_ip: str
    patterns: list[str]
    model: str


@app.get("/threats/recent")
async def get_recent_threats(
    min_score: float = 0.3,
    limit: int = 100,
):
    """Get recent requests with threat scores above threshold."""
    if not request_tracker:
        raise HTTPException(status_code=503, detail="Service not initialized")

    recent = request_tracker.get_recent_requests(window_seconds=3600, limit=1000)

    threats = [
        ThreatReportResponse(
            request_id=r.request_id,
            timestamp=r.timestamp,
            threat_score=r.threat_score,
            threat_level=threat_analyzer._score_to_level(r.threat_score).value
            if threat_analyzer
            else "unknown",
            client_ip=r.client_ip[:8] + "..."
            if len(r.client_ip) > 8
            else r.client_ip,  # Partial IP for privacy
            patterns=r.detected_patterns,
            model=r.model,
        )
        for r in recent
        if r.threat_score >= min_score
    ]

    # Sort by threat score descending
    threats.sort(key=lambda t: t.threat_score, reverse=True)

    return {
        "threats": [t.model_dump() for t in threats[:limit]],
        "total_count": len(threats),
        "time_window_seconds": 3600,
        "min_score_filter": min_score,
    }


@app.get("/threats/campaigns")
async def get_active_campaigns():
    """Get potentially coordinated attack campaigns."""
    if not request_tracker:
        raise HTTPException(status_code=503, detail="Service not initialized")

    # Find content hashes with multiple unique IPs
    recent = request_tracker.get_recent_requests(window_seconds=3600, limit=5000)

    # Group by content hash
    content_groups: dict[str, list[TrackedRequest]] = {}
    for r in recent:
        if r.content_hash:
            if r.content_hash not in content_groups:
                content_groups[r.content_hash] = []
            content_groups[r.content_hash].append(r)

    # Find campaigns (same content from multiple IPs)
    campaigns = []
    for content_hash, requests in content_groups.items():
        unique_ips = set(r.client_ip for r in requests)
        if len(unique_ips) >= 3:
            campaigns.append(
                {
                    "content_hash": content_hash[:12] + "...",
                    "unique_sources": len(unique_ips),
                    "total_requests": len(requests),
                    "avg_threat_score": sum(r.threat_score for r in requests)
                    / len(requests),
                    "first_seen": min(r.timestamp for r in requests),
                    "last_seen": max(r.timestamp for r in requests),
                }
            )

    campaigns.sort(key=lambda c: c["unique_sources"], reverse=True)

    return {
        "active_campaigns": campaigns[:20],
        "campaign_count": len(campaigns),
    }


@app.post("/threats/analyze")
async def analyze_content(
    content: dict[str, Any],
    request: Request,
):
    """
    Analyze arbitrary content for threats without proxying.
    Useful for testing and integration.
    """
    if not threat_analyzer:
        raise HTTPException(status_code=503, detail="Service not initialized")

    messages = content.get("messages", [])
    if not messages:
        raise HTTPException(status_code=400, detail="messages field required")

    tracked = TrackedRequest(
        request_id=create_request_id(),
        timestamp=time.time(),
        client_ip=get_client_ip(request),
        message_count=len(messages),
    )

    assessment = threat_analyzer.analyze(tracked, messages)

    return {
        "request_id": tracked.request_id,
        "threat_score": assessment.threat_score,
        "threat_level": assessment.threat_level.value,
        "recommended_action": assessment.recommended_action.value,
        "would_block": threat_analyzer.should_block(assessment),
        "summary": assessment.summary,
        "signals": [
            {
                "name": s.name,
                "score": s.score,
                "description": s.description,
                "category": s.category,
            }
            for s in assessment.signals
        ],
        "patterns": [
            {
                "type": p.pattern_type.value,
                "confidence": p.confidence,
                "severity": p.severity,
                "description": p.description,
                "evidence": p.evidence[:3],
            }
            for p in assessment.patterns
        ],
    }


# ============================================================================
# Fingerprinting Endpoints
# ============================================================================


class FingerprintRequest(BaseModel):
    """Request for content fingerprinting."""

    content: str
    find_similar: bool = True
    min_similarity: float = 0.7


class FingerprintResponse(BaseModel):
    """Response with fingerprint details."""

    exact_hash: str
    structure_hash: str
    semantic_hash: str
    content_type: str
    length: int
    entropy: float
    code_ratio: float
    keywords: list[str]
    entities: list[str]
    language_indicators: list[str]
    similar_matches: list[dict[str, Any]] = []


@app.post("/fingerprint", response_model=FingerprintResponse)
async def fingerprint_content(request_body: FingerprintRequest):
    """
    Generate advanced fingerprint for content.
    Useful for testing similarity detection and understanding content characteristics.
    """
    if not threat_analyzer or not threat_analyzer.fingerprinter:
        raise HTTPException(status_code=503, detail="Fingerprinting not available")

    fp = threat_analyzer.fingerprinter.fingerprint(request_body.content)

    similar_matches = []
    if request_body.find_similar:
        matches = threat_analyzer.fingerprinter.find_similar(
            fp,
            min_similarity=request_body.min_similarity,
            max_results=10,
        )
        similar_matches = [
            {
                "fingerprint": m.fingerprint_b[:12] + "...",
                "similarity": m.similarity_score,
                "match_type": m.match_type,
                "features": m.matching_features,
            }
            for m in matches
        ]

    return FingerprintResponse(
        exact_hash=fp.exact_hash,
        structure_hash=fp.structure_hash,
        semantic_hash=fp.semantic_hash,
        content_type=fp.content_type.value,
        length=fp.length,
        entropy=fp.entropy,
        code_ratio=fp.code_ratio,
        keywords=fp.keywords[:20],
        entities=fp.entities[:10],
        language_indicators=fp.language_indicators,
        similar_matches=similar_matches,
    )


@app.post("/fingerprint/compare")
async def compare_fingerprints(
    content_a: str,
    content_b: str,
):
    """
    Compare two pieces of content and return similarity metrics.
    """
    if not threat_analyzer or not threat_analyzer.fingerprinter:
        raise HTTPException(status_code=503, detail="Fingerprinting not available")

    fp_a = threat_analyzer.fingerprinter.fingerprint(content_a)
    fp_b = threat_analyzer.fingerprinter.fingerprint(content_b)

    # Compute similarities
    minhash_sim = threat_analyzer.fingerprinter._minhash_similarity(
        fp_a.minhash_signature, fp_b.minhash_signature
    )
    simhash_sim = threat_analyzer.fingerprinter._simhash_similarity(
        fp_a.simhash, fp_b.simhash
    )

    structural_match = fp_a.structure_hash == fp_b.structure_hash
    semantic_match = fp_a.semantic_hash == fp_b.semantic_hash

    # Overall similarity
    overall = (
        minhash_sim * 0.4
        + simhash_sim * 0.3
        + (1.0 if structural_match else 0.0) * 0.15
        + (1.0 if semantic_match else 0.0) * 0.15
    )

    return {
        "content_a": {
            "hash": fp_a.exact_hash,
            "length": fp_a.length,
            "type": fp_a.content_type.value,
        },
        "content_b": {
            "hash": fp_b.exact_hash,
            "length": fp_b.length,
            "type": fp_b.content_type.value,
        },
        "similarity": {
            "overall": overall,
            "minhash_jaccard": minhash_sim,
            "simhash_hamming": simhash_sim,
            "structural_match": structural_match,
            "semantic_match": semantic_match,
        },
        "is_similar": overall >= 0.7,
        "is_duplicate": overall >= 0.95,
    }


@app.get("/fingerprint/stats")
async def fingerprint_stats():
    """Get fingerprinting system statistics."""
    if not threat_analyzer or not threat_analyzer.fingerprinter:
        raise HTTPException(status_code=503, detail="Fingerprinting not available")

    return {
        "fingerprinting_enabled": True,
        **threat_analyzer.fingerprinter.get_stats(),
        "cached_recent": len(threat_analyzer._recent_fingerprints),
    }


# ============================================================================
# Legacy Utility Endpoints (from template)
# ============================================================================


@app.get("/demo")
async def demo():
    """Demo endpoint showing service capabilities."""
    return {
        "message": "OpenSafety AI Corporation of America",
        "capabilities": [
            "OpenAI-compatible chat completions API",
            "Real-time split-up attack detection",
            "Prompt injection detection",
            "Coordinated campaign detection",
            "Request rate analysis",
            "Fragment assembly detection",
            "Advanced content fingerprinting (MinHash, SimHash, LSH)",
            "Semantic similarity detection",
            "Near-duplicate content detection",
            "Structural pattern analysis",
            "High-entropy content detection",
            "Entity extraction (URLs, IPs, API keys)",
        ],
        "detection_methods": {
            "pattern_matching": "Regex-based injection/jailbreak detection",
            "behavioral_analysis": "Rate limiting and burst detection",
            "fingerprint_similarity": "MinHash Jaccard similarity + SimHash hamming distance",  # noqa: E501
            "semantic_clustering": "Keyword-based semantic hashing",
            "campaign_detection": "Cross-IP content correlation",
        },
        "status": "operational",
        "backend_type": BACKEND_TYPE,
        "backend_configured": bool(get_backend_config()[1]),
        "blocking_mode": BLOCKING_ENABLED,
    }


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        workers=1,  # Use 1 for development, increase for production
    )
