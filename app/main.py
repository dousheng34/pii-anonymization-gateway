import os
import time
import datetime
import hashlib
import json
import logging
import collections
import re
from typing import Dict, List, Optional
import httpx
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.services.pii_engine import (
    anonymize_messages, 
    restore_text, 
    get_synthetic_value, 
    SYNTHETIC_POOLS
)
from app.services.session_store import store_manager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pii_gateway.main")

app = FastAPI(
    title="Reversible PII Anonymization Gateway",
    version="1.0.0"
)

# CORS middleware for standard client compatibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ephemeral in-memory statistics buffers
AUDIT_LOG_BUFFER = collections.deque(maxlen=100)
TOTAL_REDACTED_COUNT = 0
SYSTEM_LATENCIES = collections.deque(maxlen=100)

def log_transaction(
    prompt_text: str, 
    duration_ms: float, 
    redacted_count: int, 
    redacted_types: List[str], 
    mode: str, 
    status_code: int
):
    """Logs transaction metadata to stdout using the Metadata-only Audit Pattern."""
    global TOTAL_REDACTED_COUNT
    prompt_hash = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()
    
    # Standard risk score calculation based on entity types
    weights = {
        "SSN": 1.0,
        "CREDIT_CARD": 1.0,
        "API_KEY": 1.0,
        "EMAIL": 0.9,
        "PHONE": 0.8,
        "IP": 0.7,
        "PERSON": 0.6,
        "LOCATION": 0.3
    }
    risk_score = max((weights.get(t, 0.5) for t in redacted_types), default=0.0)
    
    log_record = {
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat() + "Z",
        "prompt_hash": prompt_hash,
        "duration_ms": round(duration_ms, 2),
        "redacted_count": redacted_count,
        "redacted_types": redacted_types,
        "risk_score": risk_score,
        "mode": mode,
        "status_code": status_code
    }
    
    # Print to stdout in raw JSON format
    print(json.dumps(log_record), flush=True)
    
    # Store in memory for dashboard visualization
    AUDIT_LOG_BUFFER.append(log_record)
    TOTAL_REDACTED_COUNT += redacted_count
    SYSTEM_LATENCIES.append(duration_ms)

def get_hold_back_len(buffer: str, placeholders: List[str]) -> int:
    """Finds if the end of the stream buffer matches a prefix of an active token or name to hold back."""
    if not buffer or not placeholders:
        return 0
    
    max_len = max(len(p) for p in placeholders)
    buffer_suffix_limit = min(len(buffer), max_len)
    
    for i in range(buffer_suffix_limit, 0, -1):
        suffix = buffer[-i:]
        for p in placeholders:
            if p.startswith(suffix) and len(suffix) < len(p):
                return i
    return 0

async def stream_proxy_generator(lines_iterable, mappings: Dict[str, str]):
    """JSON-safe SSE Streaming proxy parser and token reconstruction buffer."""
    buffer = ""
    placeholders = list(mappings.keys())
    
    async for line in lines_iterable:
        if not line:
            yield b"\n"
            continue
            
        if line.startswith("data: "):
            data_content = line[6:].strip()
            
            if data_content == "[DONE]":
                if buffer:
                    restored = restore_text(buffer, mappings)
                    flush_chunk = {
                        "choices": [{
                            "index": 0,
                            "delta": {"content": restored},
                            "finish_reason": None
                        }]
                    }
                    yield f"data: {json.dumps(flush_chunk)}\n\n".encode("utf-8")
                    buffer = ""
                yield b"data: [DONE]\n\n"
                continue
                
            try:
                chunk_json = json.loads(data_content)
                choices = chunk_json.get("choices", [])
                if not choices:
                    yield f"data: {data_content}\n\n".encode("utf-8")
                    continue
                    
                choice = choices[0]
                delta = choice.get("delta", {})
                delta_text = delta.get("content", "")
                
                if delta_text:
                    buffer += delta_text
                    hold_len = get_hold_back_len(buffer, placeholders)
                    
                    if hold_len > 0:
                        process_text = buffer[:-hold_len]
                        buffer = buffer[-hold_len:]
                    else:
                        process_text = buffer
                        buffer = ""
                        
                    if process_text:
                        restored_text = restore_text(process_text, mappings)
                        choice["delta"]["content"] = restored_text
                        yield f"data: {json.dumps(chunk_json)}\n\n".encode("utf-8")
                else:
                    finish_reason = choice.get("finish_reason")
                    if finish_reason is not None and buffer:
                        restored = restore_text(buffer, mappings)
                        choice["delta"]["content"] = restored
                        buffer = ""
                    yield f"data: {json.dumps(chunk_json)}\n\n".encode("utf-8")
            except Exception as e:
                logger.error(f"Error parsing SSE chunk: {e}, Line: {line}")
                yield f"{line}\n\n".encode("utf-8")
        else:
            yield f"{line}\n".encode("utf-8")

def generate_mock_response_content(anonymized_messages: List[Dict]) -> str:
    """Generates mock response highlighting anonymized PII tokens or synthetic data."""
    last_content = ""
    if anonymized_messages:
        last_content = anonymized_messages[-1].get("content", "")
        
    placeholders = re.findall(r"\{\{[A-Z_]+_\d+\}\}", last_content)
    
    if placeholders:
        p_str = ", ".join(placeholders)
        return (
            f"Hello! I am OpenAI's secure mock LLM model. I successfully received your anonymized message. "
            f"The proxy cleaned your input and I only saw these PII tokens: {p_str}. "
            f"How can I assist you further today?"
        )
    else:
        # Check for synthetic matches
        found_syns = []
        for pool in SYNTHETIC_POOLS.values():
            for val in pool:
                if val in last_content:
                    found_syns.append(val)
        if found_syns:
            s_str = ", ".join(list(set(found_syns)))
            return (
                f"Hello! I am OpenAI's secure mock LLM model. I received your request with synthetic substitutes: {s_str}. "
                f"The original private identities were never exposed to me. "
                f"What is your next request?"
            )
            
    return (
        "Hello! I am OpenAI's secure mock LLM model. No PII tokens were detected in your prompt. "
        "How can I help you today?"
    )

async def mock_stream_generator(content: str):
    """Simulates OpenAI streaming delta events for mock testing."""
    import asyncio
    words = content.split(" ")
    chunk_id = "chatcmpl-mock" + str(int(time.time()))
    
    # 1. Role initiator
    init_chunk = {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": "mock-gpt-4",
        "choices": [{
            "index": 0,
            "delta": {"role": "assistant", "content": ""},
            "logprobs": None,
            "finish_reason": None
        }]
    }
    yield f"data: {json.dumps(init_chunk)}\n\n"
    await asyncio.sleep(0.05)
    
    # 2. Text tokens
    for i, word in enumerate(words):
        space = " " if i > 0 else ""
        chunk = {
            "id": chunk_id,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": "mock-gpt-4",
            "choices": [{
                "index": 0,
                "delta": {"content": space + word},
                "logprobs": None,
                "finish_reason": None
            }]
        }
        yield f"data: {json.dumps(chunk)}\n\n"
        await asyncio.sleep(0.03)
        
    # 3. Stop frame
    final_chunk = {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": "mock-gpt-4",
        "choices": [{
            "index": 0,
            "delta": {},
            "logprobs": None,
            "finish_reason": "stop"
        }]
    }
    yield f"data: {json.dumps(final_chunk)}\n\n"
    yield "data: [DONE]\n\n"

async def mock_lines_generator(content: str):
    """Generates mock line events to simulate response.aiter_lines() for testing."""
    async for chunk in mock_stream_generator(content):
        for line in chunk.split("\n"):
            yield line

async def get_raw_llm_completion(messages: List[Dict]) -> str:
    """Direct raw completion call to upstream OpenAI/LLM without restoration (for playground)."""
    if not settings.OPENAI_API_KEY:
        return generate_mock_response_content(messages)
        
    headers = {
        "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }
    url = f"{settings.TARGET_LLM_URL.rstrip('/')}/v1/chat/completions"
    
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                url,
                json={"model": "gpt-4o-mini", "messages": messages, "stream": False},
                headers=headers,
                timeout=30.0
            )
            if resp.status_code == 200:
                resp_json = resp.json()
                return resp_json["choices"][0]["message"]["content"]
            else:
                return f"Upstream error (HTTP {resp.status_code}): {resp.text}"
        except Exception as e:
            return f"Upstream connection failed: {str(e)}"

# --- FastAPI Endpoints ---

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """OpenAI-compatible proxy endpoint."""
    start_time = time.time()
    
    # 1. Parse headers
    redact_mode = request.headers.get("X-Redact-Mode", "mask").lower()
    if redact_mode not in ("mask", "synthetic"):
        redact_mode = "mask"
        
    session_id = request.headers.get("X-Session-ID", "")
    request_id = f"req_{hashlib.md5(str(start_time).encode()).hexdigest()[:8]}"
    
    session_key = f"session:{session_id}" if session_id else f"request:{request_id}"
    
    # 2. Parse payload
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
        
    messages = body.get("messages", [])
    if not messages:
        raise HTTPException(status_code=400, detail="messages field is required")
        
    stream = body.get("stream", False)
    
    # 3. Anonymize input payload
    anonymized_messages, mappings, redacted_count = anonymize_messages(messages, mode=redact_mode)
    
    # 4. Save mapping in Session Store
    store_manager.save_session_mapping(session_key, mappings, ttl=300)
    
    # 5. Build forwarding request body
    forward_body = dict(body)
    forward_body["messages"] = anonymized_messages
    
    # Prepare logs metadata
    prompt_text = "\n".join(msg.get("content", "") for msg in messages if isinstance(msg.get("content"), str))
    
    # Find redacted types from mapping keys
    redacted_types = []
    for k in mappings.keys():
        if k.startswith("{{") and k.endswith("}}"):
            t = k.split("_")[0].replace("{", "").replace("}", "")
            redacted_types.append(t)
        else:
            matched = False
            for pool_type, pool_vals in SYNTHETIC_POOLS.items():
                if any(k.startswith(val) for val in pool_vals):
                    redacted_types.append(pool_type)
                    matched = True
                    break
            if not matched:
                redacted_types.append("OTHER")
    redacted_types = list(set(redacted_types))
    
    is_mock = False
    if not settings.OPENAI_API_KEY and "Authorization" not in request.headers:
        is_mock = True
        
    if is_mock:
        # Mock Completion Mode
        mock_content = generate_mock_response_content(anonymized_messages)
        
        if stream:
            async def wrapped_mock_generator():
                async for chunk in stream_proxy_generator(mock_lines_generator(mock_content), mappings):
                    yield chunk
                duration_ms = (time.time() - start_time) * 1000
                log_transaction(
                    prompt_text=prompt_text,
                    duration_ms=duration_ms,
                    redacted_count=redacted_count,
                    redacted_types=redacted_types,
                    mode=redact_mode,
                    status_code=200
                )
            return StreamingResponse(wrapped_mock_generator(), media_type="text/event-stream")
        else:
            duration_ms = (time.time() - start_time) * 1000
            restored_content = restore_text(mock_content, mappings)
            
            response_json = {
                "id": "chatcmpl-mock" + str(int(time.time())),
                "object": "chat.completion",
                "created": int(time.time()),
                "model": "mock-gpt-4",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": restored_content
                    },
                    "logprobs": None,
                    "finish_reason": "stop"
                }],
                "usage": {
                    "prompt_tokens": len(prompt_text) // 4,
                    "completion_tokens": len(restored_content) // 4,
                    "total_tokens": (len(prompt_text) + len(restored_content)) // 4
                }
            }
            
            log_transaction(
                prompt_text=prompt_text,
                duration_ms=duration_ms,
                redacted_count=redacted_count,
                redacted_types=redacted_types,
                mode=redact_mode,
                status_code=200
            )
            return response_json
            
    else:
        # Real upstream proxy mode
        headers = {}
        if "Authorization" in request.headers:
            headers["Authorization"] = request.headers["Authorization"]
        elif settings.OPENAI_API_KEY:
            headers["Authorization"] = f"Bearer {settings.OPENAI_API_KEY}"
            
        headers["Content-Type"] = "application/json"
        
        client = httpx.AsyncClient()
        url = f"{settings.TARGET_LLM_URL.rstrip('/')}/v1/chat/completions"
        
        try:
            if stream:
                req = client.build_request("POST", url, json=forward_body, headers=headers, timeout=60.0)
                resp = await client.send(req, stream=True)
                
                if resp.status_code != 200:
                    await resp.aclose()
                    await client.aclose()
                    raise HTTPException(status_code=resp.status_code, detail=f"Upstream returned HTTP {resp.status_code}")
                    
                async def wrapped_stream_generator():
                    try:
                        async for chunk in stream_proxy_generator(resp.aiter_lines(), mappings):
                            yield chunk
                    finally:
                        await resp.aclose()
                        await client.aclose()
                        duration_ms = (time.time() - start_time) * 1000
                        log_transaction(
                            prompt_text=prompt_text,
                            duration_ms=duration_ms,
                            redacted_count=redacted_count,
                            redacted_types=redacted_types,
                            mode=redact_mode,
                            status_code=200
                        )
                return StreamingResponse(wrapped_stream_generator(), media_type="text/event-stream")
                
            else:
                resp = await client.post(url, json=forward_body, headers=headers, timeout=60.0)
                await client.aclose()
                
                duration_ms = (time.time() - start_time) * 1000
                log_transaction(
                    prompt_text=prompt_text,
                    duration_ms=duration_ms,
                    redacted_count=redacted_count,
                    redacted_types=redacted_types,
                    mode=redact_mode,
                    status_code=resp.status_code
                )
                
                if resp.status_code != 200:
                    return Response(content=resp.content, status_code=resp.status_code, headers=dict(resp.headers))
                    
                resp_json = resp.json()
                choices = resp_json.get("choices", [])
                if choices:
                    choice = choices[0]
                    message = choice.get("message", {})
                    content = message.get("content", "")
                    if content:
                        message["content"] = restore_text(content, mappings)
                return resp_json
                
        except Exception as e:
            await client.aclose()
            logger.error(f"Proxy request failed: {e}")
            raise HTTPException(status_code=500, detail=f"PII Proxy network error: {str(e)}")

@app.post("/api/playground/test")
async def playground_test(request: Request):
    """Dedicated endpoint to demonstrate the 4 stages of the proxy flow in the dashboard."""
    try:
        body = await request.json()
        prompt = body.get("prompt", "")
        mode = body.get("mode", "mask").lower()
        if mode not in ("mask", "synthetic"):
            mode = "mask"
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
        
    messages = [{"role": "user", "content": prompt}]
    
    # Stage 1 & 2: Anonymize
    anon_messages, mappings, redacted_count = anonymize_messages(messages, mode=mode)
    anonymized_prompt = anon_messages[0]["content"]
    
    # Stage 3: Raw response (no restoration)
    raw_response = await get_raw_llm_completion(anon_messages)
    
    # Stage 4: Restored response
    restored_response = restore_text(raw_response, mappings)
    
    return {
        "cleartext": prompt,
        "anonymized": anonymized_prompt,
        "raw_response": raw_response,
        "restored_response": restored_response
    }

@app.get("/api/stats")
async def get_stats():
    """Exposes statistics, Redis status, and logs buffer to the dashboard."""
    # Check redis connection status
    redis_healthy = store_manager.is_healthy()
    redis_status_text = "Connected" if redis_healthy else "Local Memory Fallback"
    
    avg_latency = 0.0
    if SYSTEM_LATENCIES:
        avg_latency = sum(SYSTEM_LATENCIES) / len(SYSTEM_LATENCIES)
        
    active_sessions = 0
    if redis_healthy and store_manager.redis_client:
        try:
            # Estimate active keys
            active_sessions = len(store_manager.redis_client.keys("session:*") + store_manager.redis_client.keys("request:*"))
        except Exception:
            active_sessions = store_manager.in_memory_store.get_stats()["active_sessions"]
    else:
        active_sessions = store_manager.in_memory_store.get_stats()["active_sessions"]
        
    return {
        "redis_healthy": redis_healthy,
        "redis_status_text": redis_status_text,
        "average_latency_ms": round(avg_latency, 2),
        "total_redacted_count": TOTAL_REDACTED_COUNT,
        "active_sessions_count": active_sessions,
        "audit_logs": list(reversed(AUDIT_LOG_BUFFER))
    }

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """Serves the Single Page HTML / Tailwind CSS dashboard."""
    return HTML_DASHBOARD_TEMPLATE

# --- Live HTML / Tailwind Dashboard Template ---
HTML_DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ PII Anonymization Gateway Dashboard</title>
    <!-- Tailwind CSS v3 CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- Chart.js CDN -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap');
        body {
            font-family: 'Outfit', sans-serif;
            background-color: #0b0f19;
        }
        .glass-card {
            background: rgba(17, 24, 39, 0.7);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.08);
        }
        .glow-border-green {
            box-shadow: 0 0 15px rgba(16, 185, 129, 0.15);
            border: 1px solid rgba(16, 185, 129, 0.3);
        }
        .glow-border-amber {
            box-shadow: 0 0 15px rgba(245, 158, 11, 0.15);
            border: 1px solid rgba(245, 158, 11, 0.3);
        }
    </style>
</head>
<body class="text-gray-100 min-h-screen pb-12">
    <!-- Top Nav -->
    <nav class="border-b border-gray-800 bg-gray-950/80 backdrop-blur-md sticky top-0 z-50">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
            <div class="flex items-center space-x-3">
                <span class="text-2xl">🛡️</span>
                <div>
                    <h1 class="font-bold text-lg leading-tight text-white tracking-wide">PII Gateway</h1>
                    <p class="text-xs text-emerald-400 font-semibold tracking-wider uppercase">OpenAI Security Proxy</p>
                </div>
            </div>
            
            <div class="flex items-center space-x-4">
                <div id="status-badge" class="px-3 py-1.5 rounded-full text-xs font-semibold flex items-center space-x-2 transition-all duration-300">
                    <span class="h-2 w-2 rounded-full animate-pulse bg-current"></span>
                    <span id="status-text">Checking System...</span>
                </div>
            </div>
        </div>
    </nav>

    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mt-8 space-y-8">
        <!-- Stats Cards Grid -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div class="glass-card rounded-2xl p-6 relative overflow-hidden">
                <div class="absolute -right-4 -bottom-4 opacity-5 text-6xl font-bold">SYS</div>
                <p class="text-sm font-medium text-gray-400 uppercase tracking-wider">Gateway Mode</p>
                <p class="text-3xl font-bold text-indigo-400 mt-2">LLM Proxy</p>
                <div class="text-xs text-gray-500 mt-2 flex items-center space-x-1">
                    <span>Target:</span>
                    <span class="text-gray-300 truncate" id="target-url-label">https://api.openai.com</span>
                </div>
            </div>

            <div class="glass-card rounded-2xl p-6 relative overflow-hidden">
                <div class="absolute -right-4 -bottom-4 opacity-5 text-6xl font-bold">LAT</div>
                <p class="text-sm font-medium text-gray-400 uppercase tracking-wider">Avg Latency</p>
                <p class="text-3xl font-bold text-emerald-400 mt-2" id="avg-latency">0 ms</p>
                <div class="text-xs text-gray-500 mt-2">Based on last 100 requests</div>
            </div>

            <div class="glass-card rounded-2xl p-6 relative overflow-hidden">
                <div class="absolute -right-4 -bottom-4 opacity-5 text-6xl font-bold">RED</div>
                <p class="text-sm font-medium text-gray-400 uppercase tracking-wider">Total Redacted</p>
                <p class="text-3xl font-bold text-pink-400 mt-2" id="total-redacted">0</p>
                <div class="text-xs text-gray-500 mt-2">Cumulative entities cleaned</div>
            </div>

            <div class="glass-card rounded-2xl p-6 relative overflow-hidden">
                <div class="absolute -right-4 -bottom-4 opacity-5 text-6xl font-bold">SES</div>
                <p class="text-sm font-medium text-gray-400 uppercase tracking-wider">Active Cache Keys</p>
                <p class="text-3xl font-bold text-yellow-400 mt-2" id="active-sessions">0</p>
                <div class="text-xs text-gray-500 mt-2">TTL: 300 seconds limit</div>
            </div>
        </div>

        <!-- Charts and Audit Logs Grid -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <!-- Left Side: Charts -->
            <div class="lg:col-span-2 space-y-8">
                <!-- Latency and Risk Charts -->
                <div class="glass-card rounded-2xl p-6">
                    <h2 class="text-lg font-bold text-white mb-4 flex items-center space-x-2">
                        <span>📈</span>
                        <span>Performance & Risk Metrics</span>
                    </h2>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6 h-64">
                        <div class="relative h-full">
                            <canvas id="latencyChart"></canvas>
                        </div>
                        <div class="relative h-full">
                            <canvas id="riskChart"></canvas>
                        </div>
                    </div>
                </div>

                <!-- Doughnut Chart & Status -->
                <div class="glass-card rounded-2xl p-6">
                    <h3 class="text-md font-bold text-white mb-4">Anonymized Entity Distribution</h3>
                    <div class="w-full flex justify-center h-48">
                        <canvas id="entityChart"></canvas>
                    </div>
                </div>
            </div>

            <!-- Right Side: Live Logs -->
            <div class="glass-card rounded-2xl p-6 flex flex-col max-h-[600px]">
                <div class="flex items-center justify-between mb-4 border-b border-gray-800 pb-3">
                    <h2 class="text-lg font-bold text-white flex items-center space-x-2">
                        <span class="relative flex h-2 w-2">
                            <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                            <span class="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                        </span>
                        <span>Audit Log Feed</span>
                    </h2>
                    <span class="text-xs text-gray-400 uppercase tracking-wider">Metadata-only</span>
                </div>
                <div id="logs-feed" class="overflow-y-auto space-y-3 flex-grow pr-1">
                    <p class="text-center text-sm text-gray-500 my-auto py-8">Waiting for gateway requests...</p>
                </div>
            </div>
        </div>

        <!-- Playground Section -->
        <div class="glass-card rounded-2xl p-8 border border-indigo-950">
            <h2 class="text-xl font-bold text-white mb-2 flex items-center space-x-3">
                <span class="text-indigo-400">⚡</span>
                <span>Anonymization Playground</span>
            </h2>
            <p class="text-sm text-gray-400 mb-6">Test the proxy flow locally. Write a prompt containing PII, select redaction mode, and watch the secure mapping process and restore original values.</p>
            
            <div class="space-y-6">
                <!-- Mode select and prompt field -->
                <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
                    <div class="md:col-span-1">
                        <label class="block text-xs font-bold text-gray-400 uppercase tracking-wider mb-2">Redaction Mode</label>
                        <select id="playground-mode" class="w-full bg-gray-900 border border-gray-700 rounded-xl px-4 py-3 text-sm text-gray-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500">
                            <option value="mask">mask mode (Typed Tokens)</option>
                            <option value="synthetic">synthetic mode (Realistic Fake)</option>
                        </select>
                        <div class="mt-4 text-xs text-gray-500 space-y-2 bg-gray-955 rounded-xl p-3 border border-gray-800">
                            <p id="mode-desc-mask" class="text-indigo-300">Replaces PII with tags like <b>{{PERSON_1}}</b>.</p>
                            <p id="mode-desc-synthetic" class="hidden text-amber-300">Replaces PII with fake data like <b>"Michael Smith"</b> to maintain prompt structure.</p>
                        </div>
                    </div>
                    
                    <div class="md:col-span-3">
                        <label class="block text-xs font-bold text-gray-400 uppercase tracking-wider mb-2">Prompt Input (Contains PII)</label>
                        <textarea id="playground-prompt" rows="4" class="w-full bg-gray-900 border border-gray-700 rounded-xl px-4 py-3 text-sm text-gray-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500" placeholder="Type a prompt with PII..."></textarea>
                    </div>
                </div>

                <div class="flex justify-between items-center">
                    <button onclick="loadSamplePrompt()" class="text-xs text-indigo-400 hover:text-indigo-300 font-semibold flex items-center space-x-1">
                        <span>✨</span>
                        <span>Load Sample Prompt</span>
                    </button>
                    <button onclick="submitPlayground()" id="btn-submit" class="bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm px-6 py-2.5 rounded-xl flex items-center space-x-2 transition-all duration-150">
                        <span id="spinner" class="hidden animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full"></span>
                        <span>Process Prompt</span>
                    </button>
                </div>

                <!-- 4 Stage Flow Output -->
                <div id="flow-outputs" class="hidden grid grid-cols-1 md:grid-cols-4 gap-6 pt-6 border-t border-gray-800">
                    <!-- Stage 1 -->
                    <div class="bg-gray-950/60 border border-gray-800 rounded-xl p-5 flex flex-col justify-between">
                        <div>
                            <span class="text-xs font-semibold text-gray-500 uppercase tracking-wider">1. Input Prompt</span>
                            <h4 class="font-bold text-sm text-indigo-400 mt-1 mb-3">Cleartext (Client)</h4>
                            <p id="stage-cleartext" class="text-xs text-gray-300 bg-gray-900/40 p-3 rounded-lg border border-gray-800/50 break-words whitespace-pre-wrap max-h-48 overflow-y-auto"></p>
                        </div>
                    </div>

                    <!-- Stage 2 -->
                    <div class="bg-gray-950/60 border border-gray-800 rounded-xl p-5 flex flex-col justify-between">
                        <div>
                            <span class="text-xs font-semibold text-gray-500 uppercase tracking-wider">2. Anonymized</span>
                            <h4 class="font-bold text-sm text-red-400 mt-1 mb-3">Redacted to LLM</h4>
                            <p id="stage-anonymized" class="text-xs text-gray-300 bg-gray-900/40 p-3 rounded-lg border border-gray-800/50 break-words whitespace-pre-wrap max-h-48 overflow-y-auto"></p>
                        </div>
                    </div>

                    <!-- Stage 3 -->
                    <div class="bg-gray-950/60 border border-gray-800 rounded-xl p-5 flex flex-col justify-between">
                        <div>
                            <span class="text-xs font-semibold text-gray-500 uppercase tracking-wider">3. Raw Output</span>
                            <h4 class="font-bold text-sm text-yellow-400 mt-1 mb-3">LLM Response</h4>
                            <p id="stage-raw" class="text-xs text-gray-300 bg-gray-900/40 p-3 rounded-lg border border-gray-800/50 break-words whitespace-pre-wrap max-h-48 overflow-y-auto"></p>
                        </div>
                    </div>

                    <!-- Stage 4 -->
                    <div class="bg-gray-950/60 border border-gray-800 rounded-xl p-5 flex flex-col justify-between ring-1 ring-emerald-500/30">
                        <div>
                            <span class="text-xs font-semibold text-gray-500 uppercase tracking-wider">4. Restored</span>
                            <h4 class="font-bold text-sm text-emerald-400 mt-1 mb-3">Final to Client</h4>
                            <p id="stage-restored" class="text-xs text-gray-100 bg-emerald-950/20 p-3 rounded-lg border border-emerald-900/30 break-words whitespace-pre-wrap max-h-48 overflow-y-auto"></p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <!-- Footer -->
    <footer class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mt-12 text-center text-xs text-gray-600">
        <p>Reversible PII Anonymization Gateway | Built on Python 3.12, FastAPI, Redis, and Microsoft Presidio.</p>
    </footer>

    <!-- App Dashboard JS -->
    <script>
        const SAMPLE_PROMPT = "Hi, my name is John Doe. I am working at Google. My phone number is 555-0101, email address is john.doe@google.com, and my IP is 192.168.1.101. Also, here is my OpenAI API key: sk-proj-1234567890abcdef1234567890abcdef1234567890abcdef. Can you summarize this info?";
        
        function loadSamplePrompt() {
            document.getElementById('playground-prompt').value = SAMPLE_PROMPT;
        }

        // Initialize description handlers for modes
        const modeSelect = document.getElementById('playground-mode');
        modeSelect.addEventListener('change', () => {
            if (modeSelect.value === 'mask') {
                document.getElementById('mode-desc-mask').classList.remove('hidden');
                document.getElementById('mode-desc-synthetic').classList.add('hidden');
            } else {
                document.getElementById('mode-desc-mask').classList.add('hidden');
                document.getElementById('mode-desc-synthetic').classList.remove('hidden');
            }
        });

        // Initialize Charts
        let latencyChart, riskChart, entityChart;
        
        function initCharts() {
            const ctxLatency = document.getElementById('latencyChart').getContext('2d');
            const ctxRisk = document.getElementById('riskChart').getContext('2d');
            const ctxEntity = document.getElementById('entityChart').getContext('2d');

            latencyChart = new Chart(ctxLatency, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Duration (ms)',
                        data: [],
                        borderColor: '#818cf8',
                        backgroundColor: 'rgba(129, 140, 248, 0.1)',
                        borderWidth: 2,
                        tension: 0.3,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: { display: false },
                        y: { 
                            grid: { color: 'rgba(255,255,255,0.05)' },
                            ticks: { color: '#9ca3af', font: { size: 10 } } 
                        }
                    },
                    plugins: {
                        legend: { display: false }
                    }
                }
            });

            riskChart = new Chart(ctxRisk, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Risk Score',
                        data: [],
                        backgroundColor: 'rgba(239, 68, 68, 0.6)',
                        borderColor: '#ef4444',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: { display: false },
                        y: { 
                            grid: { color: 'rgba(255,255,255,0.05)' },
                            min: 0,
                            max: 1.0,
                            ticks: { color: '#9ca3af', font: { size: 10 } }
                        }
                    },
                    plugins: {
                        legend: { display: false }
                    }
                }
            });

            entityChart = new Chart(ctxEntity, {
                type: 'doughnut',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        backgroundColor: [
                            '#ef4444', '#3b82f6', '#10b981', '#f59e0b', 
                            '#ec4899', '#8b5cf6', '#06b6d4', '#6b7280'
                        ],
                        borderWidth: 1,
                        borderColor: '#0b0f19'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { 
                            position: 'right',
                            labels: { color: '#d1d5db', font: { size: 10 } }
                        }
                    }
                }
            });
        }

        // Update Dashboard Data and Charts
        async function fetchStats() {
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();
                
                // Update badge & system text
                const statusBadge = document.getElementById('status-badge');
                const statusText = document.getElementById('status-text');
                
                statusText.innerText = data.redis_status_text;
                if (data.redis_healthy) {
                    statusBadge.className = "px-3 py-1.5 rounded-full text-xs font-semibold flex items-center space-x-2 bg-emerald-500/10 text-emerald-400 glow-border-green";
                } else {
                    statusBadge.className = "px-3 py-1.5 rounded-full text-xs font-semibold flex items-center space-x-2 bg-amber-500/10 text-amber-400 glow-border-amber";
                }

                // Update text stats
                document.getElementById('avg-latency').innerText = `${data.average_latency_ms} ms`;
                document.getElementById('total-redacted').innerText = data.total_redacted_count;
                document.getElementById('active-sessions').innerText = data.active_sessions_count;

                // Update logs feed
                const feed = document.getElementById('logs-feed');
                if (data.audit_logs.length === 0) {
                    feed.innerHTML = '<p class="text-center text-sm text-gray-500 my-auto py-8">Waiting for gateway requests...</p>';
                } else {
                    feed.innerHTML = data.audit_logs.map(log => {
                        const typesHtml = log.redacted_types.length > 0 
                            ? log.redacted_types.map(t => `<span class="bg-gray-800 text-gray-300 text-[10px] px-1.5 py-0.5 rounded border border-gray-700 font-mono">${t}</span>`).join(' ')
                            : '<span class="text-gray-500 text-[10px]">NONE</span>';
                        
                        let riskColor = 'text-green-400';
                        if (log.risk_score > 0.7) riskColor = 'text-red-400';
                        else if (log.risk_score > 0.4) riskColor = 'text-amber-400';

                        return `
                            <div class="p-3 bg-gray-900/50 border border-gray-800 rounded-xl space-y-1">
                                <div class="flex items-center justify-between text-[10px]">
                                    <span class="text-indigo-400 font-mono font-semibold">${log.prompt_hash.substring(0, 12)}...</span>
                                    <span class="text-gray-500">${new Date(log.timestamp).toLocaleTimeString()}</span>
                                </div>
                                <div class="flex items-center justify-between text-xs pt-1">
                                    <span class="text-gray-400">Duration: <strong class="text-gray-200">${log.duration_ms} ms</strong></span>
                                    <span class="font-bold ${riskColor}">Risk: ${log.risk_score}</span>
                                </div>
                                <div class="flex items-center justify-between text-xs pt-1 border-t border-gray-800/40">
                                    <span class="text-gray-500 text-[10px]">Redacted: ${log.redacted_count}</span>
                                    <div class="flex flex-wrap gap-1 max-w-[70%] justify-end">${typesHtml}</div>
                                </div>
                            </div>
                        `;
                    }).join('');
                }

                // Update charts data
                const recentLogs = [...data.audit_logs].reverse();
                
                // 1. Latency & Risk Charts (last 15 items)
                const chartLogs = recentLogs.slice(-15);
                const labels = chartLogs.map((_, index) => `#${index+1}`);
                const latencies = chartLogs.map(l => l.duration_ms);
                const risks = chartLogs.map(l => l.risk_score);

                latencyChart.data.labels = labels;
                latencyChart.data.datasets[0].data = latencies;
                latencyChart.update();

                riskChart.data.labels = labels;
                riskChart.data.datasets[0].data = risks;
                riskChart.update();

                // 2. Entity Doughnut Chart (total aggregates of types)
                const entityCounts = {};
                recentLogs.forEach(log => {
                    log.redacted_types.forEach(t => {
                        entityCounts[t] = (entityCounts[t] || 0) + log.redacted_count;
                    });
                });
                
                entityChart.data.labels = Object.keys(entityCounts);
                entityChart.data.datasets[0].data = Object.values(entityCounts);
                entityChart.update();

            } catch (err) {
                console.error("Failed to fetch statistics:", err);
            }
        }

        // Submit Playground
        async function submitPlayground() {
            const promptVal = document.getElementById('playground-prompt').value.trim();
            if (!promptVal) return;

            const modeVal = document.getElementById('playground-mode').value;
            
            const btn = document.getElementById('btn-submit');
            const spinner = document.getElementById('spinner');
            
            btn.disabled = true;
            spinner.classList.remove('hidden');

            try {
                const response = await fetch('/api/playground/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ prompt: promptVal, mode: modeVal })
                });
                
                const data = await response.json();
                
                document.getElementById('stage-cleartext').innerText = data.cleartext;
                document.getElementById('stage-anonymized').innerText = data.anonymized;
                document.getElementById('stage-raw').innerText = data.raw_response;
                document.getElementById('stage-restored').innerText = data.restored_response;
                
                document.getElementById('flow-outputs').classList.remove('hidden');
                
                // Immediately refresh stats
                fetchStats();
            } catch (err) {
                alert(`Error processing playground test: ${err}`);
            } finally {
                btn.disabled = false;
                spinner.classList.add('hidden');
            }
        }

        // Initialize UI
        window.addEventListener('load', () => {
            initCharts();
            loadSamplePrompt();
            fetchStats();
            // Poll statistics every 2 seconds
            setInterval(fetchStats, 2000);
        });
    </script>
</body>
</html>
"""
