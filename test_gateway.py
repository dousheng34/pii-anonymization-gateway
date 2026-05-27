import json
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_dashboard():
    response = client.get("/")
    assert response.status_code == 200
    assert "PII Anonymization Gateway" in response.text
    print("[OK] Dashboard endpoint returns HTML dashboard.")

def test_stats():
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert "redis_healthy" in data
    assert "total_redacted_count" in data
    assert "audit_logs" in data
    print("[OK] Stats endpoint returns JSON statistics.")

def test_playground():
    prompt = "Hello! My name is John Doe, email is john@google.com, phone is 555-0101."
    response = client.post("/api/playground/test", json={"prompt": prompt, "mode": "mask"})
    assert response.status_code == 200
    data = response.json()
    assert "cleartext" in data
    assert "anonymized" in data
    assert "raw_response" in data
    assert "restored_response" in data
    
    # Assert that PII was removed from anonymized prompt and restored in final
    assert "John Doe" not in data["anonymized"]
    assert "john@google.com" not in data["anonymized"]
    assert "John Doe" in data["restored_response"]
    assert "john@google.com" in data["restored_response"]
    print("[OK] Playground endpoint successfully runs 4-stage anonymization flow in mask mode.")

def test_chat_completions_mask():
    messages = [{"role": "user", "content": "My name is Bob Smith and my phone is 555-555-9999. Can you repeat my name and phone?"}]
    response = client.post("/v1/chat/completions", json={"messages": messages, "stream": False}, headers={"X-Redact-Mode": "mask"})
    assert response.status_code == 200
    data = response.json()
    content = data["choices"][0]["message"]["content"]
    assert "Bob Smith" in content
    assert "555-555-9999" in content
    print("[OK] Proxy endpoint works in mask mode for non-streaming completions (restores PII correctly).")

def test_chat_completions_synthetic():
    messages = [{"role": "user", "content": "My name is Bob Smith and my phone is 555-555-9999. Can you repeat my name and phone?"}]
    response = client.post("/v1/chat/completions", json={"messages": messages, "stream": False}, headers={"X-Redact-Mode": "synthetic"})
    assert response.status_code == 200
    data = response.json()
    content = data["choices"][0]["message"]["content"]
    assert "Bob Smith" in content
    assert "555-555-9999" in content
    print("[OK] Proxy endpoint works in synthetic mode for non-streaming completions (restores PII correctly).")

def test_chat_completions_streaming():
    messages = [{"role": "user", "content": "My name is Bob Smith and my phone is 555-555-9999. Can you repeat my name and phone?"}]
    response = client.post("/v1/chat/completions", json={"messages": messages, "stream": True}, headers={"X-Redact-Mode": "mask"})
    assert response.status_code == 200
    
    # Process SSE stream
    content_chunks = []
    for line in response.iter_lines():
        if line.startswith("data: "):
            data_content = line[6:].strip()
            if data_content == "[DONE]":
                break
            try:
                chunk_json = json.loads(data_content)
                delta = chunk_json["choices"][0]["delta"]
                if "content" in delta:
                    content_chunks.append(delta["content"])
            except Exception:
                pass
                
    full_content = "".join(content_chunks)
    assert "Bob Smith" in full_content
    assert "555-555-9999" in full_content
    print("[OK] Proxy endpoint works in streaming mode (restores PII correctly).")

if __name__ == "__main__":
    print("Running integration tests...")
    test_dashboard()
    test_stats()
    test_playground()
    test_chat_completions_mask()
    test_chat_completions_synthetic()
    test_chat_completions_streaming()
    print("All integration tests passed successfully! (OK)")
