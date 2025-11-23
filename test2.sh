curl -X POST "http://localhost:8001/v1/chat/completions" \
    -H "Content-Type: application/json" \
    --data '{
        "model": "huihui-ai/Huihui-Qwen3-VL-30B-A3B-Instruct-abliterated",
        "messages": [
            {
                "role": "user",
                "content": "What is the capital of France?"
            }
        ]
    }'

