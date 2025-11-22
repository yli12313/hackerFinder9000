curl -X POST "http://localhost:8001/v1/chat/completions" \
    -H "Content-Type: application/json" \
    --data '{
        "model": "huihui-ai/Llama-3.3-70B-Instruct-abliterated",
        "messages": [
            {
                "role": "user",
                "content": "What is the capital of France?"
            }
        ]
    }'

