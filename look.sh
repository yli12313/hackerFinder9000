#!/bin/sh
cat /tmp/fastapi.jsonl  | jq -r .body | jq .messages  # input calls including role:tool that was run by mcp client
cat /tmp/fastapi.jsonl  | jq -r .response_body | jq .choices[0].message  # look at LLM responses (assistant), with tool_calls parsed if any
