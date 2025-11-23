#!/bin/bash

export HF_TOKEN=HF-TOKEN
export HF_HOME="/home/ubuntu/.cache/huggingface"
export MODEL_REPO=huihui-ai/Llama-3.3-70B-Instruct-abliterated

sudo docker run \
      --gpus all \
      --ipc=host \
      -v "${HF_HOME}":/root/.cache/huggingface \
      -p 8001:8000 \
      --env "HUGGING_FACE_HUB_TOKEN=${HF_TOKEN}" \
      vllm/vllm-openai:latest \
      --model huihui-ai/Huihui-Qwen3-VL-30B-A3B-Instruct-abliterated \
      --disable-log-requests \
      --tensor-parallel-size 2 \
      --enable-expert-parallel \
      --mm-encoder-tp-mode data \
      --max-model-len 32768 \
      --enable-auto-tool-choice \
      --tool-call-parser hermes
