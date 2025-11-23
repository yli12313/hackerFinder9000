"""
Request logging middleware for logging all requests to a JSONL file.
"""

import atexit
import json
import logging
import os
from datetime import datetime, timezone
from typing import Callable, TextIO

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that logs all requests to a JSONL file."""

    _file_handle: TextIO | None = None

    def __init__(self, app, log_file: str | None = None):
        super().__init__(app)
        self.log_file = log_file or os.getenv("LOG_FILE")
        if self.log_file and self._file_handle is None:
            self._open_file()

    def _open_file(self) -> None:
        """Open the log file and register cleanup on exit."""
        if self.log_file:
            try:
                RequestLoggingMiddleware._file_handle = open(self.log_file, "a")
                atexit.register(self._close_file)
                logger.info("Request logging enabled, writing to: %s", self.log_file)
            except OSError as e:
                logger.error("Failed to open log file %s: %s", self.log_file, e)

    @classmethod
    def _close_file(cls) -> None:
        """Close the log file handle."""
        if cls._file_handle:
            cls._file_handle.close()
            cls._file_handle = None

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self._file_handle:
            return await call_next(request)

        logger.info("Processing request: %s %s", request.method, request.url.path)

        # Capture request details
        body = await request.body()

        # Extract baseline type header if present
        baseline_type = request.headers.get("x-baseline-type")

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": request.method,
            "url": str(request.url),
            "path": request.url.path,
            "query_params": dict(request.query_params),
            "headers": dict(request.headers),
            "client_host": request.client.host if request.client else None,
            "client_port": request.client.port if request.client else None,
            "body": body.decode("utf-8", errors="replace") if body else None,
            "baseline_type": baseline_type,  # "benign", "malicious", or None
        }

        # Write to persistent file handle and flush
        self._file_handle.write(json.dumps(log_entry) + "\n")
        self._file_handle.flush()

        # Get the response
        response = await call_next(request)

        # Wrap the response to capture its body
        return self._wrap_response(request, response)

    def _wrap_response(self, request: Request, response: Response) -> Response:
        """Wrap the response to capture and log its body."""
        original_iterator = response.body_iterator
        collected_chunks = []

        async def capturing_iterator():
            """Capture chunks while yielding them to the client."""
            async for chunk in original_iterator:
                collected_chunks.append(chunk)
                yield chunk

        if isinstance(response, StreamingResponse):
            # For streaming responses, wrap the iterator and log after completion
            async def wrapped_stream():
                async for chunk in capturing_iterator():
                    yield chunk
                # After stream completes, log the collected content
                await self._log_response_body(request, response, collected_chunks)

            return StreamingResponse(
                wrapped_stream(),
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type,
            )
        else:
            # For non-streaming responses, use background task to log after response is sent
            from starlette.background import BackgroundTask

            response.body_iterator = capturing_iterator()

            async def log_task():
                # Small delay to ensure all chunks are collected before logging
                import asyncio
                await asyncio.sleep(0.1)
                await self._log_response_body(request, response, collected_chunks)

            # Add background task to log after response is sent
            # Chain with any existing background task
            original_background = getattr(response, 'background', None)
            if original_background:
                async def chained_task():
                    await original_background()
                    await log_task()
                response.background = BackgroundTask(chained_task)
            else:
                response.background = BackgroundTask(log_task)

            return response

    async def _log_response_body(
        self, request: Request, response: Response, chunks: list[bytes]
    ) -> None:
        """Log the response body."""
        try:
            body_bytes = b"".join(chunks)
            response_body = body_bytes.decode("utf-8", errors="replace")

            response_log_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "method": request.method,
                "url": str(request.url),
                "path": request.url.path,
                "status_code": response.status_code,
                "response_headers": dict(response.headers),
                "response_body": response_body,
                "contains_response": True,
            }

            # Write response log entry
            self._file_handle.write(json.dumps(response_log_entry) + "\n")
            self._file_handle.flush()

        except Exception as e:
            logger.error("Failed to log response body: %s", e, exc_info=True)
