"""Entry point for `python -m fs_report.bridge`.

Reads JSON-RPC requests from stdin, dispatches them, and writes
JSON responses/events to stdout. One request per line, one response per line.

Protocol:
  Request:  {"id": <int>, "method": <str>, "params": <dict>}
  Response: {"id": <int>, "result": <any>}
  Error:    {"id": <int>, "error": <str>}
  Event:    {"id": <int>, "event": <dict>}   (during start_run only)
  Ready:    {"ready": true, "version": <str>}  (sent on startup)

Methods:
  health_check  — returns {"healthy": true, "version": "..."}
  list_recipes  — returns array of recipe metadata
  start_run     — params: {runId, config: {...}}; streams events, ends with done
  cancel_run    — params: {runId}; cancels a running report
"""

import json
import logging
import sys
import threading
from typing import Any

from fs_report.bridge.engine_wrapper import EngineWrapper, get_version

logger = logging.getLogger("fs_report.bridge")

# Global state
_wrapper = EngineWrapper()
_write_lock = threading.Lock()


def send(obj: dict[str, Any]) -> None:
    """Write a JSON object to stdout (one line, flushed). Thread-safe."""
    line = json.dumps(obj, default=str)
    with _write_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def handle_health_check(req_id: int, _params: dict[str, Any]) -> None:
    try:
        result = _wrapper.health_check()
        send({"id": req_id, "result": result})
    except Exception as e:
        send({"id": req_id, "error": str(e)})


def handle_list_recipes(req_id: int, _params: dict[str, Any]) -> None:
    try:
        recipes = _wrapper.list_recipes()
        send({"id": req_id, "result": recipes})
    except Exception as e:
        send({"id": req_id, "error": str(e)})


def handle_start_run(req_id: int, params: dict[str, Any]) -> None:
    """Start a report run in a background thread, streaming events."""
    run_id = params.get("runId")
    config = params.get("config", {})

    if not run_id:
        send({"id": req_id, "error": "runId is required"})
        return

    # Register cancel event before starting thread to avoid race with cancel_run
    try:
        _wrapper.register_run(run_id)
    except ValueError as e:
        send({"id": req_id, "error": str(e)})
        return

    def event_callback(event: dict[str, Any]) -> None:
        send({"id": req_id, "event": event})

    def run_in_thread() -> None:
        # Engine wrapper handles all errors internally and sends done events
        _wrapper.start_run(run_id, config, event_callback)

    thread = threading.Thread(target=run_in_thread, name=f"run-{run_id}", daemon=True)
    thread.start()

    # Acknowledge the run started (the thread streams events via event_callback)
    send({"id": req_id, "result": {"started": True, "runId": run_id}})


def handle_cancel_run(req_id: int, params: dict[str, Any]) -> None:
    run_id = params.get("runId")
    if not run_id:
        send({"id": req_id, "error": "runId is required"})
        return

    cancelled = _wrapper.cancel_run(run_id)
    send({"id": req_id, "result": {"cancelled": cancelled}})


def handle_cache_stats(req_id: int, _params: dict[str, Any]) -> None:
    try:
        stats = _wrapper.cache_stats()
        send({"id": req_id, "result": stats})
    except Exception as e:
        send({"id": req_id, "error": str(e)})


def handle_clear_cache(req_id: int, params: dict[str, Any]) -> None:
    cache_type = params.get("type", "all")
    if cache_type not in ("api", "nvd", "ai", "all"):
        send({"id": req_id, "error": f"Invalid cache type: {cache_type}"})
        return
    try:
        result = _wrapper.clear_cache(cache_type)
        send({"id": req_id, "result": result})
    except Exception as e:
        send({"id": req_id, "error": str(e)})


HANDLERS = {
    "health_check": handle_health_check,
    "list_recipes": handle_list_recipes,
    "start_run": handle_start_run,
    "cancel_run": handle_cancel_run,
    "cache_stats": handle_cache_stats,
    "clear_cache": handle_clear_cache,
}


def main() -> None:
    """Main loop: read stdin line by line, dispatch JSON-RPC requests."""
    # Configure logging to stderr (stdout is reserved for JSON protocol)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    # Send ready signal
    version = get_version()
    send({"ready": True, "version": version})
    logger.info("Bridge ready (version %s)", version)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON: %s", e)
            continue

        req_id = req.get("id", 0)
        method = req.get("method", "")
        params = req.get("params", {})

        handler = HANDLERS.get(method)
        if handler is None:
            send({"id": req_id, "error": f"Unknown method: {method}"})
            continue

        try:
            handler(req_id, params)
        except Exception as e:
            logger.exception("Handler error for %s", method)
            send({"id": req_id, "error": str(e)})


if __name__ == "__main__":
    main()
