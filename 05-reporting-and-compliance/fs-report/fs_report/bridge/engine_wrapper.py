"""Wraps the fs-report ReportEngine for the JSON-RPC bridge.

Translates between the bridge's JSON protocol and the ReportEngine's
Python API. Manages cancel events and progress callbacks.
"""

import logging
import sqlite3
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("fs_report.bridge")


def get_version() -> str:
    """Return fs-report version, or 'unknown' if not importable."""
    try:
        from fs_report import __version__

        return __version__
    except ImportError:
        return "unknown"


class EngineWrapper:
    """Thin wrapper around ReportEngine for the JSON-RPC bridge."""

    def __init__(self) -> None:
        self._cancel_events: dict[str, threading.Event] = {}

    def health_check(self) -> dict[str, Any]:
        """Check that fs-report is importable and return version info."""
        version = get_version()
        if version == "unknown":
            return {"healthy": False, "error": "fs_report not importable"}
        return {"healthy": True, "version": version}

    def list_recipes(self) -> list[dict[str, Any]]:
        """List all available recipes with metadata."""
        from fs_report.recipe_loader import RecipeLoader

        loader = RecipeLoader(use_bundled=True)
        recipes = loader.load_recipes()

        return [
            {
                "name": r.name,
                "category": r.category or "uncategorized",
                "description": r.description or "",
                "autoRun": r.auto_run,
                "requiresProject": r.requires_project,
                "requiresProjectOrFolder": getattr(
                    r, "requires_project_or_folder", False
                ),
                "requiresCve": r.requires_cve,
            }
            for r in recipes
        ]

    def register_run(self, run_id: str) -> threading.Event:
        """Register a cancel event for a run before starting it.

        Raises ValueError if the run_id is already in progress.
        Returns the cancel event to be passed to ReportEngine.
        """
        if run_id in self._cancel_events:
            raise ValueError(f"Run {run_id} is already in progress")
        cancel_event = threading.Event()
        self._cancel_events[run_id] = cancel_event
        return cancel_event

    def start_run(
        self,
        run_id: str,
        config_params: dict[str, Any],
        event_callback: Callable[[dict[str, Any]], None],
    ) -> None:
        """Run reports and stream events via the callback.

        This is called from a background thread. It blocks until the run
        completes, sending events via event_callback along the way.
        The cancel event must already be registered via register_run().
        """
        from fs_report.cli.run import create_config
        from fs_report.report_engine import ReportCancelled, ReportEngine

        cancel_event = self._cancel_events.get(run_id)
        if cancel_event is None:
            event_callback(
                {
                    "type": "done",
                    "status": "error",
                    "error": f"Run {run_id} not registered",
                }
            )
            return

        try:
            # Extract recipe names for filtering
            recipe_names: list[str] = config_params.get("recipes", [])
            total = len(recipe_names) if recipe_names else 0

            # Ensure output directory exists
            output_dir = Path(config_params.get("outputDir", "./output"))
            output_dir.mkdir(parents=True, exist_ok=True)

            # Build the config — passes through all create_config params.
            # Params not listed here use create_config defaults.
            config = create_config(
                token=config_params.get("token"),
                domain=config_params.get("domain"),
                output=output_dir,
                period=config_params.get("period", "30d"),
                project_filter=config_params.get("projectFilter"),
                folder_filter=config_params.get("folderFilter"),
                version_filter=config_params.get("versionFilter"),
                finding_types=config_params.get("findingTypes", "cve"),
                current_version_only=config_params.get("currentVersionOnly", True),
                cache_ttl=int(config_params.get("cacheTtl", 0)),
                cache_dir=config_params.get("cacheDir"),
                cache_refresh=config_params.get("cacheRefresh", False),
                overwrite=config_params.get("overwrite", False),
                verbose=config_params.get("verbose", False),
                open_only=config_params.get("openOnly", False),
                request_delay=float(config_params.get("requestDelay", 0.5)),
                batch_size=int(config_params.get("batchSize", 5)),
                low_memory=config_params.get("lowMemory", False),
                detected_after=config_params.get("detectedAfter"),
                ai=config_params.get("ai", False),
                ai_provider=config_params.get("aiProvider"),
                ai_model_high=config_params.get("aiModelHigh"),
                ai_model_low=config_params.get("aiModelLow"),
                ai_depth=config_params.get("aiDepth", "summary"),
                ai_prompts=config_params.get("aiPrompts", False),
                ai_export=config_params.get("aiExport"),
                ai_import=config_params.get("aiImport"),
                ai_analysis=config_params.get("aiAnalysis", False),
                nvd_api_key=config_params.get("nvdApiKey"),
                skip_nvd=config_params.get("skipNvd", False),
                cve_filter=config_params.get("cveFilter"),
                component_filter=config_params.get("componentFilter"),
                component_match=config_params.get("componentMatch", "contains"),
                component_version=config_params.get("componentVersion"),
                baseline_version=config_params.get("baselineVersion"),
                baseline_date=config_params.get("baselineDate"),
                current_version=config_params.get("currentVersion"),
                top=int(config_params.get("top", 0)),
                triage=int(config_params.get("triage", 0)),
                logo=config_params.get("logo"),
                scoring_file=config_params.get("scoringFile"),
                tp_gate=config_params.get("tpGate"),
                vex_override=config_params.get("vexOverride", False),
                apply_vex_triage=config_params.get("applyVexTriage"),
                autotriage=config_params.get("autotriage"),
                scan_types=config_params.get("scanTypes"),
                scan_statuses=config_params.get("scanStatuses"),
                context_file=config_params.get("contextFile"),
                product_type=config_params.get("productType"),
                network_exposure=config_params.get("networkExposure"),
                regulatory=config_params.get("regulatory"),
                deployment_notes=config_params.get("deploymentNotes"),
                compare_domain=config_params.get("compareDomain"),
                compare_token=config_params.get("compareToken"),
                compare_project=config_params.get("compareProject"),
                compare_version=config_params.get("compareVersion"),
                threat_context=config_params.get("threatContext"),
                data_file=config_params.get("dataFile"),
            )

            # Progress callback — fires after each recipe completes
            def on_recipe_complete(
                completed: int, recipe_total: int, name: str
            ) -> None:
                event_callback(
                    {
                        "type": "progress",
                        "completed": completed,
                        "total": recipe_total,
                        "recipe": name,
                    }
                )

            # Log capture — redirect fs-report logging to events
            log_handler = _BridgeLogHandler(event_callback)
            root_logger = logging.getLogger("fs_report")
            root_logger.addHandler(log_handler)

            try:
                engine = ReportEngine(
                    config,
                    cancel_event=cancel_event,
                    on_recipe_complete=on_recipe_complete,
                )

                # Filter to requested recipes
                if recipe_names:
                    engine.recipe_loader.recipe_filter = [
                        n.lower() for n in recipe_names
                    ]

                # Send initial progress
                event_callback(
                    {
                        "type": "progress",
                        "completed": 0,
                        "total": total or len(engine.recipe_loader.load_recipes()),
                    }
                )

                # Run the engine (blocks until done)
                result = engine.run()

                # Collect output files
                files = list(engine.generated_files) if engine.generated_files else []

                event_callback(
                    {
                        "type": "done",
                        "status": "success" if result.success else "error",
                        "files": files,
                        "error": (
                            None if result.success else "One or more recipes failed"
                        ),
                    }
                )

            finally:
                root_logger.removeHandler(log_handler)

        except ReportCancelled:
            event_callback({"type": "done", "status": "cancelled"})
        except Exception as e:
            logger.exception("Run %s failed", run_id)
            event_callback({"type": "done", "status": "error", "error": str(e)})
        finally:
            self._cancel_events.pop(run_id, None)

    def cancel_run(self, run_id: str) -> bool:
        """Cancel a running report by setting its cancel event."""
        cancel_event = self._cancel_events.get(run_id)
        if cancel_event is None:
            return False
        cancel_event.set()
        return True

    def cache_stats(self) -> dict[str, Any]:
        """Return cache statistics for API, NVD, and AI caches."""
        cache_dir = Path.home() / ".fs-report"
        result: dict[str, Any] = {
            "location": str(cache_dir),
            "api": {"entries": 0, "size_bytes": 0, "size_mb": 0.0, "files": []},
            "nvd": {"entries": 0, "size_bytes": 0, "size_mb": 0.0},
            "ai": {"entries": 0, "size_bytes": 0, "size_mb": 0.0},
        }

        if not cache_dir.exists():
            return result

        # API caches: domain-specific .db files
        for f in cache_dir.glob("*.db"):
            name = f.name
            size = f.stat().st_size
            # Include WAL/SHM sidecar files
            for ext in ("-wal", "-shm"):
                sidecar = f.with_suffix(f.suffix + ext)
                if sidecar.exists():
                    size += sidecar.stat().st_size

            if name == "nvd_cache.db":
                result["nvd"]["size_bytes"] = size
                result["nvd"]["size_mb"] = round(size / (1024 * 1024), 2)
                try:
                    with sqlite3.connect(str(f)) as conn:
                        count = conn.execute(
                            "SELECT COUNT(*) FROM nvd_cve_cache"
                        ).fetchone()[0]
                    result["nvd"]["entries"] = count
                except Exception:
                    pass
            elif name == "cache.db":
                result["ai"]["size_bytes"] = size
                result["ai"]["size_mb"] = round(size / (1024 * 1024), 2)
                try:
                    with sqlite3.connect(str(f)) as conn:
                        count = 0
                        for table in (
                            "cve_remediations",
                            "cve_detail_cache",
                            "exploit_detail_cache",
                        ):
                            try:
                                count += conn.execute(
                                    f"SELECT COUNT(*) FROM {table}"
                                ).fetchone()[0]
                            except Exception:
                                pass
                    result["ai"]["entries"] = count
                except Exception:
                    pass
            elif name != "report-server.db":
                # Domain-specific API cache
                result["api"]["size_bytes"] += size
                result["api"]["files"].append(name)
                try:
                    with sqlite3.connect(str(f)) as conn:
                        count = conn.execute(
                            "SELECT COUNT(*) FROM cache_meta"
                        ).fetchone()[0]
                    result["api"]["entries"] += count
                except Exception:
                    pass

        result["api"]["size_mb"] = round(result["api"]["size_bytes"] / (1024 * 1024), 2)
        return result

    def clear_cache(self, cache_type: str) -> dict[str, Any]:
        """Clear a specific cache type or all caches.

        Args:
            cache_type: "api", "nvd", "ai", or "all"
        """
        cache_dir = Path.home() / ".fs-report"
        cleared: list[str] = []

        if not cache_dir.exists():
            return {"cleared": cleared}

        def remove_db(path: Path) -> None:
            for p in [path, path.with_suffix(".db-wal"), path.with_suffix(".db-shm")]:
                if p.exists():
                    p.unlink()

        if cache_type in ("api", "all"):
            for f in cache_dir.glob("*.db"):
                if f.name not in ("nvd_cache.db", "cache.db", "report-server.db"):
                    remove_db(f)
                    cleared.append(f.name)

        if cache_type in ("nvd", "all"):
            nvd = cache_dir / "nvd_cache.db"
            if nvd.exists():
                remove_db(nvd)
                cleared.append("nvd_cache.db")

        if cache_type in ("ai", "all"):
            ai = cache_dir / "cache.db"
            if ai.exists():
                remove_db(ai)
                cleared.append("cache.db")

        return {"cleared": cleared}


class _BridgeLogHandler(logging.Handler):
    """Captures fs_report log records and sends them as bridge events."""

    def __init__(self, callback: Callable[[dict[str, Any]], None]) -> None:
        super().__init__(level=logging.INFO)
        self._callback = callback

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._callback(
                {
                    "type": "log",
                    "level": record.levelname.lower(),
                    "message": self.format(record),
                    "timestamp": datetime.fromtimestamp(
                        record.created, tz=UTC
                    ).isoformat(),
                }
            )
        except Exception:
            pass  # Never let logging errors break the bridge
