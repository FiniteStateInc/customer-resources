"""Tool execution service - runs tools as background tasks."""

import asyncio
import json
import os
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Template
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.database import Job
from app.services.tool_registry import ToolDefinition


def is_running_in_docker() -> bool:
    """Check if we're running inside a Docker container."""
    return os.path.exists("/.dockerenv") or os.environ.get("DOCKER_CONTAINER", False)


async def execute_tool(job_id: str, tool: ToolDefinition, parameters: dict[str, Any]) -> None:
    """
    Execute a tool in the background.

    This function runs in a background task and updates the job record
    with progress and results.
    """
    settings = get_settings()

    # Create a new database session for this background task
    engine = create_async_engine(settings.database_url, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        # Get the job record
        result = await session.execute(select(Job).where(Job.id == job_id))
        job = result.scalar_one_or_none()

        if not job:
            return

        # Update job status to running
        job.status = "running"
        job.started_at = datetime.utcnow()
        await session.commit()

        try:
            # Create output directory for this job
            output_dir = settings.output_dir / job_id
            output_dir.mkdir(parents=True, exist_ok=True)
            job.output_path = str(output_dir)

            # Render command template
            command = render_command(tool, parameters, output_dir)

            # Add environment variables
            env = os.environ.copy()
            if settings.finite_state_auth_token:
                env["FINITE_STATE_AUTH_TOKEN"] = settings.finite_state_auth_token
            if settings.finite_state_domain:
                env["FINITE_STATE_DOMAIN"] = settings.finite_state_domain

            # Execute the command
            job.logs = f"Executing: {command}\n\n"
            await session.commit()

            # Run subprocess from default working directory
            # Tool commands use cd to navigate to the correct location
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
            )

            # Capture output
            stdout, _ = await process.communicate()
            output = stdout.decode("utf-8", errors="replace") if stdout else ""

            job.logs += output

            if process.returncode == 0:
                job.status = "completed"
            else:
                job.status = "failed"
                job.error_message = f"Process exited with code {process.returncode}"

        except Exception as e:
            job.status = "failed"
            job.error_message = str(e)
            job.logs = (job.logs or "") + f"\nError: {str(e)}"

        finally:
            job.completed_at = datetime.utcnow()
            await session.commit()

    await engine.dispose()


def render_command(tool: ToolDefinition, parameters: dict[str, Any], output_dir: Path) -> str:
    """Render the command template with parameters."""
    # Add output directory to parameters
    params = {**parameters, "output_dir": str(output_dir)}

    # Add source path
    params["source_path"] = tool.source_path

    # Handle checkbox parameters (convert to boolean)
    for param_def in tool.parameters:
        if param_def.type == "checkbox":
            params[param_def.name] = param_def.name in parameters

    # Render the Jinja2 template
    template = Template(tool.command_template)
    command = template.render(**params)

    # Clean up whitespace
    command = " ".join(command.split())

    return command


def validate_parameters(tool: ToolDefinition, parameters: dict[str, Any]) -> tuple[bool, list[str]]:
    """
    Validate parameters against tool definition.

    Returns (is_valid, list_of_errors)
    """
    errors = []

    for param in tool.parameters:
        value = parameters.get(param.name)

        # Check required parameters
        if param.required and not value:
            # Check if there's a show_if condition
            if param.show_if:
                # Only required if show_if condition is met
                condition_met = all(
                    parameters.get(k) == v
                    for k, v in param.show_if.items()
                )
                if condition_met:
                    errors.append(f"Parameter '{param.label}' is required")
            else:
                errors.append(f"Parameter '{param.label}' is required")

        # Validate select options
        if value and param.type == "select" and param.options:
            valid_values = [opt["value"] for opt in param.options]
            if value not in valid_values:
                errors.append(f"Invalid value for '{param.label}'")

    return len(errors) == 0, errors
