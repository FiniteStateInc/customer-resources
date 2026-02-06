"""AI Assistant service using LiteLLM with tool execution capabilities."""

import json
import uuid
from datetime import datetime
from typing import Optional, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import ChatMessage, Job
from app.services.tool_registry import get_tool_registry, ToolDefinition


def get_tools_for_ai() -> list[dict]:
    """Get tool definitions formatted for AI function calling."""
    registry = get_tool_registry()
    tools = registry.get_all_tools()

    ai_tools = []
    for tool in tools:
        # Build parameters schema
        properties = {}
        required = []

        for param in tool.parameters:
            param_schema = {"type": "string", "description": param.label}

            if param.type == "select" and param.options:
                param_schema["enum"] = [opt["value"] for opt in param.options]
                # Add descriptions of options to help AI choose correctly
                options_desc = ", ".join([f"'{opt['value']}' ({opt['label']})" for opt in param.options])
                param_schema["description"] += f". Options: {options_desc}"
            elif param.type == "checkbox":
                param_schema["type"] = "boolean"
            elif param.type == "number":
                param_schema["type"] = "number"
            elif param.type == "project_select":
                param_schema["description"] += ". Use list_projects to find the project ID first."
            elif param.type == "version_select":
                param_schema["description"] += ". Use list_project_versions to find the version ID first."

            if param.placeholder:
                param_schema["description"] += f" {param.placeholder}"

            if param.default:
                param_schema["description"] += f" Default: {param.default}"

            properties[param.name] = param_schema

            if param.required:
                required.append(param.name)

        ai_tools.append({
            "type": "function",
            "function": {
                "name": f"execute_{tool.name.replace('-', '_')}",
                "description": f"{tool.display_name}: {tool.description}",
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            },
        })

    # Add helper tools
    ai_tools.append({
        "type": "function",
        "function": {
            "name": "list_projects",
            "description": "List all available projects in Finite State. Use this to find project IDs before running reports.",
            "parameters": {
                "type": "object",
                "properties": {
                    "search": {
                        "type": "string",
                        "description": "Optional search term to filter projects by name",
                    },
                },
                "required": [],
            },
        },
    })

    ai_tools.append({
        "type": "function",
        "function": {
            "name": "list_project_versions",
            "description": "List all versions for a specific project. Use this to find version IDs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "The project ID to list versions for",
                    },
                },
                "required": ["project_id"],
            },
        },
    })

    # Add custom report generation tool
    ai_tools.append({
        "type": "function",
        "function": {
            "name": "run_custom_findings_report",
            "description": "Generate a custom findings report with severity filtering. Use this when users want reports filtered by severity (CRITICAL, HIGH, MEDIUM, LOW).",
            "parameters": {
                "type": "object",
                "properties": {
                    "report_name": {
                        "type": "string",
                        "description": "A descriptive name for this custom report",
                    },
                    "severity_filter": {
                        "type": "string",
                        "description": "Severity levels to include. Options: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', or combinations like 'CRITICAL,HIGH'",
                    },
                    "project_id": {
                        "type": "string",
                        "description": "Optional project ID to filter by (use list_projects to find)",
                    },
                    "period": {
                        "type": "string",
                        "description": "Time period: '7d', '14d', '30d', '90d', '1m', '3m'. Default: '30d'",
                    },
                    "finding_types": {
                        "type": "string",
                        "description": "Finding types to include: 'cve', 'sast', 'credentials', 'all'. Default: 'cve'",
                    },
                },
                "required": ["report_name", "severity_filter"],
            },
        },
    })

    return ai_tools


# Enhanced system prompt
SYSTEM_PROMPT = """You are an AI assistant for the Finite State Customer Resources Portal. You help users manage their software security analysis and generate reports.

## Your Capabilities

1. **Execute Tools**: You can directly run tools on behalf of the user. When they ask for a report, execute it immediately.
2. **Find Projects & Versions**: You can search for projects and their versions to get the correct IDs.
3. **Generate YAML Recipes**: You can create custom report recipes for fs-report.
4. **Answer Questions**: You can explain tools, report types, and security concepts.

## Available Tools

{tool_details}

## CRITICAL: How to Handle User Requests

When a user asks for a report or mentions a project/version:

1. **ALWAYS use tools to look up IDs** - Never ask the user for IDs. Use `list_projects` with a search term to find project IDs.
2. **Chain your tool calls** - After finding a project ID, immediately call `list_project_versions` to get version IDs.
3. **Execute the tool** - Once you have the required IDs, execute the appropriate tool immediately.
4. **Don't just describe what you would do** - Actually do it by calling the tools.

### Example Flow for "Create a PDF report for JTest version 5":
1. Call `list_projects` with search="JTest" → Get project ID
2. Call `list_project_versions` with that project_id → Find version "5" and get its ID
3. Call `execute_fs_reporter` with project_id and version_id → Start the job
4. Tell the user the job was started with a link to check progress

## Tool Requirements

- **PDF Risk Reporter (fs-reporter)**: Requires both `project_id` AND `version_id`. Generates a comprehensive PDF with charts.
- **Report Generator (fs-report)**: Can work with just `project_id` or no filter. Generates HTML/CSV/XLSX reports.
- **License Report**: Requires `version_id`
- **Auto Triage**: Requires `version_id` for target

## IMPORTANT: Understanding Report Filters

**Finding Types** vs **Severity** - These are DIFFERENT things:
- **finding_types** = The category of security issue: `cve` (vulnerabilities), `sast` (static analysis), `credentials`, `config_issues`, etc.
- **severity** = The risk level: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`

### When users ask for severity filtering (e.g., "critical findings only"):
Use the `run_custom_findings_report` function! This generates a custom YAML recipe with the severity filter.

Example: "Show me critical CVE findings for the JTest project"
1. Call `list_projects` to find JTest's project ID
2. Call `run_custom_findings_report` with:
   - report_name: "Critical Findings for JTest"
   - severity_filter: "CRITICAL"
   - project_id: (the ID you found)
   - finding_types: "cve"

You can filter by multiple severities: "CRITICAL,HIGH" for critical and high severity findings.

## Important

- DO NOT ask users for project IDs or version IDs - look them up yourself
- DO NOT just say "I will look up..." - actually call the tool
- DO NOT confuse "finding types" (cve/sast) with "severity" (critical/high/medium/low)
- When you find multiple matches, pick the best one or ask the user to clarify
- After executing a tool, tell the user the job has been started and they can check progress on the **Jobs** page in the navigation bar
- NEVER create links to specific job URLs. Just tell the user to visit the Jobs page.

Be action-oriented. When a user asks for something, do it immediately using your tools.
"""


def get_detailed_tool_info() -> str:
    """Get detailed tool information for the system prompt."""
    registry = get_tool_registry()
    tools = registry.get_all_tools()

    lines = []
    for tool in tools:
        lines.append(f"\n### {tool.display_name} (`{tool.name}`)")
        lines.append(f"**Category**: {tool.category}")
        lines.append(f"**Description**: {tool.description}")
        lines.append("**Parameters**:")
        for param in tool.parameters:
            req = " (required)" if param.required else " (optional)"
            param_type = param.type
            if param.type == "project_select":
                param_type = "project ID (use list_projects to find)"
            elif param.type == "version_select":
                param_type = "version ID (use list_project_versions to find)"
            lines.append(f"  - `{param.name}`: {param.label}{req} - Type: {param_type}")
        lines.append("")

    return "\n".join(lines)


async def execute_tool_function(
    function_name: str,
    arguments: dict,
    session: AsyncSession,
) -> str:
    """Execute a tool function and return the result."""
    settings = get_settings()

    # Handle helper functions
    if function_name == "list_projects":
        return await _list_projects(arguments.get("search"))

    if function_name == "list_project_versions":
        project_id = arguments.get("project_id")
        if not project_id:
            return "Error: project_id is required"
        return await _list_project_versions(project_id)

    # Handle custom findings report with severity filter
    if function_name == "run_custom_findings_report":
        return await _run_custom_findings_report(arguments, session)

    # Handle tool execution
    if function_name.startswith("execute_"):
        tool_name = function_name[8:].replace("_", "-")
        registry = get_tool_registry()
        tool = registry.get_tool(tool_name)

        if not tool:
            return f"Error: Tool '{tool_name}' not found"

        # Create a job
        job_id = str(uuid.uuid4())
        job = Job(
            id=job_id,
            tool_name=tool.name,
            status="pending",
            parameters=json.dumps(arguments),
            created_at=datetime.utcnow(),
        )
        session.add(job)
        await session.commit()

        # Start tool execution in background
        from app.services.tool_executor import execute_tool
        import asyncio
        asyncio.create_task(execute_tool(job_id, tool, arguments))

        return f"Started job `{job_id[:8]}...` for {tool.display_name}. The job is now available on the Jobs page."

    return f"Unknown function: {function_name}"


async def _list_projects(search: Optional[str] = None) -> str:
    """List projects from Finite State API."""
    import httpx
    settings = get_settings()

    if not settings.finite_state_configured:
        return "Error: Finite State API not configured"

    url = f"https://{settings.finite_state_domain}/api/public/v0/projects"
    headers = {"X-Authorization": settings.finite_state_auth_token}
    params = {"limit": 50, "sort": "name:asc"}

    if search:
        params["filter"] = f"name=ilike=*{search}*"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, params=params, timeout=30.0)
            response.raise_for_status()
            data = response.json()
    except Exception as e:
        return f"Error fetching projects: {str(e)}"

    items = data.get("data", data) if isinstance(data, dict) else data
    projects = items if isinstance(items, list) else []

    if not projects:
        return "No projects found" + (f" matching '{search}'" if search else "")

    lines = ["Found projects:"]
    for p in projects[:20]:  # Limit to 20 for readability
        lines.append(f"- **{p.get('name')}** (ID: `{p.get('id')}`)")

    if len(projects) > 20:
        lines.append(f"\n...and {len(projects) - 20} more. Use a search term to narrow down.")

    return "\n".join(lines)


async def _list_project_versions(project_id: str) -> str:
    """List versions for a project from Finite State API."""
    import httpx
    settings = get_settings()

    if not settings.finite_state_configured:
        return "Error: Finite State API not configured"

    url = f"https://{settings.finite_state_domain}/api/public/v0/projects/{project_id}/versions"
    headers = {"X-Authorization": settings.finite_state_auth_token}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=30.0)
            response.raise_for_status()
            data = response.json()
    except Exception as e:
        return f"Error fetching versions: {str(e)}"

    items = data.get("data", data) if isinstance(data, dict) else data
    versions = items if isinstance(items, list) else []

    if not versions:
        return f"No versions found for project {project_id}"

    lines = ["Found versions:"]
    for v in versions[:20]:
        version_name = v.get("version") or v.get("name") or "Unknown"
        lines.append(f"- **{version_name}** (ID: `{v.get('id')}`)")

    if len(versions) > 20:
        lines.append(f"\n...and {len(versions) - 20} more.")

    return "\n".join(lines)


async def _run_custom_findings_report(arguments: dict, session: AsyncSession) -> str:
    """Generate and run a custom findings report with severity filtering."""
    import os
    import asyncio
    from pathlib import Path

    settings = get_settings()

    report_name = arguments.get("report_name", "Custom Severity Report")
    severity_filter = arguments.get("severity_filter", "CRITICAL")
    project_id = arguments.get("project_id")
    period = arguments.get("period", "30d")
    finding_types = arguments.get("finding_types", "cve")

    # Validate severity
    valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    severities = [s.strip().upper() for s in severity_filter.split(",")]
    for sev in severities:
        if sev not in valid_severities:
            return f"Error: Invalid severity '{sev}'. Valid options: CRITICAL, HIGH, MEDIUM, LOW"

    # Build the severity filter string for RSQL
    if len(severities) == 1:
        severity_rsql = f"severity=={severities[0]}"
    else:
        severity_rsql = f"severity=in=({','.join(severities)})"

    # Generate custom recipe YAML
    recipe_yaml = f'''# Auto-generated custom recipe
name: "{report_name}"
description: "Custom findings report filtered by severity: {severity_filter}"

query:
  endpoint: "/public/v0/findings"
  params:
    limit: 10000
    filter: "detected>=${{start}};detected<=${{end}};{severity_rsql}"

project_list_query:
  endpoint: "/public/v0/projects"
  params:
    limit: 10000
    archived: false

transform_function: findings_by_project_pandas_transform

output:
  formats: ["csv", "xlsx", "html"]
  table: true
  slide_title: "{report_name}"
'''

    # Create a job
    job_id = str(uuid.uuid4())
    job = Job(
        id=job_id,
        tool_name="fs-report",
        status="pending",
        parameters=json.dumps({
            "custom_recipe": True,
            "report_name": report_name,
            "severity_filter": severity_filter,
            "project_id": project_id,
            "period": period,
            "finding_types": finding_types,
        }),
        created_at=datetime.utcnow(),
    )
    session.add(job)
    await session.commit()

    # Save the custom recipe and execute
    async def run_custom_report():
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession as AS
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy import select
        import subprocess

        # Create new session for background task
        engine = create_async_engine(settings.database_url, echo=False)
        async_session = sessionmaker(engine, class_=AS, expire_on_commit=False)

        async with async_session() as bg_session:
            result = await bg_session.execute(select(Job).where(Job.id == job_id))
            bg_job = result.scalar_one_or_none()
            if not bg_job:
                return

            bg_job.status = "running"
            bg_job.started_at = datetime.utcnow()
            await bg_session.commit()

            try:
                # Create output directory
                output_dir = settings.output_dir / job_id
                output_dir.mkdir(parents=True, exist_ok=True)
                bg_job.output_path = str(output_dir)

                # Save custom recipe to a temp file in the writable data directory
                # Note: filename must NOT start with underscore (recipe loader skips those)
                recipes_dir = Path("/app/data/recipes")
                recipes_dir.mkdir(parents=True, exist_ok=True)
                custom_recipe_file = recipes_dir / f"custom_{job_id[:8]}.yaml"
                custom_recipe_file.write_text(recipe_yaml)

                # Build command - use --recipes to point to our custom recipe directory
                cmd = f'cd /app/tools/reporting/fs-report && poetry install --no-interaction --quiet && poetry run fs-report --recipes "{recipes_dir}" --recipe "{report_name}"'
                if project_id:
                    cmd += f' --project "{project_id}"'
                cmd += f' --period {period}'
                cmd += f' --finding-types {finding_types}'
                cmd += f' --output {output_dir}'

                bg_job.logs = f"Executing custom report with severity filter: {severity_filter}\n"
                bg_job.logs += f"Command: {cmd}\n\n"
                await bg_session.commit()

                # Set up environment
                env = os.environ.copy()
                if settings.finite_state_auth_token:
                    env["FINITE_STATE_AUTH_TOKEN"] = settings.finite_state_auth_token
                if settings.finite_state_domain:
                    env["FINITE_STATE_DOMAIN"] = settings.finite_state_domain

                # Run the command
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    env=env,
                )

                stdout, _ = await process.communicate()
                output = stdout.decode("utf-8", errors="replace") if stdout else ""
                bg_job.logs += output

                # Clean up custom recipe file
                try:
                    custom_recipe_file.unlink()
                except:
                    pass

                if process.returncode == 0:
                    bg_job.status = "completed"
                else:
                    bg_job.status = "failed"
                    bg_job.error_message = f"Process exited with code {process.returncode}"

            except Exception as e:
                bg_job.status = "failed"
                bg_job.error_message = str(e)
                bg_job.logs = (bg_job.logs or "") + f"\nError: {str(e)}"

            finally:
                bg_job.completed_at = datetime.utcnow()
                await bg_session.commit()

        await engine.dispose()

    # Start background task
    asyncio.create_task(run_custom_report())

    return f"Started custom findings report job `{job_id[:8]}...` with severity filter: {severity_filter}. The job is now available on the Jobs page."


async def get_ai_response(message: str, session: AsyncSession) -> str:
    """
    Get a response from the AI assistant with iterative function calling support.

    Args:
        message: User's message
        session: Database session for chat history

    Returns:
        AI response text
    """
    settings = get_settings()

    if not settings.ai_configured:
        return "AI assistant is not configured. Please add an API key in Settings."

    # Get tool information for context
    tool_details = get_detailed_tool_info()
    system_prompt = SYSTEM_PROMPT.format(tool_details=tool_details)

    # Get recent chat history for context
    result = await session.execute(
        select(ChatMessage).order_by(ChatMessage.created_at.desc()).limit(10)
    )
    history = list(reversed(result.scalars().all()))

    # Build messages array
    messages = [{"role": "system", "content": system_prompt}]

    for msg in history:
        messages.append({"role": msg.role, "content": msg.content})

    messages.append({"role": "user", "content": message})

    # Get tools for function calling
    tools = get_tools_for_ai()

    try:
        import litellm

        # Determine model based on provider
        if settings.ai_provider == "anthropic":
            model = "claude-3-5-sonnet-20241022"
            litellm.api_key = settings.anthropic_api_key
        else:
            model = "gpt-4o"
            litellm.api_key = settings.openai_api_key

        # Iterative tool calling loop - allow up to 5 rounds of tool calls
        max_iterations = 5
        iteration = 0

        while iteration < max_iterations:
            iteration += 1

            # Call the AI with tools
            response = await litellm.acompletion(
                model=model,
                messages=messages,
                tools=tools,
                tool_choice="auto",
                max_tokens=2000,
                temperature=0.7,
            )

            response_message = response.choices[0].message

            # If no tool calls, we're done - return the response
            if not response_message.tool_calls:
                return response_message.content or "I couldn't generate a response."

            # Execute each tool call
            tool_results = []
            for tool_call in response_message.tool_calls:
                function_name = tool_call.function.name
                try:
                    arguments = json.loads(tool_call.function.arguments)
                except json.JSONDecodeError:
                    arguments = {}

                result = await execute_tool_function(function_name, arguments, session)
                tool_results.append({
                    "function": function_name,
                    "result": result,
                })

            # Add assistant message with tool calls
            messages.append({
                "role": "assistant",
                "content": response_message.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in response_message.tool_calls
                ],
            })

            # Add tool results
            for i, tool_call in enumerate(response_message.tool_calls):
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": tool_results[i]["result"],
                })

            # Continue the loop to let AI process results and potentially make more calls

        # If we hit max iterations, get a final response without tools
        final_response = await litellm.acompletion(
            model=model,
            messages=messages,
            max_tokens=2000,
            temperature=0.7,
        )

        return final_response.choices[0].message.content or "I ran out of steps to complete your request."

    except Exception as e:
        return f"Error communicating with AI: {str(e)}"


async def generate_recipe_yaml(description: str) -> str:
    """
    Generate a YAML recipe based on a natural language description.

    Args:
        description: Natural language description of desired report

    Returns:
        Generated YAML recipe string
    """
    settings = get_settings()

    if not settings.ai_configured:
        return "# AI assistant is not configured"

    prompt = f"""Generate a YAML recipe for fs-report based on this description:

{description}

Generate ONLY the YAML content, no explanation. The recipe must:
1. Have a descriptive name
2. Use the correct endpoint for the data type
3. Include appropriate transforms (flatten, group_by, sort)
4. Specify output format and chart type

Start your response with the YAML directly (no markdown code blocks).
"""

    try:
        import litellm

        # Determine model based on provider
        if settings.ai_provider == "anthropic":
            model = "claude-3-5-sonnet-20241022"
            litellm.api_key = settings.anthropic_api_key
        else:
            model = "gpt-4o"
            litellm.api_key = settings.openai_api_key

        response = await litellm.acompletion(
            model=model,
            messages=[
                {"role": "system", "content": "You are a YAML recipe generator for security reports. Output only valid YAML, no markdown or explanations."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=1500,
            temperature=0.3,
        )

        yaml_content = response.choices[0].message.content

        # Clean up potential markdown code blocks
        if yaml_content.startswith("```"):
            lines = yaml_content.split("\n")
            # Remove first and last lines if they're code fences
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            yaml_content = "\n".join(lines)

        return yaml_content.strip()

    except Exception as e:
        return f"# Error generating recipe: {str(e)}"


def format_response_html(text: str) -> str:
    """
    Format AI response text as HTML with code highlighting.

    Args:
        text: Raw AI response text

    Returns:
        HTML formatted response
    """
    import re

    # Escape HTML
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Format code blocks
    def replace_code_block(match):
        lang = match.group(1) or ""
        code = match.group(2)
        return f'<pre class="bg-gray-100 dark:bg-gray-800 rounded p-3 overflow-x-auto my-2"><code class="language-{lang}">{code}</code></pre>'

    text = re.sub(r"```(\w*)\n(.*?)```", replace_code_block, text, flags=re.DOTALL)

    # Format inline code
    text = re.sub(r"`([^`]+)`", r'<code class="bg-gray-100 dark:bg-gray-800 px-1 rounded text-sm">\1</code>', text)

    # Format markdown links [text](url) -> clickable links
    text = re.sub(
        r'\[([^\]]+)\]\(([^)]+)\)',
        r'<a href="\2" class="text-fs-orange hover:underline">\1</a>',
        text
    )

    # Format bold
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)

    # Format lists (simple bullet points)
    def format_list_item(match):
        return f'<li class="ml-4">{match.group(1)}</li>'

    # Handle bullet lists
    text = re.sub(r"^- (.+)$", format_list_item, text, flags=re.MULTILINE)

    # Wrap consecutive list items in <ul>
    text = re.sub(
        r'((?:<li[^>]*>.*?</li>\s*)+)',
        r'<ul class="list-disc mb-2">\1</ul>',
        text,
        flags=re.DOTALL
    )

    # Format paragraphs
    paragraphs = text.split("\n\n")
    formatted_paragraphs = []
    for p in paragraphs:
        p = p.strip()
        if p:
            # Don't wrap if already wrapped in block elements
            if not p.startswith('<pre') and not p.startswith('<ul') and not p.startswith('<li'):
                p = f"<p class='mb-2'>{p}</p>"
            formatted_paragraphs.append(p)
    text = "".join(formatted_paragraphs)

    # Format line breaks within paragraphs (but not in code blocks)
    # Split by pre tags to avoid breaking code blocks
    parts = re.split(r'(<pre.*?</pre>)', text, flags=re.DOTALL)
    for i, part in enumerate(parts):
        if not part.startswith('<pre'):
            parts[i] = part.replace("\n", "<br>")
    text = "".join(parts)

    return text
