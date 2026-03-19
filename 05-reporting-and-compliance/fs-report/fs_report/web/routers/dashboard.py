"""Dashboard page router."""

from fastapi import APIRouter, Depends, Request

from fs_report.cli.common import redact_token
from fs_report.recipe_loader import RecipeLoader
from fs_report.web.dependencies import get_nonce, get_state
from fs_report.web.state import WebAppState

router = APIRouter(tags=["pages"])

WORKFLOWS = [
    {
        "id": "executive-dashboard",
        "title": "Executive Dashboard",
        "icon": "\U0001f4ca",
        "description": "Single-page security posture overview with 11 visualizations",
        "recipes": ["executive dashboard"],
    },
    {
        "id": "operational",
        "title": "Operational Reports",
        "icon": "\U0001f4c8",
        "description": "Operational reports: summary, scan analysis, user activity",
        "recipes": ["executive summary", "scan analysis", "user activity"],
    },
    {
        "id": "cve",
        "title": "CVE Investigation",
        "icon": "\U0001f50d",
        "description": "Deep-dive into specific CVEs across your portfolio",
        "recipes": ["cve impact"],
    },
    {
        "id": "triage",
        "title": "Triage & Prioritize",
        "icon": "\U0001f3af",
        "description": "AI-prioritized findings for a single project",
        "recipes": ["triage prioritization"],
    },
    {
        "id": "remediation",
        "title": "Remediation Package",
        "icon": "\U0001f527",
        "description": "AI-generated fix guidance for a project\u2019s vulnerabilities",
        "recipes": ["remediation package"],
    },
    {
        "id": "component-analysis",
        "title": "Component Vuln Analysis",
        "icon": "\U0001f6e1",
        "description": "Vulnerability analysis for components in a project",
        "recipes": ["component vulnerability analysis"],
    },
    {
        "id": "findings",
        "title": "Export Findings",
        "icon": "\U0001f4cb",
        "description": "Export all findings for selected projects",
        "recipes": ["findings by project"],
    },
    {
        "id": "components",
        "title": "Export Components",
        "icon": "\U0001f4e6",
        "description": "Export components and licenses for a project",
        "recipes": ["component list"],
    },
    {
        "id": "compare",
        "title": "Compare Versions",
        "icon": "\U0001f500",
        "description": "What changed between two firmware versions?",
        "recipes": ["version comparison"],
    },
    {
        "id": "license",
        "title": "License Report",
        "icon": "\U0001f4dc",
        "description": "License risk classification across your components",
        "recipes": ["license report"],
    },
    {
        "id": "cra-compliance",
        "title": "CRA Compliance",
        "icon": "\U0001f1ea\U0001f1fa",
        "description": "EU Cyber Resilience Act — exploited and KEV-listed vulnerabilities requiring regulatory notification",
        "recipes": ["cra compliance"],
    },
    {
        "id": "component-impact",
        "title": "Component Impact",
        "icon": "\U0001f4e6",
        "description": "Portfolio blast radius for a named component — all affected projects, versions, and findings",
        "recipes": ["component impact"],
    },
    {
        "id": "component-remediation",
        "title": "Component Remediation",
        "icon": "\U0001f6e1",
        "description": "Zero-day remediation guidance for a vulnerable component — upgrade paths, ecosystem health, interim mitigations",
        "recipes": ["component remediation package"],
    },
    {
        "id": "security-progress",
        "title": "Security Progress",
        "icon": "\U0001f4c8",
        "description": "Security posture improvement over time — severity delta, triage funnel snapshot, and finding trends",
        "recipes": ["security progress"],
    },
    {
        "id": "scan-quality",
        "title": "Scan Quality",
        "icon": "\U0001f50e",
        "description": "Per-asset scan coverage and quality signals — scan type gaps and reachability unknowns",
        "recipes": ["scan quality"],
    },
    {
        "id": "false-positive-analysis",
        "title": "False Positive Analysis",
        "icon": "\U0001f9ea",
        "description": "Analyze false positive patterns and surface likely FP candidates. Enable AI for LLM applicability verdicts.",
        "recipes": ["false positive analysis"],
    },
]


@router.get("/")
async def dashboard(
    request: Request,
    state: WebAppState = Depends(get_state),
    nonce: str = Depends(get_nonce),
) -> object:
    """Render the main dashboard page."""
    # Redirect to setup if not configured
    if not state.has_config:
        from starlette.responses import RedirectResponse

        return RedirectResponse(url="/setup")

    # Load recipes
    loader = RecipeLoader(use_bundled=True)
    try:
        recipe_list = loader.load_recipes()
    except Exception:
        recipe_list = []

    recipes = [
        {
            "name": r.name,
            "category": r.category or "Uncategorized",
            "auto_run": r.auto_run,
            "description": r.description or "",
        }
        for r in recipe_list
    ]

    token_display = redact_token(state.token) if state.token else "(not set)"

    # Saved recipe selection from last run (persisted in config.yaml)
    saved_recipes = state.get("selected_recipes") or []

    templates = request.app.state.templates
    return templates.TemplateResponse(
        "pages/dashboard.html",
        {
            "request": request,
            "nonce": nonce,
            "state": state,
            "token_display": token_display,
            "workflows": WORKFLOWS,
            "recipes": recipes,
            "saved_recipes": saved_recipes,
        },
    )
