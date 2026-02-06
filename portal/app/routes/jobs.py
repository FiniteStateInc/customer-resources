"""Jobs route - history and status."""

import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_session, Job

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).parent.parent / "templates")


@router.get("/", response_class=HTMLResponse)
async def list_jobs(
    request: Request,
    session: AsyncSession = Depends(get_session),
    status: Optional[str] = None,
):
    """List all jobs with optional filtering."""
    settings = get_settings()

    query = select(Job).order_by(desc(Job.created_at))
    if status:
        query = query.where(Job.status == status)

    result = await session.execute(query)
    jobs = result.scalars().all()

    return templates.TemplateResponse(
        "jobs.html",
        {
            "request": request,
            "active_page": "jobs",
            "fs_connected": settings.finite_state_configured,
            "ai_enabled": settings.ai_configured,
            "jobs": jobs,
            "filter_status": status,
        },
    )


@router.get("/{job_id}", response_class=HTMLResponse)
async def job_detail(
    request: Request,
    job_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Show job detail and output."""
    settings = get_settings()

    result = await session.execute(select(Job).where(Job.id == job_id))
    job = result.scalar_one_or_none()

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    # Get output files if available (recursively search subdirectories)
    output_files = []
    if job.output_path and os.path.exists(job.output_path):
        output_dir = Path(job.output_path)
        if output_dir.is_dir():
            # Recursively find all files
            for f in output_dir.rglob("*"):
                if f.is_file():
                    # Get relative path from output_dir for display
                    rel_path = f.relative_to(output_dir)
                    output_files.append({
                        "name": str(rel_path),
                        "size": f.stat().st_size,
                        "path": str(f)
                    })

    return templates.TemplateResponse(
        "job_detail.html",
        {
            "request": request,
            "active_page": "jobs",
            "fs_connected": settings.finite_state_configured,
            "ai_enabled": settings.ai_configured,
            "job": job,
            "output_files": output_files,
        },
    )


@router.get("/{job_id}/status", response_class=HTMLResponse)
async def job_status(
    request: Request,
    job_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Get job status partial for HTMX polling."""
    result = await session.execute(select(Job).where(Job.id == job_id))
    job = result.scalar_one_or_none()

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    return templates.TemplateResponse(
        "components/job_status.html",
        {
            "request": request,
            "job": job,
        },
    )


@router.get("/{job_id}/download/{filename:path}")
async def download_output(
    job_id: str,
    filename: str,
    session: AsyncSession = Depends(get_session),
):
    """Download a job output file."""
    result = await session.execute(select(Job).where(Job.id == job_id))
    job = result.scalar_one_or_none()

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if not job.output_path:
        raise HTTPException(status_code=404, detail="No output available")

    # Build file path and verify it's within the output directory
    output_dir = Path(job.output_path).resolve()
    file_path = (output_dir / filename).resolve()

    # Security: ensure the file is within the output directory (prevent path traversal)
    if not str(file_path).startswith(str(output_dir)):
        raise HTTPException(status_code=403, detail="Access denied")

    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    # Use just the filename for download (not the full path)
    safe_filename = file_path.name

    # Determine media type based on file extension
    extension = file_path.suffix.lower()
    media_types = {
        ".pdf": "application/pdf",
        ".html": "text/html",
        ".csv": "text/csv",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".json": "application/json",
        ".txt": "text/plain",
    }
    media_type = media_types.get(extension, "application/octet-stream")

    return FileResponse(
        path=str(file_path),
        media_type=media_type,
        filename=safe_filename,
    )


@router.delete("/{job_id}", response_class=HTMLResponse)
async def delete_job(
    request: Request,
    job_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Delete a job and its output files."""
    result = await session.execute(select(Job).where(Job.id == job_id))
    job = result.scalar_one_or_none()

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    # Delete output files
    if job.output_path and os.path.exists(job.output_path):
        import shutil
        shutil.rmtree(job.output_path, ignore_errors=True)

    # Delete job record
    await session.delete(job)
    await session.commit()

    # Return empty string - HTMX will remove the element
    return ""


@router.post("/bulk-delete", response_class=HTMLResponse)
async def bulk_delete_jobs(
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    """Delete multiple jobs at once."""
    import shutil

    form_data = await request.form()
    job_ids = form_data.getlist("job_ids")

    if not job_ids:
        raise HTTPException(status_code=400, detail="No jobs selected")

    deleted_count = 0
    for job_id in job_ids:
        result = await session.execute(select(Job).where(Job.id == job_id))
        job = result.scalar_one_or_none()

        if job:
            # Delete output files
            if job.output_path and os.path.exists(job.output_path):
                shutil.rmtree(job.output_path, ignore_errors=True)

            # Delete job record
            await session.delete(job)
            deleted_count += 1

    await session.commit()

    # Return updated job list
    result = await session.execute(select(Job).order_by(desc(Job.created_at)))
    jobs = result.scalars().all()

    return templates.TemplateResponse(
        "components/job_list.html",
        {
            "request": request,
            "jobs": jobs,
            "deleted_count": deleted_count,
        },
    )
