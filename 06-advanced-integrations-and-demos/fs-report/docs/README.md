# Documentation Directory

This directory contains project documentation organized by topic.

## Structure

- `api/` - API documentation and specifications
- `decisions/` - Architecture Decision Records (ADRs)
- `internal/` - Internal documentation and audits
- `migration/` - Migration guides and strategic documents
- `recipes/` - Recipe documentation, requirements, and guides
- `transforms/` - Transform-specific documentation

## Documentation Categories

### Architecture Decision Records
The `decisions/` directory contains detailed documentation of all significant design decisions:
- `001-architecture.md` - Core architecture (recipe system, pandas-only, execution order)
- `002-api-client.md` - API client (pagination, caching, retry logic)
- `003-data-models.md` - Data models (Pydantic schemas, finding types)
- `004-transforms.md` - Transform system (aggregations, custom functions)
- `005-scan-analysis.md` - Scan analysis domain (status interpretation, duration)
- `006-findings.md` - Findings retrieval (scoping, batching, filtering)
- `007-rendering.md` - Rendering (templates, Chart.js, multi-format)
- `008-cli.md` - CLI design (period parsing, exit codes)

### API Documentation
- `API_wishlist.md` - API feature requests and improvements

### Migration Documentation
- `ARCHIVE_SUMMARY.md` - Summary of archived features (PDF removal)
- `narrative.md` - Project narrative and context

### Recipe Documentation
- `CUSTOM_REPORT_GUIDE.md` - Guide for creating custom reports
- `RECIPE_QUICK_REFERENCE.md` - Quick reference for recipe syntax and API endpoints
- `RECIPE_TUTORIAL.md` - Tutorial for writing recipes
- `*_REQUIREMENTS.md` - Requirements for each recipe/report (formerly in transforms)

### Available Reports (6 total)
1. **Executive Summary** - High-level security dashboard for leadership
2. **Component Vulnerability Analysis** - Portfolio-wide component risk analysis
3. **Findings by Project** - Detailed security findings inventory
4. **Scan Analysis** - Scanning infrastructure performance with throughput, failure analysis, version tracking, and new vs existing project metrics
5. **Component List** - Complete software component inventory (SBOM)
6. **User Activity** - Platform usage and user engagement tracking

## Key Documents

### Architecture Decisions
- `decisions/README.md` - Overview and index of all architecture decisions
- `decisions/001-architecture.md` - Core architectural choices and rationale

### Strategic Documents
- `migration/narrative.md` - Project context and strategic direction

### User Guides
- `recipes/CUSTOM_REPORT_GUIDE.md` - How to create custom reports
- `recipes/RECIPE_TUTORIAL.md` - Step-by-step recipe creation

### Technical Documentation
- `decisions/` - Detailed technical decisions with alternatives and consequences
- `recipes/*_REQUIREMENTS.md` - Technical requirements for implemented reports
- `internal/REFACTOR_AUDIT.md` - Template refactoring documentation
- `PERFORMANCE_GUIDE.md` - Caching, filtering, and performance optimization

---

*Note: MTTR-related documentation is not present due to current API limitations regarding resolution timestamps. This documentation directory is up to date with the current project scope.* 