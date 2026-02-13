# Customer-Facing Repository Checklist

This checklist identifies all files that must be included in the customer-facing repository for `fs-report` to function properly.

## ✅ Core Application Code

### Python Package (`fs_report/`)
- [ ] `fs_report/__init__.py`
- [ ] `fs_report/api_client.py`
- [ ] `fs_report/cli.py`
- [ ] `fs_report/data_cache.py`
- [ ] `fs_report/data_transformer.py`
- [ ] `fs_report/models.py`
- [ ] `fs_report/period_parser.py`
- [ ] `fs_report/recipe_loader.py`
- [ ] `fs_report/llm_client.py`
- [ ] `fs_report/report_engine.py`
- [ ] `fs_report/report_renderer.py`
- [ ] `fs_report/sqlite_cache.py`
- [ ] `fs_report/renderers/__init__.py`
- [ ] `fs_report/renderers/chart_renderer.py`
- [ ] `fs_report/renderers/csv_renderer.py`
- [ ] `fs_report/renderers/html_renderer.py`
- [ ] `fs_report/renderers/report_renderer.py`
- [ ] `fs_report/renderers/xlsx_renderer.py`
- [ ] `fs_report/transforms/__init__.py`
- [ ] `fs_report/transforms/pandas/__init__.py`
- [ ] `fs_report/transforms/pandas/component_vulnerability_analysis.py`
- [ ] `fs_report/transforms/pandas/executive_scan_frequency_transform.py`
- [ ] `fs_report/transforms/pandas/findings_by_project.py`
- [ ] `fs_report/transforms/pandas/scan_analysis.py`
- [ ] `fs_report/transforms/pandas/triage_prioritization.py`
- [ ] `fs_report/transforms/pandas/component_list.py`
- [ ] `fs_report/transforms/pandas/user_activity.py`

## ✅ Recipe Files (`recipes/`)

- [ ] `recipes/component_vulnerability_analysis.yaml`
- [ ] `recipes/executive_summary.yaml`
- [ ] `recipes/findings_by_project.yaml`
- [ ] `recipes/scan_analysis.yaml`
- [ ] `recipes/triage_prioritization.yaml`
- [ ] `recipes/component_list.yaml`
- [ ] `recipes/user_activity.yaml`
- [ ] `recipes/README.md` (recipe overview)
- [ ] `recipes/_TEMPLATE.yaml` (template for new recipes)

## ✅ Template Files (`templates/`)

- [ ] `templates/bar_chart.html`
- [ ] `templates/base.html`
- [ ] `templates/component_vulnerability_analysis.html`
- [ ] `templates/executive_summary.html`
- [ ] `templates/findings_by_project.html`
- [ ] `templates/line_chart.html`
- [ ] `templates/pie_chart.html`
- [ ] `templates/scan_analysis.html`
- [ ] `templates/scatter_chart.html`
- [ ] `templates/triage_prioritization.html`
- [ ] `templates/table.html`
- [ ] `templates/component_list.html`
- [ ] `templates/user_activity.html`

## ✅ Scripts (`scripts/`)

- [ ] `scripts/apply_vex_triage.py` (applies VEX triage recommendations from the Triage Prioritization report to the platform)

## ✅ Configuration Files

- [ ] `pyproject.toml` (required for Poetry dependency management)
- [ ] `poetry.lock` (required for reproducible builds)
- [ ] `LICENSE` (Apache 2.0 license file)

## ✅ Documentation

- [ ] `README.md` (main project documentation)
- [ ] `RELEASE_NOTES.md` (version history and new features)
- [ ] `REPORT_GUIDE.md` (scoring methodology and report reference)
- [ ] `CUSTOMER_SETUP.md` (customer setup and usage guide)

## ✅ Custom Report Documentation

For customers who want to create custom reports (placed in `recipes/` for discoverability):

- [ ] `recipes/CUSTOM_REPORT_GUIDE.md` (comprehensive custom report guide with security considerations)
- [ ] `recipes/RECIPE_QUICK_REFERENCE.md` (quick reference for recipe syntax)

## ✅ Docker Files (if distributing via Docker)

- [ ] `Dockerfile` (for building Docker images)
- [ ] `docker-compose.yml` (optional, for Docker Compose usage)

## ❌ Files to EXCLUDE

Do **NOT** include these in the customer-facing repository:

- [ ] `dev/` directory (internal development files)
- [ ] `docs/` directory (internal documentation)
- [ ] `tests/` directory (test files)
- [ ] `scripts/` directory (internal scripts — **except** `apply_vex_triage.py` which IS included above)
- [ ] `examples/` directory (example outputs)
- [ ] `mytest/` directory (test outputs)
- [ ] `output/` directory (generated outputs)
- [ ] `dist/` directory (build artifacts)
- [ ] `htmlcov/` directory (coverage reports)
- [ ] `asset-watch/` directory (internal tooling)
- [ ] `transforms/` directory (root-level legacy directory - transforms are in `fs_report/transforms/`)
- [ ] `.git/` directory
- [ ] `__pycache__/` directories
- [ ] `*.pyc` files
- [ ] `.pytest_cache/` directory
- [ ] `.mypy_cache/` directory
- [ ] `.venv/` or `venv/` directories
- [ ] `dev/CHANGELOG.md` (internal development changelog)
- [ ] Any files with `.sha256` extensions (checksums)

## 📦 Package Distribution Notes

### For Poetry Package Distribution
When creating a distribution package (wheel or source distribution), Poetry automatically includes:
- All files listed in `pyproject.toml` under `[tool.poetry]` → `include`
- All Python packages listed under `packages`
- Files explicitly listed in `include` array:
  - `recipes/**/*`
  - `templates/**/*`
  - `LICENSE`
  - `README.md`
  - `Dockerfile`
  - `docker-compose.yml`

### For Docker Distribution
The `Dockerfile` copies:
- `pyproject.toml` and `poetry.lock`
- `README.md`
- `fs_report/` directory
- `templates/` directory
- `recipes/` directory

### For Git Repository Distribution
Include all files listed in the "Core Application Code", "Recipe Files", "Template Files", "Configuration Files", and "Documentation" sections above.

## 🔍 Verification Steps

After copying files, verify:

1. **Python package structure**:
   ```bash
   python -c "import fs_report; print('OK')"
   ```

2. **Recipe files accessible**:
   ```bash
   ls recipes/*.yaml
   ```

3. **Templates accessible**:
   ```bash
   ls templates/*.html
   ```

4. **Dependencies installable**:
   ```bash
   poetry install --dry-run
   ```

5. **CLI executable**:
   ```bash
   poetry run fs-report --help
   ```

## 📝 Quick Copy Command

If using a Unix-like system, you can use this command to copy the essential files (adjust paths as needed):

```bash
# Set the target directory (adjust path as needed)
TARGET="../customer-resources/05-reporting-and-compliance/fs-report"

# From the fs-report project root
rsync -av --delete fs_report/ "$TARGET/fs_report/"
rsync -av --delete recipes/ "$TARGET/recipes/"
rsync -av --delete templates/ "$TARGET/templates/"

# Single files
cp pyproject.toml poetry.lock LICENSE README.md "$TARGET/"
cp RELEASE_NOTES.md CUSTOMER_SETUP.md REPORT_GUIDE.md "$TARGET/"
cp Dockerfile docker-compose.yml "$TARGET/"

# Scripts (selective)
mkdir -p "$TARGET/scripts"
cp scripts/apply_vex_triage.py "$TARGET/scripts/"

# Custom report documentation (into recipes/ directory)
cp docs/recipes/CUSTOM_REPORT_GUIDE.md "$TARGET/recipes/"
cp docs/recipes/RECIPE_QUICK_REFERENCE.md "$TARGET/recipes/"
```

## 🎯 Minimum Required Files

For a minimal working installation, you need at minimum:
- All files in `fs_report/` directory
- All files in `recipes/` directory
- All files in `templates/` directory
- `pyproject.toml`
- `poetry.lock`
- `LICENSE`

