# Component Vulnerability Analysis (CVA) Report – Requirements for Cursor

## 📌 Purpose

Define the specifications for generating a **Component Vulnerability Analysis (CVA)** report. This report will help users evaluate both **individual project risks** and **portfolio-wide component vulnerabilities**, focusing on a **composite risk score** instead of just finding count.

No implementation should begin until all requirements are clarified and approved.

---

## 🧭 Narrative Context

The Component Vulnerability Analysis provides a **focused view of the most problematic components across the entire portfolio**. By joining findings data to components and calculating composite risk scores, this report identifies the **highest-risk components requiring immediate attention and remediation**.

There are **two essential ways to view the data**, and the report must include both:

### 🔍 Project-Level View (Component Instance Risk)

Each instance of a component used within a project should be considered a distinct source of risk. For example, if **Linux 4.1.2** appears in 5 different projects, then each of those 5 instances should be displayed and assessed separately. This allows project-specific severity and exposure context to be captured.

### 🧮 Portfolio-Level View (Aggregated Component Risk)

In addition to the project-level view, the report must include an **aggregated risk analysis across the portfolio**. Using the same Linux 4.1.2 example, the report should show **the total risk that this component introduces to the organization**, regardless of the number of projects it’s used in. This aggregated view helps prioritize remediation of components with wide impact or those used in mission-critical systems.

---

## ✅ Current State Summary

* Existing report uses **finding count**, not a calculated **composite risk score**.
* The recipe currently references the `risk_score` field but may not calculate it correctly.
* The report displays:

  * Individual project views
  * Portfolio-wide impact summaries

---

## 🔗 API Specification

All data for this report must be sourced using the official **Finite State API**, as defined in the project's **`swagger.json`** file, which lives in the **root directory** of the report project.

Cursor developers must:

* Use the `swagger.json` spec as the **source of truth** for field names, endpoints, and capabilities
* Respect filtering, sorting, and pagination semantics as defined in the spec
* Use endpoints including:

  * `/public/v0/components`
  * `/public/v0/findings`
  * `/public/v0/projects`
  * `/public/v0/versions/{versionId}/components`
  * `/public/v0/versions/{versionId}/findings`

### 🛠 Data Access Strategy

Depending on API capabilities and performance:

* Use server-side filtering when available and performant
* When necessary, **pull full datasets** and filter client-side
* When working with nested structures or cross-referencing relationships (e.g., findings → components → projects), leverage the existing **flatter** tool to flatten complex joins and simplify downstream processing

---

## 📊 Visualization Strategy

To support actionable risk triage and prioritization, the report should include **three primary visualizations**:

### 1. 🔢 Top Risk Components — Pareto Chart

* **Chart Type**: Bar + Cumulative Line
* **X-axis**: Components sorted by risk
* **Y-axis**: Composite risk score (bars), cumulative risk % (line)
* **Goal**: Show which components contribute disproportionately to total risk
* **Special Markers**:

  * `🔒` icon if the component has a KEV-listed finding
  * `💥` icon if any finding has a known exploit

### 2. 🎯 Scope vs Severity — Bubble Matrix

* **Chart Type**: Scatter Plot or Bubble Chart
* **X-axis**: Composite risk score
* **Y-axis**: Number of projects affected
* **Bubble Size**: Finding count or severity weighting
* **Goal**: Visualize broad vs deep impact across the portfolio

### 3. 🧱 Project Aggregation — Treemap

* **Chart Type**: Treemap
* **Block Size**: Composite risk score
* **Grouping**: By component (default) or project (optional)
* **Goal**: Show where risk is concentrated structurally

All charts must:

* Be limited to **Top 20 components** by composite risk
* Be clearly labeled and ranked
* Use consistent **colorblind-safe** severity mapping (e.g., distinct patterns or shapes)
* Be exportable for inclusion in HTML, CSV, and XLSX reports

---

## 🔄 Fallback Visualization Strategy

If the data needed for the primary visualization is not available or meaningful, fall back to a simplified format that preserves the intent:

### Pareto Chart → Basic Bar Chart

* Use if composite scores or cumulative logic is unavailable
* Sort by severity or finding count instead

### Bubble Matrix → Vertical Scatter or Risk Table

* Use vertical scatterplot if project count is missing
* Use a table with sortable columns for severity, count, and usage scope
* Alternative: Lollipop or segmented bar for ranked severity

### Treemap → Grouped Horizontal Bar Chart

* Use if project or component group metadata is missing
* Horizontal bars grouped by component or project with color-coded severity

Fallbacks should be used **only as needed** and clearly annotated in the report output.

---

## ✅ Clarified Requirements

### 1. 📊 Data Sources

* The report must pull from **both** the `/components` and `/findings` endpoints.
* The `/components` endpoint provides severity breakdowns; the `/findings` endpoint provides project associations and vulnerability-specific details.
* Project metadata from the `/projects` endpoint must be included to apply filters (e.g., for archived projects).
* **Archived projects must be filtered out manually**, by excluding associated findings, due to an API limitation that includes findings from archived projects.
* **Multiple API calls will be required** due to API behavior. For example, when querying findings, status information is only included when filtering on status. We will need to:
  * Make a call for all issues without a filter to get complete data
  * Make additional calls with specific filters (e.g., status filters)
  * Join the results to create a complete dataset
* The `/versions` endpoints may be helpful for future enhancements (e.g., tracking changes over time) but are optional unless a valuable use case is identified.

### 2. ⚠️ Risk Score Calculation

The composite risk score must be derived from multiple factors sourced from both endpoints:

#### From `/components`:

* Total counts of findings by severity (`critical`, `high`, `medium`, `low`, etc.)
* Optional: apply severity weights (e.g., `critical=5`, `high=3`, etc.) to compute a weighted severity score

#### From `/findings`:

* `risk` (numerical risk score assigned per finding)
* `epssScore` and `epssPercentile` (likelihood of exploitation)
* `reachabilityScore` (prioritization score, may be positive, negative, or zero)
* `inKev` and `inVcKev` (indicators of inclusion in known exploited vulnerability lists)
* `hasKnownExploit` (whether active exploit has been observed)

#### Weighting Guidance (Tunable in Recipe):

| Factor                    | Weight Impact                               |
| ------------------------- | ------------------------------------------- |
| `hasKnownExploit=true`    | +40 to composite risk                       |
| `inKev` or `inVcKev=true` | +30                                         |
| `reachabilityScore > 0`   | +20% multiplier on that finding’s score     |
| `reachabilityScore < 0`   | -20% multiplier                             |
| `epssPercentile > 0.95`   | +10                                         |
| `risk` (raw)              | Used as-is as a base metric                 |
| Severity Weights          | `critical=5`, `high=3`, `medium=2`, `low=1` |

**Note**: This weighting is a starting point and open to modification as we progress through implementation. All weights and thresholds must be **configurable via the recipe** so future customers can tune based on internal risk criteria.

### 3. 🧱 Report Structure

* Maintain the dual view format:

  * **Project-level risk view** (each component/project instance)
  * **Portfolio-level aggregation** (combined impact of shared components)
* **All three primary visualizations should be implemented first**:

  * Pareto bar chart (top contributors to risk)
  * Bubble matrix (severity vs scope)
  * Treemap (component clustering)
* Tables should include sortable columns for:

  * Component name
  * Affected projects
  * Finding count
  * Composite score
  * Highest severity
  * Exploit/KEV flags

### 4. 🧮 Filtering & Aggregation

* Components should be filterable by:

  * Minimum composite risk score threshold
  * Severity level
  * Component type (library, OS, etc.)
  * Project usage
* Grouping logic should allow:

  * Component/project pairs (instance view)
  * Component-only aggregation (portfolio view)
* Support both full lists and limited top-N cutoffs (e.g., Top 20 riskiest components)

### 5. 📤 Output Format Requirements

* Required export formats:

  * HTML (for human consumption)
  * CSV (for detailed data analysis)
  * XLSX (optional — confirm stakeholder need)
* Formatting:

  * Severity color codes (CRITICAL=red, HIGH=orange, etc.)
  * Clearly labeled tables with export timestamps
  * Use colorblind-accessible palettes and patterns

---

## 🔜 Next Steps

1. **Create sample data** that mimics the real API structure to test the composite risk score calculation
2. **Create a test script** similar to the other testing scripts in the project to validate the implementation
3. **Implement all three primary visualizations** (Pareto chart, bubble matrix, treemap)
4. **Test with sample data** before connecting to live APIs
5. **Iterate on weighting and calculations** based on testing results

---

## 📝 Additional Notes

* **No code will be written** until you give the go-ahead
* **No existing functionality** will be removed without explicit approval
* Cursor scripts should be **modular** and **testable**
* Visualizations should default to **matplotlib** or **Plotly** (TBD)
* **Testing approach**: Create sample data that mimics the real API structure and create a test script similar to the other testing scripts in the project

---

## 📣 Customer Pitch *(for inclusion in narrative.md)*

### 🎯 **Pitch: Take Action on the Riskiest Components Across Your Portfolio**

**"The Component Vulnerability Analysis Report is your fast lane to risk reduction."**

Modern software portfolios often contain hundreds of open-source components reused across many projects. Managing them individually is overwhelming — and often results in teams chasing noise instead of tackling what’s dangerous.

This report changes that by **spotlighting the exact components that pose the highest real-world risk to your business.**

---

### 🧠 **What makes it different?**

Unlike most vulnerability reports that simply count issues, this one:

* **Joins components to findings and projects**, giving you **context-rich insights**
* Calculates a **composite risk score** based on:

  * CVSS-like numeric risk
  * KEV presence (mandated by federal guidance)
  * Known exploits (a signal of active weaponization)
  * Reachability analysis (can attackers actually hit this code?)
  * Prevalence across your codebase

> 🔒 “A vulnerability with known exploits, in KEV, and reachable by attackers is 10x scarier than a high CVSS issue buried in unused code.”

---

### 📊 **How to use the visuals**

* **🔢 Pareto Chart**:
  Instantly see which components contribute **most of your total risk**. Most orgs find that **\~20% of components account for 80%+ of risk**. These are your first remediation candidates.

* **🎯 Bubble Matrix**:
  Find the high-severity vulnerabilities that are **widespread**. The bigger and further right a bubble is, the more urgent it becomes — especially if it has exploit flags. This lets you **balance depth vs breadth** of exposure.

* **🧱 Treemap**:
  Understand where risk clusters. Do a few legacy projects carry most of your exposure? Are certain components like zlib or log4j hiding across the portfolio?

All visuals are **colorblind-friendly**, clearly labeled, and easy to export to HTML, CSV, or Excel.

---

### ✅ **What actions can I take?**

| Finding                        | Action                                                   |
| ------------------------------ | -------------------------------------------------------- |
| High-risk component in KEV     | Patch or replace immediately — trackable compliance risk |
| Component w/ 10+ project usage | Prioritize centrally and fix once — high ROI remediation |
| Reachable + Exploitable vuln   | Alert engineering + SOC for review — active threat       |
| Low-score, legacy component    | Defer or deprioritize — good candidate for backlog       |

---

### 🛡️ **Bottom line:**

**This report helps you reduce software supply chain risk fast**, with **targeted, justifiable actions** backed by multiple dimensions of severity, exploitability, and exposure.

It’s not just about what’s broken — it’s about what’s dangerous.
