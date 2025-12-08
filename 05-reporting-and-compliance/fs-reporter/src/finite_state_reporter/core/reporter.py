#!/usr/bin/env python3
"""
Finite State Risk Reporter

Enhanced version with professional PDF styling, fonts, and layout matching the platform design.
Generates comprehensive risk summary reports from Finite State API data.

Usage:
    python finite_state_reporter.py --version-id 4591589327354492634 --subdomain acme --api-key YOUR_API_KEY
"""

import logging
import os
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List

import matplotlib.pyplot as plt
import requests
from reportlab.lib.units import inch
from reportlab.platypus import Image, NextPageTemplate, PageBreak, Paragraph, Spacer

VERSION = 0.3

# Import our enhanced styling modules
from ..pdf import colors, flowables, page_templates, styles

# Register fonts first
styles.register_fonts()

# Get professional stylesheet
_stylesheet = styles.get_stylesheet()

# Configuration constants
VULNERABILITY_BATCH_SIZE = (
    1000  # Number of vulnerabilities to fetch in each batch API call
)
API_PAGE_SIZE = 5000  # Number of items to fetch per page for subdomain API calls


class FiniteStateReporter:
    """Enhanced Finite State API client with professional PDF generation."""

    def __init__(self, subdomain: str, api_key: str):
        self.subdomain = subdomain  # Store subdomain for later use
        self.base_url = f"https://{subdomain}.finitestate.io/api"
        self.headers = {"X-Authorization": api_key, "Content-Type": "application/json"}
        self.session = requests.Session()
        self.session.headers.update(self.headers)

        # Setup temporary directory for chart images
        self.temp_dir = tempfile.mkdtemp(prefix="finite_state_charts_")
        self.temp_files = []

        # Setup logging
        logging.basicConfig(
            level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
        )
        self.logger = logging.getLogger(__name__)

    def get_all_projects(self) -> List[dict]:
        """Get all projects with pagination."""
        projects = []
        offset = 0
        limit = API_PAGE_SIZE

        while True:
            url = f"{self.base_url}/public/v0/projects"
            params = {"offset": offset, "limit": limit}

            self.logger.info(f"Fetching projects: offset={offset}, limit={limit}")
            response = self.session.get(url, params=params)
            response.raise_for_status()

            data = response.json()
            # Handle both list and dict responses
            if isinstance(data, list):
                batch = data
                total = len(data)
            else:
                batch = data.get("items", [])
                total = data.get("total", 0)
            
            projects.extend(batch)

            # Check if we've got all items or if there are more pages
            current_count = offset + len(batch)
            if current_count >= total or len(batch) < limit:
                break
            offset += limit

        self.logger.info(f"Retrieved {len(projects)} projects")
        return projects

    def get_project_versions(self, project_id: str) -> List[dict]:
        """Get all versions for a project with pagination."""
        versions = []
        offset = 0
        limit = API_PAGE_SIZE

        while True:
            url = f"{self.base_url}/public/v0/projects/{project_id}/versions"
            params = {"offset": offset, "limit": limit}

            self.logger.info(
                f"Fetching versions for project {project_id}: offset={offset}, limit={limit}"
            )
            response = self.session.get(url, params=params)
            response.raise_for_status()

            data = response.json()
            # Handle both list and dict responses
            if isinstance(data, list):
                batch = data
                total = len(data)
            else:
                batch = data.get("items", [])
                total = data.get("total", 0)
            
            versions.extend(batch)

            # Check if we've got all items or if there are more pages
            current_count = offset + len(batch)
            if current_count >= total or len(batch) < limit:
                break
            offset += limit

        self.logger.info(f"Retrieved {len(versions)} versions for project {project_id}")
        return versions

    def lookup_version_id_by_names(self, project_name: str, version_name: str) -> str:
        """Lookup version ID by project name and version name.

        Args:
            project_name: The name of the project
            version_name: The name of the version

        Returns:
            The version ID as a string

        Raises:
            ValueError: If project or version cannot be found
        """
        self.logger.info(
            f"Looking up version ID for project '{project_name}' and version '{version_name}'"
        )

        # Use filter to find matching project by name (case-insensitive)
        url = f"{self.base_url}/public/v0/projects"
        filter_param = f"name=ilike={project_name}"
        params = {"filter": filter_param, "limit": API_PAGE_SIZE}

        self.logger.info(f"Fetching project with filter: {filter_param}")
        response = self.session.get(url, params=params)
        response.raise_for_status()

        data = response.json()
        # Handle both list and dict responses
        if isinstance(data, list):
            projects = data
        else:
            projects = data.get("items", [])

        # Find case-insensitive match
        matching_project = None
        for project in projects:
            project_name_in_data = project.get("name")
            if project_name_in_data and project_name_in_data.lower() == project_name.lower():
                matching_project = project
                break

        if not matching_project:
            # If no exact match found, try to get some projects for error message
            all_projects = self.get_all_projects()
            raise ValueError(
                f"Project '{project_name}' not found. Available projects: {', '.join([p.get('name', 'Unknown') for p in all_projects[:10]])}"
            )

        project_id = matching_project.get("id")
        self.logger.info(f"Found project '{project_name}' with ID: {project_id}")

        # Get all versions for the project and find matching version
        versions = self.get_project_versions(project_id)
        self.logger.info(f"Retrieved {len(versions)} versions, checking structure...")
        
        # Debug: log the structure of the first version if available
        if versions:
            self.logger.info(f"Sample version data: {versions[0]}")
        
        matching_version = None

        for version in versions:
            # Handle case where version might be a string or have different structure
            if isinstance(version, dict):
                # API uses 'version' field for version name, not 'name'
                version_name_in_data = version.get("version") or version.get("name") or version.get("versionName")
                if version_name_in_data and version_name_in_data.lower() == version_name.lower():
                    matching_version = version
                    break
            elif isinstance(version, str):
                if version.lower() == version_name.lower():
                    matching_version = {"id": version, "version": version}
                    break

        if not matching_version:
            raise ValueError(
                f"Version '{version_name}' not found in project '{project_name}'"
            )

        version_id = matching_version.get("id")
        self.logger.info(f"Found version '{version_name}' with ID: {version_id}")

        return str(version_id)

    def get_version_details(self, version_id: str) -> dict:
        """Get detailed version information."""
        url = f"{self.base_url}/public/v0/versions/{version_id}"
        self.logger.info(f"Fetching version details: {url}")

        response = self.session.get(url)
        response.raise_for_status()
        return response.json()

    def get_version_components(self, version_id: str) -> List[dict]:
        """Get all components for a version with pagination."""
        components = []
        offset = 0
        limit = API_PAGE_SIZE

        while True:
            url = f"{self.base_url}/public/v0/versions/{version_id}/components"
            params = {"offset": offset, "limit": limit}

            self.logger.info(f"Fetching components: offset={offset}, limit={limit}")
            response = self.session.get(url, params=params)

            # Handle 404 as no components found
            if response.status_code == 404:
                self.logger.info(f"No components found for version {version_id} (404)")
                return []

            response.raise_for_status()

            data = response.json()
            # Handle both list and dict responses
            if isinstance(data, list):
                batch = data
                total = len(data)
            else:
                batch = data.get("items", [])
                total = data.get("total", 0)
            
            components.extend(batch)

            # Check if we've got all items or if there are more pages
            current_count = offset + len(batch)
            if current_count >= total or len(batch) < limit:
                break
            offset += limit

        self.logger.info(f"Retrieved {len(components)} components")
        return components

    def get_version_findings(self, version_id: str) -> List[dict]:
        """Get all findings for a version with pagination."""
        findings = []
        offset = 0
        limit = API_PAGE_SIZE

        while True:
            url = f"{self.base_url}/public/v0/versions/{version_id}/findings"
            params = {"offset": offset, "limit": limit}

            self.logger.info(f"Fetching findings: offset={offset}, limit={limit}")
            response = self.session.get(url, params=params)

            # Handle 404 as no findings found
            if response.status_code == 404:
                self.logger.info(f"No findings found for version {version_id} (404)")
                return []

            response.raise_for_status()

            data = response.json()
            # Handle both list and dict responses
            if isinstance(data, list):
                batch = data
                total = len(data)
            else:
                batch = data.get("items", [])
                total = data.get("total", 0)
            
            findings.extend(batch)

            # Check if we've got all items or if there are more pages
            current_count = offset + len(batch)
            if current_count >= total or len(batch) < limit:
                break
            offset += limit

        self.logger.info(f"Retrieved {len(findings)} findings")
        return findings

    def analyze_severity_distribution(self, findings: List[dict]) -> Dict[str, int]:
        """Analyze severity distribution of findings."""
        severity_counts = defaultdict(int)

        for finding in findings:
            severity = finding.get("severity", "Unknown")
            severity_counts[severity] += 1

        return dict(severity_counts)

    def analyze_component_types(self, components: List[dict]) -> Dict[str, int]:
        """Analyze distribution of component types."""
        type_counts = defaultdict(int)

        for component in components:
            comp_type = component.get("type", "Unknown")
            type_counts[comp_type] += 1

        return dict(type_counts)

    def analyze_component_licenses(self, components: List[dict]) -> Dict[str, int]:
        """Analyze distribution of component license types."""
        license_counts = defaultdict(int)

        for component in components:
            licenses = component.get("licenses", "Unknown")
            if licenses and licenses != "Unknown":
                # Split multiple licenses by common delimiters
                license_list = (
                    licenses.replace(" AND ", ";")
                    .replace(" OR ", ";")
                    .replace(",", ";")
                    .split(";")
                )
                for license_name in license_list:
                    license_name = license_name.strip()
                    if license_name:
                        license_counts[license_name] += 1
            else:
                license_counts["Unknown"] += 1

        return dict(license_counts)

    def get_vulnerability_metadata_batch(
        self, vulnerability_ids: List[str]
    ) -> Dict[str, dict]:
        """Get vulnerability metadata for multiple vulnerabilities in a single batch request."""
        if not vulnerability_ids:
            return {}

        # Use the new alloy vulnerability metadata endpoint
        url = "https://sip.prod-sca.fstate.ninja/v1/alloy/vulnerability_metadata"
        self.logger.info(
            f"Fetching batch vulnerability metadata for {len(vulnerability_ids)} vulnerabilities"
        )

        try:
            # Prepare the request payload with include/exclude fields
            payload = {
                "timestamp": "2021-01-01T00:00:00",  # Default timestamp
                "vulnerability_ids": vulnerability_ids,
                "include": ["id", "summary", "aliases"],
                "exclude": [],
            }

            response = self.session.post(url, json=payload)
            response.raise_for_status()
            data = response.json()

            metadata = {}
            if data.get("status") == "OK" and "data" in data:
                for vuln_data in data["data"]:
                    vuln_id = vuln_data.get("id")
                    if vuln_id:
                        summary = vuln_data.get("summary", "")
                        aliases = vuln_data.get("aliases", [])

                        # Truncate summary to 200 characters with ellipsis
                        if len(summary) > 200:
                            summary = summary[:200] + "..."

                        metadata[vuln_id] = {"summary": summary, "aliases": aliases}
            else:
                self.logger.warning(
                    f"Unexpected response format from vulnerability metadata endpoint: {data}"
                )

            return metadata
        except Exception as e:
            self.logger.warning(f"Could not fetch batch vulnerability metadata: {e}")
            return {
                vuln_id: {"summary": "No description available", "aliases": []}
                for vuln_id in vulnerability_ids
            }

    def get_cve_description(self, finding_id: str) -> str:
        """Get CVE description for a specific finding (legacy method for backward compatibility)."""
        # Extract CVE ID from finding_id if it's not already a CVE ID
        cve_id = finding_id
        if not cve_id.startswith("CVE-"):
            # Try to extract CVE ID from the finding_id
            # This is a fallback for the old method
            url = f"{self.base_url}/public/v0/findings/{finding_id}/cves"
            try:
                response = self.session.get(url)
                response.raise_for_status()
                data = response.json()

                # Extract CVE IDs from the response
                cve_ids = list(data.keys())
                if cve_ids:
                    metadata = self.get_vulnerability_metadata_batch(cve_ids)
                    # Return the first available summary
                    for cve_id, vuln_data in metadata.items():
                        if vuln_data.get("summary") != "No description available":
                            return vuln_data.get("summary", "No description available")
            except Exception as e:
                self.logger.warning(
                    f"Could not fetch CVE description for {finding_id}: {e}"
                )

        # If we have a direct CVE ID, use batch method
        metadata = self.get_vulnerability_metadata_batch([cve_id])
        vuln_data = metadata.get(cve_id, {"summary": "No description available"})
        return vuln_data.get("summary", "No description available")

    def analyze_exploits(self, findings: List[dict]) -> Dict[str, int]:
        """Analyze exploit maturity distribution from findings with exploit info."""
        # Mapping of exploitInfo values to human-readable names
        exploit_mapping = {
            "kev": "In KEV",
            "vcKev": "In VulnCheck KEV",
            "weaponized": "Weaponized",
            "poc": "PoC",
            "threatActors": "Exploited By Threat Actors",
            "ransomware": "Exploited By Ransomware",
            "botnets": "Exploited By Botnet",
            "commercial": "Commercial Exploit",
            "reported": "Reported in the Wild",
        }

        exploit_counts = defaultdict(int)

        for finding in findings:
            exploit_info = finding.get("exploitInfo", [])
            if exploit_info:
                # Use the exploitInfo data directly from the finding
                for exploit_type in exploit_info:
                    # Map to human-readable name
                    readable_name = exploit_mapping.get(
                        exploit_type, exploit_type.title()
                    )
                    exploit_counts[readable_name] += 1

        return dict(exploit_counts)

    def get_reachability_display(self, finding: dict) -> str:
        """Get reachability display string for a finding."""
        reachability_score = finding.get("reachabilityScore", 0) or 0
        if reachability_score > 0:
            return "Reachable"
        elif reachability_score < 0:
            return "Unreachable"
        else:
            return ""  # No indicator for zero/inconclusive scores

    def get_exploit_maturity_display(self, finding: dict) -> str:
        """Get exploit maturity display string for a finding with fire icon."""
        exploit_info = finding.get("exploitInfo", [])
        if not exploit_info:
            return ""

        # Mapping of exploitInfo values to human-readable names
        exploit_mapping = {
            "kev": "In KEV",
            "vcKev": "In VulnCheck KEV",
            "weaponized": "Weaponized",
            "poc": "PoC",
            "threatActors": "Exploited By Threat Actors",
            "ransomware": "Exploited By Ransomware",
            "botnets": "Exploited By Botnet",
            "commercial": "Commercial Exploit",
            "reported": "Reported in the Wild",
        }

        # Get the highest risk exploit type (first in the list is typically highest risk)
        highest_risk_exploit = exploit_info[0] if exploit_info else None
        if highest_risk_exploit:
            readable_name = exploit_mapping.get(
                highest_risk_exploit, highest_risk_exploit.title()
            )

            # Use HTML img tag to embed fire icon inline with text
            emoji_size = 12  # size in points for the fire icon
            # Use absolute path to the fire.png file
            import os

            current_dir = os.path.dirname(os.path.abspath(__file__))
            fire_path = os.path.join(current_dir, "..", "static", "images", "fire.png")
            return f'<img src="{fire_path}" width="{emoji_size}" height="{emoji_size}" valign="middle"/> {readable_name}'

        return ""

    def get_top_risks(self, findings: List[dict], limit: int = 10) -> List[dict]:
        """Get top risk findings sorted by risk score."""
        # Sort by risk score - don't filter by severity since 'none' can have high risk scores

        def get_sort_key(finding):
            risk_score = finding.get("risk", 0)

            # Handle None values
            if risk_score is None:
                risk_score = 0

            # Convert risk score to float if it's a string
            if isinstance(risk_score, str):
                try:
                    risk_score = float(risk_score)
                except:
                    risk_score = 0

            return risk_score

        # Sort by risk score, highest first
        sorted_findings = sorted(findings, key=get_sort_key, reverse=True)
        return sorted_findings[:limit]

    def get_top_risky_components(
        self, components: List[dict], limit: int = 10
    ) -> List[dict]:
        """Get top riskiest components sorted by findings count and severity."""

        def get_risk_score(component):
            # Calculate risk score based on findings count and severity
            findings_count = component.get("findings", 0)
            severity_counts = component.get("severityCounts", {})

            # Weight different severities
            critical_count = severity_counts.get("critical", 0) * 10
            high_count = severity_counts.get("high", 0) * 7
            medium_count = severity_counts.get("medium", 0) * 4
            low_count = severity_counts.get("low", 0) * 1

            # Add policy violations and warnings as additional risk factors
            violations = component.get("violations", 0) * 2
            warnings = component.get("warnings", 0) * 1

            total_risk = (
                critical_count
                + high_count
                + medium_count
                + low_count
                + violations
                + warnings
            )

            return total_risk

        # Sort by risk score, highest first
        sorted_components = sorted(components, key=get_risk_score, reverse=True)
        return sorted_components[:limit]

    def _format_epss_percentile(self, epss_percentile) -> str:
        """Safely format EPSS percentile from string or float as percentage."""
        if epss_percentile is None:
            return "N/A"
        if isinstance(epss_percentile, str):
            try:
                percentile = float(epss_percentile) * 100
                return f"{percentile:.1f}%"
            except (ValueError, TypeError):
                return epss_percentile
        try:
            percentile = float(epss_percentile) * 100
            return f"{percentile:.1f}%"
        except (ValueError, TypeError):
            return "N/A"

    def _format_number_with_commas(self, number: int) -> str:
        """Format a number with commas for better readability."""
        return f"{number:,}"

    def create_enhanced_chart(
        self,
        data: dict,
        chart_type: str,
        title: str,
        width: float = 4 * inch,
        height: float = 3 * inch,
    ) -> Image:
        """Create professional charts with brand colors."""
        self.logger.info(f"Creating {chart_type} chart '{title}' with data: {data}")

        # Set backend explicitly
        import matplotlib

        matplotlib.use("Agg")

        # Create figure with simple dimensions
        fig_width = width / inch
        fig_height = height / inch
        fig, ax = plt.subplots()

        # Set white background
        fig.patch.set_facecolor("white")
        ax.set_facecolor("white")

        if chart_type == "pie":
            # Simple pie chart with proper colors
            labels = []
            values = []
            colors_list = []

            # Define colors for different data types
            severity_colors = {
                "Critical": "#C75037",  # Red
                "High": "#F67D39",  # Orange
                "Medium": "#EECF50",  # Yellow
                "Low": "#4C82D6",  # Blue
                "None": "#8F91A6",  # Gray
                "Unknown": "#8F91A6",  # Gray
            }

            for label, value in data.items():
                if value > 0:
                    labels.append(f"{label.title()} ({value})")
                    values.append(value)
                    # Use severity colors if available, otherwise default blue
                    color = severity_colors.get(label.title(), "#2E86AB")
                    colors_list.append(color)

            if values:
                wedges, _ = ax.pie(values, colors=colors_list, startangle=90)
                ax.legend(
                    wedges, labels, loc="center left", bbox_to_anchor=(1, 0, 0.5, 1)
                )
            else:
                ax.text(
                    0.5,
                    0.5,
                    "No Data",
                    ha="center",
                    va="center",
                    transform=ax.transAxes,
                )

        elif chart_type == "bar":
            # Bar chart with different colors for each bar
            labels = list(data.keys())
            values = list(data.values())

            if any(values):
                # Define a color palette for different bars
                color_palette = [
                    "#2E86AB",  # Blue
                    "#A23B72",  # Purple
                    "#F18F01",  # Orange
                    "#C73E1D",  # Red
                    "#3B1F2B",  # Dark Purple
                    "#8B4513",  # Brown
                    "#228B22",  # Forest Green
                    "#FF69B4",  # Hot Pink
                    "#20B2AA",  # Light Sea Green
                    "#FF6347",  # Tomato
                    "#9370DB",  # Medium Purple
                    "#32CD32",  # Lime Green
                ]

                # Create bars with different colors
                bars = ax.bar(
                    range(len(labels)),
                    values,
                    color=[
                        color_palette[i % len(color_palette)]
                        for i in range(len(labels))
                    ],
                )

                # Set x-axis labels
                ax.set_xticks(range(len(labels)))
                ax.set_xticklabels(labels, rotation=45, ha="right")

                # Add value labels
                for i, (bar, value) in enumerate(zip(bars, values)):
                    if value > 0:
                        ax.text(
                            bar.get_x() + bar.get_width() / 2,
                            bar.get_height() + 0.1,
                            str(value),
                            ha="center",
                            va="bottom",
                        )

                ax.set_ylabel("Count")
                ax.set_title(title, fontsize=12, fontweight="bold")
            else:
                ax.text(
                    0.5,
                    0.5,
                    "No Data",
                    ha="center",
                    va="center",
                    transform=ax.transAxes,
                )

        # Clean up spines
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

        # Tight layout
        plt.tight_layout()

        # Save with high quality JPEG
        chart_filename = (
            f"chart_{chart_type}_{title.replace(' ', '_').replace('/', '_')}.jpg"
        )
        temp_file_path = os.path.join(self.temp_dir, chart_filename)

        # Higher quality JPEG with less compression
        plt.savefig(
            temp_file_path,
            format="jpg",
            dpi=300,
            bbox_inches="tight",
            facecolor="white",
            edgecolor="none",
        )

        # Track temp file for cleanup
        self.temp_files.append(temp_file_path)

        # Clean up
        plt.close(fig)

        self.logger.info(f"Chart saved to temporary file: {temp_file_path}")

        return Image(temp_file_path, width=width, height=height)

    def cleanup_temp_files(self):
        """Clean up temporary chart image files."""
        try:
            for temp_file in self.temp_files:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    self.logger.info(f"Removed temporary file: {temp_file}")

            # Remove temp directory if it exists and is empty
            if os.path.exists(self.temp_dir):
                os.rmdir(self.temp_dir)
                self.logger.info(f"Removed temporary directory: {self.temp_dir}")

        except Exception as e:
            self.logger.warning(f"Error cleaning up temporary files: {e}")

    def generate_enhanced_pdf_report(
        self,
        version_id: str,
        output_filename: str,
        include_detailed_findings: bool = False,
        all_severities: bool = False,
        max_detailed_findings: int = 100,
        organization_name: str = None,
    ):
        """Generate enhanced PDF report with professional styling."""
        self.logger.info(f"Generating enhanced PDF report for version {version_id}")

        # Fetch data
        version_data = self.get_version_details(version_id)
        components = self.get_version_components(version_id)
        findings = self.get_version_findings(version_id)

        # Extract summary data from API response (more efficient than analyzing individual items)
        findings_summary = version_data.get("findingsSummary", {})
        severity_dist = findings_summary.get("bySeverity", {})

        components_summary = version_data.get("componentsSummary", {})
        component_types = components_summary.get("byType", {})

        # Fallback: if API summary doesn't have component types, analyze individual components
        if not component_types and components:
            self.logger.warning(
                "No component types in API summary, analyzing individual components"
            )
            component_types = self.analyze_component_types(components)

        self.logger.info(f"Component types found: {component_types}")

        # Analyze component licenses
        component_licenses = self.analyze_component_licenses(components)
        self.logger.info(f"Component licenses found: {component_licenses}")

        # Analyze exploits
        exploit_summary = self.analyze_exploits(findings)
        self.logger.info(f"Exploit summary: {exploit_summary}")

        # Get top risks from actual findings
        top_risks = self.get_top_risks(findings)

        # Extract project information
        project_info = version_data.get("project", {})
        project_name = project_info.get("name", "Unknown Project")
        version_name = version_data.get("name", "Unknown Version")

        # Use provided organization name, or try to get from API, or fallback to subdomain
        organization = (
            organization_name
            or version_data.get("organization", {}).get("name")
            or version_data.get("organization_name")
            or self.subdomain.title()
        )

        created_date = datetime.now().strftime("%Y-%m-%d")

        # Create professional document
        doc = page_templates.ProfessionalDocTemplate(output_filename)

        # Set dynamic title based on detailed findings inclusion
        title = (
            "Project Risk Report"
            if include_detailed_findings
            else "Project Risk Summary"
        )

        doc.set_document_info(
            title=title,
            project_name=project_name,
            version_name=version_name,
            organization=organization,
            created_date=created_date,
        )

        # Build document content
        story = []

        # Cover page: Add minimal content to trigger cover template, then switch
        # The document starts with the 'cover' template by default
        story.append(
            Paragraph("", _stylesheet["Normal"])
        )  # Minimal content for cover page

        # Switch to standard page template for all subsequent content
        story.append(NextPageTemplate("standard"))
        story.append(PageBreak())

        # Introduction Page
        story.append(flowables.SectionHeading("Introduction"))

        # About Finite State Section
        story.append(Paragraph("<b>About Finite State</b>", _stylesheet["Heading3"]))
        story.append(Spacer(1, 0.15 * inch))

        about_text = """
        Finite State was founded to protect the devices that power our modern lives by illuminating the vulnerabilities
        and threats within their complex software supply chains. We recognize that supply chain security is the #1
        problem in cyber security today. Global software supply chains are opaque and complicated, involving countless
        developers, vendors, and components. Malicious actors exploit supply chain vulnerabilities to gain access to the
        networks that power our critical infrastructure and can carry out potentially devastating attacks.
        """
        story.append(Paragraph(about_text, _stylesheet["Normal"]))
        story.append(Spacer(1, 0.2 * inch))

        mission_text = """
        Finite State defends these critical devices, networks, and supply chains by leveraging massive data analysis of
        device firmware and software to provide transparency to device manufacturers and their customers - enabling
        them to understand and mitigate their risks before they are compromised.
        """
        story.append(Paragraph(mission_text, _stylesheet["Normal"]))
        story.append(Spacer(1, 0.2 * inch))

        report_text = """
        This report by Finite State provides comprehensive security analysis of your product and its firmware. Combined,
        this provides insight into the firmware and its vulnerabilities to help protect and secure your mission critical
        products.
        """
        story.append(Paragraph(report_text, _stylesheet["Normal"]))
        story.append(Spacer(1, 2.4 * inch))

        # Confidentiality and Privacy Section
        story.append(
            Paragraph("<b>Confidentiality and Privacy</b>", _stylesheet["Heading3"])
        )
        story.append(Spacer(1, 0.15 * inch))

        privacy_text = """
        Finite State, Inc., ("Finite State," "we," or "us") respects the privacy of our customers, business partners, event
        attendees, job applicants, and visitors to Finite State websites ("Sites"). We recognize the need for appropriate
        protections and management of personal information that is shared with and provided to Finite State. Finite
        State has developed this Privacy Policy to assist you to understand what personal information Finite State
        collects and how that personal information is used. It also describes your choices regarding the use, access and
        correction of your personal information. This Privacy Policy applies to Sites operated by Finite State such as
        www.finitestate.io and other webpages in which we post and directly link to this policy.
        """
        story.append(Paragraph(privacy_text, _stylesheet["Normal"]))
        story.append(PageBreak())

        # Executive Summary (now on standard template)
        story.append(flowables.SectionHeading("Executive Summary"))

        summary_text = f"""
        This report provides a comprehensive security assessment of <b>{project_name}</b> version <b>{version_name}</b>.
        The analysis identified <b>{self._format_number_with_commas(len(components))} software components</b> and <b>{self._format_number_with_commas(len(findings))} security findings</b>
        across the project.
        """
        story.append(Paragraph(summary_text, _stylesheet["Normal"]))
        story.append(Spacer(1, 0.2 * inch))

        # Summary Statistics
        stats_box = flowables.create_summary_stats(
            total_components=len(components),
            total_findings=len(findings),
            critical_count=severity_dist.get("CRITICAL", 0),
            high_count=severity_dist.get("HIGH", 0),
            medium_count=severity_dist.get("MEDIUM", 0),
            low_count=severity_dist.get("LOW", 0),
        )
        story.append(stats_box)
        story.append(Spacer(1, 0.3 * inch))

        # Risk Overview
        story.append(flowables.SectionHeading("Risk Overview"))

        if severity_dist:
            # Normalize severity keys from API (UPPERCASE) to chart format (Title Case)
            normalized_severity = {}
            for key, value in severity_dist.items():
                if key == "CRITICAL":
                    normalized_severity["Critical"] = value
                elif key == "HIGH":
                    normalized_severity["High"] = value
                elif key == "MEDIUM":
                    normalized_severity["Medium"] = value
                elif key == "LOW":
                    normalized_severity["Low"] = value
                elif key == "NONE":
                    normalized_severity["None"] = value
                else:
                    normalized_severity[key.title()] = value

            severity_chart = self.create_enhanced_chart(
                normalized_severity,
                "pie",
                "Findings by Severity",
                width=4 * inch,
                height=3 * inch,
            )
            story.append(severity_chart)
        else:
            story.append(
                Paragraph("<b>No findings identified.</b>", _stylesheet["Normal"])
            )

        story.append(Spacer(1, 0.3 * inch))

        # Component Analysis
        story.append(flowables.SectionHeading("Component Analysis"))

        if len(components) > 0:
            comp_text = f"""
            The analysis identified <b>{self._format_number_with_commas(len(components))} software components</b> within the project.
            These components have been analyzed for licensing and security vulnerabilities.
            """
        else:
            comp_text = "<b>No software components identified in this project.</b>"
        story.append(Paragraph(comp_text, _stylesheet["Normal"]))

        if component_licenses:
            self.logger.info(
                f"Generating component license chart with data: {component_licenses}"
            )
            story.append(Spacer(1, 0.2 * inch))
            try:
                license_chart = self.create_enhanced_chart(
                    component_licenses,
                    "bar",
                    "Components by License Type",
                    width=6 * inch,
                    height=4 * inch,
                )
                story.append(license_chart)

                self.logger.info("Component license chart added to story successfully")
                story.append(Spacer(1, 0.3 * inch))
            except Exception as e:
                self.logger.error(f"Failed to create component license chart: {e}")
                # Add fallback text if chart fails
                story.append(
                    Paragraph(
                        f"Component licenses: {', '.join([f'{k}: {v}' for k, v in component_licenses.items()])}",
                        _stylesheet["Normal"],
                    )
                )
        else:
            self.logger.warning(
                "No component licenses found - no chart will be displayed"
            )
            if len(components) > 0:
                story.append(Spacer(1, 0.2 * inch))
                story.append(
                    Paragraph(
                        "No license information available for components.",
                        _stylesheet["Normal"],
                    )
                )

        story.append(Spacer(1, 0.3 * inch))

        # Component Risk Analysis
        story.append(flowables.SectionHeading("Component Risk Analysis"))

        # Get top riskiest components
        top_risky_components = self.get_top_risky_components(components, limit=10)

        if top_risky_components:
            comp_risk_text = """
            The following components have been identified as the highest risk based on their vulnerability counts,
            severity levels, and policy compliance issues. These components should be prioritized for remediation.
            """
            story.append(Paragraph(comp_risk_text, _stylesheet["Normal"]))
            story.append(Spacer(1, 0.2 * inch))

            # Create table data for top risky components
            table_data = [
                [
                    "Component",
                    "Version",
                    "Critical",
                    "High",
                    "Medium",
                    "Low",
                    "Violations",
                    "Warnings",
                ]
            ]

            for component in top_risky_components:
                name = component.get("name", "Unknown")
                version = component.get("version", "Unknown")
                severity_counts = component.get("severityCounts", {})
                critical = severity_counts.get("critical", 0)
                high = severity_counts.get("high", 0)
                medium = severity_counts.get("medium", 0)
                low = severity_counts.get("low", 0)
                violations = component.get("violations", 0)
                warnings = component.get("warnings", 0)

                # Truncate component name and version to fit in table
                if len(name) > 25:
                    name = name[:22] + "..."
                if len(version) > 15:
                    version = version[:12] + "..."

                table_data.append(
                    [
                        name,
                        version,
                        str(critical),
                        str(high),
                        str(medium),
                        str(low),
                        str(violations),
                        str(warnings),
                    ]
                )

            # Define column widths to prevent wrapping (total width ~7.4 inches)
            col_widths = [
                2.2 * inch,
                0.8 * inch,
                0.8 * inch,
                0.5 * inch,
                0.8 * inch,
                0.5 * inch,
                0.9 * inch,
                0.9 * inch,
            ]

            # Create table with right alignment for numeric columns
            from reportlab.lib.enums import TA_RIGHT
            from reportlab.platypus.tables import Table, TableStyle

            # Create a regular Table instead of StyledTable to avoid style conflicts
            component_risks_table = Table(table_data, colWidths=col_widths)

            # Add comprehensive styling including right alignment for numeric columns
            table_style = TableStyle(
                [
                    ("ALIGN", (2, 0), (7, -1), "RIGHT"),  # Right align numeric columns
                    ("ALIGN", (0, 0), (1, -1), "LEFT"),  # Left align text columns
                    ("FONTNAME", (0, 0), (-1, 0), "OpenSans-Bold"),  # Bold header
                    ("FONTSIZE", (0, 0), (-1, 0), 9),  # Header font size
                    ("FONTNAME", (0, 1), (-1, -1), "OpenSans"),  # Regular font for data
                    ("FONTSIZE", (0, 1), (-1, -1), 9),  # Data font size
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.whitesmoke,
                    ),  # Header background
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    (
                        "LINEBELOW",
                        (0, 0),
                        (-1, 0),
                        1,
                        colors.midgray,
                    ),  # Divider below header
                    (
                        "LINEBELOW",
                        (0, 1),
                        (-1, -2),
                        0.5,
                        "#EEEEEE",
                    ),  # Subtle dividers between rows
                ]
            )
            component_risks_table.setStyle(table_style)

            story.append(component_risks_table)
            # Add a page break if we had top risky components
            story.append(PageBreak())
        else:
            story.append(
                Paragraph("No high-risk components identified.", _stylesheet["Normal"])
            )

        story.append(Spacer(1, 0.3 * inch))

        # Reachability Analysis (only if we have findings with reachability scores)
        findings_with_reachability = [
            f for f in findings if f.get("reachabilityScore") is not None
        ]
        if findings_with_reachability:
            story.append(flowables.SectionHeading("Reachability Analysis"))

            # Analyze findings with reachability scores
            reachable_findings = [
                f for f in findings if (f.get("reachabilityScore", 0) or 0) > 0
            ]
            unreachable_findings = [
                f for f in findings if (f.get("reachabilityScore", 0) or 0) < 0
            ]
            inconclusive_findings = [
                f for f in findings if (f.get("reachabilityScore", 0) or 0) == 0
            ]

            # Log reachability summary
            self.logger.info(
                f"Reachability data included with these counts: {{ reachable: {len(reachable_findings)}, unreachable: {len(unreachable_findings)}, inconclusive: {len(inconclusive_findings)} }}"
            )

            reachability_text = f"""
            The analysis identified <b>{len(reachable_findings)} reachable findings</b> and <b>{len(unreachable_findings)} unreachable findings</b>.
            Reachable findings indicate vulnerabilities that are potentially accessible in the codebase, while unreachable findings are not accessible.
            """
            story.append(Paragraph(reachability_text, _stylesheet["Normal"]))
            story.append(Spacer(1, 0.2 * inch))

            # Create reachability summary table
            if reachable_findings or unreachable_findings:
                # Sort: reachable findings first (by severity), then unreachable findings (by severity)
                def get_sort_key(finding):
                    reachability_score = finding.get("reachabilityScore", 0) or 0
                    severity = finding.get("severity", "unknown")

                    # Handle None severity
                    if severity is None:
                        severity = "unknown"
                    else:
                        severity = severity.lower()

                    # Severity ranking (higher = more critical)
                    severity_rank = {
                        "critical": 4,
                        "high": 3,
                        "medium": 2,
                        "low": 1,
                        "unknown": 0,
                    }

                    # First priority: reachable (True) vs unreachable (False)
                    # Second priority: severity rank (higher = more critical)
                    # Third priority: reachability score (higher = more reachable)
                    return (
                        reachability_score > 0,
                        severity_rank.get(severity, 0),
                        reachability_score,
                    )

                all_reachability_findings = reachable_findings + unreachable_findings
                sorted_reachability = sorted(
                    all_reachability_findings, key=get_sort_key, reverse=True
                )

                # Add note if we have more than 100 findings
                if len(sorted_reachability) > 100:
                    story.append(
                        Paragraph("<b>Top 100</b>", _stylesheet["CenterHeading"])
                    )
                    story.append(Spacer(1, 0.1 * inch))

                table_data = [
                    ["#", "Finding ID", "Component", "Severity", "Result", "Risk"]
                ]

                for i, finding in enumerate(
                    sorted_reachability[:100]
                ):  # Top 100 by absolute reachability score
                    finding_id = finding.get("findingId", "Unknown")
                    component = finding.get("component", {}).get("name", "Unknown")
                    severity = finding.get("severity", "Unknown").title()
                    reachability_score = finding.get("reachabilityScore", 0) or 0
                    risk_score = finding.get("risk", 0)

                    # Format risk score as decimal (divide by 10)
                    if risk_score != "N/A":
                        try:
                            risk_score = f"{float(risk_score) / 10:.1f}"
                        except (ValueError, TypeError):
                            risk_score = "N/A"

                    # Determine reachability status
                    if reachability_score > 0:
                        status_text = "Reachable"
                    else:
                        status_text = "Unreachable"

                    table_data.append(
                        [
                            i + 1,
                            finding_id,
                            component,
                            severity,
                            status_text,
                            str(risk_score),
                        ]
                    )

                # Create table with custom styling for reachability status
                from reportlab.platypus.tables import Table, TableStyle

                # Define column widths to prevent wrapping (total width ~7.4 inches)
                col_widths = [
                    0.5 * inch,
                    1.5 * inch,
                    2.0 * inch,
                    0.8 * inch,
                    1.1 * inch,
                    1.5 * inch,
                ]

                reachability_table = Table(table_data, colWidths=col_widths)

                # Create custom style with background colors for reachability status
                table_style = TableStyle(
                    [
                        ("FONTNAME", (0, 0), (-1, 0), "OpenSans-Bold"),  # Bold header
                        ("FONTSIZE", (0, 0), (-1, 0), 10),  # Header font size
                        (
                            "FONTNAME",
                            (0, 1),
                            (-1, -1),
                            "OpenSans",
                        ),  # Regular font for data
                        ("FONTSIZE", (0, 1), (-1, -1), 9),  # Data font size
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, 0),
                            colors.whitesmoke,
                        ),  # Header background
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        (
                            "LINEBELOW",
                            (0, 0),
                            (-1, 0),
                            1,
                            colors.midgray,
                        ),  # Divider below header
                        (
                            "GRID",
                            (0, 1),
                            (-1, -1),
                            0.5,
                            "#000000",
                        ),  # Thin black borders for all data cells
                    ]
                )

                # Add background colors for severity and reachability status columns
                for i, row in enumerate(table_data[1:], 1):  # Skip header row
                    severity = row[3]  # Severity column
                    # Color code based on severity with critical / high = red, med = orange and low = yellow
                    if severity and severity.lower() in ["critical", "high"]:
                        table_style.add(
                            "BACKGROUND", (3, i), (3, i), "#FFE6E6"
                        )  # Light red
                    elif severity and severity.lower() == "medium":
                        table_style.add(
                            "BACKGROUND", (3, i), (3, i), "#FFF2E6"
                        )  # Light orange
                    elif severity and severity.lower() == "low":
                        table_style.add(
                            "BACKGROUND", (3, i), (3, i), "#FFFFF0"
                        )  # Light yellow

                    status = row[4]  # Reachability Status column
                    if status == "Reachable":
                        table_style.add(
                            "BACKGROUND", (4, i), (4, i), "#FFE6FF"
                        )  # Light magenta
                    elif status == "Unreachable":
                        table_style.add(
                            "BACKGROUND", (4, i), (4, i), "#E6FFE6"
                        )  # Light green

                table_style.add(
                    "ALIGN", (0, 0), (0, -1), "RIGHT"
                )  # Right align finding number column
                table_style.add("ALIGN", (1, 0), (3, -1), "LEFT")  # Left align
                table_style.add(
                    "ALIGN", (4, 0), (5, -1), "CENTER"
                )  # Center align reachability status and risk columns

                reachability_table.setStyle(table_style)
                story.append(reachability_table)
            else:
                story.append(
                    Paragraph(
                        "No reachable or unreachable findings identified.",
                        _stylesheet["Normal"],
                    )
                )

            story.append(Spacer(1, 0.3 * inch))

        # Exploits Summary (always show, even if no exploits found)
        story.append(flowables.SectionHeading("Exploits Summary"))

        total_exploits = sum(exploit_summary.values()) if exploit_summary else 0
        if total_exploits > 0:
            exploit_text = f"""
            The analysis found <b>{self._format_number_with_commas(total_exploits)} findings with exploit information</b>.
            These have been categorized by exploit maturity and availability.
            """
        else:
            exploit_text = """
            <b>No findings with exploit information were found</b> in this analysis.
            The statistics below show all possible exploit categories.
            """
        story.append(Paragraph(exploit_text, _stylesheet["Normal"]))
        # story.append(Spacer(1, 0.2 * inch))

        # Exploit Statistics Box (always show with all categories)
        exploit_stats_box = flowables.create_exploit_stats(exploit_summary or {})
        if exploit_stats_box:
            story.append(exploit_stats_box)

        story.append(Spacer(1, 0.2 * inch))

        # Top Security Risks
        story.append(flowables.SectionHeading("Top Security Risks"))

        if top_risks:
            # Create table data
            table_data = [
                ["CVE ID", "Severity", "Risk Score", "EPSS Percentile", "Component"]
            ]

            for risk in top_risks[:10]:  # Top 10 risks
                cve_id = risk.get("findingId", "N/A")
                severity = risk.get("severity", "Unknown").title()
                risk_score = risk.get("risk", "N/A")
                # Format risk score as decimal (divide by 10)
                if risk_score != "N/A":
                    try:
                        risk_score = f"{float(risk_score) / 10:.1f}"
                    except (ValueError, TypeError):
                        risk_score = "N/A"
                epss_percentile = self._format_epss_percentile(
                    risk.get("epssPercentile")
                )
                component = risk.get("component", {}).get("name", "Unknown")

                table_data.append(
                    [cve_id, severity, str(risk_score), epss_percentile, component]
                )

            risks_table = flowables.StyledTable(table_data)
            story.append(risks_table)
        else:
            story.append(
                Paragraph("No security risks identified.", _stylesheet["Normal"])
            )

        story.append(Spacer(1, 0.3 * inch))

        # Detailed Findings (if requested)
        if include_detailed_findings and findings:
            story.append(flowables.SectionHeading("Detailed Findings"))

            # Add explanation of what findings are included
            if all_severities:
                explanation_text = f"""
                This section includes all severity levels (Critical, High, Medium, Low) up to a maximum of {max_detailed_findings} findings.
                """
            else:
                explanation_text = """
                This section includes Critical and High severity findings, plus Medium severity findings that have exploit information.
                No cap is applied to ensure all important findings are displayed.
                """

            story.append(Paragraph(explanation_text, _stylesheet["Normal"]))
            story.append(Spacer(1, 0.2 * inch))

            # Sort findings by highest risk score first
            sorted_findings = sorted(
                findings, key=lambda x: float(x.get("risk", 0) or 0), reverse=True
            )

            # Filter findings based on severity and exploit info
            if all_severities:
                # Show all findings with cap
                limited_findings = sorted_findings[:max_detailed_findings]
            else:
                # Show only Critical/High severity and Medium severity with exploit info (no cap)
                filtered_findings = []
                for finding in sorted_findings:
                    severity = finding.get("severity", "")
                    has_exploit_info = bool(finding.get("exploitInfo", []))

                    # Handle None severity
                    if severity is None:
                        severity = "unknown"
                    else:
                        severity = severity.lower()

                    # Include if Critical/High severity OR (Medium severity AND has exploit info)
                    if severity in ["critical", "high"] or (
                        severity == "medium" and has_exploit_info
                    ):
                        filtered_findings.append(finding)

                limited_findings = filtered_findings

            # Collect all vulnerability IDs for batch fetching (only for non-FS- findings)
            vulnerability_ids = []
            for finding in limited_findings:
                finding_id = finding.get("findingId", "Unknown")
                if not finding_id.startswith("FS-"):
                    vulnerability_ids.append(finding_id)

            # Fetch vulnerability metadata in batches
            all_metadata = {}
            for i in range(0, len(vulnerability_ids), VULNERABILITY_BATCH_SIZE):
                batch = vulnerability_ids[i : i + VULNERABILITY_BATCH_SIZE]
                batch_metadata = self.get_vulnerability_metadata_batch(batch)
                all_metadata.update(batch_metadata)

            for finding in limited_findings:
                finding_id = finding.get("findingId", "Unknown")

                # Get description and aliases based on finding ID pattern
                if finding_id.startswith("FS-"):
                    # Use the title field for FS- findings
                    description = finding.get("title", "No description available")
                    aliases = []
                else:
                    # Get description and aliases from batch results for non-FS- findings
                    vuln_data = all_metadata.get(
                        finding_id,
                        {"summary": "No description available", "aliases": []},
                    )
                    description = vuln_data.get("summary", "No description available")
                    aliases = vuln_data.get("aliases", [])

                # Get exploit maturity display (now includes fire icon)
                exploit_display = self.get_exploit_maturity_display(finding)

                # Get reachability display
                reachability_display = self.get_reachability_display(finding)

                # Get around duplicate credential findings bug in Alloy
                if description.startswith("FS-"):
                    continue
                # Create the heading with finding ID and exploit info if available
                if exploit_display:
                    heading_text = f"{finding_id} {exploit_display}"
                else:
                    heading_text = finding_id
                story.append(Paragraph(heading_text, _stylesheet["Heading4"]))

                # Add reachability indicator box if applicable
                if reachability_display:
                    # Create a small table with colored background for reachability status
                    from reportlab.platypus.tables import Table, TableStyle

                    # Determine background color based on reachability status
                    if reachability_display == "Reachable":
                        bg_color = "#FFE6FF"  # Light magenta
                    else:
                        bg_color = "#E6FFE6"  # Light green

                    # Create small table that will shrink to content width
                    reachability_table = Table(
                        [[reachability_display]],
                        style=[
                            ("BACKGROUND", (0, 0), (-1, -1), bg_color),
                            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                            ("FONTNAME", (0, 0), (-1, -1), "OpenSans"),
                            ("FONTSIZE", (0, 0), (-1, -1), 8),
                            ("LEFTPADDING", (0, 0), (-1, -1), 6),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                            ("TOPPADDING", (0, 0), (-1, -1), 3),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ],
                        hAlign="LEFT",
                    )

                    story.append(reachability_table)
                    story.append(Spacer(1, 0.1 * inch))

                # Format risk score as decimal (divide by 10)
                risk_score = finding.get("risk", "N/A")
                if risk_score != "N/A":
                    try:
                        risk_score = f"{float(risk_score) / 10:.1f}"
                    except (ValueError, TypeError):
                        risk_score = "N/A"

                # Get component information
                component = finding.get("component", {})
                component_name = component.get("name", "Unknown")
                component_version = component.get("version", "Unknown")

                # Build details based on finding ID pattern
                if finding_id.startswith("FS-"):
                    # For FS- findings, don't show version since they refer to files/paths
                    details = f"""
                    <b>Location:</b> {component_name}<br/>
                    <b>Description:</b> {description}<br/>
                    <b>Severity:</b> {finding.get('severity', 'Unknown').title()}<br/>
                    <b>Risk Score:</b> {risk_score}<br/>
                    <b>EPSS Percentile:</b> {self._format_epss_percentile(finding.get('epssPercentile'))}
                    """
                else:
                    # For other findings (including CVE, GHSA, etc.), show version and aliases
                    aliases_text = ""
                    if aliases:
                        aliases_text = f"<br/><b>Aliases:</b> {', '.join(aliases)}"

                    details = f"""
                    <b>Component:</b> {component_name}<br/>
                    <b>Version:</b> {component_version}<br/>
                    <b>Description:</b> {description}<br/>
                    <b>Severity:</b> {finding.get('severity', 'Unknown').title()}<br/>
                    <b>Risk Score:</b> {risk_score}<br/>
                    <b>EPSS Percentile:</b> {self._format_epss_percentile(finding.get('epssPercentile'))}{aliases_text}
                    """

                story.append(Paragraph(details, _stylesheet["Normal"]))
                story.append(Spacer(1, 0.15 * inch))

        # Helpful Information Appendix
        story.append(PageBreak())
        story.append(flowables.SectionHeading("Helpful Information"))

        appendix_text = """
        View this resource to learn more about terms, definitions, and helpful information to understand the firmware risk report.
        """
        story.append(Paragraph(appendix_text, _stylesheet["Normal"]))
        story.append(Spacer(1, 0.2 * inch))

        # Add the comprehensive appendix sections individually
        appendix_sections = flowables.create_comprehensive_appendix()

        # Add each section to the story (ReportLab will handle page breaks automatically)
        for section_name, section_elements in appendix_sections.items():
            for element in section_elements:
                story.append(element)
            # Add reduced spacing between sections
            story.append(Spacer(1, 0.1 * inch))  # Reduced from 0.2 to 0.1 inch

        # Build the PDF
        self.logger.info(f"Building PDF report: {output_filename}")
        doc.build(story)
        self.logger.info(
            f"Enhanced PDF report generated successfully: {output_filename}"
        )

        # Clean up temporary chart files
        self.cleanup_temp_files()


def main(
    token,
    subdomain,
    project_version_id,
    output_filename,
    detailed_findings=False,
    all_severities=False,
    max_detailed_findings=100,
    organization_name=None,
):
    """Main function for generating reports"""
    start_time = time.time()
    try:
        reporter = FiniteStateReporter(subdomain, token)
        reporter.generate_enhanced_pdf_report(
            project_version_id,
            output_filename,
            include_detailed_findings=detailed_findings,
            all_severities=all_severities,
            max_detailed_findings=max_detailed_findings,
            organization_name=organization_name,
        )
        elapsed_time = time.time() - start_time
        print(f"Report generation completed in {elapsed_time:.2f} seconds")
        return True
    except Exception as e:
        elapsed_time = time.time() - start_time
        print(f"Report generation failed after {elapsed_time:.2f} seconds")
        raise Exception(f"Error generating report: {e}")


if __name__ == "__main__":
    # This allows the module to be run directly for testing
    if len(sys.argv) not in [5, 6]:
        print(
            "Usage: python -m finite_state_reporter.core.reporter TOKEN SUBDOMAIN PROJECT_VERSION_ID OUTPUT_FILE [detailed_findings]"
        )
        sys.exit(1)

    token, subdomain, project_version_id, output_file = sys.argv[1:5]
    detailed_findings = len(sys.argv) == 6 and sys.argv[5].lower() in [
        "true",
        "1",
        "yes",
    ]
    main(
        token,
        subdomain,
        project_version_id,
        output_file,
        detailed_findings=detailed_findings,
    )
