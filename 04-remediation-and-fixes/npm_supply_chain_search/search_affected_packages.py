#!/usr/bin/env python3
"""
Supply Chain Attack Package Scanner

This script searches for affected packages from the S1ngularity/nx attack (Shai Hulud worm)
using the Finite State Customer API. It checks for specific package names and versions
that have been compromised in the supply chain attack.

Usage:
    python search_affected_packages.py

The script will prompt for:
- Domain (e.g., yourcompany.finitestate.io)
- API key for authentication

Or set these environment variables:
- FINITE_STATE_DOMAIN
- FINITE_STATE_AUTH_TOKEN

Features:
- Modular package list (affected_packages.json)
- Progress updates with timing
- Detailed logging
- Comprehensive error handling
- Results export to JSON
"""

import json
import requests
import time
import sys
import os
import csv
import re
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging
import getpass

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    DIM = '\033[2m'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('package_scan.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def print_banner():
    """Print an attractive banner with Finite State logo"""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                               FINITE STATE                                   ║
║                                                                              ║
║                    🛡️  SUPPLY CHAIN ATTACK SCANNER  🛡️                       ║
║                                                                              ║
║             Scanning for S1ngularity/nx Attack (Shai Hulud Worm)             ║
║                     Affected Packages Detection Tool                         ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.END}
"""
    print(banner)

def print_section_header(title: str, color: str = Colors.BLUE):
    """Print a formatted section header"""
    print(f"\n{color}{Colors.BOLD}{'=' * 80}{Colors.END}")
    print(f"{color}{Colors.BOLD}{title.center(80)}{Colors.END}")
    print(f"{color}{Colors.BOLD}{'=' * 80}{Colors.END}")

def print_info(message: str, color: str = Colors.CYAN):
    """Print an info message with formatting"""
    print(f"{color}ℹ️  {message}{Colors.END}")

def print_success(message: str):
    """Print a success message"""
    print(f"{Colors.GREEN}✅ {message}{Colors.END}")

def print_warning(message: str):
    """Print a warning message"""
    print(f"{Colors.YELLOW}⚠️  {message}{Colors.END}")

def print_error(message: str):
    """Print an error message"""
    print(f"{Colors.RED}❌ {message}{Colors.END}")

class PackageScanner:
    """Scanner for affected packages using Finite State API"""

    def __init__(self, domain: str, api_key: str):
        self.domain = domain
        self.api_key = api_key
        self.base_url = f"https://{domain}/api"
        self.session = requests.Session()
        self.session.headers.update({
            'X-Authorization': api_key,
            'Content-Type': 'application/json',
            'User-Agent': 'FiniteState-PackageScanner/1.0'
        })
        self.results = {
            'scan_timestamp': datetime.now().isoformat(),
            'domain': domain,
            'total_packages_checked': 0,  # number of package@version combinations checked
            'total_api_calls': 0,         # number of HTTP requests made to the components API
            'total_components_found': 0,
            'affected_packages_found': [],
            'scan_duration_seconds': 0,
            'errors': []
        }

    def load_affected_packages(
        self,
        file_path: str = 'affected_packages.json',
        extra_csv_path: str = 'shai-hulud-2-packages.csv',
    ) -> Dict[str, Any]:
        """Load the list of affected packages from JSON file and optional CSV."""
        try:
            print_info(f"Loading affected packages from {file_path}...")
            with open(file_path, 'r') as f:
                data = json.load(f)

            # Build a quick lookup for JSON packages
            packages_by_name: Dict[str, Dict[str, Any]] = {
                pkg['name']: pkg for pkg in data.get('packages', [])
            }

            # Optionally merge in additional packages/versions from CSV
            if os.path.exists(extra_csv_path):
                print_info(f"Loading additional affected packages from {extra_csv_path}...")
                csv_packages: Dict[str, set] = {}
                try:
                    with open(extra_csv_path, newline='') as csv_file:
                        reader = csv.DictReader(csv_file)
                        if not reader.fieldnames or 'Package' not in reader.fieldnames or 'Version' not in reader.fieldnames:
                            print_warning(
                                f"{extra_csv_path} does not have the expected 'Package' and 'Version' headers; skipping CSV merge."
                            )
                        else:
                            for row in reader:
                                name = (row.get('Package') or '').strip()
                                raw_versions = (row.get('Version') or '').strip()
                                if not name:
                                    continue
                                if not raw_versions:
                                    # The Wiz list includes a few rows without a specific version;
                                    # we skip these because the scanner expects explicit versions.
                                    msg = f"Skipping CSV row for '{name}' with empty Version field"
                                    logger.warning(msg)
                                    self.results['errors'].append(msg)
                                    continue

                                tokens = [v.strip() for v in raw_versions.split('||')]
                                versions = []
                                for tok in tokens:
                                    if not tok:
                                        continue
                                    # Strip any leading "= " or "=" prefix
                                    cleaned = re.sub(r'^=\s*', '', tok)
                                    cleaned = cleaned.strip()
                                    if cleaned:
                                        versions.append(cleaned)

                                if not versions:
                                    msg = f"Could not parse any versions from CSV row for '{name}' (raw: '{raw_versions}')"
                                    logger.warning(msg)
                                    self.results['errors'].append(msg)
                                    continue

                                version_set = csv_packages.setdefault(name, set())
                                for v in versions:
                                    version_set.add(v)

                    # Merge CSV data into JSON structure
                    for name, version_set in csv_packages.items():
                        if name in packages_by_name:
                            existing_versions = set(packages_by_name[name].get('affected_versions', []))
                            new_versions = sorted(version_set - existing_versions)
                            if new_versions:
                                packages_by_name[name]['affected_versions'].extend(new_versions)
                        else:
                            packages_by_name[name] = {
                                'name': name,
                                'affected_versions': sorted(version_set),
                            }

                    data['packages'] = list(packages_by_name.values())

                except Exception as e:
                    msg = f"Failed to merge CSV data from {extra_csv_path}: {e}"
                    print_warning(msg)
                    logger.warning(msg)
                    self.results['errors'].append(msg)

            total_versions = sum(len(pkg['affected_versions']) for pkg in data['packages'])
            print_success(f"Loaded {len(data['packages'])} affected packages with {total_versions} total versions")
            print_info(f"Attack: {data.get('attack_name', 'Unknown attack')}")
            print_info(f"Date: {data.get('attack_date', 'Unknown date')}")

            logger.info(f"Loaded {len(data['packages'])} affected packages from {file_path}")
            if os.path.exists(extra_csv_path):
                logger.info(f"Merged additional affected packages from {extra_csv_path}")
            return data
        except FileNotFoundError:
            print_error(f"Could not find {file_path}. Please ensure the file exists.")
            logger.error(f"Could not find {file_path}. Please ensure the file exists.")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print_error(f"Invalid JSON in {file_path}: {e}")
            logger.error(f"Invalid JSON in {file_path}: {e}")
            sys.exit(1)

    def search_component(self, package_name: str, version: str) -> Optional[Dict[str, Any]]:
        """Search for a specific component and version using the API"""
        try:
            # Use RSQL filter to search for exact name and version match
            filter_query = f"name=={package_name} and version=={version}"
            params = {
                'filter': filter_query,
                'limit': 100  # Get up to 100 results
            }

            response = self.session.get(
                f"{self.base_url}/public/v0/components",
                params=params,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                # Always count components found, regardless of whether they match affected packages
                components_count = len(data)
                self.results['total_components_found'] += components_count
                logger.debug(f"Found {components_count} components for {package_name}@{version}")
                if data:  # If we found components
                    return {
                        'package_name': package_name,
                        'version': version,
                        'components_found': components_count,
                        'components': data
                    }
            elif response.status_code == 400:
                logger.warning(f"Bad request for {package_name}@{version}: {response.text}")
            elif response.status_code == 401:
                logger.error("Unauthorized - check your API key")
                return None
            elif response.status_code == 404:
                logger.warning(f"API endpoint not found for {package_name}@{version}")
            else:
                logger.warning(f"Unexpected response {response.status_code} for {package_name}@{version}")

        except requests.exceptions.Timeout:
            logger.error(f"Timeout searching for {package_name}@{version}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error searching for {package_name}@{version}: {e}")

        return None


    def search_components_batch(
        self,
        checks: List[Dict[str, str]],
        chunk_size: int = 25,
    ) -> Dict[tuple, Dict[str, Any]]:
        """
        Perform batched component lookups using a single RSQL filter per chunk.

        Returns:
            Dict mapping (package_name, version) -> result dict in the same shape
            as returned by search_component().
        """
        results_by_pair: Dict[tuple, Dict[str, Any]] = {}

        total_checks = len(checks)
        if total_checks == 0:
            return results_by_pair

        print_info(f"Using batched API queries (chunk size: {chunk_size}) to reduce requests")

        for start in range(0, total_checks, chunk_size):
            chunk = checks[start:start + chunk_size]
            # Build RSQL filter like:
            # (name==pkg1 and version==1.2.3) or (name==pkg2 and version==4.5.6)
            clauses = [
                f"(name=={item['name']} and version=={item['version']})"
                for item in chunk
            ]
            filter_query = " or ".join(clauses)
            params = {
                'filter': filter_query,
                'limit': 10000,  # API now allows up to 10,000 results per call
            }

            try:
                response = self.session.get(
                    f"{self.base_url}/public/v0/components",
                    params=params,
                    timeout=60,
                )
                # Count this as one API call regardless of outcome
                self.results['total_api_calls'] += 1

                if response.status_code == 200:
                    data = response.json()
                    components_count = len(data)
                    self.results['total_components_found'] += components_count
                    logger.debug(
                        f"Batched query returned {components_count} components "
                        f"for {len(chunk)} package@version checks"
                    )

                    # Bucket components by (name, version) so we can attribute them
                    bucket: Dict[tuple, List[Any]] = {}
                    for component in data:
                        comp_name = component.get('name')
                        comp_version = component.get('version')
                        if comp_name is None or comp_version is None:
                            continue
                        key = (comp_name, comp_version)
                        bucket.setdefault(key, []).append(component)

                    # Build per-package results matching the original shape
                    for item in chunk:
                        key = (item['name'], item['version'])
                        components_for_pair = bucket.get(key)
                        if components_for_pair:
                            results_by_pair[key] = {
                                'package_name': item['name'],
                                'version': item['version'],
                                'components_found': len(components_for_pair),
                                'components': components_for_pair,
                            }

                elif response.status_code == 401:
                    logger.error("Unauthorized - check your API key")
                    self.results['errors'].append("Unauthorized (401) when querying components API")
                    break
                elif response.status_code == 400:
                    logger.warning(f"Bad request for batched components query: {response.text}")
                    self.results['errors'].append(f"Bad request for batched components query: {response.text}")
                elif response.status_code == 404:
                    logger.warning("Components API endpoint not found (404)")
                    self.results['errors'].append("Components API endpoint not found (404)")
                else:
                    logger.warning(f"Unexpected response {response.status_code} for batched components query")
                    self.results['errors'].append(
                        f"Unexpected response {response.status_code} for batched components query"
                    )

            except requests.exceptions.Timeout:
                logger.error("Timeout during batched components query")
                self.results['errors'].append("Timeout during batched components query")
            except requests.exceptions.RequestException as e:
                logger.error(f"Request error during batched components query: {e}")
                self.results['errors'].append(f"Request error during batched components query: {e}")

        return results_by_pair


    def scan_packages(self, affected_packages_data: Dict[str, Any]) -> None:
        """Scan all affected packages and versions"""
        packages = affected_packages_data['packages']
        total_checks = sum(len(pkg['affected_versions']) for pkg in packages)

        print_section_header("SCANNING PACKAGES", Colors.MAGENTA)
        print_info(f"Starting scan of {len(packages)} packages with {total_checks} total version checks")

        logger.info(f"Starting scan of {len(packages)} packages with {total_checks} total version checks")
        logger.info(f"Attack: {affected_packages_data['attack_name']}")
        logger.info(f"Date: {affected_packages_data['attack_date']}")

        # Build a flat list of all package@version checks so we can query the API in batches
        all_checks: List[Dict[str, str]] = []
        for package in packages:
            package_name = package['name']
            for version in package['affected_versions']:
                all_checks.append({'name': package_name, 'version': version})

        # Perform batched lookups up front
        batched_results = self.search_components_batch(all_checks)

        current_check = 0
        start_time = time.time()

        for package in packages:
            package_name = package['name']
            versions = package['affected_versions']

            logger.info(f"Checking package: {package_name} ({len(versions)} versions)")

            for version in versions:
                current_check += 1
                self.results['total_packages_checked'] += 1

                # Calculate progress percentage
                progress = (current_check / total_checks) * 100

                # Simple progress output
                print(f"\r{Colors.CYAN}🔍 {progress:.1f}% | {Colors.YELLOW}{package_name}@{version}{Colors.END}", end='', flush=True)

                # Look up any components found for this package@version from the batched results
                result = batched_results.get((package_name, version))
                if result:
                    self.results['affected_packages_found'].append(result)
                    print(f"\n{Colors.RED}🚨 FOUND: {package_name}@{version} - {result['components_found']} components{Colors.END}")

                    # Show project details for found components
                    for component in result['components']:
                        project_name = component.get('project', {}).get('name', 'Unknown Project')
                        project_version = component.get('projectVersion', {}).get('version', 'Unknown Version')
                        project_id = component.get('project', {}).get('id', '')
                        version_id = component.get('projectVersion', {}).get('id', '')
                        component_id = component.get('id', '')

                        # Create link to component in Finite State dashboard
                        if project_id and version_id and component_id:
                            component_url = f"https://{self.domain}/projects/{project_id}/versions/{version_id}/bill-of-materials?view=list&componentId={component_id}"
                            print(f"   {Colors.DIM}  → Project: {project_name} | Version: {project_version}{Colors.END}")
                            print(f"   {Colors.DIM}  → Link: {component_url}{Colors.END}")
                        else:
                            print(f"   {Colors.DIM}  → Project: {project_name} | Version: {project_version}{Colors.END}")

                    logger.info(f"FOUND: {package_name}@{version} - {result['components_found']} components")

        print(f"\n{Colors.GREEN}✅ Scan completed in {time.time() - start_time:.1f} seconds{Colors.END}")
        print(
            f"{Colors.CYAN}📊 Checked {self.results['total_packages_checked']} package versions "
            f"using {self.results['total_api_calls']} API calls and found "
            f"{self.results['total_components_found']} total software components{Colors.END}"
        )
        logger.info(f"Scan completed. Found {len(self.results['affected_packages_found'])} affected packages")

    def save_results(self, output_file: str = None) -> str:
        """Save scan results to JSON file"""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"scan_results_{timestamp}.json"

        try:
            print_info(f"Saving results to {output_file}...")
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            print_success(f"Results saved to {output_file}")
            logger.info(f"Results saved to {output_file}")
            return output_file
        except Exception as e:
            print_error(f"Failed to save results: {e}")
            logger.error(f"Failed to save results: {e}")
            return ""

    def print_summary(self) -> None:
        """Print a summary of the scan results"""
        print_section_header("SCAN RESULTS SUMMARY", Colors.GREEN)

        # Summary stats
        print(f"\n{Colors.CYAN}📊 Scan Statistics:{Colors.END}")
        print(f"   {Colors.WHITE}Domain:{Colors.END} {Colors.YELLOW}{self.domain}{Colors.END}")
        print(f"   {Colors.WHITE}Total packages checked:{Colors.END} {Colors.CYAN}{self.results['total_packages_checked']}{Colors.END}")
        print(f"   {Colors.WHITE}Total software components found:{Colors.END} {Colors.CYAN}{self.results['total_components_found']}{Colors.END}")
        print(f"   {Colors.WHITE}Affected packages found:{Colors.END} {Colors.RED if self.results['affected_packages_found'] else Colors.GREEN}{len(self.results['affected_packages_found'])}{Colors.END}")
        print(f"   {Colors.WHITE}Scan duration:{Colors.END} {Colors.CYAN}{self.results['scan_duration_seconds']:.2f} seconds{Colors.END}")

        # Results section
        if self.results['affected_packages_found']:
            print(f"\n{Colors.RED}🚨 AFFECTED PACKAGES FOUND:{Colors.END}")
            print(f"{Colors.RED}{'─' * 60}{Colors.END}")
            for i, result in enumerate(self.results['affected_packages_found'], 1):
                print(f"   {Colors.RED}{i}.{Colors.END} {Colors.YELLOW}{result['package_name']}@{result['version']}{Colors.END}")
                print(f"      {Colors.DIM}Components found: {result['components_found']}{Colors.END}")

                # Show project and version details for each component
                for j, component in enumerate(result['components'], 1):
                    project_name = component.get('project', {}).get('name', 'Unknown Project')
                    project_version = component.get('projectVersion', {}).get('version', 'Unknown Version')
                    branch_name = component.get('branch', {}).get('name', 'Unknown Branch')
                    project_id = component.get('project', {}).get('id', '')
                    version_id = component.get('projectVersion', {}).get('id', '')
                    component_id = component.get('id', '')

                    print(f"      {Colors.DIM}  {j}. Project: {project_name} | Version: {project_version} | Branch: {branch_name}{Colors.END}")

                    # Add link to component in Finite State dashboard
                    if project_id and version_id and component_id:
                        component_url = f"https://{self.domain}/projects/{project_id}/versions/{version_id}/bill-of-materials?view=list&componentId={component_id}"
                        print(f"         {Colors.DIM}  🔗 {component_url}{Colors.END}")

            print(f"\n{Colors.RED}⚠️  IMMEDIATE ACTION REQUIRED:{Colors.END}")
            print(f"   {Colors.WHITE}• Click the links above to view components in Finite State dashboard{Colors.END}")
            print(f"   {Colors.WHITE}• Review the affected packages and their project locations{Colors.END}")
            print(f"   {Colors.WHITE}• Check your package.json and lock files{Colors.END}")
            print(f"   {Colors.WHITE}• Update to safe versions immediately{Colors.END}")
            print(f"   {Colors.WHITE}• Review the detailed results file{Colors.END}")
        else:
            print(f"\n{Colors.GREEN}🎉 EXCELLENT NEWS!{Colors.END}")
            print(f"   {Colors.GREEN}✅ No affected packages found in your environment!{Colors.END}")
            print(f"   {Colors.GREEN}✅ Your supply chain appears to be clean{Colors.END}")
            print(f"   {Colors.GREEN}✅ Continue monitoring for future threats{Colors.END}")

        # Errors section
        if self.results['errors']:
            print(f"\n{Colors.YELLOW}⚠️  Errors encountered: {len(self.results['errors'])}{Colors.END}")
            for error in self.results['errors']:
                print(f"   {Colors.DIM}• {error}{Colors.END}")

        # Footer
        print(f"\n{Colors.CYAN}{'─' * 80}{Colors.END}")
        print(f"{Colors.CYAN}Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}")
        print(f"{Colors.CYAN}For detailed results, check the generated JSON file{Colors.END}")
        print(f"{Colors.CYAN}{'─' * 80}{Colors.END}")

def download_wiz_csv(csv_path: str = 'shai-hulud-2-packages.csv') -> bool:
    """Download the Wiz CSV file from GitHub if user chooses to"""
    csv_url = "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv"
    
    print()
    print_info("An optional extended IOC list is available from Wiz Security Research")
    print_info(f"Source: {csv_url}")
    print()
    
    while True:
        response = input(f"{Colors.CYAN}Would you like to download the extended IOC list? (y/n): {Colors.END}").strip().lower()
        if response in ['y', 'yes']:
            try:
                print_info(f"Downloading {csv_path}...")
                response = requests.get(csv_url, timeout=30)
                response.raise_for_status()
                
                with open(csv_path, 'wb') as f:
                    f.write(response.content)
                
                print_success(f"Successfully downloaded {csv_path}")
                logger.info(f"Downloaded Wiz CSV from {csv_url}")
                return True
            except requests.exceptions.RequestException as e:
                print_error(f"Failed to download CSV: {e}")
                print_warning("The scan will continue with only the core package list from affected_packages.json")
                logger.error(f"Failed to download Wiz CSV: {e}")
                return False
        elif response in ['n', 'no']:
            print_info("Skipping CSV download. The scan will use only the core package list.")
            return False
        else:
            print_error("Please enter 'y' or 'n'")

def get_user_input() -> tuple[str, str]:
    """Get domain and API key from user or environment variables"""
    print_section_header("CONFIGURATION", Colors.BLUE)
    print_info("This tool scans for packages affected by the S1ngularity/nx attack (Shai Hulud worm)")
    print_info("You'll need your Finite State domain and API key to proceed")
    print()

    # Check for environment variables first
    domain = os.getenv('FINITE_STATE_DOMAIN')
    api_key = os.getenv('FINITE_STATE_AUTH_TOKEN')
    
    if domain and api_key:
        print_success("Using configuration from environment variables!")
        print_info(f"Domain: {domain}")
        print_info("API Token: [REDACTED]")
        return domain, api_key
    
    # If environment variables not set, prompt user
    print_info("Environment variables not found. Please provide configuration manually.")
    print()

    # Get domain
    while True:
        domain = input(f"{Colors.CYAN}Enter your Finite State domain (e.g., yourcompany.finitestate.io): {Colors.END}").strip()
        if domain:
            break
        print_error("Domain is required. Please try again.")

    # Get API key (hidden input for security)
    while True:
        api_key = getpass.getpass(f"{Colors.CYAN}Enter your API key: {Colors.END}").strip()
        if api_key:
            break
        print_error("API key is required. Please try again.")

    print_success("Configuration complete!")
    return domain, api_key

def main():
    """Main function"""
    start_time = time.time()

    try:
        # Print banner
        print_banner()

        # Get user input
        domain, api_key = get_user_input()

        # Initialize scanner
        print_info("Initializing scanner...")
        scanner = PackageScanner(domain, api_key)
        print_success("Scanner initialized successfully!")

        # Check if Wiz CSV exists, offer to download if not
        csv_path = 'shai-hulud-2-packages.csv'
        if not os.path.exists(csv_path):
            download_wiz_csv(csv_path)
        
        # Load affected packages
        affected_packages_data = scanner.load_affected_packages()

        # Perform scan
        scanner.scan_packages(affected_packages_data)

        # Calculate duration
        end_time = time.time()
        scanner.results['scan_duration_seconds'] = end_time - start_time

        # Save results
        output_file = scanner.save_results()

        # Print summary
        scanner.print_summary()

        if output_file:
            print(f"\n{Colors.CYAN}📄 Detailed results saved to: {Colors.YELLOW}{output_file}{Colors.END}")

    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⚠️  Scan interrupted by user{Colors.END}")
        print(f"{Colors.YELLOW}Partial results may be available in the log file.{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
