# Supply Chain Attack Package Scanner

A Python tool to scan for packages affected by the **S1ngularity/nx attack (Shai Hulud worm)** using the Finite State Customer API. This tool helps identify compromised npm packages in your environment.

## 🚨 About the Attack

The S1ngularity/nx attack is a large-scale supply chain attack that occurred on September 16, 2025. The attackers deployed a self-propagating worm called "Shai Hulud" that:

- **Steals secrets** and publishes them to GitHub publicly
- **Runs trufflehog** and queries cloud metadata endpoints to gather secrets
- **Creates GitHub actions** with data exfiltration mechanisms
- **Makes private repositories public**
- **Self-propagates** by re-publishing itself into other npm packages owned by compromised maintainers

## 📋 Features

- ✅ **Modular package list** - Easy to update when new affected packages are discovered
- ✅ **Real-time progress** - Clean progress display showing percentage and current package being checked
- ✅ **Comprehensive logging** - Detailed logs saved to file and console
- ✅ **Error handling** - Robust error handling with detailed error messages
- ✅ **Results export** - JSON export of scan results for further analysis
- ✅ **API integration** - Uses Finite State Customer API with proper authentication
- ✅ **Batch processing** - Efficiently scans multiple packages and versions
- ✅ **Professional output** - Clean, organized results with actionable recommendations
- ✅ **Component tracking** - Shows total software components found matching affected packages
- ✅ **Project details** - Displays project name, version, and branch for each affected component found
- ✅ **Direct component links** - Clickable links to view affected components in Finite State dashboard
- ✅ **Security features** - Hidden API key input to protect sensitive credentials

## 🛠️ Requirements

- Python 3.8+
- Finite State API access
- Valid API key

## 📦 Installation

Install [uv](https://docs.astral.sh/uv/):

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

No further installation required - uv handles dependencies automatically.

## 🚀 Usage

```bash
uv run search_affected_packages.py
```

The script will:
1. **Prompt for configuration** (if not set via environment variables):
   - **Domain**: Your Finite State domain (e.g., `yourcompany.finitestate.io`)
   - **API Key**: Your Finite State API key

2. **Optionally download extended IOC list** (on first run):
   - If `shai-hulud-2-packages.csv` doesn't exist, you'll be prompted to download it
   - This extends the scan with additional affected packages from Wiz Security Research
   - You can choose to skip this and use only the core package list

Alternatively, you can set these environment variables to skip the prompts:
- `FINITE_STATE_DOMAIN`: Your Finite State domain
- `FINITE_STATE_AUTH_TOKEN`: Your API authentication token

### Example Session


```
╔══════════════════════════════════════════════════════════════════════════════╗
║                               FINITE STATE                                   ║
║                                                                              ║
║                    🛡️  SUPPLY CHAIN ATTACK SCANNER  🛡️                       ║
║                                                                              ║
║             Scanning for S1ngularity/nx Attack (Shai Hulud Worm)             ║
║                     Affected Packages Detection Tool                         ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

================================================================================
                                 CONFIGURATION
================================================================================
ℹ️  This tool scans for packages affected by the S1ngularity/nx attack (Shai Hulud worm)
ℹ️  You'll need your Finite State domain and API key to proceed

Enter your Finite State domain (e.g., yourcompany.finitestate.io): yourcompany
Enter your API key: [hidden for security]
✅ Configuration complete!

🔍 100.0% | yoo-styles@6.0.326
✅ Scan completed in 45.2 seconds

================================================================================
                              SCAN RESULTS SUMMARY
================================================================================

📊 Scan Statistics:
   Domain: yourcompany.finitestate.io
   Total packages checked: 114
   Total software components found: 1
   Affected packages found: 1
   Scan duration: 45.23 seconds

🚨 AFFECTED PACKAGES FOUND:
────────────────────────────────────────────────────────────
   1. remark-preset-lint-crowdstrike@4.0.1
      Components found: 1
        1. Project: npm supply chain attack test | Version: 2025-09-17 | Branch: main
           🔗 https://yourcompany.finitestate.io/projects/1234567890123456789/versions/9876543210987654321/bill-of-materials?view=list&componentId=1111111111111111111

🎉 EXCELLENT NEWS!
   ✅ No affected packages found in your environment!
   ✅ Your supply chain appears to be clean
   ✅ Continue monitoring for future threats

📄 Detailed results saved to: scan_results_202501XX_XXXXXX.json
```

## 📁 File Structure

```
npm_attack/
├── search_affected_packages.py    # Main scanner script
├── affected_packages.json         # Core list of affected packages (modular)
├── shai-hulud-2-packages.csv     # Optional: extended IOC list from Wiz (downloaded on first run)
├── README.md                      # This documentation
├── package_scan.log              # Log file (created during scan)
└── scan_results_YYYYMMDD_HHMMSS.json  # Results file (created after scan)
```

## 📊 Output Files

### Log File (`package_scan.log`)
Contains detailed logging information including:
- Scan start/end times
- API request details
- Error messages
- Found packages information

### Results File (`scan_results_*.json`)
JSON file containing:
```json
{
  "scan_timestamp": "2025-01-XX T XX:XX:XX",
  "domain": "yourcompany.finitestate.io",
  "total_packages_checked": 147,
  "affected_packages_found": [
    {
      "package_name": "@crowdstrike/commitlint",
      "version": "8.1.1",
      "components_found": 2,
      "components": [...]
    }
  ],
  "scan_duration_seconds": 45.23,
  "errors": []
}
```

## 🔧 Configuration

### Updating Affected Packages

To add new affected packages, edit `affected_packages.json`:

```json
{
  "attack_name": "Attack Name",
  "attack_date": "YYYY-MM-DD",
  "description": "Attack description",
  "packages": [
    {
      "name": "package-name",
      "affected_versions": ["1.0.0", "1.0.1"]
    }
  ]
}
```

In addition, if `shai-hulud-2-packages.csv` is present in the same directory, the scanner will automatically merge its package/version data into the in-memory list before scanning. This CSV is based on the public IOC list from Wiz (see **Attribution** below).

### API Configuration

The script uses the Finite State Customer API:
- **Base URL**: `https://{domain}/api`
- **Endpoint**: `/public/v0/components`
- **Authentication**: X-Authorization header
- **Filtering**: RSQL syntax for name and version matching

## 🚨 Security Considerations

- **API Key**: Never commit your API key to version control
- **Logs**: Review log files before sharing as they may contain sensitive information
- **Results**: Results files may contain internal component information

## 🧪 Testing

Before running the scanner, you can test that everything is set up correctly:

```bash
# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Run the test script
python test_scanner.py
```

This will verify:
- ✅ The affected packages file is valid JSON
- ✅ The main script imports successfully
- ✅ Required dependencies are available

## 🔍 Troubleshooting

### Common Issues

1. **"Unauthorized" Error**
   - Verify your API key is correct
   - Check that your API key has the necessary permissions

2. **"API endpoint not found"**
   - Verify your domain is correct
   - Ensure the Finite State API is accessible from your network

3. **Timeout Errors**
   - Check your internet connection
   - The API may be experiencing high load

4. **"Could not find affected_packages.json"**
   - Ensure the file exists in the same directory as the script
   - Check file permissions

### Debug Mode

For more detailed debugging, you can modify the logging level in the script:
```python
logging.basicConfig(level=logging.DEBUG, ...)
```

## 📈 Performance

- **Typical scan time**: 30-60 seconds for 147 package versions
- **API rate limiting**: Built-in 0.1 second delay between requests
- **Memory usage**: Minimal, processes results incrementally
- **Network usage**: ~1-2 MB for typical scan

## 🤝 Contributing

To contribute to this tool:

1. Update `affected_packages.json` with new affected packages
2. Test the script with your environment
3. Submit improvements or bug fixes

## 📚 References

- [Aikido Security Blog - S1ngularity/nx Attack](https://www.aikido.dev/blog/s1ngularity-nx-attackers-strike-again)
- [Finite State Customer API Documentation](https://docs.finitestate.io)
- [RSQL Query Language](https://github.com/jirutka/rsql-parser)

### Attribution

- Additional affected package indicators are sourced from Wiz's public IOC list for the Shai Hulud / S1ngularity campaign:  
  [`shai-hulud-2-packages.csv`](https://github.com/wiz-sec-public/wiz-research-iocs/blob/main/reports/shai-hulud-2-packages.csv).

  **Note**: The CSV file is not included in this repository. On first run, the script will prompt you to download it directly from Wiz's GitHub repository. You can choose to skip this and use only the core package list from `affected_packages.json`.

## ⚠️ Disclaimer

This tool is provided as-is for security assessment purposes. Always verify results and follow your organization's security procedures. The authors are not responsible for any misuse or damage caused by this tool.

## 📄 License

This project is provided under the MIT License. See LICENSE file for details.

---

**Last Updated**: January 2025
**Attack Date**: September 16, 2025
**Tool Version**: 1.0
