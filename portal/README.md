# Customer Resources Portal

A self-hosted web portal for browsing and executing Finite State customer tools, with optional AI-powered assistance for report generation and tool selection.

## Features

- **Tool Browser**: Browse all available tools organized by category with detailed descriptions
- **Form-Based Execution**: Configure and execute tools through an intuitive web interface
- **Job Management**: Track job status, view logs, and download output files
- **AI Assistant** (Optional): Chat interface for help with tools and generating custom YAML recipes
- **Self-Hosted**: Run locally with Docker - no external hosting required

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Finite State API credentials
- (Optional) OpenAI or Anthropic API key for AI features

### 1. Clone the Repository

```bash
git clone <repository-url>
cd customer-resources
```

### 2. Set Environment Variables

```bash
# Required: Finite State API credentials
export FINITE_STATE_AUTH_TOKEN="your-api-token"
export FINITE_STATE_DOMAIN="your-domain.finitestate.io"

# Optional: Enable AI assistant
export ANTHROPIC_API_KEY="sk-ant-..."
# or
export OPENAI_API_KEY="sk-..."
```

### 3. Start the Portal

```bash
docker-compose up -d
```

### 4. Access the Portal

Open your browser to: **http://localhost:8080**

## Available Tools

The portal provides access to the following tools:

### Reporting
- **Report Generator** (`fs-report`) - Generate HTML, CSV, and XLSX reports using YAML recipes
- **PDF Risk Reporter** (`fs-reporter`) - Generate comprehensive PDF risk summary reports
- **License Report** (`report-license`) - Generate CSV reports of component licenses

### Onboarding
- **Artifact Uploader** (`fs-upload`) - Bulk upload artifacts for scanning
- **Bulk User Creator** (`bulk-create-users`) - Create multiple users from CSV

### Triage
- **Auto Triage** (`autotriage`) - Automate VEX-compliant vulnerability triage

### Remediation
- **Supply Chain Scanner** (`search-affected-packages`) - Scan for packages affected by supply chain attacks

### Advanced
- **Component Plus** (`componentplus`) - SBOM-based component injection

## AI Assistant

When an AI API key is configured, the portal includes an AI assistant that can:

- Answer questions about available tools
- Help select the right tool for your needs
- Generate custom YAML recipes for `fs-report` based on natural language descriptions
- Explain report outputs and findings

### Example Prompts

- "What tools are available for reporting?"
- "Generate a recipe showing critical vulnerabilities by project for the last month"
- "How do I triage findings in bulk?"

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `FINITE_STATE_AUTH_TOKEN` | Yes | Your Finite State API token |
| `FINITE_STATE_DOMAIN` | Yes | Your Finite State domain (e.g., `acme.finitestate.io`) |
| `OPENAI_API_KEY` | No | OpenAI API key (enables AI assistant with GPT-4o) |
| `ANTHROPIC_API_KEY` | No | Anthropic API key (enables AI assistant with Claude) |
| `DEBUG` | No | Enable debug mode (default: `false`) |

### Data Storage

All data is stored locally in a Docker volume:
- SQLite database (jobs, chat history, recipes)
- Generated output files

To clear all data, use the "Erase All Data" button in Settings.

## Running Locally (Recommended for Development)

Running locally is recommended because it uses your existing tool installations with their dependencies already set up.

```bash
cd portal

# Install portal dependencies
poetry install

# Set environment variables
export FINITE_STATE_AUTH_TOKEN="your-token"
export FINITE_STATE_DOMAIN="your-domain.finitestate.io"

# Optional: Enable AI assistant
export ANTHROPIC_API_KEY="sk-ant-..."

# Run the portal
poetry run uvicorn app.main:app --reload --port 8080
```

Then open http://localhost:8080

**Note:** When running locally, update the tool definitions in `tool_definitions/*.yaml` to use relative paths from the repo root instead of container paths. For example, change `source_path: "/app/tools/reporting/fs-report"` to `source_path: "../05-reporting-and-compliance/fs-report"`.

## Docker Deployment

Docker deployment requires that tool dependencies are installed inside the container. This is still a work in progress.

### Project Structure

```
portal/
├── app/
│   ├── main.py              # FastAPI application entry
│   ├── config.py            # Settings and environment config
│   ├── database.py          # SQLite setup and models
│   ├── routes/              # API route handlers
│   │   ├── home.py          # Dashboard
│   │   ├── tools.py         # Tool browser and execution
│   │   ├── jobs.py          # Job management
│   │   ├── chat.py          # AI chat interface
│   │   └── settings.py      # Settings and data management
│   ├── services/            # Business logic
│   │   ├── tool_registry.py # Tool discovery
│   │   ├── tool_executor.py # Tool execution
│   │   ├── ai_assistant.py  # AI integration
│   │   └── recipe_validator.py
│   └── templates/           # Jinja2 HTML templates
├── tool_definitions/        # YAML tool configurations
├── Dockerfile
├── pyproject.toml
└── README.md
```

### Adding New Tools

1. Create a YAML definition in `tool_definitions/`:

```yaml
name: my-tool
display_name: "My Tool"
description: "Description of what the tool does"
category: "Category Name"
source_path: "../path/to/tool"

parameters:
  - name: param1
    type: text
    label: "Parameter 1"
    required: true

command_template: |
  cd {{ source_path }} && python my_tool.py --param1 "{{ param1 }}"

outputs:
  - type: file
    pattern: "*.csv"
    label: "Output CSV"
```

2. Restart the portal to pick up the new tool definition

## Troubleshooting

### Portal won't start

1. Check Docker is running: `docker ps`
2. Check logs: `docker-compose logs portal`
3. Verify environment variables are set

### Tools fail to execute

1. Ensure `FINITE_STATE_AUTH_TOKEN` and `FINITE_STATE_DOMAIN` are correct
2. Test API connection in Settings
3. Check job logs for specific error messages

### AI Assistant not working

1. Verify API key is set: `echo $ANTHROPIC_API_KEY` or `echo $OPENAI_API_KEY`
2. Restart the portal after setting the key
3. Check the Settings page shows AI as "Enabled"

## Security

- API credentials are read from environment variables only (never stored in the database)
- AI API keys can optionally be stored encrypted in the database
- All tool parameters are validated before execution
- File downloads are restricted to job output directories

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.
