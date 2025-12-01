# 03 - Findings Triage Workflows

This section covers triaging, prioritizing, and managing findings efficiently through automated workflows and manual processes.

## Overview

Effectively managing findings is crucial for maintaining security without overwhelming your team. This stage provides tools and workflows for triaging findings, setting priorities, and automating common triage tasks.

## Goals

By the end of this stage, you should be able to:

- Understand different triage strategies
- Automate finding prioritization
- Set up workflows for finding management
- Use the Autotriage Script effectively
- Create custom triage rules and filters

## Getting Started

### Prerequisites

- Completed first scan and have findings to manage
- API access for programmatic finding management
- Understanding of your security priorities and policies

### Required Environment Variables

Before running any scripts or tools in this section, ensure you have the required environment variables set:

```bash
export FINITE_STATE_AUTH_TOKEN=<your_api_token>
export FINITE_STATE_DOMAIN=<your_fqdn>
```

### Quick Start

1. **Review your findings** - Understand the types of findings you're seeing
2. **Set up triage rules** - Define what needs immediate attention
3. **Automate triage** - Use the Autotriage Script to automate common tasks
4. **Establish workflows** - Create processes for your team

## Common Use Cases

### Automated Triage

- **Autotriage Script** - Automatically categorize and prioritize findings based on rules
- Risk-based prioritization
- Duplicate detection and merging
- False positive filtering

### Manual Triage Workflows

- Review and validation processes
- Team assignment workflows
- Escalation procedures
- Status tracking

### Finding Management

- Bulk operations on findings
- Finding enrichment with additional context
- Integration with ticketing systems
- Status updates and lifecycle management

## Available Resources

### Autotriage Script

The **Autotriage Script** automates finding triage based on configurable rules:

- **Risk scoring** - Automatically score findings based on severity, CVSS, and context
- **Categorization** - Group findings by type, component, or other criteria
- **Priority assignment** - Assign priorities based on business rules
- **Duplicate detection** - Identify and merge duplicate findings
- **False positive marking** - Automatically mark known false positives

#### Getting Started with Autotriage

```bash
# Example usage
python autotriage.py --config triage-rules.json --scan-id <scan-id>
```

#### Configuration

The Autotriage Script uses configuration files to define triage rules. Examples include:

- Severity-based prioritization
- Component-specific rules
- CVE-based filtering
- Custom business logic

### Triage Workflow Examples

- **Basic triage workflow** - Simple prioritization and assignment
- **Advanced workflow** - Multi-stage triage with escalation
- **Team-based workflow** - Assignment and routing by team
- **Compliance workflow** - Triage focused on compliance requirements

### Tools

- Finding filters and queries
- Bulk operation utilities
- Integration examples
- Reporting utilities

## Triage Strategies

### Risk-Based Triage

Prioritize findings based on:
- CVSS scores
- Exploitability
- Asset criticality
- Business impact

### Time-Based Triage

Organize findings by:
- Discovery date
- Age of vulnerability
- SLA requirements
- Compliance deadlines

### Component-Based Triage

Group findings by:
- Application components
- Infrastructure layers
- Team ownership
- Technology stack

## Best Practices

- **Define clear criteria** - Establish consistent rules for prioritization
- **Automate repetitive tasks** - Use scripts for common triage operations
- **Document decisions** - Track why findings are prioritized or dismissed
- **Regular reviews** - Periodically review and update triage rules
- **Team alignment** - Ensure everyone understands the triage process

## Integration Examples

### Ticketing Systems

- Create tickets for high-priority findings
- Sync status between systems
- Update tickets based on scan results

### Notification Systems

- Alert teams when critical findings are discovered
- Daily/weekly triage summaries
- Escalation notifications

## Next Steps

After establishing triage workflows:

- Move to **[04 - Remediation and Fixes](../04-remediation-and-fixes/)** to address findings
- Review **[05 - Reporting and Compliance](../05-reporting-and-compliance/)** for triage reporting
- Explore **[06 - Advanced Integrations](../06-advanced-integrations-and-demos/)** for custom integrations

## Related Resources

- [Shared API Clients](../shared/api-clients/) - For programmatic finding management
- [Shared Common Helpers](../shared/common-helpers/) - For filtering and processing utilities
- [Support Guide](../SUPPORT.md) - For help with triage workflows

## Troubleshooting

### Common Issues

**Autotriage Script errors**
- Verify configuration file format
- Check API credentials and permissions
- Review rule logic for errors

**Finding status updates**
- Ensure proper API permissions
- Check finding IDs are correct
- Verify status values are valid

**Performance with large datasets**
- Use pagination for large result sets
- Consider batch processing
- Optimize query filters

### Getting Help

- Review Autotriage Script documentation
- Check example configurations
- Open an issue with your use case

