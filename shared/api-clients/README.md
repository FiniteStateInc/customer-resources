# API Clients

This directory contains shared API client libraries and utilities for interacting with the platform APIs.

## Overview

API clients in this directory provide:

- Authenticated API access
- Common request/response handling
- Error handling and retry logic
- Rate limiting support
- Standardized data models

## Available Clients

*(Clients will be documented here as they are added)*

## Required Environment Variables

All API clients require the following environment variables:

```bash
export FINITE_STATE_AUTH_TOKEN=<your_api_token>
export FINITE_STATE_DOMAIN=<your_fqdn>
```

## Usage Example

```python
# Example usage pattern
from api_clients import PlatformClient
import os

client = PlatformClient(
    api_token=os.getenv('FINITE_STATE_AUTH_TOKEN'),
    domain=os.getenv('FINITE_STATE_DOMAIN')
)
results = client.get_scans()
```

## Authentication

API clients use authentication tokens provided via environment variables:

- `FINITE_STATE_AUTH_TOKEN` - Your API authentication token
- `FINITE_STATE_DOMAIN` - The FQDN for your Finite State instance (e.g., `acme.finitestate.io`). The domain typically corresponds to your instance and often includes your company name.

**Important**: Never commit API tokens or credentials to version control. Always use environment variables or secure secret management systems.

## Contributing

When adding new API clients:

1. Follow the existing client patterns
2. Include comprehensive error handling
3. Add usage examples and documentation
4. Include tests if applicable
5. Document authentication requirements

## Documentation

For detailed API documentation, refer to the official API documentation or the platform's API reference.

