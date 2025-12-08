#!/usr/bin/env python3
"""
Main entry point for Finite State Reporter.

This script provides a simple way to run the finite-state-reporter CLI
using the standard Python pattern: python main.py

Usage:
    python main.py --token YOUR_TOKEN --subdomain YOUR_SUBDOMAIN --project-version-id YOUR_VERSION_ID
    python main.py --token YOUR_TOKEN --subdomain YOUR_SUBDOMAIN --project YOUR_PROJECT_NAME --project-version YOUR_VERSION_NAME
"""

if __name__ == "__main__":
    from src.finite_state_reporter.cli import cli

    cli()
