#!/usr/bin/env python3
"""Unit tests for CLI argument parsing and validation."""
import argparse
import os
import sys
from io import StringIO
from unittest import mock

import pytest

from finite_state_reporter.cli import cli


class TestCLIArgumentParsing:
    """Test CLI successfully parses project name and version name arguments."""

    @mock.patch.dict(os.environ, {"FINITE_STATE_AUTH_TOKEN": "test-token", "FINITE_STATE_DOMAIN": "acme.finitestate.io"})
    @mock.patch("finite_state_reporter.cli.main")
    @mock.patch("finite_state_reporter.core.reporter.FiniteStateReporter")
    def test_cli_parses_project_and_version_arguments(self, mock_reporter_class, mock_main):
        """Test that CLI correctly parses --project and --project-version arguments."""
        mock_reporter = mock.MagicMock()
        mock_reporter.lookup_version_id_by_names.return_value = "12345"
        mock_reporter_class.return_value = mock_reporter

        # Mock sys.argv
        with mock.patch.object(
            sys,
            "argv",
            ["finite-state-reporter", "--project", "TestProject", "--project-version", "v1.0.0"],
        ):
            cli()

        # Verify lookup was called with correct arguments
        mock_reporter.lookup_version_id_by_names.assert_called_once_with("TestProject", "v1.0.0")

        # Verify main was called with the looked-up version ID
        mock_main.assert_called_once()
        call_args = mock_main.call_args[0]
        assert call_args[0] == "test-token"  # token
        assert call_args[1] == "acme"  # subdomain
        assert call_args[2] == "12345"  # version_id from lookup

    @mock.patch.dict(os.environ, {"FINITE_STATE_AUTH_TOKEN": "test-token", "FINITE_STATE_DOMAIN": "acme.finitestate.io"})
    @mock.patch("finite_state_reporter.cli.main")
    def test_cli_parses_project_version_id_argument(self, mock_main):
        """Test that CLI correctly parses --project-version-id argument."""
        with mock.patch.object(
            sys,
            "argv",
            ["finite-state-reporter", "--project-version-id", "67890"],
        ):
            cli()

        # Verify main was called with the provided version ID
        mock_main.assert_called_once()
        call_args = mock_main.call_args[0]
        assert call_args[0] == "test-token"  # token
        assert call_args[1] == "acme"  # subdomain
        assert call_args[2] == "67890"  # version_id


class TestCLIMutuallyExclusiveArguments:
    """Test CLI raises errors for mutually exclusive arguments used incorrectly."""

    @mock.patch.dict(os.environ, {"FINITE_STATE_AUTH_TOKEN": "test-token", "FINITE_STATE_DOMAIN": "acme.finitestate.io"})
    def test_cli_error_project_without_project_version(self):
        """Test that CLI raises error when --project is used without --project-version."""
        with mock.patch.object(
            sys,
            "argv",
            ["finite-state-reporter", "--project", "TestProject"],
        ):
            with pytest.raises(SystemExit) as exc_info:
                with mock.patch("sys.stderr", new_callable=StringIO):
                    cli()
            
            # SystemExit with code 2 indicates argument parsing error
            assert exc_info.value.code == 2

    @mock.patch.dict(os.environ, {"FINITE_STATE_AUTH_TOKEN": "test-token", "FINITE_STATE_DOMAIN": "acme.finitestate.io"})
    def test_cli_error_project_version_without_project(self):
        """Test that CLI raises error when --project-version is used without --project."""
        with mock.patch.object(
            sys,
            "argv",
            ["finite-state-reporter", "--project-version", "v1.0.0"],
        ):
            with pytest.raises(SystemExit) as exc_info:
                with mock.patch("sys.stderr", new_callable=StringIO):
                    cli()
            
            # SystemExit with code 2 indicates argument parsing error
            assert exc_info.value.code == 2

    @mock.patch.dict(os.environ, {"FINITE_STATE_AUTH_TOKEN": "test-token", "FINITE_STATE_DOMAIN": "acme.finitestate.io"})
    def test_cli_error_both_version_id_methods_used(self):
        """Test that CLI raises error when both version identification methods are used."""
        with mock.patch.object(
            sys,
            "argv",
            [
                "finite-state-reporter",
                "--project-version-id",
                "12345",
                "--project",
                "TestProject",
                "--project-version",
                "v1.0.0",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                with mock.patch("sys.stderr", new_callable=StringIO):
                    cli()
            
            # SystemExit with code 2 indicates argument parsing error
            assert exc_info.value.code == 2

    @mock.patch.dict(os.environ, {"FINITE_STATE_AUTH_TOKEN": "test-token", "FINITE_STATE_DOMAIN": "acme.finitestate.io"})
    def test_cli_error_neither_version_identification_method(self):
        """Test that CLI raises error when neither version identification method is provided."""
        with mock.patch.object(
            sys,
            "argv",
            ["finite-state-reporter"],
        ):
            with pytest.raises(SystemExit) as exc_info:
                with mock.patch("sys.stderr", new_callable=StringIO):
                    cli()
            
            # SystemExit with code 2 indicates argument parsing error
            assert exc_info.value.code == 2
