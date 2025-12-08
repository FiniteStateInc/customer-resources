#!/usr/bin/env python3
"""Unit tests for FiniteStateReporter lookup methods and API client error handling."""
from unittest import mock

import pytest
import requests

from finite_state_reporter.core.reporter import FiniteStateReporter


class TestLookupVersionIdByNames:
    """Test lookup_version_id_by_names method error handling."""

    def test_lookup_raises_value_error_when_project_not_found(self):
        """Test that lookup_version_id_by_names raises ValueError when project name is not found."""
        reporter = FiniteStateReporter("acme", "test-token")

        # Mock get_all_projects to return a list without the target project
        with mock.patch.object(reporter, "get_all_projects") as mock_get_projects:
            mock_get_projects.return_value = [
                {"id": "1", "name": "Project A"},
                {"id": "2", "name": "Project B"},
                {"id": "3", "name": "Project C"},
            ]

            # Should raise ValueError with appropriate message
            with pytest.raises(ValueError) as exc_info:
                reporter.lookup_version_id_by_names("NonExistentProject", "v1.0.0")

            # Verify the error message contains the project name
            assert "NonExistentProject" in str(exc_info.value)
            assert "not found" in str(exc_info.value)

    def test_lookup_raises_value_error_when_version_not_found(self):
        """Test that lookup_version_id_by_names raises ValueError when version name is not found."""
        reporter = FiniteStateReporter("acme", "test-token")

        # Mock get_all_projects to return a project
        with mock.patch.object(reporter, "get_all_projects") as mock_get_projects:
            mock_get_projects.return_value = [
                {"id": "123", "name": "TestProject"},
            ]

            # Mock get_project_versions to return versions without the target version
            with mock.patch.object(reporter, "get_project_versions") as mock_get_versions:
                mock_get_versions.return_value = [
                    {"id": "v1", "version": "v1.0.0"},
                    {"id": "v2", "version": "v2.0.0"},
                    {"id": "v3", "version": "v3.0.0"},
                ]

                # Should raise ValueError with appropriate message
                with pytest.raises(ValueError) as exc_info:
                    reporter.lookup_version_id_by_names("TestProject", "v4.0.0")

                # Verify the error message contains the version name and project name
                assert "v4.0.0" in str(exc_info.value)
                assert "TestProject" in str(exc_info.value)
                assert "not found" in str(exc_info.value)

    def test_lookup_succeeds_when_project_and_version_found(self):
        """Test that lookup_version_id_by_names returns correct version ID when both are found."""
        reporter = FiniteStateReporter("acme", "test-token")

        # Mock get_all_projects to return the target project
        with mock.patch.object(reporter, "get_all_projects") as mock_get_projects:
            mock_get_projects.return_value = [
                {"id": "123", "name": "TestProject"},
            ]

            # Mock get_project_versions to return the target version
            with mock.patch.object(reporter, "get_project_versions") as mock_get_versions:
                mock_get_versions.return_value = [
                    {"id": "v456", "version": "v1.0.0"},
                ]

                # Should return the version ID successfully
                version_id = reporter.lookup_version_id_by_names("TestProject", "v1.0.0")
                assert version_id == "v456"


class TestAPIClientEmptyResponseHandling:
    """Test API client methods correctly handle 404 responses and empty data."""

    def test_get_all_projects_returns_empty_list_for_404(self):
        """Test that get_all_projects returns empty list for 404 response."""
        reporter = FiniteStateReporter("acme", "test-token")

        # Mock the session.get to return 404
        with mock.patch.object(reporter.session, "get") as mock_get:
            mock_response = mock.Mock()
            mock_response.status_code = 404
            mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Not Found")
            mock_get.return_value = mock_response

            # Should raise HTTPError (not handle 404 specially for projects)
            with pytest.raises(requests.exceptions.HTTPError):
                reporter.get_all_projects()

    def test_get_all_projects_returns_empty_list_for_empty_data(self):
        """Test that get_all_projects returns empty list when API returns empty data."""
        reporter = FiniteStateReporter("acme", "test-token")

        # Mock the session.get to return empty list
        with mock.patch.object(reporter.session, "get") as mock_get:
            mock_response = mock.Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = []
            mock_get.return_value = mock_response

            result = reporter.get_all_projects()
            assert result == []

    def test_get_all_projects_returns_empty_list_for_empty_items(self):
        """Test that get_all_projects returns empty list when API returns empty items."""
        reporter = FiniteStateReporter("acme", "test-token")

        # Mock the session.get to return dict with empty items
        with mock.patch.object(reporter.session, "get") as mock_get:
            mock_response = mock.Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"items": [], "total": 0}
            mock_get.return_value = mock_response

            result = reporter.get_all_projects()
            assert result == []

    def test_get_project_versions_returns_empty_list_for_404(self):
        """Test that get_project_versions returns empty list for 404 response."""
        reporter = FiniteStateReporter("acme", "test-token")

        # Mock the session.get to return 404
        with mock.patch.object(reporter.session, "get") as mock_get:
            mock_response = mock.Mock()
            mock_response.status_code = 404
            mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Not Found")
            mock_get.return_value = mock_response

            # Should raise HTTPError (not handle 404 specially for versions)
            with pytest.raises(requests.exceptions.HTTPError):
                reporter.get_project_versions("123")

    def test_get_project_versions_returns_empty_list_for_empty_data(self):
        """Test that get_project_versions returns empty list when API returns empty data."""
        reporter = FiniteStateReporter("acme", "test-token")

        # Mock the session.get to return empty list
        with mock.patch.object(reporter.session, "get") as mock_get:
            mock_response = mock.Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = []
            mock_get.return_value = mock_response

            result = reporter.get_project_versions("123")
            assert result == []

    def test_get_components_returns_empty_list_for_404(self):
        """Test that get_version_components returns empty list for 404 response."""
        reporter = FiniteStateReporter("acme", "test-token")

        # Mock the session.get to return 404
        with mock.patch.object(reporter.session, "get") as mock_get:
            mock_response = mock.Mock()
            mock_response.status_code = 404
            mock_get.return_value = mock_response

            # Should return empty list for 404 (handled in the method)
            result = reporter.get_version_components("version-123")
            assert result == []

    def test_get_components_returns_empty_list_for_empty_data(self):
        """Test that get_version_components returns empty list when API returns empty data."""
        reporter = FiniteStateReporter("acme", "test-token")

        # Mock the session.get to return empty list
        with mock.patch.object(reporter.session, "get") as mock_get:
            mock_response = mock.Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = []
            mock_get.return_value = mock_response

            result = reporter.get_version_components("version-123")
            assert result == []

    def test_get_components_returns_empty_list_for_empty_items(self):
        """Test that get_version_components returns empty list when API returns empty items."""
        reporter = FiniteStateReporter("acme", "test-token")

        # Mock the session.get to return dict with empty items
        with mock.patch.object(reporter.session, "get") as mock_get:
            mock_response = mock.Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"items": [], "total": 0}
            mock_get.return_value = mock_response

            result = reporter.get_version_components("version-123")
            assert result == []

    def test_get_findings_returns_empty_list_for_404(self):
        """Test that get_version_findings returns empty list for 404 response."""
        reporter = FiniteStateReporter("acme", "test-token")

        # Mock the session.get to return 404
        with mock.patch.object(reporter.session, "get") as mock_get:
            mock_response = mock.Mock()
            mock_response.status_code = 404
            mock_get.return_value = mock_response

            # Should return empty list for 404 (handled in the method)
            result = reporter.get_version_findings("version-123")
            assert result == []

    def test_get_findings_returns_empty_list_for_empty_data(self):
        """Test that get_version_findings returns empty list when API returns empty data."""
        reporter = FiniteStateReporter("acme", "test-token")

        # Mock the session.get to return empty list
        with mock.patch.object(reporter.session, "get") as mock_get:
            mock_response = mock.Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = []
            mock_get.return_value = mock_response

            result = reporter.get_version_findings("version-123")
            assert result == []

    def test_get_findings_returns_empty_list_for_empty_items(self):
        """Test that get_version_findings returns empty list when API returns empty items."""
        reporter = FiniteStateReporter("acme", "test-token")

        # Mock the session.get to return dict with empty items
        with mock.patch.object(reporter.session, "get") as mock_get:
            mock_response = mock.Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"items": [], "total": 0}
            mock_get.return_value = mock_response

            result = reporter.get_version_findings("version-123")
            assert result == []
