# Copyright (c) 2025 Aiven, Helsinki, Finland. https://aiven.io/
"""Tests for Google Cloud Storage credential handling after oauth2client replacement."""

from __future__ import annotations

from io import StringIO
from rohmu.object_storage.google import get_credentials
from unittest.mock import Mock, patch

import json
import pytest


def test_get_credentials_with_service_account_dict() -> None:
    """Test loading service account credentials from dictionary."""
    service_account_creds = {
        "type": "service_account",
        "project_id": "test-project",
        "private_key_id": "key-id",
        "private_key": (
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...\n"
            "-----END PRIVATE KEY-----\n"
        ),
        "client_email": "test@test-project.iam.gserviceaccount.com",
        "client_id": "123456789",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test%40test-project.iam.gserviceaccount.com",
    }

    mock_creds = Mock()
    with patch("google.auth.load_credentials_from_dict") as mock_load:
        mock_load.return_value = (mock_creds, "test-project")

        result = get_credentials(credentials=service_account_creds)

        assert result is mock_creds
        mock_load.assert_called_once_with(service_account_creds, scopes=["https://www.googleapis.com/auth/cloud-platform"])


def test_get_credentials_with_authorized_user_dict() -> None:
    """Test loading authorized user credentials from dictionary."""
    authorized_user_creds = {
        "type": "authorized_user",
        "client_id": "123456789.apps.googleusercontent.com",
        "client_secret": "client-secret",
        "refresh_token": "refresh-token",
    }

    mock_creds = Mock()
    with patch("google.auth.load_credentials_from_dict") as mock_load:
        mock_load.return_value = (mock_creds, "test-project")

        result = get_credentials(credentials=authorized_user_creds)

        assert result is mock_creds
        mock_load.assert_called_once_with(authorized_user_creds, scopes=["https://www.googleapis.com/auth/cloud-platform"])


def test_get_credentials_from_file() -> None:
    """Test loading credentials from a file object."""
    service_account_creds = {
        "type": "service_account",
        "project_id": "test-project",
        "client_email": "test@test-project.iam.gserviceaccount.com",
    }

    credential_file = StringIO(json.dumps(service_account_creds))
    mock_creds = Mock()

    with patch("google.auth.load_credentials_from_dict") as mock_load:
        mock_load.return_value = (mock_creds, "test-project")

        result = get_credentials(credential_file=credential_file)

        assert result is mock_creds
        # Verify that the credentials were enhanced with required fields
        expected_creds = service_account_creds.copy()
        expected_creds.update(
            {
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            }
        )
        mock_load.assert_called_once_with(expected_creds, scopes=["https://www.googleapis.com/auth/cloud-platform"])


def test_get_credentials_default() -> None:
    """Test falling back to default credentials when no credentials provided."""
    mock_creds = Mock()
    with patch("google.auth.default") as mock_default:
        mock_default.return_value = (mock_creds, "test-project")

        result = get_credentials()

        assert result is mock_creds
        mock_default.assert_called_once_with(scopes=["https://www.googleapis.com/auth/cloud-platform"])


def test_get_credentials_file_precedence() -> None:
    """Test that credential_file takes precedence over credentials dict."""
    file_creds = {"type": "service_account", "project_id": "file-project"}
    dict_creds = {"type": "service_account", "project_id": "dict-project"}

    credential_file = StringIO(json.dumps(file_creds))
    mock_creds = Mock()

    with patch("google.auth.load_credentials_from_dict") as mock_load:
        mock_load.return_value = (mock_creds, "file-project")

        result = get_credentials(credential_file=credential_file, credentials=dict_creds)

        assert result is mock_creds
        # Should load from file, not dict, with enhanced fields
        expected_creds = file_creds.copy()
        expected_creds.update(
            {
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            }
        )
        mock_load.assert_called_once_with(expected_creds, scopes=["https://www.googleapis.com/auth/cloud-platform"])


def test_get_credentials_malformed_json_file() -> None:
    """Test handling of malformed JSON in credential file."""
    credential_file = StringIO('{"invalid": json,}')

    with pytest.raises(json.JSONDecodeError):
        get_credentials(credential_file=credential_file)


def test_get_credentials_empty_file() -> None:
    """Test handling of empty credential file."""
    credential_file = StringIO("")

    with pytest.raises(json.JSONDecodeError):
        get_credentials(credential_file=credential_file)


def test_get_credentials_auth_error() -> None:
    """Test handling of authentication errors from google.auth."""
    invalid_creds = {"type": "service_account", "invalid": "credentials"}

    with patch("google.auth.load_credentials_from_dict") as mock_load:
        mock_load.side_effect = ValueError("Invalid credentials")

        with pytest.raises(ValueError, match="Invalid credentials"):
            get_credentials(credentials=invalid_creds)


def test_get_credentials_default_auth_error() -> None:
    """Test handling of default credential lookup failures."""
    with patch("google.auth.default") as mock_default:
        mock_default.side_effect = Exception("No credentials found")

        with pytest.raises(Exception, match="No credentials found"):
            get_credentials()


def test_get_credentials_scopes() -> None:
    """Test that the correct scopes are always passed."""
    expected_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

    # Test with credentials dict
    mock_creds = Mock()
    with patch("google.auth.load_credentials_from_dict") as mock_load:
        mock_load.return_value = (mock_creds, "test-project")
        get_credentials(credentials={"type": "service_account"})
        expected_creds = {
            "type": "service_account",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        }
        mock_load.assert_called_with(expected_creds, scopes=expected_scopes)

    # Test with default credentials
    with patch("google.auth.default") as mock_default:
        mock_default.return_value = (mock_creds, "test-project")
        get_credentials()
        mock_default.assert_called_with(scopes=expected_scopes)


def test_get_credentials_missing_service_account_fields() -> None:
    """Test that missing service account fields are added with defaults."""
    incomplete_creds = {
        "type": "service_account",
        "project_id": "test-project",
        "client_email": "test@test-project.iam.gserviceaccount.com",
        # Missing: auth_uri, token_uri, auth_provider_x509_cert_url
    }

    mock_creds = Mock()
    with patch("google.auth.load_credentials_from_dict") as mock_load:
        mock_load.return_value = (mock_creds, "test-project")

        result = get_credentials(credentials=incomplete_creds)

        assert result is mock_creds
        # Verify that the missing fields were added
        expected_creds = incomplete_creds.copy()
        expected_creds.update(
            {
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            }
        )
        mock_load.assert_called_once_with(expected_creds, scopes=["https://www.googleapis.com/auth/cloud-platform"])


def test_get_credentials_preserves_existing_fields() -> None:
    """Test that existing service account fields are preserved."""
    complete_creds = {
        "type": "service_account",
        "project_id": "test-project",
        "client_email": "test@test-project.iam.gserviceaccount.com",
        "auth_uri": "https://custom.auth.uri/oauth2/auth",
        "token_uri": "https://custom.token.uri/token",
        "auth_provider_x509_cert_url": "https://custom.certs.uri/certs",
    }

    mock_creds = Mock()
    with patch("google.auth.load_credentials_from_dict") as mock_load:
        mock_load.return_value = (mock_creds, "test-project")

        result = get_credentials(credentials=complete_creds)

        assert result is mock_creds
        # Verify that existing custom fields were preserved
        mock_load.assert_called_once_with(complete_creds, scopes=["https://www.googleapis.com/auth/cloud-platform"])


def test_get_credentials_non_service_account_unchanged() -> None:
    """Test that non-service account credentials are not modified."""
    authorized_user_creds = {
        "type": "authorized_user",
        "client_id": "123456789.apps.googleusercontent.com",
        "client_secret": "client-secret",
        "refresh_token": "refresh-token",
    }

    mock_creds = Mock()
    with patch("google.auth.load_credentials_from_dict") as mock_load:
        mock_load.return_value = (mock_creds, "test-project")

        result = get_credentials(credentials=authorized_user_creds)

        assert result is mock_creds
        # Verify that authorized_user credentials were not modified
        mock_load.assert_called_once_with(authorized_user_creds, scopes=["https://www.googleapis.com/auth/cloud-platform"])
