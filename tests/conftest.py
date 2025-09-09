import os
import json
import tempfile
import shutil
from pathlib import Path
from typing import Generator, Dict, Any
from unittest.mock import Mock, MagicMock

import pytest


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory that is cleaned up after the test."""
    temp_path = Path(tempfile.mkdtemp())
    try:
        yield temp_path
    finally:
        shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def mock_config() -> Dict[str, Any]:
    """Provide a mock configuration dictionary for testing."""
    return {
        "aws": {
            "region": "us-east-1",
            "account_id": "123456789012",
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        },
        "azure": {
            "subscription_id": "00000000-0000-0000-0000-000000000000",
            "tenant_id": "00000000-0000-0000-0000-000000000000",
            "client_id": "00000000-0000-0000-0000-000000000000",
            "client_secret": "example_secret",
        },
        "gcp": {
            "project_id": "example-project-123",
            "credentials_path": "/path/to/credentials.json",
        },
        "output": {
            "format": "json",
            "path": "/tmp/output",
        },
        "log_level": "INFO",
        "parallel_execution": True,
        "max_workers": 4,
    }


@pytest.fixture
def mock_aws_client():
    """Create a mock AWS client for testing."""
    client = MagicMock()
    client.describe_regions.return_value = {
        "Regions": [
            {"RegionName": "us-east-1"},
            {"RegionName": "us-west-2"},
        ]
    }
    return client


@pytest.fixture
def mock_aws_session():
    """Create a mock AWS session for testing."""
    session = MagicMock()
    session.client = MagicMock(return_value=mock_aws_client())
    return session


@pytest.fixture
def sample_finding() -> Dict[str, Any]:
    """Provide a sample finding dictionary for testing."""
    return {
        "SchemaVersion": "2018-10-08",
        "Id": "test-finding-id",
        "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/electriceye/electriceye",
        "GeneratorId": "test-generator",
        "AwsAccountId": "123456789012",
        "Types": ["Software and Configuration Checks/Industry and Regulatory Standards"],
        "FirstObservedAt": "2024-01-01T00:00:00Z",
        "LastObservedAt": "2024-01-01T00:00:00Z",
        "CreatedAt": "2024-01-01T00:00:00Z",
        "UpdatedAt": "2024-01-01T00:00:00Z",
        "Severity": {
            "Label": "MEDIUM",
            "Normalized": 50
        },
        "Title": "Test Finding",
        "Description": "This is a test finding for unit tests",
        "Resources": [{
            "Type": "AwsEc2Instance",
            "Id": "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
            "Region": "us-east-1",
        }],
        "Compliance": {
            "Status": "FAILED",
            "RelatedRequirements": ["TEST-1.1"],
        },
    }


@pytest.fixture
def mock_env_vars(monkeypatch):
    """Set up mock environment variables for testing."""
    env_vars = {
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_ACCOUNT_ID": "123456789012",
        "ELECTRICEYE_OUTPUT_FORMAT": "json",
        "ELECTRICEYE_LOG_LEVEL": "INFO",
    }
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)
    return env_vars


@pytest.fixture
def temp_file(temp_dir: Path) -> Generator[Path, None, None]:
    """Create a temporary file within the temp directory."""
    file_path = temp_dir / "test_file.txt"
    file_path.write_text("test content")
    yield file_path


@pytest.fixture
def json_file(temp_dir: Path) -> Generator[Path, None, None]:
    """Create a temporary JSON file with test data."""
    file_path = temp_dir / "test_data.json"
    test_data = {
        "test": "data",
        "nested": {
            "key": "value"
        },
        "list": [1, 2, 3]
    }
    file_path.write_text(json.dumps(test_data, indent=2))
    yield file_path


@pytest.fixture
def mock_cloud_provider():
    """Create a mock cloud provider instance."""
    provider = Mock()
    provider.name = "test_provider"
    provider.is_authenticated = Mock(return_value=True)
    provider.get_resources = Mock(return_value=[
        {"id": "resource-1", "type": "instance"},
        {"id": "resource-2", "type": "bucket"},
    ])
    return provider


@pytest.fixture(autouse=True)
def reset_singleton_instances():
    """Reset any singleton instances between tests to ensure test isolation."""
    yield


@pytest.fixture
def capture_logs(caplog):
    """Fixture to capture log messages during tests."""
    caplog.set_level("DEBUG")
    return caplog


@pytest.fixture
def mock_datetime(monkeypatch):
    """Mock datetime for consistent test results."""
    import datetime
    
    class MockDatetime:
        @staticmethod
        def now():
            return datetime.datetime(2024, 1, 1, 12, 0, 0)
        
        @staticmethod
        def utcnow():
            return datetime.datetime(2024, 1, 1, 12, 0, 0)
    
    monkeypatch.setattr("datetime.datetime", MockDatetime)
    return MockDatetime


def pytest_configure(config):
    """Configure pytest with custom settings."""
    config.addinivalue_line(
        "markers", "requires_aws: mark test as requiring AWS credentials"
    )
    config.addinivalue_line(
        "markers", "requires_network: mark test as requiring network access"
    )
    config.addinivalue_line(
        "markers", "destructive: mark test as potentially destructive"
    )