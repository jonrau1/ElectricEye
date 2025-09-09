import sys
import os
from pathlib import Path

import pytest


class TestSetupValidation:
    """Validation tests to ensure the testing infrastructure is properly configured."""
    
    def test_python_version(self):
        """Verify Python version is 3.8 or higher."""
        assert sys.version_info >= (3, 8), "Python 3.8 or higher is required"
    
    def test_pytest_installed(self):
        """Verify pytest is installed and importable."""
        import pytest
        assert pytest.__version__
    
    def test_pytest_cov_installed(self):
        """Verify pytest-cov is installed and importable."""
        import pytest_cov
        assert pytest_cov
    
    def test_pytest_mock_installed(self):
        """Verify pytest-mock is installed and importable."""
        import pytest_mock
        assert pytest_mock
    
    def test_project_structure(self):
        """Verify the project structure is set up correctly."""
        project_root = Path(__file__).parent.parent
        
        # Check main package exists
        assert (project_root / "eeauditor").exists()
        assert (project_root / "eeauditor" / "__init__.py").exists()
        
        # Check test directories exist
        assert (project_root / "tests").exists()
        assert (project_root / "tests" / "__init__.py").exists()
        assert (project_root / "tests" / "unit").exists()
        assert (project_root / "tests" / "unit" / "__init__.py").exists()
        assert (project_root / "tests" / "integration").exists()
        assert (project_root / "tests" / "integration" / "__init__.py").exists()
        
        # Check configuration files exist
        assert (project_root / "pyproject.toml").exists()
    
    def test_conftest_fixtures(self, temp_dir, mock_config, sample_finding):
        """Verify conftest fixtures are working properly."""
        # Test temp_dir fixture
        assert temp_dir.exists()
        assert temp_dir.is_dir()
        
        # Test mock_config fixture
        assert isinstance(mock_config, dict)
        assert "aws" in mock_config
        assert "azure" in mock_config
        assert "gcp" in mock_config
        
        # Test sample_finding fixture
        assert isinstance(sample_finding, dict)
        assert sample_finding["SchemaVersion"] == "2018-10-08"
        assert "Resources" in sample_finding
    
    @pytest.mark.unit
    def test_unit_marker(self):
        """Test that unit test marker works."""
        assert True
    
    @pytest.mark.integration
    def test_integration_marker(self):
        """Test that integration test marker works."""
        assert True
    
    @pytest.mark.slow
    def test_slow_marker(self):
        """Test that slow test marker works."""
        assert True
    
    def test_coverage_configuration(self):
        """Verify coverage is configured correctly."""
        project_root = Path(__file__).parent.parent
        pyproject_path = project_root / "pyproject.toml"
        
        with open(pyproject_path, 'r') as f:
            content = f.read()
            
        # Check coverage configuration exists
        assert "[tool.coverage.run]" in content
        assert "[tool.coverage.report]" in content
        assert "cov-fail-under=80" in content
    
    def test_temp_file_fixture(self, temp_file):
        """Test the temp_file fixture works correctly."""
        assert temp_file.exists()
        assert temp_file.read_text() == "test content"
    
    def test_json_file_fixture(self, json_file):
        """Test the json_file fixture works correctly."""
        import json
        
        assert json_file.exists()
        data = json.loads(json_file.read_text())
        assert data["test"] == "data"
        assert data["nested"]["key"] == "value"
        assert data["list"] == [1, 2, 3]
    
    def test_mock_env_vars_fixture(self, mock_env_vars):
        """Test the mock_env_vars fixture sets environment variables."""
        assert os.environ.get("AWS_DEFAULT_REGION") == "us-east-1"
        assert os.environ.get("AWS_ACCOUNT_ID") == "123456789012"
        assert os.environ.get("ELECTRICEYE_OUTPUT_FORMAT") == "json"
        assert os.environ.get("ELECTRICEYE_LOG_LEVEL") == "INFO"
    
    def test_capture_logs_fixture(self, capture_logs):
        """Test the capture_logs fixture works correctly."""
        import logging
        
        logger = logging.getLogger(__name__)
        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        
        assert "Debug message" in capture_logs.text
        assert "Info message" in capture_logs.text
        assert "Warning message" in capture_logs.text
    
    def test_mock_datetime_fixture(self, mock_datetime):
        """Test the mock_datetime fixture provides consistent dates."""
        # Just verify the fixture can be accessed
        assert mock_datetime is not None
        assert hasattr(mock_datetime, 'now')
        assert hasattr(mock_datetime, 'utcnow')