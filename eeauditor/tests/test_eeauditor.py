#This file is part of ElectricEye.
#SPDX-License-Identifier: Apache-2.0

#Licensed to the Apache Software Foundation (ASF) under one
#or more contributor license agreements.  See the NOTICE file
#distributed with this work for additional information
#regarding copyright ownership.  The ASF licenses this file
#to you under the Apache License, Version 2.0 (the
#"License"); you may not use this file except in compliance
#with the License.  You may obtain a copy of the License at

#http://www.apache.org/licenses/LICENSE-2.0

#Unless required by applicable law or agreed to in writing,
#software distributed under the License is distributed on an
#"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#KIND, either express or implied.  See the License for the
#specific language governing permissions and limitations
#under the License.

import json
import pytest
from unittest.mock import Mock, patch, MagicMock

from . import context
from eeauditor import EEAuditor
from .test_modules.plugin1 import plugin_func_1


class TestEEAuditorPluginLoading:
    """Test plugin loading functionality"""
    
    def test_eeauditor_plugin_loader(self):
        """Test loading all plugins from a directory"""
        app = EEAuditor(name="test controller", search_path="./tests/test_modules")
        app.load_plugins()
        for k, v in app.registry.checks["test"].items():
            assert k == "plugin_func_1"

    def test_eeauditor_plugin_loader_named(self):
        """Test loading a specific named plugin"""
        app = EEAuditor(name="test controller", search_path="./tests/test_modules")
        app.load_plugins(auditorName="plugin1")
        for k, v in app.registry.checks["test"].items():
            assert k == "plugin_func_1"

    def test_eeauditor_plugin_run_checks(self):
        """Test running all loaded checks"""
        app = EEAuditor(name="test controller", search_path="./tests/test_modules")
        # Since other tests are importing auditor modules that register checks in the
        # registry, it is possible checks other than those in the search_path will be
        # loaded and run here.  This statement clears the checks dictionary prior to
        # calling load_plugins
        app.registry.checks.clear()
        app.load_plugins()
        for result in app.run_checks():
            assert result == {"SchemaVersion": "2018-10-08", "Id": "test-finding"}

    def test_eeauditor_plugin_run_one_check(self):
        """Test running a specific check"""
        app = EEAuditor(name="test controller", search_path="./tests/test_modules")
        app.load_plugins(auditorName="plugin1")
        for result in app.run_checks(requested_check_name="plugin_func_1"):
            assert result == {"SchemaVersion": "2018-10-08", "Id": "test-finding"}


class TestEEAuditorEndpointCaching:
    """Test AWS endpoints data caching"""
    
    @patch('eeauditor.get')
    def test_get_aws_endpoints_data_caching(self, mock_get):
        """Test that AWS endpoints data is cached"""
        mock_response = Mock()
        mock_response.text = json.dumps({"partitions": []})
        mock_get.return_value = mock_response
        
        # Note: This test would need a mock CloudConfig setup
        # Simplified test to verify caching concept
        app = EEAuditor(name="test", search_path="./tests/test_modules")
        
        # Call twice
        data1 = app._get_aws_endpoints_data()
        data2 = app._get_aws_endpoints_data()
        
        # Should return same cached data
        assert data1 is data2
        # HTTP request should only happen once
        assert mock_get.call_count == 1


class TestEEAuditorServiceEndpointAvailability:
    """Test service endpoint availability checking"""
    
    def test_check_service_endpoint_availability_fis_available(self):
        """Test FIS service availability in supported region"""
        app = EEAuditor(name="test", search_path="./tests/test_modules")
        
        endpoint_data = {"partitions": []}
        result = app.check_service_endpoint_availability(
            endpoint_data, "aws", "fis", "us-east-1"
        )
        
        assert result is True
    
    def test_check_service_endpoint_availability_fis_unavailable(self):
        """Test FIS service unavailability in unsupported region"""
        app = EEAuditor(name="test", search_path="./tests/test_modules")
        
        endpoint_data = {"partitions": []}
        result = app.check_service_endpoint_availability(
            endpoint_data, "aws", "fis", "ap-south-2"
        )
        
        assert result is False
    
    def test_check_service_endpoint_availability_service_override(self):
        """Test service name overrides"""
        app = EEAuditor(name="test", search_path="./tests/test_modules")
        
        endpoint_data = {
            "partitions": [{
                "partition": "aws",
                "services": {
                    "iam": {
                        "endpoints": {
                            "aws-global": {}
                        }
                    }
                }
            }]
        }
        
        # globalaccelerator should be treated as iam
        result = app.check_service_endpoint_availability(
            endpoint_data, "aws", "globalaccelerator", "us-east-1"
        )
        
        assert result is True


class TestEEAuditorTypeAnnotations:
    """Test that methods have proper type annotations"""
    
    def test_load_plugins_type_hints(self):
        """Test load_plugins has proper type hints"""
        from typing import get_type_hints
        
        hints = get_type_hints(EEAuditor.load_plugins)
        
        # Should have Optional[str] for auditorName and None return
        assert 'auditorName' in hints
        assert hints['return'] is type(None)
    
    def test_run_aws_checks_type_hints(self):
        """Test run_aws_checks has proper type hints"""
        from typing import get_type_hints
        
        hints = get_type_hints(EEAuditor.run_aws_checks)
        
        # Should have Optional[str] for pluginName and int for delay
        assert 'pluginName' in hints
        assert 'delay' in hints


class TestEEAuditorPrintMethods:
    """Test print methods"""
    
    @patch('builtins.print')
    def test_print_checks_md(self, mock_print):
        """Test markdown table printing"""
        app = EEAuditor(name="test", search_path="./tests/test_modules")
        app.registry.checks.clear()
        app.load_plugins()
        
        app.print_checks_md()
        
        # Should have called print
        assert mock_print.called
        # Should contain markdown table headers
        call_args = str(mock_print.call_args)
        assert "Auditor Name" in call_args or "Check Name" in call_args
    
    @patch('builtins.print')
    def test_print_controls_json(self, mock_print):
        """Test JSON controls printing"""
        app = EEAuditor(name="test", search_path="./tests/test_modules")
        app.registry.checks.clear()
        app.load_plugins()
        
        app.print_controls_json()
        
        # Should have called print
        assert mock_print.called


class TestEEAuditorConstructor:
    """Test EEAuditor constructor with type annotations"""
    
    @patch('eeauditor.CloudConfig')
    def test_constructor_type_annotations(self, mock_cloud_config):
        """Test constructor accepts properly typed arguments"""
        mock_cloud_config.return_value = Mock(
            awsAccountTargets=["123456789012"],
            awsRegionsSelection=["us-east-1"],
            electricEyeRoleName="TestRole"
        )
        
        # Should accept Optional[str] for args, tomlPath, searchPath
        app = EEAuditor(
            assessmentTarget="AWS",
            args=None,
            useToml="False",
            tomlPath=None,
            searchPath=None
        )
        
        assert app.name == "AWS"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
