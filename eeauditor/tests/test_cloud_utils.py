#This file is part of ElectricEye.
#SPDX-License-Identifier: Apache-2.0

import pytest
from unittest.mock import Mock, patch, MagicMock, mock_open
import json
import sys
from botocore.exceptions import ClientError

# Add parent directory to path for imports
from . import context
from cloud_utils import CloudConfig, OU_ID_REGEX, AWS_MULTI_ACCOUNT_TARGET_TYPE_CHOICES, CREDENTIALS_LOCATION_CHOICES


class TestCloudConfigConstants:
    """Test module-level constants"""
    
    def test_aws_multi_account_target_type_choices(self):
        assert AWS_MULTI_ACCOUNT_TARGET_TYPE_CHOICES == ["Accounts", "OU", "Organization"]
    
    def test_credentials_location_choices(self):
        assert CREDENTIALS_LOCATION_CHOICES == ["AWS_SSM", "AWS_SECRETS_MANAGER", "CONFIG_FILE"]
    
    def test_ou_id_regex_valid(self):
        """Test OU ID regex matches valid OUs"""
        valid_ous = [
            "ou-1234-abcd1234",
            "ou-abcd-12345678",
            "ou-1a2b-a1b2c3d4"
        ]
        for ou in valid_ous:
            assert OU_ID_REGEX.match(ou), f"Should match valid OU: {ou}"
    
    def test_ou_id_regex_invalid(self):
        """Test OU ID regex rejects invalid OUs"""
        invalid_ous = [
            "ou-123-abc",  # Too short
            "ou-ABCD-12345678",  # Uppercase
            "invalid-ou",
            "ou-1234",
            ""
        ]
        for ou in invalid_ous:
            assert not OU_ID_REGEX.match(ou), f"Should not match invalid OU: {ou}"


class TestCloudConfigClientCaching:
    """Test boto3 client caching functionality"""
    
    @patch('cloud_utils.boto3.client')
    @patch('cloud_utils.tomload')
    @patch('builtins.open', new_callable=mock_open, read_data=b'')
    def test_boto3_client_caching(self, mock_file, mock_tomload, mock_boto3_client):
        """Test that boto3 clients are cached and reused"""
        mock_tomload.return_value = {
            "global": {
                "aws_multi_account_target_type": "Accounts",
                "credentials_location": "CONFIG_FILE"
            },
            "regions_and_accounts": {
                "aws": {
                    "aws_account_targets": ["123456789012"],
                    "aws_regions_selection": ["us-east-1"],
                    "aws_electric_eye_iam_role_name": "TestRole"
                }
            }
        }
        
        mock_client = Mock()
        mock_boto3_client.return_value = mock_client
        
        config = CloudConfig("AWS", None, "True", None)
        
        # Call _get_boto3_client twice with same service
        client1 = config._get_boto3_client("ec2")
        client2 = config._get_boto3_client("ec2")
        
        # Should return same cached client
        assert client1 is client2
        # boto3.client should only be called once
        assert mock_boto3_client.call_count == 1
    
    @patch('cloud_utils.boto3.client')
    @patch('cloud_utils.tomload')
    @patch('builtins.open', new_callable=mock_open, read_data=b'')
    def test_boto3_client_different_services(self, mock_file, mock_tomload, mock_boto3_client):
        """Test that different services get different cached clients"""
        mock_tomload.return_value = {
            "global": {
                "aws_multi_account_target_type": "Accounts",
                "credentials_location": "CONFIG_FILE"
            },
            "regions_and_accounts": {
                "aws": {
                    "aws_account_targets": ["123456789012"],
                    "aws_regions_selection": ["us-east-1"],
                    "aws_electric_eye_iam_role_name": "TestRole"
                }
            }
        }
        
        config = CloudConfig("AWS", None, "True", None)
        
        # Call with different services
        config._get_boto3_client("ec2")
        config._get_boto3_client("s3")
        
        # Should create two different clients
        assert mock_boto3_client.call_count == 2


class TestCloudConfigCallerIdentityCaching:
    """Test AWS caller identity caching"""
    
    @patch('cloud_utils.boto3.client')
    @patch('cloud_utils.tomload')
    @patch('builtins.open', new_callable=mock_open, read_data=b'')
    def test_caller_identity_caching(self, mock_file, mock_tomload, mock_boto3_client):
        """Test that caller identity is cached"""
        mock_tomload.return_value = {
            "global": {
                "aws_multi_account_target_type": "Accounts",
                "credentials_location": "CONFIG_FILE"
            },
            "regions_and_accounts": {
                "aws": {
                    "aws_account_targets": [],
                    "aws_regions_selection": ["us-east-1"],
                    "aws_electric_eye_iam_role_name": "TestRole"
                }
            }
        }
        
        mock_sts = Mock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        mock_boto3_client.return_value = mock_sts
        
        config = CloudConfig("AWS", None, "True", None)
        
        # Call multiple times
        identity1 = config._get_aws_caller_identity()
        identity2 = config._get_aws_caller_identity()
        
        # Should return same cached identity
        assert identity1 is identity2
        # get_caller_identity should only be called once
        assert mock_sts.get_caller_identity.call_count == 1


class TestCloudConfigAWSRegions:
    """Test AWS regions retrieval and caching"""
    
    @patch('cloud_utils.boto3.client')
    @patch('cloud_utils.tomload')
    @patch('builtins.open', new_callable=mock_open, read_data=b'')
    def test_get_aws_regions_caching(self, mock_file, mock_tomload, mock_boto3_client):
        """Test that AWS regions are cached"""
        mock_tomload.return_value = {
            "global": {
                "aws_multi_account_target_type": "Accounts",
                "credentials_location": "CONFIG_FILE"
            },
            "regions_and_accounts": {
                "aws": {
                    "aws_account_targets": ["123456789012"],
                    "aws_regions_selection": ["us-east-1"],
                    "aws_electric_eye_iam_role_name": "TestRole"
                }
            }
        }
        
        mock_ec2 = Mock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"},
                {"RegionName": "us-west-2", "OptInStatus": "opt-in-not-required"}
            ]
        }
        mock_boto3_client.return_value = mock_ec2
        
        config = CloudConfig("AWS", None, "True", None)
        
        # Call multiple times
        regions1 = config.get_aws_regions()
        regions2 = config.get_aws_regions()
        
        # Should return same cached tuple
        assert regions1 is regions2
        assert isinstance(regions1, tuple)
        # describe_regions should only be called once
        assert mock_ec2.describe_regions.call_count == 1


class TestCloudConfigPagination:
    """Test pagination support for AWS Organizations APIs"""
    
    @patch('cloud_utils.boto3.client')
    @patch('cloud_utils.tomload')
    @patch('builtins.open', new_callable=mock_open, read_data=b'')
    def test_get_aws_accounts_from_organization_pagination(self, mock_file, mock_tomload, mock_boto3_client):
        """Test that organization accounts are retrieved with pagination"""
        mock_tomload.return_value = {
            "global": {
                "aws_multi_account_target_type": "Organization",
                "credentials_location": "CONFIG_FILE"
            },
            "regions_and_accounts": {
                "aws": {
                    "aws_account_targets": [],
                    "aws_regions_selection": ["us-east-1"],
                    "aws_electric_eye_iam_role_name": "TestRole"
                }
            }
        }
        
        mock_org = Mock()
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {
                "Accounts": [
                    {"Id": "111111111111", "Status": "ACTIVE"},
                    {"Id": "222222222222", "Status": "ACTIVE"}
                ]
            },
            {
                "Accounts": [
                    {"Id": "333333333333", "Status": "ACTIVE"},
                    {"Id": "444444444444", "Status": "SUSPENDED"}
                ]
            }
        ]
        mock_org.get_paginator.return_value = mock_paginator
        mock_boto3_client.return_value = mock_org
        
        config = CloudConfig("AWS", None, "True", None)
        accounts = config.get_aws_accounts_from_organization()
        
        # Should only include ACTIVE accounts
        assert len(accounts) == 3
        assert "111111111111" in accounts
        assert "222222222222" in accounts
        assert "333333333333" in accounts
        assert "444444444444" not in accounts


class TestCloudConfigPartitionDetection:
    """Test AWS partition detection"""
    
    def test_check_aws_partition_standard(self):
        """Test standard AWS partition detection"""
        assert CloudConfig.check_aws_partition("us-east-1") == "aws"
        assert CloudConfig.check_aws_partition("eu-west-1") == "aws"
    
    def test_check_aws_partition_govcloud(self):
        """Test GovCloud partition detection"""
        assert CloudConfig.check_aws_partition("us-gov-east-1") == "aws-us-gov"
        assert CloudConfig.check_aws_partition("us-gov-west-1") == "aws-us-gov"
    
    def test_check_aws_partition_china(self):
        """Test China partition detection"""
        assert CloudConfig.check_aws_partition("cn-north-1") == "aws-cn"
        assert CloudConfig.check_aws_partition("cn-northwest-1") == "aws-cn"
    
    def test_check_aws_partition_secret(self):
        """Test secret region partition detection"""
        assert CloudConfig.check_aws_partition("us-isob-east-1") == "aws-isob"
        assert CloudConfig.check_aws_partition("us-iso-east-1") == "aws-iso"
        assert CloudConfig.check_aws_partition("us-isof-south-1") == "aws-isof"


class TestCloudConfigNonTomlArgs:
    """Test non-TOML argument processing"""
    
    @patch('cloud_utils.boto3.client')
    @patch('cloud_utils.boto3.Session')
    def test_process_non_toml_args_aws(self, mock_session, mock_boto3_client):
        """Test processing AWS arguments from JSON"""
        mock_sts = Mock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        mock_ec2 = Mock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"}
            ]
        }
        
        def client_side_effect(service_name, **kwargs):
            if service_name == "sts":
                return mock_sts
            elif service_name == "ec2":
                return mock_ec2
            return Mock()
        
        mock_boto3_client.side_effect = client_side_effect
        mock_session.return_value.region_name = "us-east-1"
        
        args_json = json.dumps({
            "credentials_location": "CONFIG_FILE",
            "aws_multi_account_target_type": "Accounts",
            "aws_account_targets": ["123456789012"],
            "aws_regions_selection": ["us-east-1"],
            "aws_electric_eye_iam_role_name": "TestRole"
        })
        
        config = CloudConfig("AWS", None, "False", args_json)
        
        assert config.awsAccountTargets == ["123456789012"]
        assert config.awsRegionsSelection == ["us-east-1"]
        assert config.electricEyeRoleName == "TestRole"


class TestCloudConfigCredentialRetrieval:
    """Test credential retrieval methods"""
    
    @patch('cloud_utils.boto3.client')
    @patch('cloud_utils.tomload')
    @patch('builtins.open', new_callable=mock_open, read_data=b'')
    def test_get_credential_from_aws_ssm(self, mock_file, mock_tomload, mock_boto3_client):
        """Test SSM credential retrieval"""
        mock_tomload.return_value = {
            "global": {
                "aws_multi_account_target_type": "Accounts",
                "credentials_location": "CONFIG_FILE"
            },
            "regions_and_accounts": {
                "aws": {
                    "aws_account_targets": ["123456789012"],
                    "aws_regions_selection": ["us-east-1"],
                    "aws_electric_eye_iam_role_name": "TestRole"
                }
            }
        }
        
        mock_ssm = Mock()
        mock_ssm.get_parameter.return_value = {
            "Parameter": {"Value": "secret-value"}
        }
        mock_boto3_client.return_value = mock_ssm
        
        config = CloudConfig("AWS", None, "True", None)
        credential = config.get_credential_from_aws_ssm("/path/to/param", "test_param")
        
        assert credential == "secret-value"
        mock_ssm.get_parameter.assert_called_once_with(
            Name="/path/to/param",
            WithDecryption=True
        )


class TestCloudConfigStaticMethods:
    """Test static methods"""
    
    @patch('cloud_utils.boto3.client')
    def test_create_aws_session(self, mock_boto3_client):
        """Test AWS session creation"""
        mock_sts = Mock()
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "SessionToken": "token"
            }
        }
        mock_boto3_client.return_value = mock_sts
        
        with patch('cloud_utils.boto3.Session') as mock_session:
            session = CloudConfig.create_aws_session(
                "123456789012",
                "aws",
                "us-east-1",
                "TestRole"
            )
            
            mock_sts.assume_role.assert_called_once()
            mock_session.assert_called_once()
    
    @patch('cloud_utils.boto3.Session')
    def test_get_aws_support_eligibility_true(self, mock_session):
        """Test AWS Support eligibility check - eligible"""
        mock_support = Mock()
        mock_support.describe_trusted_advisor_checks.return_value = {}
        
        session = Mock()
        session.client.return_value = mock_support
        
        result = CloudConfig.get_aws_support_eligibility(session)
        
        assert result is True
    
    @patch('cloud_utils.boto3.Session')
    def test_get_aws_support_eligibility_false(self, mock_session):
        """Test AWS Support eligibility check - not eligible"""
        mock_support = Mock()
        mock_support.describe_trusted_advisor_checks.side_effect = ClientError(
            {"Error": {"Code": "SubscriptionRequiredException"}},
            "describe_trusted_advisor_checks"
        )
        
        session = Mock()
        session.client.return_value = mock_support
        
        result = CloudConfig.get_aws_support_eligibility(session)
        
        assert result is False


class TestCloudConfigGCP:
    """Test GCP credential setup"""
    
    @patch('cloud_utils.service_account.Credentials.from_service_account_info')
    @patch('cloud_utils.tomload')
    @patch('builtins.open', new_callable=mock_open, read_data=b'')
    def test_setup_gcp_credentials(self, mock_file, mock_tomload, mock_gcp_creds):
        """Test GCP credentials setup"""
        mock_tomload.return_value = {
            "global": {
                "credentials_location": "CONFIG_FILE"
            },
            "regions_and_accounts": {
                "gcp": {
                    "gcp_project_ids": ["project-1"]
                }
            },
            "credentials": {
                "gcp": {
                    "gcp_service_account_json_payload_value": '{"type": "service_account"}'
                }
            }
        }
        
        mock_cred_obj = Mock()
        mock_gcp_creds.return_value = mock_cred_obj
        
        config = CloudConfig("GCP", None, "True", None)
        
        assert config.gcpCredentials is mock_cred_obj
        mock_gcp_creds.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
