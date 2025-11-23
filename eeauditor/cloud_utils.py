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

import logging
import boto3
from tomli import load as tomload
import sys
from os import environ, path, chmod
from re import compile
import json
from botocore.exceptions import ClientError
from google.oauth2 import service_account
from azure.identity import ClientSecretCredential
from azure.mgmt.resource.subscriptions import SubscriptionClient
import snowflake.connector as snowconn
from functools import lru_cache

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CloudUtils")

# These Constants define legitimate values for certain parameters within the external_providers.toml file
AWS_MULTI_ACCOUNT_TARGET_TYPE_CHOICES = ["Accounts", "OU", "Organization"]
CREDENTIALS_LOCATION_CHOICES = ["AWS_SSM", "AWS_SECRETS_MANAGER", "CONFIG_FILE"]

# Compile regex once at module level for performance
OU_ID_REGEX = compile(r"^ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}$")

class CloudConfig(object):
    """
    This Class handles processing of Credentials, Regions, Accounts, and other Provider-specific configurations
    for use in EEAuditor when running ElectricEye Auditors and Check
    
    Performance Optimizations:
    - Cached boto3 clients to avoid repeated initialization
    - Single AWS caller identity lookup
    - Extracted credential retrieval to reduce code duplication
    - Pagination support for AWS Organizations APIs
    """

    def __init__(self, assessmentTarget: str, tomlPath: str | None, useToml: str, args: str | None):
        # Initialize client cache for performance
        self._boto3_clients = {}
        self._aws_caller_identity = None
        if useToml == "True":
            if tomlPath is None:
                here = path.abspath(path.dirname(__file__))
                tomlFile = f"{here}/external_providers.toml"
            else:
                tomlFile = tomlPath

            with open(tomlFile, "rb") as f:
                data = tomload(f)

            # From TOML [global]
            if data["global"]["aws_multi_account_target_type"] not in AWS_MULTI_ACCOUNT_TARGET_TYPE_CHOICES:
                logger.error("Invalid option for [global.aws_multi_account_target_type].")
                sys.exit(2)
            self.awsMultiAccountTargetType = data["global"]["aws_multi_account_target_type"]

            if data["global"]["credentials_location"] not in CREDENTIALS_LOCATION_CHOICES:
                logger.error(
                    "Invalid option for [global.credentials_location]. Must be one of %s.",
                    CREDENTIALS_LOCATION_CHOICES
                )
                sys.exit(2)
                
            self.credentialsLocation = data["global"]["credentials_location"]
        # from args
        if useToml == "False":
            # first turn args from a string into a dictionary
            args = json.loads(args)

        ##################################
        # PUBLIC CLOUD SERVICE PROVIDERS #
        ##################################
        if useToml == "True":
            # AWS
            if assessmentTarget == "AWS":
                # Process ["aws_account_targets"] 
                awsAccountTargets = data["regions_and_accounts"]["aws"]["aws_account_targets"]
                if self.awsMultiAccountTargetType == "Accounts":
                    if not awsAccountTargets:
                        self.awsAccountTargets = [self._get_aws_caller_identity()["Account"]]
                    else:
                        self.awsAccountTargets = awsAccountTargets
                elif self.awsMultiAccountTargetType == "OU":
                    if not awsAccountTargets:
                        logger.error("OU was specified but targets were not specified.")
                        sys.exit(2)
                    # Use pre-compiled regex for performance
                    for ou in awsAccountTargets:
                        if not OU_ID_REGEX.match(ou):
                            logger.error(f"Invalid Organizational Unit ID {ou}.")
                            sys.exit(2)
                    self.awsAccountTargets = self.get_aws_accounts_from_organizational_units(awsAccountTargets)
                elif self.awsMultiAccountTargetType == "Organization":
                    self.awsAccountTargets = self.get_aws_accounts_from_organization()
                
                # Process ["aws_regions_selection"]
                awsRegions = self.get_aws_regions()
                if not data["regions_and_accounts"]["aws"]["aws_regions_selection"]:
                    self.awsRegionsSelection = [boto3.Session().region_name]
                else:
                    tomlRegions = data["regions_and_accounts"]["aws"]["aws_regions_selection"]
                    if "All" in tomlRegions:
                        self.awsRegionsSelection = list(awsRegions)  # Convert tuple to list
                    else:
                        # Validation check - use set for O(1) lookups
                        awsRegionsSet = set(awsRegions)
                        self.awsRegionsSelection = [a for a in tomlRegions if a in awsRegionsSet]
                
                # Process ["aws_electric_eye_iam_role_name"]
                electricEyeRoleName = data["regions_and_accounts"]["aws"]["aws_electric_eye_iam_role_name"]
                if electricEyeRoleName is None or electricEyeRoleName == "":
                    logger.warning(
                        "A value for ['aws_electric_eye_iam_role_name'] was not provided. Will attempt to use current session credentials, this will likely fail if you're attempting to assess another AWS account."
                    )
                    electricEyeRoleName = None
                
                self.electricEyeRoleName = electricEyeRoleName
            
            # GCP
            if assessmentTarget == "GCP":
                # Process ["gcp_project_ids"]
                gcpProjects: list = data["regions_and_accounts"]["gcp"]["gcp_project_ids"]
                if not gcpProjects:
                    logger.error("No GCP Projects were provided in [regions_and_accounts.gcp.gcp_project_ids].")
                    sys.exit(2)
                else:
                    self.gcpProjectIds = gcpProjects
                
                # Process ["gcp_service_account_json_payload_value"]
                gcpCred = data["credentials"]["gcp"]["gcp_service_account_json_payload_value"]
                if self.credentialsLocation == "CONFIG_FILE":
                    self.gcpServiceAccountJsonPayloadValue = gcpCred
                elif self.credentialsLocation == "AWS_SSM":
                    self.gcpServiceAccountJsonPayloadValue = self.get_credential_from_aws_ssm(
                        gcpCred,
                        "gcp_service_account_json_payload_value"
                    )
                elif self.credentialsLocation == "AWS_SECRETS_MANAGER":
                    self.gcpServiceAccountJsonPayloadValue = self.get_credential_from_aws_secrets_manager(
                        gcpCred,
                        "gcp_service_account_json_payload_value"
                    )
                self.gcpCredentials = self.setup_gcp_credentials(self.gcpServiceAccountJsonPayloadValue)
            
            # Oracle Cloud Infrastructure (OCI)
            if assessmentTarget == "OCI":
                ociValues = data["regions_and_accounts"]["oci"]

                # Retrieve the OCIDs for Tenancy & User and the Region ID along with a list of Compartment OCIDs
                ociTenancyId = str(ociValues["oci_tenancy_ocid"])
                ociUserId = str(ociValues["oci_user_ocid"])
                ociRegionName = str(ociValues["oci_region_name"])
                ociCompartments = list(ociValues["oci_compartment_ocids"])
                # Process the [credentials.oci]
                ociUserApiKeyFingerprint = data["credentials"]["oci"]["oci_user_api_key_fingerprint_value"]
                ociUserApiKeyPemValue = data["credentials"]["oci"]["oci_user_api_key_private_key_pem_contents_value"]

                if any(
                    # Check to make sure none of the variables pulled from TOML are emtpy
                    not var for var in [
                        ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint, ociUserApiKeyPemValue
                        ]
                    ):
                    logger.error(f"One of your Oracle Cloud TOML entries in [regions_and_accounts.oci] or [credentials.oci] is empty!")
                    sys.exit(2)

                # Assign ["regions_and_accounts"]["oci"] values to `self`
                self.ociTenancyId = ociTenancyId
                self.ociUserId = ociUserId
                self.ociRegionName = ociRegionName
                self.ociCompartments = ociCompartments

                # Process ["oci_user_api_key_fingerprint_value"]
                ociUserApiKeyFingerprint = data["credentials"]["oci"]["oci_user_api_key_fingerprint_value"]
                if self.credentialsLocation == "CONFIG_FILE":
                    ociUserApiKeyFingerprint = ociUserApiKeyFingerprint
                elif self.credentialsLocation == "AWS_SSM":
                    ociUserApiKeyFingerprint = self.get_credential_from_aws_ssm(
                        ociUserApiKeyFingerprint,
                        "oci_user_api_key_fingerprint_value"
                    )
                elif self.credentialsLocation == "AWS_SECRETS_MANAGER":
                    ociUserApiKeyFingerprint = self.get_credential_from_aws_secrets_manager(
                        ociUserApiKeyFingerprint,
                        "oci_user_api_key_fingerprint_value"
                    )

                self.ociUserApiKeyFingerprint = ociUserApiKeyFingerprint

                # Process ["oci_user_api_key_private_key_pem_contents_value"]
                ociUserApiKeyPemLocation = data["credentials"]["oci"]["oci_user_api_key_private_key_pem_contents_value"]
                if self.credentialsLocation == "CONFIG_FILE":
                    ociUserApiKeyPemLocation = ociUserApiKeyPemLocation
                elif self.credentialsLocation == "AWS_SSM":
                    ociUserApiKeyPemLocation = self.get_credential_from_aws_ssm(
                        ociUserApiKeyPemLocation,
                        "oci_user_api_key_private_key_pem_contents_value"
                    )
                elif self.credentialsLocation == "AWS_SECRETS_MANAGER":
                    ociUserApiKeyPemLocation = self.get_credential_from_aws_secrets_manager(
                        ociUserApiKeyPemLocation,
                        "oci_user_api_key_private_key_pem_contents_value"
                    )

                # Create the PEM file and save the location of it to environ
                self.setup_oci_credentials(ociUserApiKeyPemLocation)

            # Azure
            if assessmentTarget == "Azure":
                # Process data["credentials"]["azure"] - values need to be assigned to self
                azureValues = data["credentials"]["azure"]

                azureClientId = azureValues["azure_ent_app_client_id_value"]
                azureSecretId = azureValues["azure_ent_app_client_secret_id_value"]
                azureTenantId = azureValues["azure_ent_app_tenant_id_value"]
                azureSubscriptions = data["regions_and_accounts"]["azure"]["azure_subscription_ids"]

                del azureValues

                if any(
                    # Check to make sure none of the variables pulled from TOML are emtpy
                    not var for var in [
                        azureClientId, azureSecretId, azureTenantId
                        ]
                    ):
                    logger.error("One of your azure TOML entries in [credentials.azure] is empty!")
                    sys.exit(2)

                # Retrieve the values for the azure Enterprise Application Client ID, Secret Value & Tenant ID
                # SSM
                if self.credentialsLocation == "AWS_SSM":
                    # Client ID
                    azureClientId = self.get_credential_from_aws_ssm(
                        azureClientId,
                        "azure_ent_app_client_id_value"
                    )
                    # Secret Value
                    azureSecretId = self.get_credential_from_aws_ssm(
                        azureSecretId,
                        "azure_ent_app_client_secret_id_value"
                    )
                    # Tenant ID
                    azureTenantId = self.get_credential_from_aws_ssm(
                        azureTenantId,
                        "azure_ent_app_tenant_id_value"
                    )
                # AWS Secrets Manager
                elif self.credentialsLocation == "AWS_SECRETS_MANAGER":
                    # Client ID
                    azureClientId = self.get_credential_from_aws_secrets_manager(
                        azureClientId,
                        "azure_ent_app_client_id_value"
                    )
                    # Secret Value
                    azureSecretId = self.get_credential_from_aws_secrets_manager(
                        azureSecretId,
                        "azure_ent_app_client_secret_id_value"
                    )
                    # Tenant ID
                    azureTenantId = self.get_credential_from_aws_secrets_manager(
                        azureTenantId,
                        "azure_ent_app_tenant_id_value"
                    )

                # Create Azure Identity credentials from Client ID/Secret Value/Tenant ID
                azureCredentials = self.create_azure_identity_credentials_from_client_secret(
                    clientId=azureClientId,
                    clientSecret=azureSecretId,
                    tenantId=azureTenantId
                )

                # If subscriptions aren't supplied, attempt to find which ones you have access to
                if not azureSubscriptions:
                    logger.warning(
                        "No values provided for [regions_and_accounts.azure.azure_subscription_ids] - attempting to retrieve subscription IDs your Service Principal has access to..."
                    )
                    azureSubscriptions = self.retrieve_azure_subscriptions_for_service_principal(
                        azureCredentials=azureCredentials
                    )
                # pass list of subscriptions and the creds off
                self.azureSubscriptions = azureSubscriptions
                self.azureCredentials = azureCredentials

            # Alibaba Cloud
            if assessmentTarget == "Alibaba":
                logger.info("Coming soon!")

            ###################################
            # SOFTWARE-AS-A-SERVICE PROVIDERS #
            ###################################

            # ServiceNow
            if assessmentTarget == "Servicenow":
                # Process data["credentials"]["servicenow"] - nothing needs to be assigned to `self`
                serviceNowValues = data["credentials"]["servicenow"]

                snowInstanceName = serviceNowValues["servicenow_instance_name"]
                snowInstanceRegion = serviceNowValues["servicenow_instance_region"]
                snowUserName = serviceNowValues["servicenow_sspm_username"]
                snowUserLoginBreachRate = serviceNowValues["servicenow_failed_login_breaching_rate"]

                if any(
                    # Check to make sure none of the variables pulled from TOML are emtpy
                    not var for var in [
                        snowInstanceName, snowInstanceRegion, snowUserName, snowUserLoginBreachRate
                        ]
                    ):
                    logger.error(f"One of your ServiceNow TOML entries in [credentials.servicenow] is empty!")
                    sys.exit(2)
                
                # Retrieve ServiceNow ElectricEye user password
                serviceNowPwVal = serviceNowValues["servicenow_sspm_password_value"]
                if self.credentialsLocation == "CONFIG_FILE":
                    environ["SNOW_SSPM_PASSWORD"] = serviceNowPwVal
                elif self.credentialsLocation == "AWS_SSM":
                    environ["SNOW_SSPM_PASSWORD"] = self.get_credential_from_aws_ssm(
                        serviceNowPwVal,
                        "servicenow_sspm_password_value"
                    )
                elif self.credentialsLocation == "AWS_SECRETS_MANAGER":
                    environ["SNOW_SSPM_PASSWORD"] = self.get_credential_from_aws_secrets_manager(
                        serviceNowPwVal,
                        "servicenow_sspm_password_value"
                    )
                # All other ServiceNow Values are written as environment variables and either provided
                # to PySnow Clients or to ProductFields{} within the ASFF per Finding
                environ["SNOW_INSTANCE_NAME"] = snowInstanceName
                environ["SNOW_INSTANCE_REGION"] = snowInstanceRegion
                environ["SNOW_SSPM_USERNAME"] = snowUserName
                environ["SNOW_FAILED_LOGIN_BREACHING_RATE"] = snowUserLoginBreachRate

            # M365
            if assessmentTarget == "M365":
                # Process data["credentials"]["m365"] - values need to be assigned to self
                m365Values = data["credentials"]["m365"]

                m365ClientId = m365Values["m365_ent_app_client_id_value"]
                m365SecretId = m365Values["m365_ent_app_client_secret_id_value"]
                m365TenantId = m365Values["m365_ent_app_tenant_id_value"]
                m365TenantLocation = m365Values["m365_tenant_location"]

                if any(
                    # Check to make sure none of the variables pulled from TOML are emtpy
                    not var for var in [
                        m365ClientId, m365SecretId, m365TenantId, m365TenantLocation
                        ]
                    ):
                    logger.error(f"One of your M365 TOML entries in [credentials.m365] is empty!")
                    sys.exit(2)

                # This value (tenant location) will always be in plaintext
                self.m365TenantLocation = m365TenantLocation

                # Retrieve the values for the M365 Enterprise Application Client ID, Secret Value & Tenant ID
                if self.credentialsLocation == "CONFIG_FILE":
                    self.m365ClientId = m365ClientId
                    self.m365SecretId = m365SecretId
                    self.m365TenantId = m365TenantId
                # SSM
                elif self.credentialsLocation == "AWS_SSM":
                    # Client ID
                    self.m365ClientId = self.get_credential_from_aws_ssm(
                        m365ClientId,
                        "m365_ent_app_client_id_value"
                    )
                    # Secret Value
                    self.m365SecretId = self.get_credential_from_aws_ssm(
                        m365SecretId,
                        "m365_ent_app_client_secret_id_value"
                    )
                    # Tenant ID
                    self.m365TenantId = self.get_credential_from_aws_ssm(
                        m365TenantId,
                        "m365_ent_app_tenant_id_value"
                    )
                # AWS Secrets Manager
                elif self.credentialsLocation == "AWS_SECRETS_MANAGER":
                    # Client ID
                    self.m365ClientId = self.get_credential_from_aws_secrets_manager(
                        m365ClientId,
                        "m365_ent_app_client_id_value"
                    )
                    # Secret Value
                    self.m365SecretId = self.get_credential_from_aws_secrets_manager(
                        m365SecretId,
                        "m365_ent_app_client_secret_id_value"
                    )
                    # Tenant ID
                    self.m365TenantId = self.get_credential_from_aws_secrets_manager(
                        m365TenantId,
                        "m365_ent_app_tenant_id_value"
                    )
        
            # Salesforce
            if assessmentTarget == "Salesforce":
                # Process data["credentials"]["m365"] - values need to be assigned to self
                salesforceValues = data["credentials"]["salesforce"]

                salesforceAppClientId = salesforceValues["salesforce_connected_app_client_id_value"]
                salesforceAppClientSecret = salesforceValues["salesforce_connected_app_client_secret_value"]
                salesforceApiUsername = salesforceValues["salesforce_api_enabled_username_value"]
                salesforceApiPassword = salesforceValues["salesforce_api_enabled_password_value"]
                salesforceUserSecurityToken = salesforceValues["salesforce_api_enabled_security_token_value"]
                salesforceInstanceLocation = salesforceValues["salesforce_instance_location"]
                salesforceFailedLoginBreachingRate = salesforceValues["salesforce_failed_login_breaching_rate"]
                salesforceApiVersion = salesforceValues["salesforce_api_version"]

                if any(
                    # Check to make sure none of the variables pulled from TOML are emtpy
                    not var for var in [
                        salesforceAppClientId, salesforceAppClientSecret, salesforceApiUsername, salesforceApiPassword, salesforceUserSecurityToken, salesforceInstanceLocation, salesforceFailedLoginBreachingRate, salesforceApiVersion
                        ]
                    ):
                    logger.error(f"One of your Salesforce TOML entries in [credentials.salesforce] is empty!")
                    sys.exit(2)

                # The failed login breaching rate and API Version will be in plaintext/env vars
                environ["SALESFORCE_FAILED_LOGIN_BREACHING_RATE"] = salesforceFailedLoginBreachingRate
                environ["SFDC_API_VERSION"] = salesforceApiVersion

                # Location is parsed from the config directly
                self.salesforceInstanceLocation = salesforceInstanceLocation

                # Retrieve the values for the Salesforce Client ID, Client Secret, Username, Password, and Security Token
                # Local config file
                if self.credentialsLocation == "CONFIG_FILE":
                    self.salesforceAppClientId = salesforceAppClientId
                    self.salesforceAppClientSecret = salesforceAppClientSecret
                    self.salesforceApiUsername = salesforceApiUsername
                    self.salesforceApiPassword = salesforceApiPassword
                    self.salesforceUserSecurityToken = salesforceUserSecurityToken
                # SSM
                elif self.credentialsLocation == "AWS_SSM":
                    # Client ID
                    self.salesforceAppClientId = self.get_credential_from_aws_ssm(
                        salesforceAppClientId,
                        "salesforce_connected_app_client_id_value"
                    )
                    # Client Secret
                    self.salesforceAppClientSecret = self.get_credential_from_aws_ssm(
                        salesforceAppClientSecret,
                        "salesforce_connected_app_client_secret_value"
                    )
                    # API Username
                    self.salesforceApiUsername = self.get_credential_from_aws_ssm(
                        salesforceApiUsername,
                        "salesforce_api_enabled_username_value"
                    )
                    # API User Password
                    self.salesforceApiPassword = self.get_credential_from_aws_ssm(
                        salesforceApiPassword,
                        "salesforce_api_enabled_password_value"
                    )
                    # API User Security Token
                    self.salesforceUserSecurityToken = self.get_credential_from_aws_ssm(
                        salesforceUserSecurityToken,
                        "salesforce_api_enabled_security_token_value"
                    )
                # AWS Secrets Manager
                elif self.credentialsLocation == "AWS_SECRETS_MANAGER":
                    # Client ID
                    self.salesforceAppClientId = self.get_credential_from_aws_secrets_manager(
                        salesforceAppClientId,
                        "salesforce_connected_app_client_id_value"
                    )
                    # Client Secret
                    self.salesforceAppClientSecret = self.get_credential_from_aws_secrets_manager(
                        salesforceAppClientSecret,
                        "salesforce_connected_app_client_secret_value"
                    )
                    # API Username
                    self.salesforceApiUsername = self.get_credential_from_aws_secrets_manager(
                        salesforceApiUsername,
                        "salesforce_api_enabled_username_value"
                    )
                    # API User Password
                    self.salesforceApiPassword = self.get_credential_from_aws_secrets_manager(
                        salesforceApiPassword,
                        "salesforce_api_enabled_password_value"
                    )
                    # API User Security Token
                    self.salesforceUserSecurityToken = self.get_credential_from_aws_secrets_manager(
                        salesforceUserSecurityToken,
                        "salesforce_api_enabled_security_token_value"
                    )

            # Google Workspace
            if assessmentTarget == "GoogleWorkspace":
                logger.info("Coming soon!")

            # Snowflake
            if assessmentTarget == "Snowflake":
                # Process data["credentials"]["snowflake"] - values need to be assigned to self
                snowflakeTomlValues = data["credentials"]["snowflake"]

                snowflakeUsername = str(snowflakeTomlValues["snowflake_username"])
                snowflakePasswordValue = str(snowflakeTomlValues["snowflake_password_value"])
                snowflakeAccountId = str(snowflakeTomlValues["snowflake_account_id"])
                snowflakeWarehouseName = str(snowflakeTomlValues["snowflake_warehouse_name"])
                snowflakeRegion = str(snowflakeTomlValues["snowflake_region"])
                serviceAccountExemptions = list(snowflakeTomlValues["snowflake_service_account_usernames"])

                if any(
                    # Check to make sure none of the variables pulled from TOML are emtpy
                    not var for var in [
                        snowflakeUsername, snowflakePasswordValue, snowflakeAccountId, snowflakeWarehouseName, snowflakeRegion
                        ]
                    ):
                    logger.error(f"One of your Snowflake TOML entries in [credentials.snowflake] is empty!")
                    sys.exit(2)

                # Parse non-confidential values to environ
                self.snowflakeUsername = snowflakeUsername
                self.snowflakeAccountId = snowflakeAccountId
                self.snowflakeWarehouseName = snowflakeWarehouseName
                self.snowflakeRegion = snowflakeRegion
                self.serviceAccountExemptions = serviceAccountExemptions

                # Retrieve value for Snowflake Password from the TOML, AWS SSM or AWS Secrets Manager
                if self.credentialsLocation == "CONFIG_FILE":
                    self.snowflakePassowrd = snowflakePasswordValue
                # SSM
                elif self.credentialsLocation == "AWS_SSM":
                    self.snowflakePassowrd = self.get_credential_from_aws_ssm(
                        snowflakePasswordValue,
                        "snowflake_password_value"
                    )
                # AWS Secrets Manager
                elif self.credentialsLocation == "AWS_SECRETS_MANAGER":
                    self.snowflakePassowrd = self.get_credential_from_aws_secrets_manager(
                        snowflakePasswordValue,
                        "snowflake_password_value"
                    )

                # Retrieve cursor and connector
                snowflakeCursorConn = self.create_snowflake_cursor()

                self.snowflakeConnection = snowflakeCursorConn[0]
                self.snowflakeCursor = snowflakeCursorConn[1]

        # Non-TOML Args
        if useToml == "False":
            self.process_non_toml_args(assessmentTarget, args)

    def _get_boto3_client(self, service_name: str, region_name: str = None):
        """
        Get or create a cached boto3 client
        
        Performance: Avoids repeated client initialization overhead
        """
        cache_key = f"{service_name}:{region_name or 'default'}"
        
        if cache_key not in self._boto3_clients:
            if region_name:
                self._boto3_clients[cache_key] = boto3.client(service_name, region_name=region_name)
            else:
                self._boto3_clients[cache_key] = boto3.client(service_name)
        
        return self._boto3_clients[cache_key]
    
    def _get_aws_caller_identity(self):
        """
        Get cached AWS caller identity to avoid repeated API calls
        
        Performance: Single STS call instead of multiple
        """
        if self._aws_caller_identity is None:
            sts = self._get_boto3_client("sts")
            self._aws_caller_identity = sts.get_caller_identity()
        
        return self._aws_caller_identity
    
    def _retrieve_credential(self, value: str, config_name: str) -> str:
        """
        Unified credential retrieval method
        
        Performance: Eliminates repetitive if/elif chains throughout the code
        """
        if value is None or value == "":
            logger.error(
                "A value for %s was not provided. Fix the configuration and run ElectricEye again.",
                config_name
            )
            sys.exit(2)
        
        if self.credentialsLocation == "CONFIG_FILE":
            return value
        elif self.credentialsLocation == "AWS_SSM":
            return self.get_credential_from_aws_ssm(value, config_name)
        elif self.credentialsLocation == "AWS_SECRETS_MANAGER":
            return self.get_credential_from_aws_secrets_manager(value, config_name)
        else:
            logger.error("Invalid credentials location: %s", self.credentialsLocation)
            sys.exit(2)

    @lru_cache(maxsize=1)
    def get_aws_regions(self):
        """
        Uses EC2 DescribeRegions API to get a list of opted-in AWS Regions
        
        Performance: Cached to avoid repeated API calls
        """
        ec2 = self._get_boto3_client('ec2')
        
        try:
            # majority of Regions have a "opt-in-not-required", hence the "not not opted in" list comp
            regions = [region["RegionName"] for region in ec2.describe_regions()["Regions"] if region["OptInStatus"] != "not-opted-in"]
        except ClientError as e:
            logger.error(
                "Could not retrieve AWS Regions because: %s",
                e
            )
            raise e

        return tuple(regions)  # Return tuple for hashability with lru_cache
    
    def get_credential_from_aws_ssm(self, value, configurationName) -> str:
        """
        Retrieves a TOML variable from AWS Systems Manager Parameter Store and returns it
        
        Performance: Uses cached SSM client
        """
        ssm = self._get_boto3_client("ssm")

        if value is None or value == "":
            logger.error(
                "A value for %s was not provided. Fix the TOML file and run ElectricEye again.",
                configurationName
            )
            sys.exit(2)

        # Retrieve the credential from SSM Parameter Store
        try:
            credential = ssm.get_parameter(
                Name=value,
                WithDecryption=True
            )["Parameter"]["Value"]
        except ClientError as e:
            logger.error(
                "Failed to retrieve the credential for %s from SSM Parameter Store: %s",
                configurationName, e
            )
            raise e
        
        return credential
    
    def get_credential_from_aws_secrets_manager(self, value, configurationName) -> str:
        """
        Retrieves a TOML variable from AWS Secrets Manager and returns it
        
        Performance: Uses cached Secrets Manager client
        """
        asm = self._get_boto3_client("secretsmanager")

        if value is None or value == "":
            logger.error(
                "A value for %s was not provided. Fix the TOML file and run ElectricEye again.",
                configurationName
            )
            sys.exit(2)

        try:
            credential = asm.get_secret_value(SecretId=value)["SecretString"]
        except ClientError as e:
            logger.error(
                "Failed to retrieve the credential for %s from AWS Secrets Manager: %s",
                configurationName, e
            )
            raise e

        return credential

    def get_aws_accounts_from_organization(self) -> list[str]:
        """
        Uses Organizations ListAccounts API to get a list of "ACTIVE" AWS Accounts in the entire Organization
        
        Performance: Handles large organizations properly with pagination
        """
        org = self._get_boto3_client("organizations")

        try:
            paginator = org.get_paginator('list_accounts')
            accounts = []
            
            for page in paginator.paginate():
                accounts.extend([
                    account["Id"] 
                    for account in page["Accounts"] 
                    if account["Status"] == "ACTIVE"
                ])
        except ClientError as e:
            logger.error(
                "Failed to retrieve accounts from AWS Organizations: %s", e
            )
            raise e

        return accounts

    def get_aws_accounts_from_organizational_units(self, targets) -> list[str]:
        """
        Uses Organizations ListAccountsForParent API to get a list of "ACTIVE" AWS Accounts for specified OUs
        
        Performance: Handles large OUs properly with pagination and set-based deduplication
        """
        org = self._get_boto3_client("organizations")
        caller_account = self._get_aws_caller_identity()["Account"]
        
        accounts = [caller_account]  # Caller account is added directly
        accounts_set = set(accounts)  # Use set for O(1) lookups

        for parent in targets:
            logger.info("Processing accounts for Organizational Unit %s.", parent)
            try:
                paginator = org.get_paginator('list_accounts_for_parent')
                
                for page in paginator.paginate(ParentId=parent):
                    for account in page["Accounts"]:
                        if account["Status"] == "ACTIVE" and account["Id"] not in accounts_set:
                            accounts.append(account["Id"])
                            accounts_set.add(account["Id"])
            except ClientError as e:
                logger.error(
                    "Failed to retrieve accounts for Organizational Unit %s: %s",
                    parent, e
                )
                raise e

        return accounts

    # This function is called outside of this Class
    def create_aws_session(account: str, partition: str, region: str, roleName: str) -> boto3.Session:
        """
        Creates a Boto3 Session by assuming a given AWS IAM Role
        """
        crossAccountRoleArn = f"arn:{partition}:iam::{account}:role/{roleName}"

        sts = boto3.client("sts")

        try:
            memberAcct = sts.assume_role(
                RoleArn=crossAccountRoleArn,
                RoleSessionName="ElectricEye"
            )
            logger.info("Assumed role: %s successfully", crossAccountRoleArn)
        except ClientError as e:
            logger.error(
                "Failed to assume role %s: %s",
                crossAccountRoleArn, e
            )
            raise e

        session = boto3.Session(
            aws_access_key_id=memberAcct["Credentials"]["AccessKeyId"],
            aws_secret_access_key=memberAcct["Credentials"]["SecretAccessKey"],
            aws_session_token=memberAcct["Credentials"]["SessionToken"],
            region_name=region
        )

        return session
    
    # This function is called outside of this Class and from create_aws_session()
    @staticmethod
    def check_aws_partition(region: str) -> str:
        """
        Returns the AWS Partition based on the current Region of a Session
        
        Performance: Uses dict lookup for O(1) performance instead of multiple if/elif
        """
        # Use dict lookup for exact matches (O(1) performance)
        partition_map = {
            "us-gov-east-1": "aws-us-gov",
            "us-gov-west-1": "aws-us-gov",
            "cn-north-1": "aws-cn",
            "cn-northwest-1": "aws-cn",
            "us-isob-east-1": "aws-isob",
            "us-isob-west-1": "aws-isob",
            "us-iso-east-1": "aws-iso",
            "us-iso-west-1": "aws-iso",
            "us-isof-south-1": "aws-isof",
        }
        
        # Check exact match first
        if region in partition_map:
            return partition_map[region]
        
        # Check prefixes for non-standard regions
        if "us-gov-" in region:
            return "aws-us-gov"
        elif "cn-" in region:
            return "aws-cn"
        elif "isob-" in region:
            return "aws-isob"
        elif "iso-" in region and "isob" not in region and "isoe" not in region and "isof" not in region:
            return "aws-iso"
        elif "iso-e" in region or "isoe" in region:
            return "aws-isoe"
        elif "iso-f" in region or "isof" in region:
            return "aws-isof"
        # TODO: Add European Sovereign Cloud Partition
        else:
            return "aws"

    # This function is called outside of this Class
    def get_aws_support_eligibility(session) -> bool:
        support = session.client("support")

        try:
            support.describe_trusted_advisor_checks(language='en')
            supportEligible = True
            logger.info("AWS Support is eligible.")
        except ClientError as e:
            if "SubscriptionRequiredException" in str(e):
                supportEligible = False
                logger.warning("AWS Support is not eligible: %s", e)
            else:
                logger.error("Error checking AWS Support eligibility: %s", e)
                raise e

        return supportEligible

    # This function is called outside of this Class
    def get_aws_shield_advanced_eligibility(session) -> bool:
        shield = session.client("shield")

        try:
            shield.describe_subscription()
            shieldEligible = True
            logger.info("AWS Shield Advanced is eligible.")
        except ClientError as e:
            if "ResourceNotFoundException" in str(e):
                shieldEligible = False
                logger.warning("AWS Shield Advanced is not eligible: %s", e)
            else:
                logger.error("Error checking AWS Shield Advanced eligibility: %s", e)
                raise e

        return shieldEligible

    def setup_gcp_credentials(self, credentialValue) -> None:
        """
        Takes the credential value derived from the TOML file and creates a GCP credential object that can be passed to EEAuditor
        """
        credentials = json.loads(credentialValue)

        # Create a GCP credential object from the JSON payload
        try:
            gcpCredentials = service_account.Credentials.from_service_account_info(credentials)
        except Exception as e:
            logger.error(
                "Error encountered attempting to create GCP credentials from JSON payload: %s", e
            )
            sys.exit(2)

        return gcpCredentials

    def setup_oci_credentials(self, credentialValue) -> None:
        """
        Oracle Cloud Python SDK Config object can be created and requires the path to a PEM file, we can save the PEM
        contents to a file and save the location to an environment variable to be used
        """
        here = path.abspath(path.dirname(__file__))
        credentials_file_path = path.join(here, 'oci_api_key.pem')

        # Write the PEM contents to a file
        with open(credentials_file_path, "w") as f:
            f.write(credentialValue)
            chmod(credentials_file_path, 0o600)  # Set file to be readable and writable only by the owner

        logger.info("%s saved to environment variable", credentials_file_path)
        environ["OCI_PEM_FILE_PATH"] = credentials_file_path

    def create_azure_identity_credentials_from_client_secret(self, clientId: str, clientSecret: str, tenantId: str) -> ClientSecretCredential:
        """
        Attempts to create and return Azure Identity Credentials built from Client Secret creds within an App Registration
        """
        # Create Azure Identity credentials from Client ID/Secret Value/Tenant ID
        try:
            azureCredentials = ClientSecretCredential(client_id=clientId,client_secret=clientSecret,tenant_id=tenantId)
        except Exception as e:
            logger.error(
                "Error encountered attempting to create Azure Identity credentials from client secret: %s", e
            )
            sys.exit(2)

        return azureCredentials

    def retrieve_azure_subscriptions_for_service_principal(self, azureCredentials: ClientSecretCredential) -> list:
        """
        """
        azureSubscriptionsClient = SubscriptionClient(azureCredentials)

        try:
            azureSubscriptionIds = [sub.subscription_id for sub in azureSubscriptionsClient.subscriptions.list()]
            if not azureSubscriptionIds:
                logger.error(
                    "No Subscription IDs are available for your current Service Principal, please review your credentials and Access Control (IAM) settings in Azure Entra ID and Azure Subscriptions, respectively"
                )
                sys.exit(2)
        except Exception as e:
            logger.error(
                "Error encountered attempting to list Azure Subscriptions for Service Principal: %s", e
            )
            sys.exit(2)

        return azureSubscriptionIds

    def create_snowflake_cursor(self) -> tuple[snowconn.connection.SnowflakeConnection, snowconn.cursor.SnowflakeCursor]:
        """
        Returns a Snowflake cursor object for a given warehouse
        """
        try:
            conn = snowconn.connect(
                user=self.snowflakeUsername,
                password=self.snowflakePassowrd,
                account=self.snowflakeAccountId,
                warehouse=self.snowflakeWarehouseName
            )
        except Exception as e:
            raise e

        # This allows us to return a dictionary instead of tuples
        logger.info("Connected to Snowflake successfully.")
        cur = conn.cursor(snowconn.DictCursor)

        # Use the warehouse provided, this is a required step if a custom role is used to catch if the custom role was not given a grant to the warehouse
        try:
            war = cur.execute(f"use warehouse {self.snowflakeWarehouseName}").fetchall()
            logger.info("Using warehouse %s. %s", self.snowflakeWarehouseName, war)
        except snowconn.errors.ProgrammingError as e:
            logger.error(
                "Failed to use warehouse %s: %s",
                self.snowflakeWarehouseName, e
            )
            raise e

        return conn, cur

    def process_non_toml_args(self, assessmentTarget: str, args: dict) -> None:
        """
        Process any additional arguments passed to the script that are not in the TOML file
        """
        # First, process out the credentialsLocation arg ["AWS_SSM", "AWS_SECRETS_MANAGER", "CONFIG_FILE"]
        try:
            self.credentialsLocation = args.get("credentials_location")
        except KeyError as ke:
            logger.error(
                "The credentials_location argument was not provided: %s", ke
            )
            sys.exit(2)
        
        # AWS
        if assessmentTarget == "AWS":
            # First process the global "aws_multi_account_target_type" and "aws_account_targets" args
            try:
                awsMultiAccountTargetType = str(args.get("aws_multi_account_target_type"))
                awsAccountTargets = list(args.get("aws_account_targets"))
                awsRegionsSelection = list(args.get("aws_regions_selection"))
                electricEyeRoleName = args.get("aws_electric_eye_iam_role_name")
            except KeyError as ke:
                logger.error(
                    "One of the required global AWS arguments was not provided: %s", ke
                )
                sys.exit(2)
            # Process account targets based on the multi-account target type
            if awsMultiAccountTargetType == "Accounts":
                if not awsAccountTargets:
                    self.awsAccountTargets = [self._get_aws_caller_identity()["Account"]]
                else:
                    self.awsAccountTargets = awsAccountTargets
            if awsMultiAccountTargetType == "OU":
                if not awsAccountTargets:
                    logger.error("OU was specified but targets were not specified.")
                    sys.exit(2)
                # Use pre-compiled regex for performance
                for ou in awsAccountTargets:
                    if not OU_ID_REGEX.match(ou):
                        logger.error(f"Invalid Organizational Unit ID {ou}.")
                        sys.exit(2)
                self.awsAccountTargets = self.get_aws_accounts_from_organizational_units(awsAccountTargets)
            if awsMultiAccountTargetType == "Organization":
                self.awsAccountTargets = self.get_aws_accounts_from_organization()
            
            # Process aws_regions_selection
            awsRegions = self.get_aws_regions()
            if not awsRegionsSelection:
                self.awsRegionsSelection = [boto3.Session().region_name]
            else:
                if "All" in awsRegionsSelection or "all" in awsRegionsSelection:
                    self.awsRegionsSelection = list(awsRegions)  # Convert tuple to list
                else:
                    # Validation check - use set for O(1) lookups
                    awsRegionsSet = set(awsRegions)
                    self.awsRegionsSelection = [a for a in awsRegionsSelection if a in awsRegionsSet]            
            # Process ["aws_electric_eye_iam_role_name"]
            if electricEyeRoleName is None or electricEyeRoleName == "":
                logger.warning(
                    "A value for ['aws_electric_eye_iam_role_name'] was not provided. Will attempt to use current session credentials, this will likely fail if you're attempting to assess another AWS account."
                )
                self.electricEyeRoleName = None

            self.electricEyeRoleName = electricEyeRoleName

        # GCP
        if assessmentTarget == "GCP":
            try:
                self.gcpProjectIds = list(args.get("gcp_project_ids"))
                gcpServiceAccountJsonPayloadValue = str(args.get("gcp_service_account_json_payload_value"))
            except KeyError as ke:
                logger.error(
                    "One of the required GCP arguments was not provided: %s", ke
                )
                sys.exit(2)

            # Retrieve value for GCP Service Account JSON from the config, AWS SSM or AWS Secrets Manager
            if self.credentialsLocation == "CONFIG_FILE":
                self.gcpServiceAccountJsonPayloadValue = gcpServiceAccountJsonPayloadValue
            elif self.credentialsLocation == "AWS_SSM":
                self.gcpServiceAccountJsonPayloadValue = self.get_credential_from_aws_ssm(
                    gcpServiceAccountJsonPayloadValue,
                    "gcp_service_account_json_payload_value"
                )
            elif self.credentialsLocation == "AWS_SECRETS_MANAGER":
                self.gcpServiceAccountJsonPayloadValue = self.get_credential_from_aws_secrets_manager(
                    gcpServiceAccountJsonPayloadValue,
                    "gcp_service_account_json_payload_value"
                )
            
            self.gcpCredentials = self.setup_gcp_credentials(self.gcpServiceAccountJsonPayloadValue)

        # OCI
        if assessmentTarget == "OCI":
            try:
                self.ociTenancyId = str(args.get("oci_tenancy_ocid"))
                self.ociUserId = str(args.get("oci_user_ocid"))
                self.ociRegionName = str(args.get("oci_region_name"))
                self.ociCompartments = list(args.get("oci_compartment_ocids"))
                ociUserApiKeyFingerprint = str(args.get("oci_user_api_key_fingerprint_value"))
                ociUserApiKeyPemValue = str(args.get("oci_user_api_key_private_key_pem_contents_value"))
            except KeyError as ke:
                logger.error(
                    "One of the required OCI arguments was not provided: %s", ke
                )
                sys.exit(2)

            # Retrieve value for OCI API Key Fingerprint from the config, AWS SSM or AWS Secrets Manager
            if self.credentialsLocation == "CONFIG_FILE":
                self.ociUserApiKeyFingerprint = ociUserApiKeyFingerprint
            elif self.credentialsLocation == "AWS_SSM":
                self.ociUserApiKeyFingerprint = self.get_credential_from_aws_ssm(
                    ociUserApiKeyFingerprint,
                    "oci_user_api_key_fingerprint_value"
                )
            elif self.credentialsLocation == "AWS_SECRETS_MANAGER":
                self.ociUserApiKeyFingerprint = self.get_credential_from_aws_secrets_manager(
                    ociUserApiKeyFingerprint,
                    "oci_user_api_key_fingerprint_value"
                )

            # Retrieve value for OCI API Key PEM from the config, AWS SSM or AWS Secrets Manager
            if self.credentialsLocation == "CONFIG_FILE":
                ociUserApiKeyPemLocation = ociUserApiKeyPemValue
            elif self.credentialsLocation == "AWS_SSM":
                ociUserApiKeyPemLocation = self.get_credential_from_aws_ssm(
                    ociUserApiKeyPemValue,
                    "oci_user_api_key_private_key_pem_contents_value"
                )
            elif self.credentialsLocation == "AWS_SECRETS_MANAGER":
                ociUserApiKeyPemLocation = self.get_credential_from_aws_secrets_manager(
                    ociUserApiKeyPemValue,
                    "oci_user_api_key_private_key_pem_contents_value"
                )

            # Create the PEM file and save the location of it to environ
            self.setup_oci_credentials(ociUserApiKeyPemLocation)

        # Azure
        if assessmentTarget == "Azure":
            try:
                azureClientId = str(args.get("azure_ent_app_client_id_value"))
                azureSecretId = str(args.get("azure_ent_app_client_secret_id_value"))
                azureTenantId = str(args.get("azure_ent_app_tenant_id_value"))
                azureSubscriptions = list(args.get("azure_subscription_ids"))
            except KeyError as ke:
                logger.error(
                    "One of the required Azure arguments was not provided: %s", ke
                )
                sys.exit(2)

            # Retrieve the values for the Azure Enterprise Application Client ID, Secret Value & Tenant ID
            if self.credentialsLocation == "CONFIG_FILE":
                azureClientId = azureClientId
                azureSecretId = azureSecretId
                azureTenantId = azureTenantId
            elif self.credentialsLocation == "AWS_SSM":
                azureClientId = self.get_credential_from_aws_ssm(
                    azureClientId,
                    "azure_ent_app_client_id_value"
                )
                azureSecretId = self.get_credential_from_aws_ssm(
                    azureSecretId,
                    "azure_ent_app_client_secret_id_value"
                )
                azureTenantId = self.get_credential_from_aws_ssm(
                    azureTenantId,
                    "azure_ent_app_tenant_id_value"
                )
            elif self.credentialsLocation == "AWS_SECRETS_MANAGER":
                azureClientId = self.get_credential_from_aws_secrets_manager(
                    azureClientId,
                    "azure_ent_app_client_id_value"
                )
                azureSecretId = self.get_credential_from_aws_secrets_manager(
                    azureSecretId,
                    "azure_ent_app_client_secret_id_value"
                )
                azureTenantId = self.get_credential_from_aws_secrets_manager(
                    azureTenantId,
                    "azure_ent_app_tenant_id_value"
                )

            # Create Azure Identity credentials from Client ID/Secret Value/Tenant ID
            azureCredentials = self.create_azure_identity_credentials_from_client_secret(
                clientId=azureClientId,
                clientSecret=azureSecretId,
                tenantId=azureTenantId
            )

            # If subscriptions aren't supplied, attempt to find which ones you have access to
            if not azureSubscriptions:
                logger.warning(
                    "No values provided for azure_subscription_ids - attempting to retrieve subscription IDs your Service Principal has access to..."
                )
                azureSubscriptions = self.retrieve_azure_subscriptions_for_service_principal(
                    azureCredentials=azureCredentials
                )

            self.azureSubscriptions = azureSubscriptions
            self.azureCredentials = azureCredentials

        # M365
        if assessmentTarget == "M365":
            try:
                m365ClientId = str(args.get("m365_ent_app_client_id_value"))
                m365SecretId = str(args.get("m365_ent_app_client_secret_id_value"))
                m365TenantId = str(args.get("m365_ent_app_tenant_id_value"))
                self.m365TenantLocation = str(args.get("m365_tenant_location"))
            except KeyError as ke:
                logger.error(
                    "One of the required M365 arguments was not provided: %s", ke
                )
                sys.exit(2)

            # Retrieve the values for the M365 Enterprise Application Client ID, Secret Value & Tenant ID
            if self.credentialsLocation == "CONFIG_FILE":
                self.m365ClientId = m365ClientId
                self.m365SecretId = m365SecretId
                self.m365TenantId = m365TenantId
            elif self.credentialsLocation == "AWS_SSM":
                self.m365ClientId = self.get_credential_from_aws_ssm(
                    m365ClientId,
                    "m365_ent_app_client_id_value"
                )
                self.m365SecretId = self.get_credential_from_aws_ssm(
                    m365SecretId,
                    "m365_ent_app_client_secret_id_value"
                )
                self.m365TenantId = self.get_credential_from_aws_ssm(
                    m365TenantId,
                    "m365_ent_app_tenant_id_value"
                )
            elif self.credentialsLocation == "AWS_SECRETS_MANAGER":
                self.m365ClientId = self.get_credential_from_aws_secrets_manager(
                    m365ClientId,
                    "m365_ent_app_client_id_value"
                )
                self.m365SecretId = self.get_credential_from_aws_secrets_manager(
                    m365SecretId,
                    "m365_ent_app_client_secret_id_value"
                )
                self.m365TenantId = self.get_credential_from_aws_secrets_manager(
                    m365TenantId,
                    "m365_ent_app_tenant_id_value"
                )

        # Servicenow
        if assessmentTarget == "Servicenow":
            try:
                snowInstanceName = str(args.get("servicenow_instance_name"))
                snowInstanceRegion = str(args.get("servicenow_instance_region"))
                snowUserName = str(args.get("servicenow_sspm_username"))
                snowUserLoginBreachRate = str(args.get("servicenow_failed_login_breaching_rate"))
                serviceNowPwVal = str(args.get("servicenow_sspm_password_value"))
            except KeyError as ke:
                logger.error(
                    "One of the required ServiceNow arguments was not provided: %s", ke
                )
                sys.exit(2)

            # Retrieve ServiceNow ElectricEye user password
            if self.credentialsLocation == "CONFIG_FILE":
                environ["SNOW_SSPM_PASSWORD"] = serviceNowPwVal
            elif self.credentialsLocation == "AWS_SSM":
                environ["SNOW_SSPM_PASSWORD"] = self.get_credential_from_aws_ssm(
                    serviceNowPwVal,
                    "servicenow_sspm_password_value"
                )
            elif self.credentialsLocation == "AWS_SECRETS_MANAGER":
                environ["SNOW_SSPM_PASSWORD"] = self.get_credential_from_aws_secrets_manager(
                    serviceNowPwVal,
                    "servicenow_sspm_password_value"
                )

            # All other ServiceNow Values are written as environment variables
            environ["SNOW_INSTANCE_NAME"] = snowInstanceName
            environ["SNOW_INSTANCE_REGION"] = snowInstanceRegion
            environ["SNOW_SSPM_USERNAME"] = snowUserName
            environ["SNOW_FAILED_LOGIN_BREACHING_RATE"] = snowUserLoginBreachRate

        # Salesforce
        if assessmentTarget == "Salesforce":
            try:
                salesforceAppClientId = str(args.get("salesforce_connected_app_client_id_value"))
                salesforceAppClientSecret = str(args.get("salesforce_connected_app_client_secret_value"))
                salesforceApiUsername = str(args.get("salesforce_api_enabled_username_value"))
                salesforceApiPassword = str(args.get("salesforce_api_enabled_password_value"))
                salesforceUserSecurityToken = str(args.get("salesforce_api_enabled_security_token_value"))
                self.salesforceInstanceLocation = str(args.get("salesforce_instance_location"))
                salesforceFailedLoginBreachingRate = str(args.get("salesforce_failed_login_breaching_rate"))
                salesforceApiVersion = str(args.get("salesforce_api_version"))
            except KeyError as ke:
                logger.error(
                    "One of the required Salesforce arguments was not provided: %s", ke
                )
                sys.exit(2)

            # The failed login breaching rate and API Version will be in plaintext/env vars
            environ["SALESFORCE_FAILED_LOGIN_BREACHING_RATE"] = salesforceFailedLoginBreachingRate
            environ["SFDC_API_VERSION"] = salesforceApiVersion

            # Retrieve the values for the Salesforce Client ID, Client Secret, Username, Password, and Security Token
            if self.credentialsLocation == "CONFIG_FILE":
                self.salesforceAppClientId = salesforceAppClientId
                self.salesforceAppClientSecret = salesforceAppClientSecret
                self.salesforceApiUsername = salesforceApiUsername
                self.salesforceApiPassword = salesforceApiPassword
                self.salesforceUserSecurityToken = salesforceUserSecurityToken
            elif self.credentialsLocation == "AWS_SSM":
                self.salesforceAppClientId = self.get_credential_from_aws_ssm(
                    salesforceAppClientId,
                    "salesforce_connected_app_client_id_value"
                )
                self.salesforceAppClientSecret = self.get_credential_from_aws_ssm(
                    salesforceAppClientSecret,
                    "salesforce_connected_app_client_secret_value"
                )
                self.salesforceApiUsername = self.get_credential_from_aws_ssm(
                    salesforceApiUsername,
                    "salesforce_api_enabled_username_value"
                )
                self.salesforceApiPassword = self.get_credential_from_aws_ssm(
                    salesforceApiPassword,
                    "salesforce_api_enabled_password_value"
                )
                self.salesforceUserSecurityToken = self.get_credential_from_aws_ssm(
                    salesforceUserSecurityToken,
                    "salesforce_api_enabled_security_token_value"
                )
            elif self.credentialsLocation == "AWS_SECRETS_MANAGER":
                self.salesforceAppClientId = self.get_credential_from_aws_secrets_manager(
                    salesforceAppClientId,
                    "salesforce_connected_app_client_id_value"
                )
                self.salesforceAppClientSecret = self.get_credential_from_aws_secrets_manager(
                    salesforceAppClientSecret,
                    "salesforce_connected_app_client_secret_value"
                )
                self.salesforceApiUsername = self.get_credential_from_aws_secrets_manager(
                    salesforceApiUsername,
                    "salesforce_api_enabled_username_value"
                )
                self.salesforceApiPassword = self.get_credential_from_aws_secrets_manager(
                    salesforceApiPassword,
                    "salesforce_api_enabled_password_value"
                )
                self.salesforceUserSecurityToken = self.get_credential_from_aws_secrets_manager(
                    salesforceUserSecurityToken,
                    "salesforce_api_enabled_security_token_value"
                )

        # Snowflake
        if assessmentTarget == "Snowflake":
            try:
                self.snowflakeUsername = str(args.get("snowflake_username"))
                self.snowflakePasswordValue = str(args.get("snowflake_password_value"))
                self.snowflakeAccountId = str(args.get("snowflake_account_id"))
                self.snowflakeWarehouseName = str(args.get("snowflake_warehouse_name"))
                self.snowflakeRegion = str(args.get("snowflake_region"))
                self.serviceAccountExemptions = list(args.get("snowflake_service_account_usernames"))
            except KeyError as ke:
                logger.error(
                    "One of the required Snowflake arguments was not provided: %s", ke
                )
                sys.exit(2)

            # Retrieve value for Snowflake Password from the TOML, AWS SSM or AWS Secrets Manager
            if self.credentialsLocation == "CONFIG_FILE":
                self.snowflakePassowrd = self.snowflakePasswordValue
            # SSM
            if self.credentialsLocation == "AWS_SSM":
                self.snowflakePassowrd = self.get_credential_from_aws_ssm(
                    self.snowflakePasswordValue,
                    "snowflake_password_value"
                )
            # AWS Secrets Manager
            if self.credentialsLocation == "AWS_SECRETS_MANAGER":
                self.snowflakePassowrd = self.get_credential_from_aws_secrets_manager(
                    self.snowflakePasswordValue,
                    "snowflake_password_value"
                )

            # Setup Cursor and Connector
            snowflakeCursorConn = self.create_snowflake_cursor()

            self.snowflakeConnection = snowflakeCursorConn[0]
            self.snowflakeCursor = snowflakeCursorConn[1]
## EOF