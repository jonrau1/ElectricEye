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
from azure.identity import ClientSecretCredential
from azure.mgmt.resource.subscriptions import SubscriptionClient
import snowflake.connector as snowconn

logger = logging.getLogger("CloudUtils")

# These Constants define legitimate values for certain parameters within the external_providers.toml file
AWS_MULTI_ACCOUNT_TARGET_TYPE_CHOICES = ["Accounts", "OU", "Organization"]
CREDENTIALS_LOCATION_CHOICES = ["AWS_SSM", "AWS_SECRETS_MANAGER", "CONFIG_FILE"]

class CloudConfig(object):
    """
    This Class handles processing of Credentials, Regions, Accounts, and other Provider-specific configurations
    for use in EEAuditor when running ElectricEye Auditors and Check
    """

    def __init__(self, assessmentTarget, tomlPath):
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

        ##################################
        # PUBLIC CLOUD SERVICE PROVIDERS #
        ##################################
        
        # AWS
        if assessmentTarget == "AWS":
            sts = boto3.client("sts")
            # Process ["aws_account_targets"] 
            awsAccountTargets = data["regions_and_accounts"]["aws"]["aws_account_targets"]
            if self.awsMultiAccountTargetType == "Accounts":
                if not awsAccountTargets:
                    self.awsAccountTargets = [sts.get_caller_identity()["Account"]]
                else:
                    self.awsAccountTargets = awsAccountTargets
            elif self.awsMultiAccountTargetType == "OU":
                if not awsAccountTargets:
                    logger.error("OU was specified but targets were not specified.")
                    sys.exit(2)
                # Regex to check for Valid OUs
                ouIdRegex = compile(r"^ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}$")
                for ou in awsAccountTargets:
                    if not ouIdRegex.match(ou):
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
                    self.awsRegionsSelection = awsRegions
                else:
                    # Validation check
                    self.awsRegionsSelection = [a for a in tomlRegions if a in awsRegions]
            
            # Process ["aws_electric_eye_iam_role_name"]
            electricEyeRoleName = data["regions_and_accounts"]["aws"]["aws_electric_eye_iam_role_name"]
            if electricEyeRoleName is None or electricEyeRoleName == "":
                logger.warning(
                    "A value for ['aws_electric_eye_iam_role_name'] was not provided. Will attempt to use current session credentials, this will likely fail if you're attempting to assess another AWS account."
                )
                electricEyeRoleName = None
            
            self.electricEyeRoleName = electricEyeRoleName
        
        # GCP
        elif assessmentTarget == "GCP":
            # Process ["gcp_project_ids"]
            gcpProjects = data["regions_and_accounts"]["gcp"]["gcp_project_ids"]
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
            self.setup_gcp_credentials(self.gcpServiceAccountJsonPayloadValue)
        
        # Oracle Cloud Infrastructure (OCI)
        elif assessmentTarget == "OCI":
            ociValues = data["regions_and_accounts"]["oci"]

            # Retrieve the OCIDs for Tenancy & User and the Region ID along with a list of Compartment OCIDs
            ociTenancyId = ociValues["oci_tenancy_ocid"]
            ociUserId = ociValues["oci_user_ocid"]
            ociRegionName = ociValues["oci_region_name"]
            ociCompartments = ociValues["oci_compartment_ocids"]
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
        elif assessmentTarget == "Azure":
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
        elif assessmentTarget == "Alibaba":
            logger.info("Coming soon!")

        ###################################
        # SOFTWARE-AS-A-SERVICE PROVIDERS #
        ###################################

        # ServiceNow
        elif assessmentTarget == "Servicenow":
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
        elif assessmentTarget == "M365":
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
        elif assessmentTarget == "Salesforce":
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
        elif assessmentTarget == "GoogleWorkspace":
            logger.info("Coming soon!")

        # Snowflake
        elif assessmentTarget == "Snowflake":
            # Process data["credentials"]["snowflake"] - values need to be assigned to self
            snowflakeTomlValues = data["credentials"]["snowflake"]

            snowflakeUsername = str(snowflakeTomlValues["snowflake_username"])
            snowflakePasswordValue = str(snowflakeTomlValues["snowflake_password_value"])
            snowflakeAccountId = str(snowflakeTomlValues["snowflake_account_id"])
            snowflakeWarehouseName = str(snowflakeTomlValues["snowflake_warehouse_name"])
            snowflakeRegion = str(snowflakeTomlValues["snowflake_region"])

            if any(
                # Check to make sure none of the variables pulled from TOML are emtpy
                not var for var in [
                    snowflakeUsername, snowflakePasswordValue, snowflakeAccountId, snowflakeWarehouseName, snowflakeRegion
                    ]
                ):
                logger.error(f"One of your Salesforce TOML entries in [credentials.salesforce] is empty!")
                sys.exit(2)

            # Parse non-confidential values to environ
            self.snowflakeUsername = snowflakeUsername
            self.snowflakeAccountId = snowflakeAccountId
            self.snowflakeWarehouseName = snowflakeWarehouseName
            self.snowflakeRegion = snowflakeRegion

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
            snowflakeCursorConn = self.connectToSnowflake()

            self.snowflakeConnection = snowflakeCursorConn[0]
            self.snowflakeCursor = snowflakeCursorConn[1]

    def get_aws_regions(self):
        """
        Uses EC2 DescribeRegions API to get a list of opted-in AWS Regions
        """

        ec2 = boto3.client('ec2')
        
        try:
            # majority of Regions have a "opt-in-not-required", hence the "not not opted in" list comp
            regions = [region["RegionName"] for region in ec2.describe_regions()["Regions"] if region["OptInStatus"] != "not-opted-in"]
        except ClientError as e:
            logger.error(
                "Could not retrieve AWS Regions because: %s",
                e
            )
            raise e

        return regions
    
    def get_credential_from_aws_ssm(self, value, configurationName):
        """
        Retrieves a TOML variable from AWS Systems Manager Parameter Store and returns it
        """

        ssm = boto3.client("ssm")

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
    
    def get_credential_from_aws_secrets_manager(self, value, configurationName):
        """
        Retrieves a TOML variable from AWS Secrets Manager and returns it
        """
        asm = boto3.client("secretsmanager")

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

    def get_aws_accounts_from_organization(self):
        """
        Uses Organizations ListAccounts API to get a list of "ACTIVE" AWS Accounts in the entire Organization
        """
        org = boto3.client("organizations")

        try:
            accounts = [account["Id"] for account in org.list_accounts()["Accounts"] if account["Status"] == "ACTIVE"]
        except ClientError as e:
            logger.error(
                "Failed to retrieve accounts from AWS Organizations: %s", e
            )
            raise e

        return accounts

    def get_aws_accounts_from_organizational_units(self, targets):
        """
        Uses Organizations ListAccountsForParent API to get a list of "ACTIVE" AWS Accounts for specified OUs
        """
        sts = boto3.client("sts")
        org = boto3.client("organizations")

        accounts = [sts.get_caller_identity()["Account"]]  # Caller account is added directly.

        for parent in targets:
            logger.info("Processing accounts for Organizational Unit %s.", parent)
            try:
                active_accounts = [account["Id"] for account in org.list_accounts_for_parent(ParentId=parent)["Accounts"] if account["Status"] == "ACTIVE"]
                accounts.extend(account for account in active_accounts if account not in accounts)
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
    def check_aws_partition(region: str):
        """
        Returns the AWS Partition based on the current Region of a Session
        """

        # GovCloud partition override
        if region in ["us-gov-east-1", "us-gov-west-1"] or "us-gov-" in region:
            partition = "aws-us-gov"
        # China partition override
        elif region in ["cn-north-1", "cn-northwest-1"] or "cn-" in region:
            partition = "aws-cn"
        # AWS Secret Region override
        elif region in ["us-isob-east-1", "us-isob-west-1"] or "isob-" in region:
            partition = "aws-isob"
        # AWS Top Secret Region override
        elif region in ["us-iso-east-1", "us-iso-west-1"] or "iso-" in region:
            partition = "aws-iso"
        # AWS UKSOF / British MOD Region override
        elif "iso-e" in region or "isoe" in region:
            partition = "aws-isoe"
        # AWS Intel Community us-isof-south-1 Region override
        elif region in ["us-isof-south-1"] or "iso-f" in region or "isof" in region:
            partition = "aws-isof"
        # TODO: Add European Sovreign Cloud Partition
        else:
            partition = "aws"

        return partition

    # This function is called outside of this Class
    def get_aws_support_eligibility(session):
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
    def get_aws_shield_advanced_eligibility(session):
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

    def setup_gcp_credentials(self, credentialValue):
        """
        The Python Google Client SDK defaults to checking for credentials in the "GOOGLE_APPLICATION_CREDENTIALS"
        environment variable. This can be the location of a GCP Service Account (SA) Key which is stored in a JSON file.
        ElectricEye utilizes Service Accounts and provides multi-Project support by virtue of the Email of an SA added
        to those Projects as an IAM Role Binding Member will proper Roles (Viewer & Security Reviewer) added.

        This function simply takes the value of the TOML configuration ["gcp_service_account_json_payload_value"] derived 
        by this overall Class (CloudConfig), writes it to a JSON file, and specifies that location as the environment variable "GOOGLE_APPLICATION_CREDENTIALS"
        """
        here = path.abspath(path.dirname(__file__))
        credentials_file_path = path.join(here, 'gcp_cred.json')

        # Attempt to parse the credential value and write it to a file
        try:
            credentials = json.loads(credentialValue)
            with open(credentials_file_path, 'w') as jsonfile:
                json.dump(credentials, jsonfile, indent=2)
                chmod(credentials_file_path, 0o600)  # Set file to be readable and writable only by the owner
        except json.JSONDecodeError as e:
            logger.error(
                "Failed to parse GCP credentials JSON: %s", e
            )
            raise e

        logger.info("%s saved to environment variable", credentials_file_path)
        environ["GOOGLE_APPLICATION_CREDENTIALS"] = credentials_file_path

    def setup_oci_credentials(self, credentialValue):
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

    def connectToSnowflake(self) -> tuple[snowconn.connection.SnowflakeConnection, snowconn.cursor.SnowflakeCursor]:
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
    
        cur = conn.cursor()

        return conn, cur

## EOF