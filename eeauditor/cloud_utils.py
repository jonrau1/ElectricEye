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

import boto3
import tomli
import sys
import os
import re
import json
from botocore.exceptions import ClientError

# Boto3 Clients
sts = boto3.client("sts")
ssm = boto3.client("ssm")
asm = boto3.client("secretsmanager")
org = boto3.client("organizations")

# These Constants define legitimate values for certain parameters within the external_providers.toml file
AWS_MULTI_ACCOUNT_TARGET_TYPE_CHOICES = ["Accounts", "OU", "Organization"]
CREDENTIALS_LOCATION_CHOICES = ["AWS_SSM", "AWS_SECRETS_MANAGER", "CONFIG_FILE"]

class CloudConfig(object):
    """
    This Class handles processing of Credentials, Regions, Accounts, and other Provider-specific configurations
    for use in EEAuditor when running ElectricEye Auditors and Check
    """

    def __init__(self, assessmentTarget):
        here = os.path.abspath(os.path.dirname(__file__))
        tomlFile = f"{here}/external_providers.toml"

        with open(tomlFile, "rb") as f:
            data = tomli.load(f)

        # From TOML [global]
        if data["global"]["aws_multi_account_target_type"] not in AWS_MULTI_ACCOUNT_TARGET_TYPE_CHOICES:
            print("Invalid option for [global.aws_multi_account_target_type].")
            sys.exit(2)
        self.awsMultiAccountTargetType = data["global"]["aws_multi_account_target_type"]

        if data["global"]["credentials_location"] not in CREDENTIALS_LOCATION_CHOICES:
            print(f"Invalid option for [global.credentials_location]. Must be one of {str(CREDENTIALS_LOCATION_CHOICES)}.")
            sys.exit(2)
        self.credentialsLocation = data["global"]["credentials_location"]

        ##################################
        # PUBLIC CLOUD SERVICE PROVIDERS #
        ##################################
        
        # AWS
        if assessmentTarget == "AWS":
            # Process ["aws_account_targets"] 
            awsAccountTargets = data["regions_and_accounts"]["aws"]["aws_account_targets"]
            if self.awsMultiAccountTargetType == "Accounts":
                if not awsAccountTargets:
                    self.awsAccountTargets = [sts.get_caller_identity()["Account"]]
                else:
                    self.awsAccountTargets = awsAccountTargets
            elif self.awsMultiAccountTargetType == "OU":
                if not awsAccountTargets:
                    print("OU was specified but targets were not specified.")
                    sys.exit(2)
                # Regex to check for Valid OUs
                ouIdRegex = re.compile(r"^ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}$")
                for ou in awsAccountTargets:
                    if not ouIdRegex.match(ou):
                        print(f"Invalid Organizational Unit ID {ou}.")
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
            if electricEyeRoleName == (None or ""):
                print(f"A value for ['aws_electric_eye_iam_role_name'] was not provided. Fix the TOML file and run ElectricEye again.")
                sys.exit(2)
            self.electricEyeRoleName = electricEyeRoleName
        
        # GCP
        elif assessmentTarget == "GCP":
            # Process ["gcp_project_ids"]
            gcpProjects = data["regions_and_accounts"]["gcp"]["gcp_project_ids"]
            if not gcpProjects:
                print("No GCP Projects were provided in [regions_and_accounts.gcp.gcp_project_ids].")
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
                print(f"One of your Oracle Cloud TOML entries in [regions_and_accounts.oci] or [credentials.oci] is empty!")
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

            # Create the PEM file and save the location of it to os.environ
            self.setup_oci_credentials(ociUserApiKeyPemLocation)

        # Azure
        elif assessmentTarget == "Azure":
            print("Coming soon!")

        # Alibaba Cloud
        elif assessmentTarget == "Alibaba":
            print("Coming soon!")

        # VMWare Cloud on AWS
        elif assessmentTarget == "VMC":
            print("Coming soon!")

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
                print(f"One of your ServiceNow TOML entries in [credentials.servicenow] is empty!")
                sys.exit(2)
            
            # Retrieve ServiceNow ElectricEye user password
            serviceNowPwVal = serviceNowValues["servicenow_sspm_password_value"]
            if self.credentialsLocation == "CONFIG_FILE":
                os.environ["SNOW_SSPM_PASSWORD"] = serviceNowPwVal
            elif self.credentialsLocation == "AWS_SSM":
                os.environ["SNOW_SSPM_PASSWORD"] = self.get_credential_from_aws_ssm(
                    serviceNowPwVal,
                    "servicenow_sspm_password_value"
                )
            elif self.credentialsLocation == "AWS_SECRETS_MANAGER":
                os.environ["SNOW_SSPM_PASSWORD"] = self.get_credential_from_aws_secrets_manager(
                    serviceNowPwVal,
                    "servicenow_sspm_password_value"
                )
            # All other ServiceNow Values are written as environment variables and either provided
            # to PySnow Clients or to ProductFields{} within the ASFF per Finding
            os.environ["SNOW_INSTANCE_NAME"] = snowInstanceName
            os.environ["SNOW_INSTANCE_REGION"] = snowInstanceRegion
            os.environ["SNOW_SSPM_USERNAME"] = snowUserName
            os.environ["SNOW_FAILED_LOGIN_BREACHING_RATE"] = snowUserLoginBreachRate

        # M365
        elif assessmentTarget == "Servicenow":
            # Process data["credentials"]["servicenow"] - values need to be assigned to self
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
                print(f"One of your M365 TOML entries in [credentials.m365] is empty!")
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
    
    def get_aws_regions(self):
        """
        Uses EC2 DescribeRegions API to get a list of opted-in AWS Regions
        """

        ec2 = boto3.client('ec2')
        
        try:
            # majority of Regions have a "opt-in-not-required", hence the "not not opted in" list comp
            regions = [region["RegionName"] for region in ec2.describe_regions()["Regions"] if region["OptInStatus"] != "not-opted-in"]
        except ClientError as e:
            raise e

        return regions
    
    def get_credential_from_aws_ssm(self, value, configurationName):
        """
        Retrieves a TOML variable from AWS Systems Manager Parameter Store and returns it
        """

        # Check that a value was provided
        if value == (None or ""):
            print(f"A value for {configurationName} was not provided. Fix the TOML file and run ElectricEye again.")
            sys.exit(2)

        # Retrieve the credential from SSM Parameter Store
        try:
            credential = ssm.get_parameter(
                Name=value,
                WithDecryption=True
            )["Parameter"]["Value"]
        except ClientError as e:
            raise e
        
        return credential
    
    def get_credential_from_aws_secrets_manager(self, value, configurationName):
        """
        Retrieves a TOML variable from AWS Secrets Manager and returns it
        """

        # Check that a value was provided
        if value == (None or ""):
            print(f"A value for {configurationName} was not provided. Fix the TOML file and run ElectricEye again.")
            sys.exit(2)

        # Retrieve the credential from AWS Secrets Manager
        try:
            credential = asm.get_secret_value(
                SecretId=value,
            )["SecretString"]
        except ClientError as e:
            raise e
        
        return credential

    def get_aws_accounts_from_organization(self):
        """
        Uses Organizations ListAccounts API to get a list of "ACTIVE" AWS Accounts in the entire Organization
        """
        try:
            accounts = [account["Id"] for account in org.list_accounts() if account["Status"] == "ACTIVE"]
        except ClientError as e:
            raise e
        
        return accounts

    def get_aws_accounts_from_organizational_units(self, targets):
        """
        Uses Organizations ListAccountsForParent API to get a list of "ACTIVE" AWS Accounts for specified OUs
        """
        accounts = []

        for parent in targets:
            print(f"Processing accounts for Organizational Unit {parent}.")
            try:
                for account in org.list_accounts_for_parent(ParentId=parent)["Accounts"]:
                    if account["Status"] == "ACTIVE":
                        accounts.append(account["Id"])
            except ClientError as e:
                raise e
        
        return accounts
    
    # This function is called outside of this Class
    def create_aws_session(account, partition, region, roleName):
        """
        Uses STS AssumeRole to create a temporary Boto3 Session with a specified Account, Partition, and Region
        """

        crossAccountRoleArn = f"arn:{partition}:iam::{account}:role/{roleName}"

        try:
            memberAcct = sts.assume_role(
                RoleArn=crossAccountRoleArn,
                RoleSessionName="ElectricEye"
            )
        except ClientError as e:
            raise e

        session = boto3.Session(
            aws_access_key_id=memberAcct["Credentials"]["AccessKeyId"],
            aws_secret_access_key=memberAcct["Credentials"]["SecretAccessKey"],
            aws_session_token=memberAcct["Credentials"]["SessionToken"],
            region_name=region
        )

        return session
    
    # This function is called outside of this Class and from create_aws_session()
    def check_aws_partition(region):
        """
        Returns the AWS Partition based on the current Region of a Session
        """
        # GovCloud partition override
        if region in ["us-gov-east-1", "us-gov-west-1"]:
            partition = "aws-us-gov"
        # China partition override
        elif region in ["cn-north-1", "cn-northwest-1"]:
            partition = "aws-cn"
        # AWS Secret Region override
        elif region in ["us-isob-east-1", "us-isob-west-1"]:
            partition = "aws-isob"
        # AWS Top Secret Region override
        elif region in ["us-iso-east-1", "us-iso-west-1"]:
            partition = "aws-iso"
        else:
            partition = "aws"

        return partition

    def setup_gcp_credentials(self, credentialValue):
        """
        The Python Google Client SDK defaults to checking for credentials in the "GOOGLE_APPLICATION_CREDENTIALS"
        environment variable. This can be the location of a GCP Service Account (SA) Key which is stored in a JSON file.
        ElectricEye utilizes Service Accounts and provides multi-Project support by virtue of the Email of an SA added
        to those Projects as an IAM Role Binding Member will proper Roles (Viewer & Security Reviewer) added.

        This function simply takes the value of the TOML configuration ["gcp_service_account_json_payload_value"] derived 
        by this overall Class (CloudConfig), writes it to a JSON file, and specifies that location as the environment variable "GOOGLE_APPLICATION_CREDENTIALS"
        """
        here = os.path.abspath(os.path.dirname(__file__))
        # Write the result of ["gcp_service_account_json_payload_value"] to file
        with open(f"{here}/gcp_cred.json", 'w') as jsonfile:
            json.dump(
                json.loads(
                    credentialValue
                ),
                jsonfile,
                indent=2
            )
        # Set Cred global path
        print(f"{here}/gcp_cred.json saved to environment variable")
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = f"{here}/gcp_cred.json"

    def setup_oci_credentials(self, credentialValue):
        """
        Oracle Cloud Python SDK Config object can be created and requires the path to a PEM file, we can save the PEM
        contents to a file and save the location to an environment variable to be used
        """
        here = os.path.abspath(os.path.dirname(__file__))
        # Write the result of ["oci_user_api_key_private_key_pem_contents_value"] to file
        with open(f"{here}/oci_api_key.pem", "w") as f:
            f.write(credentialValue)

        # Set the location
        print(f"{here}/oci_api_key.pem saved to environment variable")
        os.environ["OCI_PEM_FILE_PATH"] = f"{here}/oci_api_key.pem"
        
## EOF