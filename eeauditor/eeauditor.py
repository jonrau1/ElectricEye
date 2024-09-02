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
from os import path
from functools import partial
from inspect import getfile
from time import sleep
from traceback import format_exc
import json
from requests import get
from check_register import CheckRegister
from cloud_utils import CloudConfig
from pluginbase import PluginBase

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("EEAuditor")

here = path.abspath(path.dirname(__file__))
getPath = partial(path.join, here)

class EEAuditor(object):
    """
    ElectricEye Controller: loads plugins, prints Checks & Auditors, calls cloud_uitls.CloudConfig to setup
    credentials and cross-boundary configurations, and runs Checks and yields results back to controller.py CLI
    """

    def __init__(self, assessmentTarget, args, useToml, tomlPath=None, searchPath=None):
        # each check must be decorated with the @registry.register_check("cache_name")
        # to be discovered during plugin loading.
        self.registry = CheckRegister()
        self.name = assessmentTarget
        self.plugin_base = PluginBase(package="electriceye")
        ##################################
        # PUBLIC CLOUD SERVICE PROVIDERS #
        ##################################
        # AWS
        if assessmentTarget == "AWS":
            searchPath = "./auditors/aws"
            utils = CloudConfig(assessmentTarget, tomlPath, useToml, args)
            # parse specific values for Assessment Target - these should match 1:1 with CloudConfig
            self.awsAccountTargets = utils.awsAccountTargets
            self.awsRegionsSelection = utils.awsRegionsSelection
            self.electricEyeRoleName = utils.electricEyeRoleName
        # GCP
        if assessmentTarget == "GCP":
            searchPath = "./auditors/gcp"
            utils = CloudConfig(assessmentTarget, tomlPath, useToml, args)
            # parse specific values for Assessment Target - these should match 1:1 with CloudConfig
            self.gcpProjectIds = utils.gcp_project_ids
        # OCI
        if assessmentTarget == "OCI":
            searchPath = "./auditors/oci"
            utils = CloudConfig(assessmentTarget, tomlPath, useToml, args)
            # parse specific values for Assessment Target - these should match 1:1 with CloudConfig
            self.ociTenancyId = utils.ociTenancyId
            self.ociUserId = utils.ociUserId
            self.ociRegionName = utils.ociRegionName
            self.ociCompartments = utils.ociCompartments
            self.ociUserApiKeyFingerprint = utils.ociUserApiKeyFingerprint
        # Azure
        if assessmentTarget == "Azure":
            searchPath = "./auditors/azure"
            utils = CloudConfig(assessmentTarget, tomlPath, useToml, args)
            # parse specific values for Assessment Target - these should match 1:1 with CloudConfig
            self.azureSubscriptions = utils.azureSubscriptions
            self.azureCredentials = utils.azureCredentials
        # Alibaba
        if assessmentTarget == "Alibaba":
            searchPath = "./auditors/alibabacloud"
            utils = CloudConfig(assessmentTarget, tomlPath, useToml, args)
        
        ###################################
        # SOFTWARE-AS-A-SERVICE PROVIDERS #
        ###################################
        # Servicenow
        if assessmentTarget == "Servicenow":
            searchPath = "./auditors/servicenow"
            utils = CloudConfig(assessmentTarget, tomlPath, useToml, args)
        # M365
        if assessmentTarget == "M365":
            searchPath = "./auditors/m365"
            utils = CloudConfig(assessmentTarget, tomlPath, useToml, args)
            # parse specific values for Assessment Target - these should match 1:1 with CloudConfig
            self.m365TenantLocation = utils.m365TenantLocation
            self.m365ClientId = utils.m365ClientId
            self.m365SecretId = utils.m365SecretId
            self.m365TenantId = utils.m365TenantId
        # Salesforce
        if assessmentTarget == "Salesforce":
            searchPath = "./auditors/salesforce"
            utils = CloudConfig(assessmentTarget, tomlPath, useToml, args)
            # parse specific values for Assessment Target - these should match 1:1 with CloudConfig
            self.salesforceAppClientId = utils.salesforceAppClientId
            self.salesforceAppClientSecret = utils.salesforceAppClientSecret
            self.salesforceApiUsername = utils.salesforceApiUsername
            self.salesforceApiPassword = utils.salesforceApiPassword
            self.salesforceUserSecurityToken = utils.salesforceUserSecurityToken
            self.salesforceInstanceLocation = utils.salesforceInstanceLocation
        # Snowflake
        if assessmentTarget == "Snowflake":
            searchPath = "./auditors/snowflake"
            utils = CloudConfig(assessmentTarget, tomlPath, useToml, args)
            # parse specific values for Assessment Target - these should match 1:1 with CloudConfig
            self.snowflakeAccountId = utils.snowflakeAccountId
            self.snowflakeRegion = utils.snowflakeRegion
            self.snowflakeCursor = utils.snowflakeCursor
            self.snowflakeConnection = utils.snowflakeConnection
            self.serviceAccountExemptions = utils.serviceAccountExemptions
        # Google Workspace
        if assessmentTarget == "GoogleWorkspace":
            searchPath = "./auditors/google_workspace"
            utils = CloudConfig(assessmentTarget, tomlPath, useToml, args)

        # Search path for Auditors
        self.source = self.plugin_base.make_plugin_source(
            searchpath=[getPath(searchPath)], identifier=self.name
        )
    
    # Called from eeauditor/controller.py print_checks() and run_auditor()
    def load_plugins(self, auditorName=None):
        """
        Loads from pluginbase, works on a search path override as long as the checks have the registry class and decorator
        """
        if auditorName:
            try:
                self.source.load_plugin(auditorName)
            except Exception as e:
                logger.error(
                    "Failed to load plugin %s with exception: %s",
                    auditorName, e
                )
                raise e
        else:
            for auditorName in self.source.list_plugins():
                try:
                    self.source.load_plugin(auditorName)
                except Exception as e:
                    logger.error(
                        "Failed to load plugin %s with exception: %s",
                        auditorName, e
                    )
                    raise e

    # Called within this class    
    def check_service_endpoint_availability(self, endpointData, awsPartition, service, awsRegion):
        """
        This function downloads the latest version of botocore's endpoints.json file from GitHub and checks if a provided
        service within a specific AWS Partition and Region is available
        """

        # these are "endpoints" and not real regions, since ElectricEye provides local overrides to the "global"
        # AWS region within each Auditor already as long as these are present for a specific service then we're good
        globalEndpointPseudoRegions = [
            "aws-global", "fips-aws-global", "aws-cn-global", "aws-us-gov-global", "aws-us-gov-global-fips", "iam-govcloud", "iam-govcloud-fips", "aws-iso-global", "aws-iso-b-global", "aws-iso-e-global"
        ]

        # FIS isn't in the endpoints for some reason, which is stupid, so I need to have a list of FIS regions
        # https://docs.aws.amazon.com/general/latest/gr/fis.html
        fisRegions = [
            "us-east-2", "us-east-1", "us-west-2", "us-west-1", "af-south-1", "ap-east-1", "ap-south-1", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ca-central-1", "eu-central-1", "eu-west-1", "eu-west-2", "eu-south-1", "eu-west-3", "eu-north-1", "me-south-1", "sa-east-1", "us-gov-east-1", "us-gov-west-1"
        ]

        # overrides - some services fall under a service's "endpoint" and not so much a dedicated namespace from what I can tell??
        # we're overriding these just to trick ElectricEye into *not* aborting for certain services and also not re-naming plugins which use the same cache
        if service == "globalaccelerator":
            service = "iam"
        elif service == "imagebuilder":
            service = "ec2"
        elif service == "elasticloadbalancingv2":
            service = "elasticloadbalancing"
        elif service == "fis":
            if awsRegion in fisRegions:
                return True
            else:
                return False

        for partition in endpointData["partitions"]:
            if awsPartition == partition["partition"]:
                services = partition["services"]
                for serviceName, serviceData in services.items():
                    try:
                        # ecr, sagemaker, and a few other services have "api." on their names
                        # which is not consistent with the service at all
                        serviceName = str(serviceName).split("api.")[1]
                    except IndexError:
                        serviceName = serviceName
                    
                    # Compare the provided service name (from ElectricEye Plugin name) to service derived from the endpoint data
                    if service == serviceName:
                        regions = list(serviceData["endpoints"].keys())
                        # Backcheck on the "global" services e.g., Support, Trustedadvisor, CloudFront, IAM
                        if any(item in globalEndpointPseudoRegions for item in regions):
                            serviceAvailable = True
                            break
                        # Each service endpoint has a dict of Regions where the endpoint is available, at this point we have a valid service availability for the region + partition
                        if awsRegion in regions:
                            serviceAvailable = True
                            break
                        else:
                            serviceAvailable = False
                        # break if there is nothing else
                        break
                    else:
                        serviceAvailable = False

        return serviceAvailable
    
    # Called from eeauditor/controller.py run_auditor()
    def run_aws_checks(self, pluginName=None, delay=0):
        """
        Runs AWS Auditors across all TOML-specified Accounts and Regions in a specific Partition
        """

        # "Global" Auditors that should only need to be ran once per Account
        globalAuditors = ["cloudfront", "globalaccelerator", "iam", "health", "support", "account", "s3"]
        
        # Retrieve the endpoints.json data to prevent multiple outbound calls
        endpointData = json.loads(
            get(
                "https://raw.githubusercontent.com/boto/botocore/develop/botocore/data/endpoints.json"
            ).text
        )

        for account in self.awsAccountTargets:

            # This list will contain the "global" services so they're not run multiple times
            globalAuditorsCompleted = []

            for region in self.awsRegionsSelection:
                for serviceName, checkList in self.registry.checks.items():
                    # Pass the Cache at the "serviceName" level aka Plugin
                    auditorCache = {}
                    # Dervice the Partition ID from the AWS Region - needed for ASFF & service availability checks
                    partition = CloudConfig.check_aws_partition(region)
                    # Setup Boto3 Session with STS AssumeRole
                    if self.electricEyeRoleName is not None:
                        session = CloudConfig.create_aws_session(
                            account,
                            partition,
                            region,
                            self.electricEyeRoleName
                        )
                    # attempt to use current session creds
                    else:
                        import boto3
                        session = boto3.Session(region_name=region)
                    # Check service availability, not always accurate
                    if self.check_service_endpoint_availability(endpointData, partition, serviceName, region) is False:
                        logger.info(
                            "%s is not available in %s",
                            serviceName, region
                        )
                        continue

                    # For Support & Shield (Advanced) Auditors, check if the Account in question has the proper Support level and/or an active Shield Advanced Subscription
                    if serviceName == "support":
                        if CloudConfig.get_aws_support_eligibility is False:
                            logger.info(
                                "%s cannot access Trusted Advisor Checks due to not having Business, Enterprise or Enterprise On-Ramp Support.",
                                account
                            )
                            globalAuditorsCompleted.append(serviceName)
                            continue

                    if serviceName == "shield":
                        if CloudConfig.get_aws_shield_advanced_eligibility is False:
                            logger.info(
                                "%s cannot access Shield Advanced Checks due to not having an active Subscription.",
                                account    
                            )
                            globalAuditorsCompleted.append(serviceName)
                            continue
                    
                    # add the global services to the "globalAuditorsCompleted" so they can be skipped after they run once
                    # in the `session` for each of these, the Auditor will override with the "parent region" as some endpoints
                    # are not smart enough to do that - for instance, CloudFront and Health won't respond outside of us-east-1 but IAM will
                    if serviceName in globalAuditors:
                        if serviceName not in globalAuditorsCompleted:
                            globalAuditorsCompleted.append(serviceName)
                        else:
                            logger.info(
                                "%s Auditor was either already run or ineligble to run for AWS Account %s. Global Auditors only need to run once per Account.",
                                serviceName.capitalize(), account    
                            )
                            continue

                    for checkName, check in checkList.items():
                        # if a specific check is requested, only run that one check
                        if (
                            not pluginName
                            or pluginName
                            and pluginName == checkName
                        ):
                            try:
                                logger.info(
                                    "Executing Check %s for Account %s in region %s",
                                    checkName, account, region
                                )
                                for finding in check(
                                    cache=auditorCache,
                                    session=session,
                                    awsAccountId=account,
                                    awsRegion=region,
                                    awsPartition=partition,
                                ):
                                    if finding is not None:
                                        yield finding
                            except Exception:
                                logger.warn(
                                    "Failed to execute check %s with traceback %s",
                                    checkName, format_exc()
                                )
                        
            # optional sleep if specified - defaults to 0 seconds
            sleep(delay)

    # Called from eeauditor/controller.py run_auditor()
    def run_gcp_checks(self, pluginName=None, delay=0):
        """
        Runs GCP Auditors across all TOML-specified Projects
        """
        # hardcode the region and account for GCP
        region = "us-placeholder-1"
        account = "000000000000"
        partition = "not-aws"

        for project in self.gcpProjectIds:
            for serviceName, checkList in self.registry.checks.items():
                # Pass the Cache at the "serviceName" level aka Plugin
                auditorCache = {}
                for checkName, check in checkList.items():
                    # if a specific check is requested, only run that one check
                    if (
                        not pluginName
                        or pluginName
                        and pluginName == checkName
                    ):
                        try:
                            logger.info(
                                "Executing Check %s for GCP Project %s",
                                checkName, project
                            )
                            for finding in check(
                                cache=auditorCache,
                                awsAccountId=account,
                                awsRegion=region,
                                awsPartition=partition,
                                gcpProjectId=project
                            ):
                                if finding is not None:
                                    yield finding
                        except Exception as e:
                            logger.warning(
                                "Failed to execute check %s with exception: %s",
                                checkName, e
                            )
                # optional sleep if specified - defaults to 0 seconds
                sleep(delay)

    # Called from eeauditor/controller.py run_auditor()
    def run_oci_checks(self, pluginName=None, delay=0):
        """
        Run OCI Auditors for all Compartments specified in the TOML for a Tenancy
        """
        # hardcode the region and account for OCI
        region = "us-placeholder-1"
        account = "000000000000"
        partition = "not-aws"

        logger.info("Oracle Cloud Infrastructure assessment has started.")

        for serviceName, checkList in self.registry.checks.items():
            # Pass the Cache at the "serviceName" level aka Plugin
            auditorCache = {}
            for checkName, check in checkList.items():
                # if a specific check is requested, only run that one check
                if (
                    not pluginName
                    or pluginName
                    and pluginName == checkName
                ):
                    try:
                        logger.info(
                            "Executing Check %s for OCI",
                            checkName
                        )
                        for finding in check(
                            cache=auditorCache,
                            awsAccountId=account,
                            awsRegion=region,
                            awsPartition=partition,
                            ociTenancyId=self.ociTenancyId,
                            ociUserId=self.ociUserId,
                            ociRegionName=self.ociRegionName,
                            ociCompartments=self.ociCompartments,
                            ociUserApiKeyFingerprint=self.ociUserApiKeyFingerprint
                        ):
                            if finding is not None:
                                yield finding
                    except Exception as e:
                        logger.warning(
                            "Failed to execute check %s with exception: %s",
                            checkName, e
                        )
            # optional sleep if specified - defaults to 0 seconds
            sleep(delay)

    # Called from eeauditor/controller.py run_auditor()
    def run_azure_checks(self, pluginName=None, delay=0):
        """
        Runs Azure Auditors using Client Secret credentials from an Application Registration
        """
        # hardcode the region and account for Azure
        region = "us-placeholder-1"
        account = "000000000000"
        partition = "not-aws"

        logger.info("Microsoft Azure assessment has started.")

        for azSubId in self.azureSubscriptions:
            for serviceName, checkList in self.registry.checks.items():
                # Pass the Cache at the "serviceName" level aka Plugin
                auditorCache = {}
                for checkName, check in checkList.items():
                    # if a specific check is requested, only run that one check
                    if (
                        not pluginName
                        or pluginName
                        and pluginName == checkName
                    ):
                        try:
                            logger.info(
                                "Executing Check %s for Azure Sub %s",
                                checkName, azSubId
                            )
                            for finding in check(
                                cache=auditorCache,
                                awsAccountId=account,
                                awsRegion=region,
                                awsPartition=partition,
                                azureCredential=self.azureCredentials,
                                azSubId=azSubId
                            ):
                                if finding is not None:
                                    yield finding
                        except Exception as e:
                            logger.warning(
                                "Failed to execute check %s with exception: %s",
                                checkName, e
                            )
            # optional sleep if specified - defaults to 0 seconds
            sleep(delay)

    # Called from eeauditor/controller.py run_auditor()
    def run_m365_checks(self, pluginName=None, delay=0):
        """
        Runs M365 Auditors using Client Secret credentials from an Enterprise Application
        """
        # hardcode the region and account for non-AWS checks
        region = "us-placeholder-1"
        account = "000000000000"
        partition = "not-aws"

        logger.info("M365 assessment has started.")

        for serviceName, checkList in self.registry.checks.items():
            # Pass the Cache at the "serviceName" level aka Plugin
            auditorCache = {}
            for checkName, check in checkList.items():
                # if a specific check is requested, only run that one check
                if (
                    not pluginName
                    or pluginName
                    and pluginName == checkName
                ):
                    try:
                        logger.info(
                            "Executing Check %s for M365",
                            checkName
                        )
                        for finding in check(
                            cache=auditorCache,
                            awsAccountId=account,
                            awsRegion=region,
                            awsPartition=partition,
                            tenantId=self.m365TenantId,
                            clientId=self.m365ClientId,
                            clientSecret=self.m365SecretId,
                            tenantLocation=self.m365TenantLocation,
                        ):
                            if finding is not None:
                                yield finding
                    except Exception as e:
                        logger.warning(
                            "Failed to execute check %s with exception: %s",
                            checkName, e
                        )
            # optional sleep if specified - defaults to 0 seconds
            sleep(delay)

    # Called from eeauditor/controller.py run_auditor()
    def run_salesforce_checks(self, pluginName=None, delay=0):
        """
        Runs Salesforce Auditors using Password-based OAuth flow with Username, Password along with a 
        Connected Application Client ID and Client Secret and a User Security Token
        """
        # hardcode the region and account for SFDC
        region = "us-placeholder-1"
        account = "000000000000"
        partition = "not-aws"

        logger.info("Salesforce assessment has started.")

        for serviceName, checkList in self.registry.checks.items():
            # Pass the Cache at the "serviceName" level aka Plugin
            auditorCache = {}
            for checkName, check in checkList.items():
                # if a specific check is requested, only run that one check
                if (
                    not pluginName
                    or pluginName
                    and pluginName == checkName
                ):
                    try:
                        logger.info(
                            "Executing Check %s for Salesforce",
                            checkName
                        )
                        for finding in check(
                            cache=auditorCache,
                            awsAccountId=account,
                            awsRegion=region,
                            awsPartition=partition,
                            salesforceAppClientId = self.salesforceAppClientId,
                            salesforceAppClientSecret = self.salesforceAppClientSecret,
                            salesforceApiUsername = self.salesforceApiUsername,
                            salesforceApiPassword = self.salesforceApiPassword,
                            salesforceUserSecurityToken = self.salesforceUserSecurityToken,
                            salesforceInstanceLocation = self.salesforceInstanceLocation
                        ):
                            if finding is not None:
                                yield finding
                    except Exception as e:
                        logger.warning(
                            "Failed to execute check %s with exception: %s",
                            checkName, e
                        )
            # optional sleep if specified - defaults to 0 seconds
            sleep(delay)

    # Called from eeauditor/controller.py run_auditor()
    def run_snowflake_checks(self, pluginName=None, delay=0):
        """
        Runs Snowflake Auditors using Username and Password for a given Warehouse
        """
        # hardcode the region and account for non-AWS checks
        region = "us-placeholder-1"
        account = "000000000000"
        partition = "not-aws"

        logger.info("Snowflake assessment has started.")

        for serviceName, checkList in self.registry.checks.items():
            # Pass the Cache at the "serviceName" level aka Plugin
            auditorCache = {}
            for checkName, check in checkList.items():
                # if a specific check is requested, only run that one check
                if (
                    not pluginName
                    or pluginName
                    and pluginName == checkName
                ):
                    try:
                        logger.info(
                            "Executing Check %s for Snowflake",
                            checkName
                        )
                        for finding in check(
                            cache=auditorCache,
                            awsAccountId=account,
                            awsRegion=region,
                            awsPartition=partition,
                            snowflakeAccountId=self.snowflakeAccountId,
                            snowflakeRegion=self.snowflakeRegion,
                            snowflakeCursor=self.snowflakeCursor,
                            serviceAccountExemptions=self.serviceAccountExemptions
                        ):
                            if finding is not None:
                                yield finding
                    except Exception as e:
                        logger.warning(
                            "Failed to execute check %s with exception: %s",
                            checkName, e
                        )
            # optional sleep if specified - defaults to 0 seconds
            sleep(delay)

        # close the connection to the Snowflake Warehouse
        curClose = self.snowflakeCursor.close()
        connClose = self.snowflakeConnection.close()

        if curClose is True and connClose is None:
            logger.info("Snowflake connection and cursor closed.")
        else:
            logger.warning("Failed to close Snowflake connection and/or cursor.")

    # Called from eeauditor/controller.py run_auditor()
    def run_non_aws_checks(self, pluginName=None, delay=0):
        """
        Generic function to run Auditors, unless specialized logic is required, Assessment Target default to running here
        """
        # hardcode the region and account for Non-AWS Checks
        region = "us-placeholder-1"
        account = "000000000000"
        partition = "not-aws"

        for serviceName, checkList in self.registry.checks.items():
            # Pass the Cache at the "serviceName" level aka Plugin
            auditorCache = {}
            for checkName, check in checkList.items():
                # if a specific check is requested, only run that one check
                if (
                    not pluginName
                    or pluginName
                    and pluginName == checkName
                ):
                    try:
                        logger.info(
                            "Executing Check %s",
                            checkName
                        )
                        for finding in check(
                            cache=auditorCache,
                            awsAccountId=account,
                            awsRegion=region,
                            awsPartition=partition
                        ):
                            if finding is not None:
                                yield finding
                    except Exception as e:
                        logger.warning(
                            "Failed to execute check %s with exception: %s",
                            checkName, e
                        )
            # optional sleep if specified - defaults to 0 seconds
            sleep(delay)

    # Called from eeauditor/controller.py print_checks()
    def print_checks_md(self):
        table = []
        table.append("| Auditor Name | Check Name | Check Description |")
        table.append("|---|---|---|")
        # Just use some built-in functions to get the function name (__name__) and the Description/docstring (__doc__)
        for serviceName, checkList in self.registry.checks.items():
            for checkName, check in checkList.items():
                doc = check.__doc__
                if doc:
                    description = str(check.__doc__).replace("\n", "").replace("    ", "")
                else:
                    description = "Docstring is missing, please open an Issue!"

                auditorFile = getfile(check).rpartition("/")[2]
                auditorName = auditorFile.split(".py")[0]
                
                table.append(
                    f"| {auditorName} | {check.__name__} | {description} |"
                )

        print("\n".join(table))
    
    # Called from eeauditor/controller.py print_checks()
    def print_controls_json(self):
        controlPrinter = []

        for serviceName, checkList in self.registry.checks.items():
            for checkName, check in checkList.items():
                doc = check.__doc__
                if doc:
                    description = str(check.__doc__).replace("\n", "").replace("    ", "")
                else:
                    description = "Docstring is missing, please open an Issue!"
                
                controlPrinter.append(description)

        print(json.dumps(controlPrinter,indent=4))
        
# EOF