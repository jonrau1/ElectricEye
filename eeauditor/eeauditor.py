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

from functools import partial
import inspect
import os
from time import sleep
import traceback
import json
import requests
from check_register import CheckRegister, accumulate_paged_results
from cloud_utils import CloudConfig
from pluginbase import PluginBase

here = os.path.abspath(os.path.dirname(__file__))
getPath = partial(os.path.join, here)

class EEAuditor(object):
    """
    ElectricEye Controller: loads plugins, prints Checks & Auditors, calls cloud_uitls.CloudConfig to setup
    credentials and cross-boundary configurations, and runs Checks and yields results back to controller.py CLI
    """

    def __init__(self, assessmentTarget, searchPath=None):
        # each check must be decorated with the @registry.register_check("cache_name")
        # to be discovered during plugin loading.
        self.registry = CheckRegister()
        self.name = assessmentTarget
        self.plugin_base = PluginBase(package="electriceye")
        
        if assessmentTarget == "AWS":
            searchPath = "./auditors/aws"
            utils = CloudConfig(assessmentTarget)
            # parse specific values for Assessment Target - these should match 1:1 with CloudConfig
            self.aws_account_targets = utils.aws_account_targets
            self.aws_regions_selection = utils.aws_regions_selection
            self.aws_electric_eye_iam_role_name = utils.aws_electric_eye_iam_role_name
        elif assessmentTarget == "Azure":
            searchPath = "./auditors/azure"
            utils = CloudConfig(assessmentTarget)
        elif assessmentTarget == "GCP":
            searchPath = "./auditors/gcp"
            utils = CloudConfig(assessmentTarget)
            # parse specific values for Assessment Target - these should match 1:1 with CloudConfig
            self.gcp_project_ids = utils.gcp_project_ids
        elif assessmentTarget == "OracleCloud":
            searchPath = "./auditors/oci"
            utils = CloudConfig(assessmentTarget)
        elif assessmentTarget == "GitHub":
            searchPath = "./auditors/github"
            utils = CloudConfig(assessmentTarget)
        elif assessmentTarget == "Servicenow":
            searchPath = "./auditors/servicenow"
            utils = CloudConfig(assessmentTarget)
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
                print(f"Failed to load plugin {auditorName} with exception {e}")
        else:
            for auditorName in self.source.list_plugins():
                try:
                    self.source.load_plugin(auditorName)
                except Exception as e:
                    print(f"Failed to load plugin {auditorName} with exception {e}")
        
    def check_service_endpoint_availability(self, awsPartition, service, awsRegion):
        """
        This function downloads the latest version of botocore's endpoints.json file from GitHub and checks if a provided
        service within a specific AWS Partition and Region is available
        """

        # these are "endpoints" and not so much regions, since ElectricEye provides local overrides to the "global"
        # AWS region within each Auditor already as long as these are present for a specific service then we're good
        globalEndpointPseudoRegions = [
            "aws-global", "fips-aws-global", "aws-cn-global", "aws-us-gov-global", "aws-us-gov-global-fips","iam-govcloud", "iam-govcloud-fips", "aws-iso-global", "aws-iso-b-global", "aws-iso-e-global"
        ]

        endpointUrl = "https://raw.githubusercontent.com/boto/botocore/develop/botocore/data/endpoints.json"
        endpointData = json.loads(
            requests.get(endpointUrl).text
        )

        # overrides
        if service == "globalaccelerator":
            service = "iam"
        elif service == "imagebuilder":
            service = "ec2"

        for partition in endpointData['partitions']:
            if awsPartition == partition['partition']:
                services = partition['services']
                for serviceName, serviceData in services.items():
                    try:
                        # ecr, sagemaker, and a few other services have "api." on their names
                        # which is not consistent with the service at all
                        serviceName = serviceName.split("api.")[1]
                    except IndexError:
                        serviceName = serviceName
                    if service == serviceName:
                        regions = list(serviceData['endpoints'].keys())
                        # Backcheck on the "global" services e.g., Support, Trustedadvisor, CloudFront, IAM
                        if any(item in globalEndpointPseudoRegions for item in regions):
                            serviceAvailable = True
                            break
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

        for account in self.aws_account_targets:
            for region in self.aws_regions_selection:
                for serviceName, checkList in self.registry.checks.items():
                    # Setup Session & Partition
                    session = CloudConfig.create_aws_session(
                        account,
                        region,
                        self.aws_electric_eye_iam_role_name
                    )
                    partition = CloudConfig.check_aws_partition(region)

                    # Check service availability, not always accurate
                    if self.check_service_endpoint_availability(partition, serviceName, region) == False:
                        print(f"{serviceName} is not available in {region}")
                        continue

                    for checkName, check in checkList.items():
                        # clearing cache for each control whithin a auditor
                        auditorCache = {}
                        # if a specific check is requested, only run that one check
                        if (
                            not pluginName
                            or pluginName
                            and pluginName == checkName
                        ):
                            try:
                                print(f"Executing Check {checkName} for Account {account} in {region}")
                                for finding in check(
                                    cache=auditorCache,
                                    session=session,
                                    awsAccountId=account,
                                    awsRegion=region,
                                    awsPartition=partition,
                                ):
                                    yield finding
                            except Exception:
                                print(f"Failed to execute check {checkName}")
                                print(traceback.format_exc())
                        
            # optional sleep if specified - hardcode to 0 seconds
            sleep(delay)

    # Called from eeauditor/controller.py run_auditor()
    def run_gcp_checks(self, pluginName=None, delay=0):
        """
        Runs GCP Auditors across all TOML-specified Projects
        """

        # These details are needed for the ASFF...
        import boto3

        sts = boto3.client("sts")

        region = boto3.Session().region_name
        account = sts.get_caller_identity()["Account"]

        # GovCloud partition override
        if region in ["us-gov-east-1", "us-gov-west-1"]:
            partition = "aws-us-gov"
        # China partition override
        elif region in ["cn-north-1", "cn-northwest-1"]:
            partition = "aws-cn"
        # AWS Secret Region override - sc2s.sgov.gov
        elif region in ["us-isob-east-1", "us-isob-west-1"]:
            partition = "aws-isob"
        # AWS Top Secret Region override - c2s.ic.gov
        elif region in ["us-iso-east-1", "us-iso-west-1"]:
            partition = "aws-iso"
        # UK GCHQ Classified Region override - cloud.adc-e.uk
        elif region in ["eu-isoe-west-1", "eu-isoe-west-2"]:
            partition = "aws-isoe"
        else:
            partition = "aws"

        for project in self.gcp_project_ids:
            for serviceName, checkList in self.registry.checks.items():
                for checkName, check in checkList.items():
                    # clearing cache for each control whithin a auditor
                    auditorCache = {}
                    # if a specific check is requested, only run that one check
                    if (
                        not pluginName
                        or pluginName
                        and pluginName == checkName
                    ):
                        try:
                            print(f"Executing Check {checkName} for GCP Project {project}")
                            for finding in check(
                                cache=auditorCache,
                                awsAccountId=account,
                                awsRegion=region,
                                awsPartition=partition,
                                gcpProjectId=project
                            ):
                                yield finding
                        except Exception:
                            print(traceback.format_exc())
                            print(f"Failed to execute check {checkName}")
                # optional sleep if specified - hardcode to 0 seconds
                sleep(delay)

    # Called from eeauditor/controller.py run_auditor()
    def run_non_aws_checks(self, pluginName=None, delay=0):
        """
        Generic function to run Auditors, unless specialized logic is required, Assessment Target default to running here
        """

        import boto3

        sts = boto3.client("sts")

        region = boto3.Session().region_name
        account = sts.get_caller_identity()["Account"]

        # GovCloud partition override
        if region in ["us-gov-east-1", "us-gov-west-1"]:
            partition = "aws-us-gov"
        # China partition override
        elif region in ["cn-north-1", "cn-northwest-1"]:
            partition = "aws-cn"
        # AWS Secret Region override - sc2s.sgov.gov
        elif region in ["us-isob-east-1", "us-isob-west-1"]:
            partition = "aws-isob"
        # AWS Top Secret Region override - c2s.ic.gov
        elif region in ["us-iso-east-1", "us-iso-west-1"]:
            partition = "aws-iso"
        # UK GCHQ Classified Region override - cloud.adc-e.uk
        elif region in ["eu-isoe-west-1", "eu-isoe-west-2"]:
            partition = "aws-isoe"
        else:
            partition = "aws"

        for serviceName, checkList in self.registry.checks.items():
            for checkName, check in checkList.items():
                # clearing cache for each control whithin a auditor
                auditorCache = {}
                # if a specific check is requested, only run that one check
                if (
                    not pluginName
                    or pluginName
                    and pluginName == checkName
                ):
                    try:
                        print(f"Executing Check: {checkName}")
                        for finding in check(
                            cache=auditorCache,
                            awsAccountId=account,
                            awsRegion=region,
                            awsPartition=partition
                        ):
                            yield finding
                    except Exception as e:
                        print(traceback.format_exc())
                        print(f"Failed to execute check {checkName} with exception {e}")
            # optional sleep if specified - hardcode to 0 seconds
            sleep(delay)

    # Called from eeauditor/controller.py print_checks()
    def print_checks_md(self):
        table = []
        table.append(
            "| Auditor File Name                      | Scanned Resource Name         | Auditor Scan Description                                                               |"
        )
        table.append(
            "|----------------------------------------|-------------------------------|----------------------------------------------------------------------------------------|"
        )

        for serviceName, checkList in self.registry.checks.items():
            for checkName, check in checkList.items():
                doc = check.__doc__
                if doc:
                    description = (check.__doc__).replace("\n", "")
                else:
                    description = ""
                table.append(
                    f"|{inspect.getfile(check).rpartition('/')[2]} | {serviceName} | {description}"
                )

        print("\n".join(table))

    def print_controls_json(self):
        controlPrinter = []

        for serviceName, checkList in self.registry.checks.items():
            for checkName, check in checkList.items():
                doc = check.__doc__
                if doc:
                    description = (check.__doc__).replace("\n", "")
                else:
                    description = ""
                
                
                controlPrinter.append(description)

        print(json.dumps(controlPrinter,indent=2))

# EOF