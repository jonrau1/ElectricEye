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
from check_register import CheckRegister, accumulate_paged_results
from pluginbase import PluginBase
import traceback

here = os.path.abspath(os.path.dirname(__file__))
get_path = partial(os.path.join, here)

class EEAuditor(object):
    """
    ElectricEye controller

    This class manages loading auditor plugins and running checks

    AWS Requires `session` and `region` which are assembled within controller.py setup_aws_credentials()

    Azure Requires...

    GCP requires a Project ID that matches the provided Service Account JSON payload stored in SSM that is referenced in the TOML

    GitHub Requires...
    """

    def __init__(self, target_provider, session, region, gcp_project_id, search_path=None):
        # each check must be decorated with the @registry.register_check("cache_name")
        # to be discovered during plugin loading.
        self.registry = CheckRegister()
        self.name = target_provider
        self.plugin_base = PluginBase(package="electriceye")
        
        if target_provider == "AWS":
            search_path = "./auditors/aws"

            # Here is where STS AssumeRole Creds are supplied or a default Session object is used
            self.session = session
            sts = session.client("sts")
            self.awsAccountId = sts.get_caller_identity()["Account"]
            self.awsRegion = region
            
            # GovCloud partition override
            if self.awsRegion in ["us-gov-east-1", "us-gov-west-1"]:
                self.awsPartition = "aws-us-gov"
            # China partition override
            elif self.awsRegion in ["cn-north-1", "cn-northwest-1"]:
                self.awsPartition = "aws-cn"
            # AWS Secret Region override
            elif self.awsRegion in ["us-isob-east-1"]:
                self.awsPartition = "aws-isob"
            # AWS Top Secret Region override
            # TS West: https://aws.amazon.com/blogs/publicsector/announcing-second-aws-top-secret-region-extending-support-us-government-classified-missions/
            elif self.awsRegion in ["us-iso-east-1", "us-iso-west-1"]:
                self.awsPartition = "aws-iso"
            else:
                # default to Commercial AWS Partition
                self.awsPartition = "aws"

        elif target_provider == "AZURE":
            search_path = "./auditors/azure"
        elif target_provider == "GCP":
            search_path = "./auditors/gcp"

            self.gcpProjectId = gcp_project_id

        elif target_provider == "GitHub":
            search_path = "./auditors/github"
        elif target_provider == "Servicenow":
            search_path = "./auditors/servicenow"

        # If there is a desire to add support for multiple clouds, this would be
        # a great place to implement it.
        self.source = self.plugin_base.make_plugin_source(
            searchpath=[get_path(search_path)], identifier=self.name
        )

    
    def load_plugins(self, plugin_name=None):
        """
        Loads from pluginbase, works on a search path override as long as the checks have the registry class and decorator
        """
        if plugin_name:
            try:
                self.source.load_plugin(plugin_name)
            except Exception as e:
                print(f"Failed to load plugin {plugin_name} with exception {e}")
        else:
            for plugin_name in self.source.list_plugins():
                try:
                    self.source.load_plugin(plugin_name)
                except Exception as e:
                    print(f"Failed to load plugin {plugin_name} with exception {e}")
 
    def get_regions(self, service):
        """
        This is only used for AWS and only for Commerical Partition -- checks against SSM-managed Parameter to see what services are available in a Region
        It is not exactly foolproof as AMB and CloudSearch and a few others are still jacked up...
        """
        # Pull session
        session = self.session
        ssm = session.client("ssm")

        # create an empty list for Commercial Region lookups
        values = []

        if self.awsPartition == "aws":
            # only check validity for AWS Commercial Region
            # Handle the weird v2 services names - global service overrides for lookup
            if service == 'kinesisanalyticsv2':
                service = 'kinesisanalytics'
            elif service == 'macie2':
                service = 'macie'
            elif service == 'elbv2':
                service = 'elb'
            elif service == 'wafv2':
                service = 'waf'
            else:
                service = service

            paginator = ssm.get_paginator("get_parameters_by_path")
            response_iterator = paginator.paginate(
                Path=f"/aws/service/global-infrastructure/services/{service}/regions",
                PaginationConfig={"MaxItems": 1000, "PageSize": 10},
            )
            results = accumulate_paged_results(
                page_iterator=response_iterator, key="Parameters")
            
            for parameter in results["Parameters"]:
                values.append(parameter["Value"])
        else:
            print(f"Service endpoint validity cannot be checked in {self.awsPartition}.")

        return values

    def run_aws_checks(self, requested_check_name=None, delay=0):
        """
        Separated logic for different checks - this one is for AWS as it calls get_regions(self, service) for the Commerical Partition
        """
        # Last call for session validation logging
        print(f'Running ElectricEye in AWS Account {self.awsAccountId} in Region {self.awsRegion}')

        for service_name, check_list in self.registry.checks.items():
            # only check regions if in AWS Commerical Partition
            if self.awsPartition == "aws":
                if self.awsRegion not in self.get_regions(service_name):
                    next

            for check_name, check in check_list.items():
                # clearing cache for each control whithin a auditor
                auditor_cache = {}
                # if a specific check is requested, only run that one check
                if (
                    not requested_check_name
                    or requested_check_name
                    and requested_check_name == check_name
                ):
                    try:
                        print(f"Executing Check: {check_name}")
                        for finding in check(
                            cache=auditor_cache,
                            session=self.session,
                            awsAccountId=self.awsAccountId,
                            awsRegion=self.awsRegion,
                            awsPartition=self.awsPartition,
                        ):
                            yield finding
                    except Exception as e:
                        print(traceback.format_exc())
                        print(f"Failed to execute check {check_name} with exception {e}")
            # optional sleep if specified - hardcode to 0 seconds
            sleep(delay)

    def run_gcp_checks(self, requested_check_name=None, delay=0):
        """
        This "run check" function is for GCP as it accepts a Project ID as an argument in the GCP Auditors
        
        NOTE: In the future, this function may change
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
        # AWS Secret Region override
        elif region in ["us-isob-east-1"]:
            partition = "aws-isob"
        # AWS Top Secret Region override
        elif region in ["us-iso-east-1", "us-iso-west-1"]:
            partition = "aws-iso"
        else:
            partition = "aws"

        for service_name, check_list in self.registry.checks.items():
            for check_name, check in check_list.items():
                # clearing cache for each control whithin a auditor
                auditor_cache = {}
                # if a specific check is requested, only run that one check
                if (
                    not requested_check_name
                    or requested_check_name
                    and requested_check_name == check_name
                ):
                    try:
                        print(f"Executing Check: {check_name}")
                        for finding in check(
                            cache=auditor_cache,
                            awsAccountId=account,
                            awsRegion=region,
                            awsPartition=partition,
                            gcpProjectId=self.gcpProjectId
                        ):
                            yield finding
                    except Exception as e:
                        print(traceback.format_exc())
                        print(f"Failed to execute check {check_name} with exception {e}")
            # optional sleep if specified - hardcode to 0 seconds
            sleep(delay)

    def run_non_aws_checks(self, requested_check_name=None, delay=0):
        """
        This "run check" function is for all SSPM and non-AWS providers as it does not contain a check against SSM for service eligibility
        
        NOTE: In the future, this function may be split off into other providers if other arguments or checks are required
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
        # AWS Secret Region override
        elif region in ["us-isob-east-1"]:
            partition = "aws-isob"
        # AWS Top Secret Region override
        elif region in ["us-iso-east-1", "us-iso-west-1"]:
            partition = "aws-iso"
        else:
            partition = "aws"

        for service_name, check_list in self.registry.checks.items():
            for check_name, check in check_list.items():
                # clearing cache for each control whithin a auditor
                auditor_cache = {}
                # if a specific check is requested, only run that one check
                if (
                    not requested_check_name
                    or requested_check_name
                    and requested_check_name == check_name
                ):
                    try:
                        print(f"Executing Check: {check_name}")
                        for finding in check(
                            cache=auditor_cache,
                            awsAccountId=account,
                            awsRegion=region,
                            awsPartition=partition
                        ):
                            yield finding
                    except Exception as e:
                        print(traceback.format_exc())
                        print(f"Failed to execute check {check_name} with exception {e}")
            # optional sleep if specified - hardcode to 0 seconds
            sleep(delay)

    # called from eeauditor/controller.py print_checks()
    def print_checks_md(self):
        table = []
        table.append(
            "| Auditor File Name                      | Scanned Resource Name         | Auditor Scan Description                                                               |"
        )
        table.append(
            "|----------------------------------------|-------------------------------|----------------------------------------------------------------------------------------|"
        )

        for service_name, check_list in self.registry.checks.items():
            for check_name, check in check_list.items():
                doc = check.__doc__
                if doc:
                    description = (check.__doc__).replace("\n", "")
                else:
                    description = ""
                table.append(
                    f"|{inspect.getfile(check).rpartition('/')[2]} | {service_name} | {description}"
                )

        print("\n".join(table))