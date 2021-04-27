# This file is part of ElectricEye.

# ElectricEye is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# ElectricEye is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with ElectricEye.
# If not, see https://github.com/jonrau1/ElectricEye/blob/master/LICENSE.
from functools import partial
import inspect
import json
import os
from time import sleep
import re
import boto3
from check_register import CheckRegister, accumulate_paged_results
from pluginbase import PluginBase

here = os.path.abspath(os.path.dirname(__file__))
get_path = partial(os.path.join, here)
ssm = boto3.client("ssm")


class EEAuditor(object):
    """ElectricEye controller

        This class manages loading auditor plugins and running checks
    """

    def __init__(self, name, search_path=None):
        if not search_path:
            search_path = "./auditors/aws"
        self.name = name
        self.plugin_base = PluginBase(package="electriceye")
        # each check must be decorated with the @registry.register_check("cache_name")
        # to be discovered during plugin loading.
        self.registry = CheckRegister()
        # vendor specific credentials dictionary
        sts = boto3.client("sts")
        self.awsAccountId = sts.get_caller_identity()["Account"]
        self.awsRegion = os.environ.get("AWS_REGION", sts.meta.region_name)
        self.awsPartition = "aws"
        if self.awsRegion in ["us-gov-east-1", "us-gov-west-1"]:
            self.awsPartition = "aws-us-gov"
        elif self.awsRegion in ["cn-north-1", "cn-northwest-1"]:
            self.awsPartition = "aws-cn"
        # If there is a desire to add support for multiple clouds, this would be
        # a great place to implement it.
        self.source = self.plugin_base.make_plugin_source(
            searchpath=[get_path(search_path)], identifier=self.name
        )

    def load_plugins(self, plugin_name=None):
        if plugin_name:
            try:
                plugin = self.source.load_plugin(plugin_name)
            except Exception as e:
                print(f"Failed to load plugin {plugin_name} with exception {e}")
        else:
            for plugin_name in self.source.list_plugins():
                try:
                    plugin = self.source.load_plugin(plugin_name)
                except Exception as e:
                    print(f"Failed to load plugin {plugin_name} with exception {e}")

    def get_regions(self, service):
        # Handle the weird v2 services names
        if service == 'kinesisanalyticsv2':
            service = 'kinesisanalytics'
        elif service == 'macie2':
            service = 'macie'
        else:
            service = service
        paginator = ssm.get_paginator("get_parameters_by_path")
        response_iterator = paginator.paginate(
            Path=f"/aws/service/global-infrastructure/services/{service}/regions",
            PaginationConfig={"MaxItems": 1000, "PageSize": 10},
        )
        results = accumulate_paged_results(
            page_iterator=response_iterator, key="Parameters")
        values = []
        for parameter in results["Parameters"]:
            values.append(parameter["Value"])
        return values

    def run_checks(self, requested_check_name=None, delay=0):
        # TODO: Add multi-region capabilities here
        '''
        regionList = []
        ec2regions = boto3.client("ec2")
        for regions in ec2regions.describe_regions()['Regions']:
            regionName = str(r['RegionName'])
                optInStatus = str(r['OptInStatus'])
                if optInStatus == 'not-opted-in':
                    pass
                else:
                    regionList.append(regionName)

        for region in regionList:
            ### TODO: Implement Below... ###
        '''
        for service_name, check_list in self.registry.checks.items():
            if self.awsRegion not in self.get_regions(service_name):
                print(f"AWS region {self.awsRegion} not supported for {service_name}")
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
                        # print(f"Executing check {self.name}.{check_name}")
                        for finding in check(
                            cache=auditor_cache,
                            awsAccountId=self.awsAccountId,
                            awsRegion=self.awsRegion,
                            awsPartition=self.awsPartition,
                        ):
                            yield finding
                    except Exception as e:
                        print(f"Failed to execute check {check_name} with exception {e}")
            sleep(delay)

    def print_checks_md(self):
        table = []
        table.append(
            "| Auditor File Name                      | AWS Service                   | Auditor Scan Description                                                               |"
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
                    f"|{inspect.getfile(check).rpartition('/')[2]} |{service_name} |{description}"
                )
        print("\n".join(table))