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
import yaml
from time import sleep

import boto3

from check_register import CheckRegister, accumulate_paged_results
from pluginbase import PluginBase

here = os.path.abspath(os.path.dirname(__file__))
get_path = partial(os.path.join, here)
ssm = boto3.client("ssm")

debug_log=False
auditorfiles_log=False
configfile_log=False


class EEAuditor(object):
    """ElectricEye controller

        This class manages loading auditor plugins and running checks
    """

    def __init__(self, name, search_path=None,debug_log=False,auditorfiles_log=False,configfile_log=False):
        if not search_path:
            search_path = "/eeauditor/auditors/aws"
        self.debug_log=debug_log
        self.auditorfiles_log=auditorfiles_log
        self.configfile_log=configfile_log

        #Auditor files
        if auditorfiles_log:
            print(f"Auditor search path:", search_path)
            auditfilecount = 0
            for r, d, f in os.walk(search_path):
                for file in f:
                    if '.py' in file: 
                        auditfilecount += 1
                        if auditorfiles_log:
                            print(f"Found Auditor file: {file}")
        if auditorfiles_log:
            print(f"Located {auditfilecount} audit files in {search_path}")

        #Config files
        self.config_file = ""
        if configfile_log:
            print(f"Configfile search path:", search_path)
            print(f"Note: first .yaml file located is chosen for Configfile")
            for r, d, f in os.walk(search_path):
                for file in f:
                    if '.yaml' in file: 
                        self.config_file = file
                        print(f"Found Configfile: {self.config_file}")
                        break
        if self.config_file:
                print(f"Located Configfile {self.config_file} in {search_path}. Checks and Resources will be scoped per this file.")
        else:
                print(f"No config file detected, will execute ALL Checks against ALL Resources.")
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
        # If there is a desire to add support for multiple clouds, this would be
        # a great place to implement it.
        self.source = self.plugin_base.make_plugin_source(
            searchpath=[get_path(search_path)], identifier=self.name
        )

    def load_plugins(self, plugin_name=None):
        if self.debug_log:
                print(f"eeauditor.py -> load_plugins method START")
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
        if self.debug_log:
                print(f"eeauditor.py -> load_plugins method END")

    def get_regions(self, service):
        paginator = ssm.get_paginator("get_parameters_by_path")
        response_iterator = paginator.paginate(
            Path=f"/aws/service/global-infrastructure/services/{service}/regions",
            PaginationConfig={"MaxItems": 1000, "PageSize": 10},
        )
        results = accumulate_paged_results(page_iterator=response_iterator, key="Parameters")
        values = []
        for parameter in results["Parameters"]:
            values.append(parameter["Value"])
        return values

    def run_checks(self, requested_check_name=None, delay=0):
        if self.debug_log:
                print(f"eeauditor.py -> run_checks method START")

        if self.auditorfiles_log:
            print(f"Listing Services found in Auditor files:")
            for service_name in self.registry.checks.items():
                print(f"{service_name}")

        #config file processing
        if self.config_file:
            #load our yaml config
            print(f"Parsing config_file: {self.config_file}")
            stream = open(f"/eeauditor/auditors/aws/{self.config_file}", 'r')
            dictionary = yaml.load(stream, Loader=yaml.FullLoader)

            #parse config file and pull checks
            for key, value in dictionary.items():
                if key == "checks":
                    check_filter = value
                    if self.configfile_log:
                        print(f"Checks from config file: {check_filter}")

            #parse checks and pull services 
            service_filter = set()
            for check in check_filter:
                service_filter.add(check.split(".")[0])
            if self.configfile_log:
                print(f"Services from config file checks: {service_filter}")                    

            #parse checks and detect wildcard checks
            for check in check_filter:
                if (check.split(".")[1] == "*"):
                    wildcard = check.split(".")[0]
                    if self.configfile_log:
                        print(f"Detected wildcard (*) on {wildcard} service, will run ALL checks for this service.")

        # iterate thru all audit services and execute
        for service_name, check_list in self.registry.checks.items():
            # either no config file or only use services in our service_filter
            if not(self.config_file) or service_name in service_filter:
                if self.configfile_log:
                    print(f"Executing checks in service {service_name}")
                if self.awsRegion not in self.get_regions(service_name):
                    print(f"AWS region {self.awsRegion} not supported for {service_name}")
                    next
                # a dictionary to be used by checks that are part of the same service
                auditor_cache = {}

                # either no config file or 
                # only use checks in our check_filter
                # or all checks if wildcard (*) is used
                for check_name, check in check_list.items():
                    if not(self.config_file) or f"{service_name}.*" in check_filter or f"{service_name}.{check_name}" in check_filter:
                        if self.configfile_log:
                            print(f"Executing check {service_name}.{check_name}")
                        # if a specific check is requested, only run that one check
                        if (
                            not requested_check_name
                            or requested_check_name
                            and requested_check_name == check_name
                        ):
                            try:
                                for finding in check(
                                    cache=auditor_cache,
                                    awsAccountId=self.awsAccountId,
                                    awsRegion=self.awsRegion,
                                    awsPartition=self.awsPartition,
                                ):
                                    yield finding
                            except Exception as e:
                                print(f"Failed to execute check {check_name} with exception {e}")
                    else: 
                        if self.configfile_log:
                            print(f"Skipping check {service_name}.{check_name} as it is missing from the check_filter.")
                sleep(delay)
            else:
                if self.configfile_log:
                    print(f"Skipping service {service_name} as it is missing from the service_filter.")
        if self.debug_log:
            print(f"eeauditor.py -> run_checks method END")

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
