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
import json
import os
import report
import boto3
from pluginbase import PluginBase
from check_register import CheckRegister

here = os.path.abspath(os.path.dirname(__file__))
get_path = partial(os.path.join, here)
ssm = boto3.client("ssm")


class EEAuditor(object):
    """ElectricEye controller

        Load and execute all auditor plugins.
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
                print(
                    f"Failed to load plugin {plugin_name} with exception {e}")
        else:
            for plugin_name in self.source.list_plugins():
                try:
                    plugin = self.source.load_plugin(plugin_name)
                except Exception as e:
                    print(
                        f"Failed to load plugin {plugin_name} with exception {e}")

    def get_regions(self, service):
        results = ssm.get_parameters_by_path(
            Path="/aws/service/global-infrastructure/services/" + service + "/regions",
        )
        parameters = results["Parameters"]
        while True:
            try:
                results = ssm.get_parameters_by_path(
                    Path="/aws/service/global-infrastructure/services/sqs/regions",
                    NextToken=results["NextToken"]
                )
                parameters += results["Parameters"]
            except:
                break
        values = []
        for parameter in parameters:
            values.append(parameter["Value"])
        return values

    def run_checks(self, requested_check_name=None):
        for cache_name, cache in self.registry.checks.items():
            if self.awsRegion not in self.get_regions(cache_name):
                print(f"AWS region not supported for {cache_name}")
                break
            # if self.awsRegion in ['us-gov-east-1', 'us-gov-west-1']:
            #     #TODO: make check run on govcloud
            # a dictionary to be used by checks that share a common cache
            auditor_cache = {}
            for check_name, check in cache.items():
                # if a specific check is requested, only run that one check
                if (
                    not requested_check_name
                    or requested_check_name
                    and requested_check_name == check_name
                ):
                    try:
                        print(f"Executing check {self.name}.{check_name}")
                        for finding in check(
                            cache=auditor_cache,
                            awsAccountId=self.awsAccountId,
                            awsRegion=self.awsRegion,
                        ):
                            yield finding
                    except Exception as e:
                        print(
                            f"Failed to execute check {check_name} with exception {e}")

    def run(self, sechub=True, output=False, check_name=None):
        # TODO: currently streaming all findings to a statically defined file on the file
        # system.  Should support a custom file name.
        # TODO: Consider removing this file after execution if the user doesn't ask to
        # persist the output as a json file.
        first = True
        json_out_location = ""
        with open("findings.json", "w") as json_out:
            print('{"Findings":[', file=json_out)
            json_out_location = os.path.abspath(json_out.name)
            for result in self.run_checks(requested_check_name=check_name):
                # print a comma separation between findings except before first finding
                if first:
                    first = False
                else:
                    print(",", file=json_out)
                json.dump(result, json_out, indent=2)
            print("]}", file=json_out)
        json_out.close()
        if sechub:
            securityhub = boto3.client("securityhub")
            with open(json_out_location) as read_json_findings:
                findings = json.load(read_json_findings)
                findings_list = Findings = findings["Findings"]
                print(f"Writing {len(findings_list)} results to SecurityHub")
                if findings_list:
                    securityhub.batch_import_findings(Findings=findings_list)
            read_json_findings.close()
        else:
            print("Not writing results to SecurityHub")
        if output:
            report.csv_output(input_file=json_out_location,
                              output_file=output_file)
        return json_out_location
