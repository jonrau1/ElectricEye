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
import getopt
import json
import os
import report
import sys
import boto3
from pluginbase import PluginBase
from check_register import CheckRegister


sts = boto3.client("sts")

here = os.path.abspath(os.path.dirname(__file__))
get_path = partial(os.path.join, here)


class EEAuditor(object):
    """ElectricEye controller
    
        Load and execute all auditor plugins.
    """

    def __init__(self, name):
        self.name = name
        self.plugin_base = PluginBase(package="electriceye")
        # each check must be decorated with the @registry.register_check("cache_name")
        # to be discovered during plugin loading.
        self.registry = CheckRegister()
        # vendor specific credentials dictionary
        self.awsAccountId = sts.get_caller_identity()["Account"]
        self.awsRegion = os.environ["AWS_REGION"]
        # If there is a desire to add support for multiple clouds, this would be
        # a great place to implement it.
        self.source = self.plugin_base.make_plugin_source(
            searchpath=[get_path("./auditors/aws")], identifier=self.name
        )

    def load_plugins(self, plugin_name):
        if plugin_name:
            try:
                plugin = self.source.load_plugin(plugin_name)
                plugin.setup(self)
            except Exception as e:
                print(f"Failed to load plugin {plugin_name} with exception {e}")
        else:
            for plugin_name in self.source.list_plugins():
                try:
                    plugin = self.source.load_plugin(plugin_name)
                except Exception as e:
                    print(f"Failed to load plugin {plugin_name} with exception {e}")

    def run_checks(self, requested_check_name):
        for cache_name, cache in self.registry.checks.items():
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
                        print(f"Failed to execute check {check_name} with exception {e}")


def main(argv):
    findings_list = []  # used if --output is specified
    profile_name = ""
    auditor_name = ""
    check_name = ""
    output = False
    output_file = ""
    help_text = (
        "auditor.py [-p <profile_name> -a <auditor_name> -c <check_name> -o <output_file_name>]"
    )
    try:
        opts, args = getopt.getopt(
            argv, "ho:p:a:c:", ["help", "output=", "profile=", "auditor=", "check="]
        )
    except getopt.GetoptError:
        print(help_text)
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print(help_text)
            sys.exit(2)
        if opt in ("-o", "--output"):
            output = True
            output_file = arg
        if opt in ("-p", "--profile"):
            profile_name = arg.strip()
        if opt in ("-a", "--auditor"):
            auditor_name = arg
        if opt in ("-c", "--check"):
            check_name = arg
    if profile_name:
        boto3.setup_default_session(profile_name=profile_name)

    app = EEAuditor(name="AWS Auditor")
    app.load_plugins(plugin_name=auditor_name)
    first = True
    file_location = ""
    with open("findings.json", "w") as f:
        print('{"Findings":[', file=f)
        file_location = os.path.abspath(f.name)
        for result in app.run_checks(requested_check_name=check_name):
            # print a comma separation between findings except before first finding
            if first:
                first = False
            else:
                print(",", file=f)
            json.dump(result, f, indent=2)
        print("]}", file=f)
    f.close()
    securityhub = boto3.client("securityhub")
    with open(file_location) as f:
        findings = json.load(f)
        securityhub.batch_import_findings(Findings=findings["Findings"])
    f.close()
    if output:
        report.csv_output(input_file=file_location, output_file=output_file)
    print("Done")


if __name__ == "__main__":
    # this is for local testing where the AWS_REGION is not liekly set
    if not os.environ.get("AWS_REGION", None):
        os.environ["AWS_REGION"] = "us-east-1"
    main(sys.argv[1:])
