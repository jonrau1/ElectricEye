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

import json
import getopt
import importlib
import os
import sys
import boto3
from time import sleep
from auditors.Auditor import Auditor, AuditorCollection


def main(argv):
    profile_name = ""
    auditor_name = ""
    check_name = ""
    output = False
    try:
        opts, args = getopt.getopt(argv, "op:a:c:", ["output", "profile=", "auditor=", "check="])
    except getopt.GetoptError:
        print("audit_controller.py [-p <profile_name> -a <auditor_name> -c <check_name>]")
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-o", "--output"):
            output = True
        if opt in ("-p", "--profile"):
            profile_name = arg
        if opt in ("-a", "--auditor"):
            auditor_name = arg
        if opt in ("-c", "--check"):
            check_name = arg
    if profile_name:
        boto3.setup_default_session(profile_name=profile_name)

    # load all Auditor plugins in the "auditors" directory
    auditors = AuditorCollection("auditors")
    securityhub = boto3.client("securityhub")

    for plugin in auditors.plugins:
        try:
            # if user specifies a specific auditor on CLI, skip all other auditors
            if auditor_name:
                if "auditors." + auditor_name != plugin.get("auditors"):
                    continue
            check = plugin.get("check")
            # if user specifies a specific check on CLI, skip all other checks
            if check_name:
                if check.name != check_name:
                    continue
            print(f"Executing auditor: {check.name}")
            for finding in check.execute():
                # it would be possible to collect these fidnings a batch them up before sending.
                # this has the advantage of small memory footprint, but could be a slight
                # performance improvement to batch and make one securityhub call per check.
                response = securityhub.batch_import_findings(Findings=[finding])
                # if -o arg, print active findings to stdout
                if output and finding["RecordState"] == "ACTIVE":
                    print(json.dumps(finding, indent=2))
            sleep(0.5)  # a hack to avoid api limit by sleeping between checks
        except Exception as e:
            print(f"Error running plugin {plugin.get('check').name} with exception {e}")


if __name__ == "__main__":
    # this is for local testing where the AWS_REGION is not liekly set
    if not os.environ.get("AWS_REGION", None):
        os.environ["AWS_REGION"] = "us-east-1"
    main(sys.argv[1:])
