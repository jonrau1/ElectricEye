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

import csv
import json
import getopt
import importlib
import os
import sys
import boto3
from time import sleep
from functools import reduce
from auditors.Auditor import Auditor, AuditorCollection


# Return nested dictionary values by passing in dictionary and keys separated by "."
def deep_get(dictionary, keys):
    return reduce(
        lambda d, key: d.get(key) if isinstance(d, dict) else None,
        keys.split("."),
        dictionary,
    )


def csv_output(output_file, findings):
    csv_columns = [
        {"name": "Id", "path": "Id"},
        {"name": "Title", "path": "Title"},
        {"name": "ProductArn", "path": "ProductArn"},
        {"name": "AwsAccountId", "path": "AwsAccountId"},
        {"name": "Severity", "path": "Severity.Label"},
        {"name": "Confidence", "path": "Confidence"},
        {"name": "Description", "path": "Description"},
        {"name": "RecordState", "path": "RecordState"},
        {"name": "Compliance Status", "path": "Compliance.Status"},
        {
            "name": "Remediation Recommendation",
            "path": "Remediation.Recommendation.Text",
        },
        {
            "name": "Remediation Recommendation Link",
            "path": "Remediation.Recommendation.Url",
        },
    ]
    csv_file = output_file
    try:
        with open(csv_file, "w") as csvfile:
            writer = csv.writer(csvfile, dialect="excel")
            writer.writerow(item["name"] for item in csv_columns)
            for finding in findings:
                row_data = []
                for column_dict in csv_columns:
                    row_data.append(deep_get(finding, column_dict["path"]))
                writer.writerow(row_data)
    except IOError:
        print("I/O error")


def main(argv):
    findings_list = []  # used if --output is specified
    profile_name = ""
    auditor_name = ""
    check_name = ""
    output = False
    output_file = ""
    help_text = "audit_controller.py [-p <profile_name> -a <auditor_name> -c <check_name> -o <output_file_name>]"
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
                if "auditors." + auditor_name != plugin.get("auditor"):
                    continue
            check = plugin.get("check")
            # if user specifies a specific check on CLI, skip all other checks
            if check_name:
                if check.name != check_name:
                    continue
            print(f"Executing check: {check.name}")
            for finding in check.execute():
                # It would be possible to collect these findings and batch them up before sending.
                # This current implementation has the advantage of a small memory footprint, but
                # could be a slight performance improvement to batch and make one securityhub
                # call per check.
                response = securityhub.batch_import_findings(Findings=[finding])
                # if -o arg, add finding to findings list to be used to generate csv output
                if output:
                    findings_list.append(finding)
            sleep(0.5)  # a hack to avoid api limit by sleeping between checks
        except Exception as e:
            print(f"Error running plugin {plugin.get('check').name} with exception {e}")
    if output:
        print(f"Writing {len(findings_list)} findings to {output_file}")
        csv_output(output_file, findings_list)

    print("Done")


if __name__ == "__main__":
    # this is for local testing where the AWS_REGION is not liekly set
    if not os.environ.get("AWS_REGION", None):
        os.environ["AWS_REGION"] = "us-east-1"
    main(sys.argv[1:])
