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

import sys
import boto3
import click
from insights import create_sechub_insights
from eeauditor import EEAuditor
from processor.main import get_providers, process_findings


def print_checks():
    app = EEAuditor(name="AWS Auditor")

    app.load_plugins()
    
    app.print_checks_md()

def run_auditor(session_override=None, region_override=None, auditor_name=None, check_name=None, delay=0, outputs=None, output_file=""):
    if not outputs:
        # default to AWS SecHub even if somehow Click destination is stripped
        outputs = ["sechub"]

    print(type(session_override))

    if not region_override:
        region_override = boto3.Session().region_name

    if session_override:
        session = boto3.Session(
            aws_access_key_id=session_override[0],
            aws_secret_access_key=session_override[1],
            aws_session_token=session_override[2],
            region_name=region_override
        )
    else:
        session = boto3.Session()

    app = EEAuditor(name="AWS Auditor", session=session, region=region_override)

    app.load_plugins(plugin_name=auditor_name)

    findings = list(app.run_checks(requested_check_name=check_name, delay=delay))

    # This function writes the findings to Security Hub, or otherwise
    process_findings(findings=findings, outputs=outputs, output_file=output_file)

    print("Done running Checks")

@click.command()
# Session Object Override
@click.option(
    "--session-override",
    default="",
    help="To use ElectricEye on other AWS Accounts provide a tuple of ('aws_access_key_id','aws_secret_access_key','aws_session_token') received from STS AssumeRole  - this can be used with --region-override"
)
@click.option(
    "--region-override",
    default="",
    help="To use ElectricEye in other Regions provide a region name (e.g., eu-central-1) - this can be used with --session-override"
)
# AWSCLI Profile
@click.option(
    "-p",
    "--profile-name",
    default="",
    help="User profile to use if set using AWS CLI. Defaults to no specification"
)
# Run Specific Auditor
@click.option(
    "-a",
    "--auditor-name",
    default="",
    help="Specify which Auditor you want to run by using its name NOT INCLUDING .py. Defaults to ALL Auditors"
)
# Run Specific Check
@click.option(
    "-c",
    "--check-name",
    default="",
    help="Specify which specific Check in a speciifc Auditor you want to run. Defaults to ALL Checks")
# Delay
@click.option(
    "-d", 
    "--delay", 
    default=0, 
    help="Time in seconds to sleep between Auditors being ran, defaults to 0"
)
# Outputs
@click.option(
    "-o",
    "--outputs",
    multiple=True,
    default=(["sechub"]),
    show_default=True,
    help="Where to send the findings to (another platform or to file)",
)
# Output File Name
@click.option(
    "--output-file",
    default="output", 
    show_default=True, 
    help="Name of the file for output, if using anything other than SecHub or Dops"
)
# List Output Options
@click.option(
    "--list-options",
    is_flag=True,
    help="Lists all valid Output options"
)
# List Checks
@click.option(
    "--list-checks",
    is_flag=True,
    help="List all Checks within every Auditor"
)
# Insights
@click.option(
    "--create-insights",
    is_flag=True,
    help="Create SecurityHub insights for ElectricEye.  This only needs to be done once per Security Hub instance",
)

def main(
    session_override,
    region_override,
    profile_name,
    auditor_name,
    check_name,
    delay,
    outputs,
    output_file,
    list_options,
    list_checks,
    create_insights,
):
    if list_options:
        print(get_providers())
        sys.exit(2)

    if list_checks:
        print_checks()
        sys.exit(2)

    if profile_name:
        boto3.setup_default_session(profile_name=profile_name)

    if create_insights:
        create_sechub_insights()
        sys.exit(2)

    run_auditor(
        session_override=session_override,
        region_override=region_override,
        auditor_name=auditor_name,
        check_name=check_name,
        delay=delay,
        outputs=outputs,
        output_file=output_file,
    )

if __name__ == "__main__":
    main(sys.argv[1:])