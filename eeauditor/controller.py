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
import click
from insights import create_sechub_insights
from eeauditor import EEAuditor
from processor.main import get_providers, process_findings

def print_checks(assessmentTarget, auditor_name=None):
    app = EEAuditor(assessmentTarget)

    app.load_plugins(plugin_name=auditor_name)
        
    app.print_checks_md()

def run_auditor(assessmentTarget, auditor_name=None, check_name=None, delay=0, outputs=None, output_file=""):
    if not outputs:
        # default to AWS SecHub even if somehow Click destination is stripped
        outputs = ["sechub"]
    
    app = EEAuditor(assessmentTarget)
    app.load_plugins(plugin_name=auditor_name)
    if assessmentTarget == "AWS":
        findings = list(app.run_aws_checks(requested_check_name=check_name, delay=delay))
    elif assessmentTarget == "GCP":
        findings = list(app.run_gcp_checks(requested_check_name=check_name, delay=delay))
    else:
        findings = list(app.run_non_aws_checks(requested_check_name=check_name, delay=delay))

    # This function writes the findings to Security Hub, or otherwise
    print(f"Done running Checks for {assessmentTarget}")
    process_findings(findings=findings, outputs=outputs, output_file=output_file)    

@click.command()
# Assessment Target
@click.option(
    "-t",
    "--target-provider",
    default="AWS",
    type=click.Choice(
        [
            'AWS',
            'GCP',
            'GitHub',
            'Servicenow'
        ],
        case_sensitive=True
    ),
    help="CSP or SaaS Vendor to perform assessments against and load specific plugins, ensure that any -a or -c arg maps to your target provider e.g., -t AWS -a Amazon_APGIW_Auditor"
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
    target_provider,
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
        sys.exit(0)

    if list_checks:
        print_checks(
            assessmentTarget=target_provider
        )
        sys.exit(0)

    if create_insights:
        create_sechub_insights()
        sys.exit(0)

    run_auditor(
        assessmentTarget=target_provider,
        auditor_name=auditor_name,
        check_name=check_name,
        delay=delay,
        outputs=outputs,
        output_file=output_file,
    )

if __name__ == "__main__":
    main(sys.argv[1:])