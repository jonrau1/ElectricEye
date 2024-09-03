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
from eeauditor import EEAuditor
from processor.main import get_providers, process_findings
from os import environ

def print_controls(assessmentTarget, args, useToml, auditorName=None, tomlPath=None):
    app = EEAuditor(assessmentTarget, args, useToml, tomlPath)

    app.load_plugins(auditorName)
        
    app.print_controls_json()

def print_checks(assessmentTarget, args, useToml, auditorName=None, tomlPath=None):
    app = EEAuditor(assessmentTarget, args, useToml, tomlPath)

    app.load_plugins(auditorName)
        
    app.print_checks_md()

def run_auditor(assessmentTarget, args, useToml, auditorName=None, pluginName=None, delay=0, outputs=None, outputFile="", tomlPath=None):
    if not outputs:
        outputs = ["stdout"]
    
    app = EEAuditor(assessmentTarget, args, useToml, tomlPath)

    app.load_plugins(auditorName)
    # Per-target calls - ensure you use the right run_*_checks*() function
    
    # Amazon Web Services
    if assessmentTarget == "AWS":
        findings = list(app.run_aws_checks(pluginName=pluginName, delay=delay))
    # Google Cloud Platform
    if assessmentTarget == "GCP":
        findings = list(app.run_gcp_checks(pluginName=pluginName, delay=delay))
    # Oracle Cloud Infrastructure
    if assessmentTarget == "OCI":
        findings = list(app.run_oci_checks(pluginName=pluginName, delay=delay))
    # Microsoft Azure
    if assessmentTarget == "Azure":
        findings = list(app.run_azure_checks(pluginName=pluginName, delay=delay))
    # Microsoft 365
    if assessmentTarget == "M365":
        findings = list(app.run_m365_checks(pluginName=pluginName, delay=delay))
    # Salesforce
    if assessmentTarget == "Salesforce":
        findings = list(app.run_salesforce_checks(pluginName=pluginName, delay=delay))
    # Snowflake
    if assessmentTarget == "Snowflake":
        findings = list(app.run_snowflake_checks(pluginName=pluginName, delay=delay))
    # ServiceNow
    if assessmentTarget == "ServiceNow":
        findings = list(app.run_non_aws_checks(pluginName=pluginName, delay=delay))

    print(f"Done running Checks for {assessmentTarget}")

    if tomlPath is None:
        environ["TOML_FILE_PATH"] = "None"
    else:
        environ["TOML_FILE_PATH"] = tomlPath
    
    # Multiple outputs supported
    process_findings(
        findings=findings,
        outputs=outputs,
        output_file=outputFile
    )

@click.command()
# Assessment Target
@click.option(
    "-t",
    "--target-provider",
    default="AWS",
    type=click.Choice(
        [
            "AWS",
            "Azure",
            "OCI",
            "GCP",
            "Servicenow",
            "M365",
            "Salesforce",
            "Snowflake"
        ],
        case_sensitive=True
    ),
    help="Public cloud or SaaS assessment target, ensure that any -a or -c arg maps to your target provider to avoid any errors. e.g., -t AWS -a Amazon_APGIW_Auditor"
)
# Run Specific Auditor
@click.option(
    "-a",
    "--auditor-name",
    default="",
    help="Specify which Auditor you want to run by using its name NOT INCLUDING .py. . Use the --list-checks arg to receive a list. Defaults to ALL Auditors"
)
# Run Specific Check
@click.option(
    "-c",
    "--check-name",
    default="",
    help="A specific Check in a specific Auditor you want to run, this correlates to the function name. Use the --list-checks arg to receive a list. Defaults to ALL Checks")
# Delay
@click.option(
    "-d", 
    "--delay", 
    default=0, 
    help="Time in seconds to sleep between Auditors being ran, defaults to 0. Use this argument to avoid rate limiting"
)
# Outputs
@click.option(
    "-o",
    "--outputs",
    multiple=True,
    default=(["ocsf_stdout"]),
    show_default=True,
    help="A list of Outputs (files, APIs, databases, ChatOps) to send ElectricEye Findings, specify multiple with additional arguments: -o csv -o postgresql -o slack",
)
# Output File Name
@click.option(
    "-of",
    "--output-file",
    default="output", 
    show_default=True, 
    help="For file outputs such as JSON and CSV, the name of the file, DO NOT SPECIFY .file_type"
)
# List Output Options
@click.option(
    "-lo",
    "--list-options",
    is_flag=True,
    help="Lists all valid Output options"
)
# List Checks
@click.option(
    "-lch",
    "--list-checks",
    is_flag=True,
    help="Prints a table of Auditors, Checks, and Check descriptions to stdout - use this command for help with populating -a (Auditor selection) or -c (Check selection) args"
)
# Controls (Description)
@click.option(
    "-lco",
    "--list-controls",
    is_flag=True,
    help="Lists all ElectricEye controls - that is to say: the Check Titles - for an Assessment Target"
)
# TOML Path
@click.option(
    "-tp",
    "--toml-path",
    default=None,
    help="The full path to the TOML file used for configure e.g., ~/path/to/mydir/external_providers.toml. If this value is not provided the default path of ElectricEye/eeauditor/external_providers.toml is used."
)
# Use TOML
@click.option(
    "-ut",
    "--use-toml",
    default="True",
    type=click.Choice(
        [
            "True",
            "False"
        ],
        case_sensitive=True
    ),
    help="Set to False to disable the use of the TOML file for external providers, defaults to True. THIS IS AN EXPERIMENTAL FEATURE!"
)
# EXPERIMENTAL: Supply arguments in a stringified dictionary format
@click.option(
    "--args",
    default=None,
    help="Supply arguments in a stringified dictionary format, e.g., '{\"credentials_location\": \"CONFIG_FILE\", \"snowflake_username\": \"ELECTRIC_EYE\"}'. THIS IS AN EXPERIMENTAL FEATURE!"
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
    list_controls,
    toml_path,
    use_toml,
    args
):
    if list_controls:
        print_controls(
            assessmentTarget=target_provider,
            args=args,
            tomlPath=toml_path,
            useToml=use_toml,
        )
        sys.exit(0)

    if list_options:
        print(
            sorted(
                get_providers()
            )
        )
        sys.exit(0)

    if list_checks:
        print_checks(
            assessmentTarget=target_provider,
            args=args,
            tomlPath=toml_path,
            useToml=use_toml,
        )
        sys.exit(0)

    run_auditor(
        assessmentTarget=target_provider,
        args=args,
        auditorName=auditor_name,
        pluginName=check_name,
        delay=delay,
        outputs=outputs,
        outputFile=output_file,
        tomlPath=toml_path,
        useToml=use_toml
    )

if __name__ == "__main__":
    main(sys.argv[1:])

# EOF