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
import tomli
import json
import os
from insights import create_sechub_insights
from eeauditor import EEAuditor
from processor.main import get_providers, process_findings

here = os.path.abspath(os.path.dirname(__file__))

def read_toml():
    with open(f"{here}/external_providers.toml", "rb") as f:
        data = tomli.load(f)

    return data

def setup_aws_credentials(assume_role_account=None, assume_role_name=None, region_override=None):
    """
    For AWS-specific provider
    """

    if not region_override:
        region_override = boto3.Session().region_name

    if assume_role_account and assume_role_name:
        sts = boto3.client("sts")
        crossAccountRoleArn = f"arn:aws:iam::{assume_role_account}:role/{assume_role_name}"
        memberAcct = sts.assume_role(
            RoleArn=crossAccountRoleArn,
            RoleSessionName="ElectricEye"
        )

        session = boto3.Session(
            aws_access_key_id=memberAcct["Credentials"]["AccessKeyId"],
            aws_secret_access_key=memberAcct["Credentials"]["SecretAccessKey"],
            aws_session_token=memberAcct["Credentials"]["SessionToken"],
            region_name=region_override
        )
    else:
        session = boto3.Session()

    return session, region_override

def setup_azure_credentials():
    """
    For Azure...TODO: Implement
    """

    return {}

def setup_gcp_credentials():
    """
    Google Cloud Platform's (GCP's) simplest identity primitive is a Service Account (SA). SA's are given roles for a specific Project (or Folder/Org) and can
    save the credentials into a JSON file where it is picked up by gcloud. The entire JSON payload can be stored in AWS SSM Parameter Store as a SecureString and loaded
    into memory dynamically within a container so it's safer.

    In external_providers.toml specify the name of the SSM SecureString Parameter in `gcp_service_account_json_payload_parameter_name = ""` under [gcp]
    """

    ssm = boto3.client("ssm")

    # GCP only needs the JSON Document
    gcpCredLocation = read_toml()["gcp"]["gcp_service_account_json_payload_parameter_name"]

    if gcpCredLocation == (None or ""):
        print("GCP Credential SSM Parameter not provided!")
        sys.exit(2)

    gcpCreds = ssm.get_parameter(Name=gcpCredLocation, WithDecryption=True)["Parameter"]["Value"]

    # Write the creds locally
    with open("./gcp_cred.json", 'w') as jsonfile:
        json.dump(json.loads(gcpCreds), jsonfile, indent=2)

    # Set Cred global path
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = "./gcp_cred.json"

    return True

def setup_github_credentials():
    """
    Retrieves a Personal Access Token (PAT) from a SSM
    """

    return {}

def print_checks(gcp_project_id=None, target_provider=None, assume_role_account=None, assume_role_name=None, region_override=None):
    if target_provider == "AWS":
        awsCreds = setup_aws_credentials(assume_role_account, assume_role_name, region_override)

        app = EEAuditor(target_provider, awsCreds[0], awsCreds[1], gcp_project_id=None)

        app.load_plugins()
        
        app.print_checks_md()
    elif target_provider == "GitHub":
        github_creds = setup_github_credentials()

        # TODO: EXPAND TO INCLUDE THE VALUES
        app = EEAuditor(target_provider, session=None, region=None)

        app.load_plugins()
        
        app.print_checks_md()
    elif target_provider == "GCP":
        # Save these locally
        setup_gcp_credentials()

        app = EEAuditor(target_provider, session=None, region=None, gcp_project_id=gcp_project_id)

        app.load_plugins()
        
        app.print_checks_md()

def run_auditor(gcp_project_id, target_provider, assume_role_account=None, assume_role_name=None, region_override=None, auditor_name=None, check_name=None, delay=0, outputs=None, output_file=""):
    if not outputs:
        # default to AWS SecHub even if somehow Click destination is stripped
        outputs = ["sechub"]
        

    if target_provider == "AWS":
        awsCreds = setup_aws_credentials(assume_role_account, assume_role_name, region_override)

        app = EEAuditor(target_provider=target_provider, session=awsCreds[0], region=awsCreds[1], gcp_project_id=None)

        app.load_plugins(plugin_name=auditor_name)

        findings = list(app.run_aws_checks(requested_check_name=check_name, delay=delay))

        # This function writes the findings to Security Hub, or otherwise
        process_findings(findings=findings, outputs=outputs, output_file=output_file)
    elif target_provider == "GCP":
        setup_gcp_credentials()

        app = EEAuditor(target_provider=target_provider, session=None, region=None, gcp_project_id=gcp_project_id)

        app.load_plugins(plugin_name=auditor_name)

        findings = list(app.run_gcp_checks(requested_check_name=check_name, delay=delay))

        # This function writes the findings to Security Hub, or otherwise
        process_findings(findings=findings, outputs=outputs, output_file=output_file)

    print("Done running Checks")

@click.command()
# GCP Project
@click.option(
    "--gcp-project-id",
    default="",
    help="GCP Project ID for when --target-provider is set to GCP. Must match the Service Account JSON stored in SSM Parameter Store mentioned in external_providers.toml"
)
# Assessment Target
@click.option(
    "-t",
    "--target-provider",
    default="AWS",
    help="CSP or SaaS Vendor to perform assessments against and load specific plugins, ensure that any -a or -c arg maps to your target provider e.g., -t AWS -a Amazon_APGIW_Auditor"
)
# Remote Account Options
@click.option(
    "--assume-role-account",
    default="",
    help="AWS Account ID of an Account to attempt to assume the role supplied by --assume-role-name"
)
@click.option(
    "--assume-role-name",
    default="",
    help="Name of an AWS IAM Role in another Account supplied by --assume-role-account that trusts the current Account "
)
# Region Override
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
    gcp_project_id,
    target_provider,
    assume_role_account,
    assume_role_name,
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
        print_checks(
            gcp_project_id,
            target_provider,
            assume_role_account=assume_role_account,
            assume_role_name=assume_role_name,
            region_override=region_override
        )
        sys.exit(2)

    if profile_name:
        boto3.setup_default_session(profile_name=profile_name)

    if create_insights:
        create_sechub_insights()
        sys.exit(2)

    run_auditor(
        gcp_project_id=gcp_project_id,
        target_provider=target_provider,
        assume_role_account=assume_role_account,
        assume_role_name=assume_role_name,
        region_override=region_override,
        auditor_name=auditor_name,
        check_name=check_name,
        delay=delay,
        outputs=outputs,
        output_file=output_file,
    )

if __name__ == "__main__":
    main(sys.argv[1:])