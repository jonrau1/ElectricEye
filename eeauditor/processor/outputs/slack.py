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

import boto3
import tomli
import os
import sys
import datetime
import json
import requests
from time import sleep
from botocore.exceptions import ClientError
from processor.outputs.output_base import ElectricEyeOutput

# Boto3 Clients
ssm = boto3.client("ssm")
asm = boto3.client("secretsmanager")

# These Constants define legitimate values for certain parameters within the external_providers.toml file
CREDENTIALS_LOCATION_CHOICES = ["AWS_SSM", "AWS_SECRETS_MANAGER", "CONFIG_FILE"]

@ElectricEyeOutput
class PostgresProvider(object):
    __provider__ = "slack"

    def __init__(self):
        print("Preparing Slack credentials.")

        # Get the absolute path of the current directory
        currentDir = os.path.abspath(os.path.dirname(__file__))
        # Go two directories back to /eeauditor/
        twoBack = os.path.abspath(os.path.join(currentDir, "../../"))

        # TOML is located in /eeauditor/ directory
        tomlFile = f"{twoBack}/external_providers.toml"
        with open(tomlFile, "rb") as f:
            data = tomli.load(f)

        # Parse from [global] to determine credential location of PostgreSQL Password
        if data["global"]["credentials_location"] not in CREDENTIALS_LOCATION_CHOICES:
            print(f"Invalid option for [global.credentials_location]. Must be one of {str(CREDENTIALS_LOCATION_CHOICES)}.")
            sys.exit(2)
        self.credentialsLocation = data["global"]["credentials_location"]

        # Variable for the entire [outputs.slack] section
        slackDetails = data["outputs"]["slack"]

        # Parse non-sensitive values
        channelId = slackDetails["slack_channel_identifier"]
        messageType = slackDetails["electric_eye_slack_message_type"]
        severityFilter = slackDetails["electric_eye_slack_severity_filter"]
        stateFilter = slackDetails["electric_eye_slack_finding_state_filter"]

        # Parse Bot Token
        if self.credentialsLocation == "CONFIG_FILE":
            slackBotToken = slackDetails["slack_app_bot_token_value"]
        elif self.credentialsLocation == "AWS_SSM":
            slackBotToken = self.get_credential_from_aws_ssm(
                slackDetails["slack_app_bot_token_value"],
                "slack_app_bot_token_value"
            )
        elif self.credentialsLocation == "AWS_SECRETS_MANAGER":
            slackBotToken = self.get_credential_from_aws_secrets_manager(
                slackDetails["slack_app_bot_token_value"],
                "slack_app_bot_token_value"
            )

        # Ensure that values are provided for all variable - use all() and a list comprehension to check the vars
        # empty strings will trigger `if not`
        if not all(s for s in [channelId, messageType, severityFilter, stateFilter, slackBotToken]):
            print("An empty value was detected in '[outputs.slack]'. Review the TOML file and try again!")
            sys.exit(2)

        # Set them motherfuckin vars to the motherfuckin self, word to your moms
        self.channelId = channelId
        self.messageType = messageType
        self.severityFilter = severityFilter
        self.stateFilter = stateFilter
        self.slackBotToken = slackBotToken

    def write_findings(self, findings: list, **kwargs):
        if len(findings) == 0:
            print("There are not any findings to write!")
            exit(0)

        # Call another method depending on whether or not the user configured the TOML for Summary or per-Finding
        if self.messageType == "Findings":
            processedBlocks = self.create_findings_blocks_payload(findings)
            del findings

            # Send the findings to Slack
            for blocks in processedBlocks:
                # Token & Channel must be with "blocks" in the POST Args
                slackPayload = {
                    'token': self.slackBotToken,
                    'channel': self.channelId,
                    'blocks': json.dumps(blocks)
                }
                # Send request and backoff if throttled
                r = requests.post('https://slack.com/api/chat.postMessage', slackPayload)
                if r.status_code == 429:
                    retry = r.headers["retry-after"]
                    print(f"Slack Bot is being throttled, retrying in {retry} second(s).")

                    backoff = int(retry) + 0.25
                    sleep(backoff)
            
            print(f"Finished sending Findings to Slack!")

        elif self.messageType == "Summary":
            summaryBlock = self.create_summary_blocks_payload(findings)
            del findings

            # Token & Channel must be with "blocks" in the POST Args
            slackPayload = {
                'token': self.slackBotToken,
                'channel': self.channelId,
                'blocks': json.dumps(summaryBlock)
            }
            # Send request and backoff if throttled
            r = requests.post('https://slack.com/api/chat.postMessage', slackPayload)

            print(f"Finished sending Summary to Slack!")
        else:
            print(f"Unsupported value for [outputs.slack][electric_eye_slack_message_type]")
            sys.exit(2)

    def get_credential_from_aws_ssm(self, value, configurationName):
        """
        Retrieves a TOML variable from AWS Systems Manager Parameter Store and returns it
        """

        # Check that a value was provided
        if value == (None or ""):
            print(f"A value for {configurationName} was not provided. Fix the TOML file and run ElectricEye again.")
            sys.exit(2)

        # Retrieve the credential from SSM Parameter Store
        try:
            credential = ssm.get_parameter(
                Name=value,
                WithDecryption=True
            )["Parameter"]["Value"]
        except ClientError as e:
            raise e
        
        return credential
    
    def get_credential_from_aws_secrets_manager(self, value, configurationName):
        """
        Retrieves a TOML variable from AWS Secrets Manager and returns it
        """

        # Check that a value was provided
        if value == (None or ""):
            print(f"A value for {configurationName} was not provided. Fix the TOML file and run ElectricEye again.")
            sys.exit(2)

        # Retrieve the credential from AWS Secrets Manager
        try:
            credential = asm.get_secret_value(
                SecretId=value,
            )["SecretString"]
        except ClientError as e:
            raise e
        
        return credential

    def create_summary_blocks_payload(self, findings):
        """
        This function receives ElectricEye findings and returns a "chat.postMessage" Block of a summarization
        """

        print(f"Creating Summary report of {len(findings)} to send to slack")

        # Total
        totalFindings = len(findings)
        # Compliance Passed v Failed
        totalPassed = [finding for finding in findings if finding["Compliance"]["Status"] == "PASSED"]
        totalFailed = [finding for finding in findings if finding["Compliance"]["Status"]== "FAILED"]
        totalFailedCount = len(totalFailed)
        failingPercentage = (totalFailedCount / totalFindings) * 100
        roundedPercentage = f"{round(failingPercentage, 2)}%"
        # Severity Status
        criticalFindings = [finding for finding in findings if finding["Severity"]["Label"] == "CRITICAL"]
        highFindings = [finding for finding in findings if finding["Severity"]["Label"] == "HIGH"]
        mediumFindings = [finding for finding in findings if finding["Severity"]["Label"] == "MEDIUM"]
        lowFindings = [finding for finding in findings if finding["Severity"]["Label"] == "LOW"]
        infoFindings = [finding for finding in findings if finding["Severity"]["Label"] == "INFORMATIONAL"]
        # Resource IDs
        uniqueResources = []
        allResources = [d.get("Resources").get([0]).get("Id") for d in findings]
        for resource in allResources:
            if resource not in uniqueResources:
                uniqueResources.append(resource)
        # Assets
        uniqueClass = list(set(d.get("AssetClass") for d in findings))
        #allServices = [d.get("AssetService") for d in findings]
        uniqueServices = list(set(d.get("AssetService") for d in findings))
        #allComponents = [d.get("AssetComponent") for d in findings]
        uniqueComponents = list(set(d.get("AssetComponent") for d in findings))
        # Accounts
        uniqueAccounts = list(set(d.get("ProviderAccountId") for d in findings))
        # Regions
        uniqueRegions = list(set(d.get("AssetRegion") for d in findings))

        date = datetime.datetime.now()

        block = [
            # Header
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f":notebook_with_decorative_cover: New ElectricEye Summary as of {str(date)} :notebook_with_decorative_cover:"
                }
            },
            # Finding Counts & Pass Fail Percentage
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Total Findings:* `{totalFindings}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Passing Findings:* `{len(totalPassed)}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Failing Findings:* `{totalFailedCount}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*ElectricEye Audit Readiness \n Failing Percentage:* `{roundedPercentage}`"
                    }
                ]
            },
            # Finding Breakdowns by Severity + Total Resources
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Total Assets:* `{len(allResources)}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Critical Severity Total:* `{len(criticalFindings)}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*High Severity Total:* `{len(highFindings)}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Medium Severity Total:* `{len(mediumFindings)}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Low Severity Total:* `{len(lowFindings)}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Informational Severity Total:* `{len(infoFindings)}`"
                    }
                ]
            },
            # Unique Asset & Provider Totals
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Unique Assets:* `{len(uniqueResource)}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Unique Asset Class:* `{len(uniqueClass)}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Unique Asset Services:* `{len(uniqueServices)}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Unique Asset Components:* `{len(uniqueComponents)}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Total Accounts:* `{len(uniqueAccounts)}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Total Regions:* `{len(uniqueRegions)}`"
                    }
                ]
            }
        ]
        
        return block

    def create_findings_blocks_payload(self, findings):
        """
        This function receives ElectricEye findings and returns a list of "chat.postMessage" Blocks that match
        filtration (e.g., "Critical only" or "Active findings only")
        """

        # Slack chat.PostMessage API expects "blocks" of Markdown, Overflow, or other sorts of output
        # we will parse the findings for what we need, and craft these "blocks" which are lists and append
        # them over here...like, no shit
        aBlockyListOfSlackBlocks = []

        print(f"Processing {len(findings)} findings to send to Slack.")

        # Pull forward the filters to ensure we only parse what we need
        severityFilter = self.severityFilter
        stateFilter = self.stateFilter

        for finding in findings:
            # Check if the Severity & Record State matches
            severity = finding["Severity"]["Label"]
            findingState = finding["RecordState"]
            if severity not in severityFilter:
                continue
            if findingState not in stateFilter:
                continue

            # Maps to header:title
            headerSeverity = severity.lower().capitalize()

            # Finding Details Vars
            title = finding["Title"]
            description = finding["Description"]
            remediationText = finding["Remediation"]["Recommendation"]["Text"]
            remediationUrl = finding["Remediation"]["Recommendation"]["Url"]

            # Provider Section Vars
            provider = finding["ProductFields"]["Provider"]
            # This will transform the text written in the Block field going to Slack based on what it is
            if provider == "AWS":
                providerMarkdownText = "AWS Account ID"
            elif provider == "GCP":
                providerMarkdownText = "Google Cloud Project ID"
            elif provider == "OCI":
                providerMarkdownText = "Oracle Cloud Infrastructure Tenancy"
            elif provider == "Servicenow":
                providerMarkdownText = "ServiceNow Instance"
            providerAccountId = finding["ProductFields"]["ProviderAccountId"]
            providerType = finding["ProductFields"]["ProviderType"]
            assetRegion = finding["ProductFields"]["AssetRegion"]

            # Asset Section Vars
            resourceId = finding["Resources"][0]["Id"]
            assetClass = finding["ProductFields"]["AssetClass"]
            assetService = finding["ProductFields"]["AssetService"]
            assetComponent = finding["ProductFields"]["AssetComponent"]
            
            # Workflow/Compliance Vars
            createdAt = finding["CreatedAt"]
            #severity = finding["Severity"]["Label"]
            #findingState = finding["RecordState"]
            relatedControls = ""
            for control in finding["Compliance"]["RelatedRequirements"]:
                relatedControls += f"`{control}` \n "

            block = [
                # Header
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f":warning: New {headerSeverity} Severity ElectricEye Finding :warning:"
                    }
                },
                # Finding Details (Title, Description, Remediations, CreatedAt)
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Check:* `{title}`"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Description:* `{description}`"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Remediation Instructions:* `{remediationText}`"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Remediation URL:* `{remediationUrl}`"
                        }
                    ]
                },
                # Providers Section
                {
                    "type": "section",
                    "fields": [
                        # Provider
                        {
                            "type": "mrkdwn",
                            "text": f"*Provider:* `{provider}`" 
                        },
                        # Provider Type
                        {
                            "type": "mrkdwn",
                            "text": f"*Provider Type:* `{providerType}`" 
                        },
                        # Provider Account ID
                        {
                            "type": "mrkdwn",
                            "text": f"*{providerMarkdownText}:* `{providerAccountId}`"
                        },
                        # Region
                        {
                            "type": "mrkdwn",
                            "text": f"*Region:* `{assetRegion}`"
                        }
                    ]
                },
                # Asset Section
                {
                    "type": "section",
                    "fields": [
                        # Resource ID
                        {
                            "type": "mrkdwn",
                            "text": f"*Asset GUID:* `{resourceId}`"
                        },
                        # Asset Class
                        {
                            "type": "mrkdwn",
                            "text": f"*Asset Class:* `{assetClass}`" 
                        },
                        # Asset Service
                        {
                            "type": "mrkdwn",
                            "text": f"*Asset Service:* `{assetService}`"
                        },
                        # Asset Type
                        {
                            "type": "mrkdwn",
                            "text": f"*Asset Component:* `{assetComponent}`"
                        }
                    ]
                },
                # Workflow, Severity and Compliance Section
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Created At:* `{createdAt}`"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Severity:* `{severity}`"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Finding State:* `{findingState}`"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Related Controls:* {relatedControls}"
                        }
                    ]
                }
            ]

            aBlockyListOfSlackBlocks.append(block)
   
        print(f"Processed {len(aBlockyListOfSlackBlocks)} findings after filters to send to Slack.")

        return aBlockyListOfSlackBlocks

## EOF