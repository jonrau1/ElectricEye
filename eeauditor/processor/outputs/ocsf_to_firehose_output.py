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

import logging
import tomli
import boto3
import sys
from typing import NamedTuple
from os import path, environ
from processor.outputs.output_base import ElectricEyeOutput
import json
from base64 import b64decode
from datetime import datetime
from botocore.exceptions import ClientError

logger = logging.getLogger("OCSF_to_KDF_Output")

# NOTE TO SELF: Updated this and FAQ.md as new standards are added
SUPPORTED_FRAMEWORKS = [
    "NIST CSF V1.1",
    "NIST SP 800-53 Rev. 4",
    "AICPA TSC",
    "ISO 27001:2013",
    "CIS Critical Security Controls V8",
    "NIST SP 800-53 Rev. 5",
    "NIST SP 800-171 Rev. 2",
    "CSA Cloud Controls Matrix V4.0",
    "CMMC 2.0",
    "UK NCSC Cyber Essentials V2.2",
    "HIPAA Security Rule 45 CFR Part 164 Subpart C",
    "FFIEC Cybersecurity Assessment Tool",
    "NERC Critical Infrastructure Protection",
    "NYDFS 23 NYCRR Part 500",
    "UK NCSC Cyber Assessment Framework V3.1",
    "PCI-DSS V4.0",
    "NZISM V3.5",
    "ISO 27001:2022",
    "Critical Risk Profile V1.2",
    "ECB CROE",
    "Equifax SCF V1.0",
    "FBI CJIS Security Policy V5.9",
    "CIS Amazon Web Services Foundations Benchmark V1.5",
    "CIS Amazon Web Services Foundations Benchmark V2.0",
    "CIS Amazon Web Services Foundations Benchmark V3.0",
    "MITRE ATT&CK",
    "CIS AWS Database Services Benchmark V1.0",
    "CIS Microsoft Azure Foundations Benchmark V2.0.0",
    "CIS Snowflake Foundations Benchmark V1.0.0"
]

class SeverityAccountTypeComplianceMapping(NamedTuple):
    severityId: int
    severity: str
    cloudAccountTypeId: int
    cloudAccountType: str
    complianceStatusId: int
    complianceStatus: str

class ActivityStatusTypeMapping(NamedTuple):
    activityId: int
    activityName: str
    statusId: int
    status: str
    typeUid: int
    typeName: str

here = path.abspath(path.dirname(__file__))
with open(f"{here}/mapped_compliance_controls.json") as jsonfile:
    CONTROLS_CROSSWALK = json.load(jsonfile)

@ElectricEyeOutput
class OcsfFirehoseOutput(object):
    __provider__ = "ocsf_kdf"

    def __init__(self):
        print("Preparing to send OCSF V1.4.0 Compliance Findings to Amazon Kinesis Data Firehose.")

        if environ["TOML_FILE_PATH"] == "None":
            # Get the absolute path of the current directory
            currentDir = path.abspath(path.dirname(__file__))
            # Go two directories back to /eeauditor/
            twoBack = path.abspath(path.join(currentDir, "../../"))
            # TOML is located in /eeauditor/ directory
            tomlFile = f"{twoBack}/external_providers.toml"
        else:
            tomlFile = environ["TOML_FILE_PATH"]

        with open(tomlFile, "rb") as f:
            data = tomli.load(f)

        # Variable for the entire [outputs.amazon_sqs] section
        sqsDetails = data["outputs"]["firehose"]

        deliveryStream = sqsDetails["kinesis_firehose_delivery_stream_name"]
        awsRegion = sqsDetails["kinesis_firehose_region"]
        if awsRegion is None or awsRegion == "":
            awsRegion = boto3.Session().region_name

        # Ensure that values are provided for all variable - use all() and a list comprehension to check the vars
        # empty strings will trigger `if not`
        if not deliveryStream:
            logger.error("An empty value was detected in '[outputs.firehose]'. Review the TOML file and try again!")
            sys.exit(2)

        self.deliveryStream = deliveryStream
        self.firehose = boto3.client("firehose", region_name=awsRegion)

    def write_findings(self, findings: list, **kwargs):
        if len(findings) == 0:
            logger.error("There are not any findings to send to Kinesis Data Firehose!")
            sys.exit(0)

        logger.info(
            "Writing %s OCSF Compliance Findings to Kinesis Data Firehose!",
            len(findings)
        )

        """# Use another list comprehension to remove `ProductFields.AssetDetails` from non-Asset reporting outputs
        newFindings = [
            {**d, "ProductFields": {k: v for k, v in d["ProductFields"].items() if k != "AssetDetails"}} for d in findings
        ]

        del findings"""

        """
        This list comprhension will base64 decode and convert a string to JSON for all instances of `ProductFields.AssetDetails`
        except where it is a None type (this is done for placeholders in Checks where the Asset doesn't exist) and it will also
        skip over areas in the event that `ProductFields` is missing any Cloud Asset Management required fields
        """
        decodedFindings = [
            {**d, "ProductFields": {**d["ProductFields"],
                "AssetDetails": json.loads(b64decode(d["ProductFields"]["AssetDetails"]).decode("utf-8"))
                    if d["ProductFields"]["AssetDetails"] is not None
                    else None
            }} if "AssetDetails" in d["ProductFields"]
            else d
            for d in findings
        ]

        del findings

        # Map in the new compliance controls
        for finding in decodedFindings:
            complianceRelatedRequirements = list(finding["Compliance"]["RelatedRequirements"])
            newControls = []
            nistCsfControls = [control for control in complianceRelatedRequirements if control.startswith("NIST CSF V1.1")]
            for control in nistCsfControls:
                crosswalkedControls = self.nist_csf_v_1_1_controls_crosswalk(control)
                # Not every single NIST CSF Control maps across to other frameworks
                if crosswalkedControls:
                    for crosswalk in crosswalkedControls:
                        if crosswalk not in newControls:
                            newControls.append(crosswalk)
                else:
                    continue

            complianceRelatedRequirements.extend(newControls)
            
            del finding["Compliance"]["RelatedRequirements"]
            finding["Compliance"]["RelatedRequirements"] = complianceRelatedRequirements

        ocsfFindings = self.ocsf_compliance_finding_mapping(decodedFindings)

        del decodedFindings

        firehose = self.firehose

        # TODO: Make this more performant, because woah dawg, this shit's stupid!
        for i in range(0, len(ocsfFindings), 25):
            encodedRecords = []
            records = ocsfFindings[i : i + 25]
            for record in records:
                encodedRecords.append({"Data": json.dumps(record).encode("utf-8")})
            del records

            try:
                response = firehose.put_record_batch(
                    DeliveryStreamName=self.deliveryStream,
                    Records=encodedRecords
                )
                if response["FailedPutCount"] > 0:
                    logger.warning(
                        "Failed to deliver %s records",
                        response["FailedPutCount"]
                    )
            except ClientError as e:
                logger.warning(
                    "Error with sending batch to Firehose due to: %s",
                    e.response["Error"]["Message"]
                )
                continue

        print("Finished write OCSF Compliance Findings to Kinesis Data Firehose.")
            
        return True
    
    def nist_csf_v_1_1_controls_crosswalk(self, nistCsfSubcategory):
        """
        This function returns a list of additional control framework control IDs that mapped into a provided
        NIST CSF V1.1 Subcategory (control)
        """

        # Not every single NIST CSF Control maps across to other frameworks
        try:
            return CONTROLS_CROSSWALK[nistCsfSubcategory]
        except KeyError:
            return []
        
    def compliance_finding_ocsf_normalization(self, severityLabel: str, cloudProvider: str, complianceStatusLabel: str) -> SeverityAccountTypeComplianceMapping:
        """
        Normalizes the following ASFF Severity, Cloud Account Provider, and Compliance values into OCSF
        """

        # map Severity.Label -> base_event.severity_id, base_event.severity
        if severityLabel == "INFORMATIONAL":
            severityId = 1
            severity = severityLabel.lower().capitalize()
        if severityLabel == "LOW":
            severityId = 2
            severity = severityLabel.lower().capitalize()
        if severityLabel == "MEDIUM":
            severityId = 3
            severity = severityLabel.lower().capitalize()
        if severityLabel == "HIGH":
            severityId = 4
            severity = severityLabel.lower().capitalize()
        if severityLabel == "CRITICAL":
            severityId = 5
            severity = severityLabel.lower().capitalize()
        else:
            severityId = 99
            severity = severityLabel.lower().capitalize()

        # map ProductFields.Provider -> cloud.account.type_id, cloud.account.type
        if cloudProvider == "AWS":
            acctTypeId = 10
            acctType = "AWS Account"
        elif cloudProvider == "GCP":
            acctTypeId = 11
            acctType = "GCP Project"
        elif cloudProvider == "OCI":
            acctTypeId = 12
            acctType = "OCI Compartment"
        elif cloudProvider == "Azure":
            acctTypeId = 13
            acctType = "Azure Subscription"
        elif cloudProvider == "Salesforce":
            acctTypeId = 14
            acctType = "Salesforce Account"
        elif cloudProvider == "Google Workspace":
            acctTypeId = 15
            acctType = "Google Workspace"
        elif cloudProvider == "ServiceNow":
            acctTypeId = 16
            acctType = "ServiceNow Instance"
        elif cloudProvider == "M365":
            acctTypeId = 17
            acctType = "M365 Tenant"
        else:
            acctTypeId = 99
            acctType = cloudProvider

        # map Compliance.Status -> compliance.status_id, compliance.status
        if complianceStatusLabel == "PASSED":
            complianceStatusId = 1
            complianceStatus = "Pass"
        elif complianceStatusLabel == "WARNING":
            complianceStatusId = 2
            complianceStatus = "Warning"
        elif complianceStatusLabel == "FAILED":
            complianceStatusId = 3
            complianceStatus = "Fail"
        else:
            complianceStatusId = 99
            complianceStatus = complianceStatusLabel.lower().capitalize()

        return SeverityAccountTypeComplianceMapping(
            severityId=severityId,
            severity=severity,
            cloudAccountTypeId=acctTypeId,
            cloudAccountType=acctType,
            complianceStatusId=complianceStatusId,
            complianceStatus=complianceStatus
        )

    def iso8061_to_epochseconds(self, iso8061: str) -> int:
        """
        Converts ISO 8061 datetime into Epochseconds timestamp
        """
        return int(datetime.fromisoformat(iso8061).timestamp())
    
    def record_state_to_status(self, recordState: str) -> ActivityStatusTypeMapping:
        """
        Maps ElectricEye RecordState to OCSF Status
        """
        if recordState == "ACTIVE":
            return ActivityStatusTypeMapping(
                activityId=1,
                activityName="Create",
                statusId=1,
                status="New",
                typeUid=200301,
                typeName="Compliance Finding: Create"
            )
        
        if recordState == "ARCHIVED":
            return ActivityStatusTypeMapping(
                activityId=3,
                activityName="Close",
                statusId=4,
                status="Resolved",
                typeUid=200303,
                typeName="Compliance Finding: Close"
            )

    def ocsf_compliance_finding_mapping(self, findings: list) -> list:
        """
        Takes ElectricEye ASFF and outputs to OCSF v1.1.0 Compliance Finding (2003), returns a list of new findings
        """

        ocsfFindings = []

        logger.info("Mapping ASFF to OCSF")

        for finding in findings:
            # Generate metadata.processed_time
            timeNow = datetime.now().isoformat()
            procssedTime = self.iso8061_to_epochseconds(timeNow)

            # check if the compliance.requirements start with the control frameworks and append the unique ones into a list for compliance.stnadards
            standard = []
            requirements = finding["Compliance"]["RelatedRequirements"]
            for control in requirements:
                for framework in SUPPORTED_FRAMEWORKS:
                    if str(control).startswith(framework) and framework not in standard:
                        standard.append(framework)

            asffToOcsf = self.compliance_finding_ocsf_normalization(
                severityLabel=finding["Severity"]["Label"],
                cloudProvider=finding["ProductFields"]["Provider"],
                complianceStatusLabel=finding["Compliance"]["Status"]
            )

            # Non-AWS checks have hardcoded "dummy" data for Account, Region, and Partition - set these to none
            provider = finding["ProductFields"]["Provider"]
            partition = finding["Resources"][0]["Partition"]
            region = finding["ProductFields"]["AssetRegion"]
            accountId = finding["ProductFields"]["ProviderAccountId"]

            if provider != "AWS" or partition == "not-aws":
                partition = None

            if region == "us-placeholder-1":
                region = None

            if region == "aws-global":
                region = "us-east-1"

            if accountId == "000000000000":
                accountId = None

            eventTime = self.iso8061_to_epochseconds(finding["CreatedAt"])

            recordState = finding["RecordState"]
            recordStateMapping = self.record_state_to_status(recordState)
            
            ocsf = {
                # Base Event data
                "activity_id": recordStateMapping.activityId,
                "activity_name": recordStateMapping.activityName,
                "category_name": "Findings",
                "category_uid": 2,
                "class_name": "Compliance Finding",
                "class_uid": 2003,
                "confidence_score": finding["Confidence"],
                "severity": asffToOcsf.severity,
                "severity_id": asffToOcsf.severityId,
                "status": recordStateMapping.status,
                "status_id": recordStateMapping.statusId,
                "start_time": eventTime,
                "time": eventTime,
                "type_name": recordStateMapping.typeName,
                "type_uid": recordStateMapping.typeUid,
                # Profiles / Metadata
                "metadata": {
                    "uid": finding["Id"],
                    "correlation_uid": finding["GeneratorId"],
                    "log_provider": "ElectricEye",
                    "logged_time": eventTime,
                    "original_time": finding["CreatedAt"],
                    "processed_time": procssedTime,
                    "version":"1.4.0",
                    "profiles":["cloud"],
                    "product": {
                        "name":"ElectricEye",
                        "version":"3.0",
                        "url_string":"https://github.com/jonrau1/ElectricEye",
                        "vendor_name":"ElectricEye"
                    },
                },
                "cloud": {
                    "provider": finding["ProductFields"]["Provider"],
                    "region": region,
                    "account": {
                        "uid": accountId,
                        "type": asffToOcsf.cloudAccountType,
                        "type_uid": asffToOcsf.cloudAccountTypeId
                    }
                },
                # Observables
                "observables": [
                    # Cloud Account (Project) UID
                    {
                        "name": "cloud.account.uid",
                        "type": "Account UID",
                        "type_id": 35,
                        "value": accountId
                    },
                    # Resource UID
                    {
                        "name": "resource.uid",
                        "type": "Resource UID",
                        "type_id": 10,
                        "value": finding["Resources"][0]["Id"]
                    }
                ],
                # Compliance Finding Class Info
                "compliance": {
                    "requirements": sorted(requirements),
                    "control": str(finding["Title"]).split("] ")[0].replace("[",""),
                    "standards": sorted(standard),
                    "status": asffToOcsf[5],
                    "status_id": asffToOcsf[4]
                },
                "finding_info": {
                    "created_time": eventTime,
                    "desc": finding["Description"],
                    "first_seen_time": self.iso8061_to_epochseconds(finding["FirstObservedAt"]),
                    "modified_time": self.iso8061_to_epochseconds(finding["UpdatedAt"]),
                    "product_uid": finding["ProductArn"],
                    "title": finding["Title"],
                    "types": finding["Types"],
                    "uid": finding["Id"]
                },
                "remediation": {
                    "desc": finding["Remediation"]["Recommendation"]["Text"],
                    "references": [finding["Remediation"]["Recommendation"]["Url"]]
                },
                "resources": [
                    {
                        "data": finding["ProductFields"]["AssetDetails"],
                        "cloud_partition": partition,
                        "region": region,
                        "type": finding["ProductFields"]["AssetService"],
                        "uid": finding["Resources"][0]["Id"]
                    }
                ],
                "unmapped": {
                    "provider_type": finding["ProductFields"]["ProviderType"],
                    "asset_class": finding["ProductFields"]["AssetClass"],
                    "asset_component": finding["ProductFields"]["AssetComponent"],
                    "workflow_status": finding["Workflow"]["Status"],
                    "record_state": finding["RecordState"]
                }
            }
            ocsfFindings.append(ocsf)

        return ocsfFindings