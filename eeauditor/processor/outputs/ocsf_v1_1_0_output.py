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
import sys
from typing import NamedTuple
from os import path
from processor.outputs.output_base import ElectricEyeOutput
import json
from base64 import b64decode
from datetime import datetime

logger = logging.getLogger("OCSF_V1.1.0_Output")

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
    "CIS Microsoft Azure Foundations Benchmark V2.0.0"
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
class OcsfV110Output(object):
    __provider__ = "ocsf_v1_1_0"

    def write_findings(self, findings: list, output_file: str, **kwargs):
        if len(findings) == 0:
            logger.error("There are not any findings to write to file!")
            sys.exit(0)

        logger.info(
            "Writing %s OCSF Compliance Findings to JSON!",
            len(findings)
        )

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
        
        # create output file based on inputs
        jsonfile = f"{output_file}_ocsf_v1-1-0_compliance_findings.json"
        logger.info(f"Output file named: {jsonfile}")
        
        with open(jsonfile, "w") as jsonfile:
            json.dump(
                ocsfFindings,
                jsonfile,
                indent=4,
                default=str
            )
            
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
        
    def asff_to_ocsf_normalization(self, severityLabel: str, cloudProvider: str, complianceStatusLabel: str) -> SeverityAccountTypeComplianceMapping:
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
            acctTypeId = 5
            acctType = "GCP Account"
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

        return (
            severityId,
            severity,
            acctTypeId,
            acctType,
            complianceStatusId,
            complianceStatus
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

            # check if the compliance.requirements start with the control frameworks and append the unique ones into a list for compliance.stnadards
            standard = []
            requirements = finding["Compliance"]["RelatedRequirements"]
            for control in requirements:
                for framework in SUPPORTED_FRAMEWORKS:
                    if str(control).startswith(framework) and framework not in standard:
                        standard.append(framework)

            asffToOcsf = self.asff_to_ocsf_normalization(
                severityLabel=finding["Severity"]["Label"],
                cloudProvider=finding["ProductFields"]["Provider"],
                complianceStatusLabel=finding["Compliance"]["Status"]
            )

            # Non-AWS checks have hardcoded "dummy" data for Account, Region, and Partition - set these to none
            partition = finding["Resources"][0]["Partition"]
            region = finding["ProductFields"]["AssetRegion"]
            accountId = finding["ProductFields"]["ProviderAccountId"]

            if partition != "AWS" or partition == "not-aws":
                partition = None

            if partition == "AWS" and region == "us-placeholder-1":
                region = None

            if region == "aws-global":
                region = "us-east-1"

            if partition == "AWS" and accountId == "000000000000":
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
                "status_id": recordStateMapping.status,
                "start_time": eventTime,
                "time": eventTime,
                "type_name": recordStateMapping.typeName,
                "type_uid": recordStateMapping.typeUid,
                # Profiles / Metadata
                "metadata": {
                    "uid": finding["Id"],
                    "correlation_uid": finding["GeneratorId"],
                    "version":"1.1.0",
                    "product": {
                        "name":"ElectricEye",
                        "version":"3.0",
                        "url_string":"https://github.com/jonrau1/ElectricEye",
                        "vendor_name":"ElectricEye"
                    },
                    "profiles":[
                        "cloud"
                    ]
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
                        "type": "Resource UID",
                        "type_id": 10,
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
                    "created_time": self.iso8061_to_epochseconds(finding["CreatedAt"]),
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
                "resource": {
                    "data": finding["ProductFields"]["AssetDetails"],
                    "cloud_partition": partition,
                    "region": region,
                    "type": finding["ProductFields"]["AssetService"],
                    "uid": finding["Resources"][0]["Id"]
                },
                "unmapped": {
                    "provider_type": finding["ProductFields"]["ProviderType"],
                    "asset_class": finding["ProductFields"]["AssetClass"],
                    "asset_component": finding["ProductFields"]["AssetComponent"],
                    "workflow_status": finding["Workflow"]["Status"],
                    "record_state": finding["RecordState"]
                }
            }
            ocsfFindings.append(ocsf)

            del standard
            del requirements

        return ocsfFindings