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

from typing import NamedTuple
from os import path
from processor.outputs.output_base import ElectricEyeOutput
import json
from base64 import b64decode
from datetime import datetime

# NOTE TO SELF: Updated this and FAQ.md as new standards are added
SUPPORTED_STANDARDS = [
    "NIST Cybersecurity Framework Version 1.1",
    "NIST Special Publication 800-53 Revision 4",
    "NIST Special Publication 800-53 Revision 5",
    "NIST Special Publication 800-171 Revision 2",
    "American Institute of Certified Public Accountants (AICPA) Trust Service Criteria (TSC) 2017/2020 for SOC 2",
    "ISO/IEC 27001:2013/2017 Annex A",
    "ISO/IEC 27001:2022 Annex A",
    "Center for Internet Security (CIS) Critical Security Controls Version 8",
    "Cloud Security Alliance (CSA) Cloud Controls Matrix (CCM) Version 4.0",
    "United States Department of Defense Cybersecurity Maturity Model Certification (CMMC) Version 2.0",
    "United States Federal Bureau of Investigation (FBI) Criminal Justice Information System (CJIS) Security Policy Version 5.9",
    "United Kingdom National Cybercrime Security Center (NCSC) Cyber Essentials Version 2.2",
    "United Kingdom National Cybercrime Security Center (NCSC) Assessment Framework Version 3.1",
    "HIPAA 'Security Rule' U.S. Code 45 CFR Part 164 Subpart C",
    "Federal Financial Institutions Examination Council (FFIEC) Cybersecurity Assessment Tool (CAT)",
    "North American Electric Reliability Corporation (NERC) Critical Infrastructure Protection (CIP) Standard",
    "New Zealand Information Security Manual Version 3.5",
    "New York Department of Financial Services (NYDFS) Series 23 NYCRR Part 500; AKA NYDFS500",
    "Critical Risk Institute (CRI) Critical Risk Profile Version 1.2",
    "European Central Bank (ECB) Cyber Resilience Oversight Expectations (CROEs)",
    "Equifax Security Controls Framework Version 1.0",
    "Payment Card Industry (PCI) Data Security Standard (DSS) Version 4.0"
]

class AsffOcsfNormalizedMapping(NamedTuple):
    severityId: int
    severity: str
    cloudAccountTypeId: int
    cloudAccountType: str
    complianceStatusId: int
    complianceStatus: str

here = path.abspath(path.dirname(__file__))
with open(f"{here}/mapped_compliance_controls.json") as jsonfile:
    CONTROLS_CROSSWALK = json.load(jsonfile)

@ElectricEyeOutput
class OcsfV110Output(object):
    __provider__ = "ocsf_v1_1_0"

    def write_findings(self, findings: list, output_file: str, **kwargs):
        if len(findings) == 0:
            print("There are not any findings to write to file!")
            exit(0)

        print(f"Writing {len(findings)} OCSF Compliance Findings to JSON!")

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
        
        # create output file based on inputs
        jsonfile = f"{output_file}_ocsf_v1-1-0_compliance_findings.json"
        print(f"Output file named: {jsonfile}")
        
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
        
    def asff_to_ocsf_normalization(self, severityLabel: str, cloudProvider: str, complianceStatusLabel: str) -> AsffOcsfNormalizedMapping:
        """
        Normalizes the following ASFF Severity, Cloud Account Provider, and Compliance values into OCSF
        """

        # map Severity.Label -> base_event.severity_id, base_event.severity
        if severityLabel == "INFORMATIONAL":
            severityId = 1
            severity = severityLabel.lower()
        if severityLabel == "LOW":
            severityId = 2
            severity = severityLabel.lower()
        if severityLabel == "MEDIUM":
            severityId = 3
            severity = severityLabel.lower()
        if severityLabel == "HIGH":
            severityId = 4
            severity = severityLabel.lower()
        if severityLabel == "CRITICAL":
            severityId = 5
            severity = severityLabel.lower()
        else:
            severityId = 99
            severity = severityLabel.lower()

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
        
    def ocsf_compliance_finding_mapping(self, findings: list) -> list:
        """
        Takes ElectricEye ASFF and outputs to OCSF v1.1.0(-dev) Compliance Finding (2003), returns a list of new findings
        """

        ocsfFindings = []

        for finding in findings:

            asffToOcsf = self.asff_to_ocsf_normalization(
                severityLabel=finding["Severity"]["Label"],
                cloudProvider=finding["ProductFields"]["Provider"],
                complianceStatusLabel=finding["Compliance"]["Status"]
            )
            
            ocsf = {
                # Base Event data
                "activity_id": 1,
                "activity_name": "Create",
                "category_name": "Findings",
                "category_uid": 2,
                "class_name": "Compliance Finding",
                "class_uid": 2003,
                "confidence_score": finding["Confidence"],
                "severity": asffToOcsf[1],
                "severity_id": asffToOcsf[0],
                "status": "New",
                "status_id": 1,
                "time": self.iso8061_to_epochseconds(finding["CreatedAt"]),
                "type_name": "Compliance Finding: Create",
                "type_uid": 200301,
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
                    "project_uid": finding["ProductFields"]["ProviderAccountId"],
                    "region": finding["ProductFields"]["AssetRegion"],
                    "account": {
                        "uid": finding["ProductFields"]["ProviderAccountId"],
                        "type": asffToOcsf[3],
                        "type_uid": asffToOcsf[2]
                    }
                },
                # Compliance Finding Class Info
                "compliance": {
                    "requirements": finding["Compliance"]["RelatedRequirements"],
                    "control": str(finding["Title"]).split("] ")[0].replace("[",""),
                    "standards": SUPPORTED_STANDARDS,
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
                    "cloud_partition": finding["Resources"][0]["Partition"],
                    "region": finding["ProductFields"]["AssetRegion"],
                    "type": finding["ProductFields"]["AssetService"],
                    "uid": finding["Resources"][0]["Id"]
                },
                "unmapped": {
                    "provide_type": finding["ProductFields"]["ProviderType"],
                    "asset_class": finding["ProductFields"]["AssetClass"],
                    "asset_service": finding["ProductFields"]["AssetService"],
                    "asset_component": finding["ProductFields"]["AssetComponent"],
                    "workflow_status": finding["Workflow"]["Status"],
                    "record_state": finding["RecordState"]
                }
            }

        return ocsfFindings