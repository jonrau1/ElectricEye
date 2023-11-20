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

from os import path
from processor.outputs.output_base import ElectricEyeOutput
import json
from base64 import b64decode

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

        print(f"Writing {len(findings)} findings to JSON file")

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
            complianceRelatedRequirements = finding["Compliance"]["RelatedRequirements"]
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

        
        # create output file based on inputs
        jsonfile = f"{output_file}.json"
        print(f"Output file named: {jsonfile}")
        
        with open(jsonfile, "w") as jsonfile:
            json.dump(
                decodedFindings,
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
        
    def ocsf_compliance_finding_mapping(self, findings: list) -> list:
        """
        Takes ElectricEye ASFF and outputs to OCSF v1.1.0(-dev) Compliance Finding (2003), returns a list of new findings
        """

        ocsfFindings = []

        for finding in findings:
            
            ocsf = {
                # Base Event data
                "activity_id": 1,
                "activity_name": "Create",
                "category_name": "Findings",
                "category_uid": 2,
                "class_name": "Compliance Finding",
                "class_uid": 2003,
                "severity": "Fatal",
                "severity_id": 6,
                "start_time": 1700438858661032,
                "status": "foo",
                "status_id": 4,
                "time": 1700438858663387,
                "timezone_offset": 50,
                "type_name": "Compliance Finding: Create",
                "type_uid": 200301,
                # Profiles / Metadata
                "metadata":{
                    "version":"1.1.0-dev",
                    "product":{
                        "name":"ElectricEye",
                        "version":"1.1.0-dev",
                        "url_string":"https://github.com/jonrau1/ElectricEye",
                        "vendor_name":"ElectricEye"
                    },
                    "profiles":[
                        "cloud"
                    ]
                },
                "cloud":{
                    "provider": finding["ProductFields"]["Provider"],
                    "project_uid": finding["ProductFields"]["ProviderAccountId"],
                    "region": finding["ProductFields"]["AssetRegion"],
                    "account": {
                        "uid": finding["ProductFields"]["ProviderAccountId"],
                        "type": finding["ProductFields"]["Provider"],
                        "type_uid": 99
                    }
                },
                # Compliance Finding Class Info
                "resource":{
                    "data": finding["ProductFields"]["AssetDetails"],
                    "cloud_partition": finding["Resources"][0]["Partition"],
                    "region": finding["ProductFields"]["AssetRegion"],
                    "type": finding["ProductFields"]["AssetService"],
                    "uid": finding["Resources"][0]["Id"]
                },
                "finding_info":{
                    "product_uid": "ElectricEye",
                    "title": finding["Title"],
                    "desc": finding["Description"],
                    "uid": finding["Title"],
                    "types": finding["Types"],
                    "last_seen_time":1700438858662612
                },
                "remediation":{
                    "desc":"eminem fifteen mb"
                }
            }

        return ocsfFindings