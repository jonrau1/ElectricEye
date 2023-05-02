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

from processor.outputs.output_base import ElectricEyeOutput
import json
import base64

@ElectricEyeOutput
class CamJsonProvider(object):
    __provider__ = "cam_json"

    def write_findings(self, findings: list, output_file: str, **kwargs):
        if len(findings) == 0:
            print("There are not any findings to write to file!")
            exit(0)

        camOutput = CamJsonProvider.process_findings(findings)

        del findings
    
        # create output file based on inputs
        jsonfile = f"ElectricEyeCAM_{output_file}.json"
        print(f"Output file named: {jsonfile}")
        
        with open(jsonfile, "w") as jsonfile:
            json.dump(
                camOutput,
                jsonfile,
                indent=4,
                default=str
            )
            
        return True
    
    def process_findings(findings):
        """
        This function uses the list comprehension to base64 decode all `AssetDetails` and then takes a selective
        cross-section of unique per-asset details to be written to file within the main function
        """
        # This list contains the CAM output
        cloudAssetManagementFindings = []
        # Create a new list from raw findings that base64 decodes `AssetDetails` where it is not None, if it is, just
        # use None and bring forward `ProductFields` where it is missing `AssetDetails`...which shouldn't happen
        print(f"Base64 decoding AssetDetails for {len(findings)} ElectricEye findings.")

        data = [
            {**d, "ProductFields": {**d["ProductFields"],
                "AssetDetails": json.loads(base64.b64decode(d["ProductFields"]["AssetDetails"]).decode("utf-8"))
                    if d["ProductFields"]["AssetDetails"] is not None
                    else None
            }} if "AssetDetails" in d["ProductFields"]
            else d
            for d in findings
        ]

        print(f"Completed base64 decoding for {len(data)} ElectricEye findings.")

        # This list will contain unique identifiers from `Resources.[*].Id`
        uniqueIds = set(item["Resources"][0]["Id"] for item in data)

        print(f"Processing Asset and Finding Summary data for {len(uniqueIds)} unique Assets.")

        for uid in uniqueIds:
            subData = [item for item in data if item["Resources"][0]["Id"] == uid]
            productFields = subData[0]["ProductFields"]
            infoSevFindings = lowSevFindings = medSevFindings = highSevFindings = critSevFindings = 0
            
            for item in subData:
                sevLabel = item["Severity"]["Label"]
                if sevLabel == "INFORMATIONAL":
                    infoSevFindings += 1
                elif sevLabel == "LOW":
                    lowSevFindings += 1
                elif sevLabel == "MEDIUM":
                    medSevFindings += 1
                elif sevLabel == "HIGH":
                    highSevFindings += 1
                elif sevLabel == "CRITICAL":
                    critSevFindings += 1
                
            
            cloudAssetManagementFindings.append(
                {
                    "AssetId": uid,
                    "AssetClass": productFields.get("AssetClass", ""),
                    "AssetService": productFields.get("AssetService", ""),
                    "AssetComponent": productFields.get("AssetComponent", ""),
                    "Provider": productFields.get("Provider", ""),
                    "ProviderType": productFields.get("ProviderType", ""),
                    "ProviderAccountId": productFields.get("ProviderAccountId", ""),
                    "AssetRegion": productFields.get("AssetRegion", ""),
                    "AssetDetails": productFields.get("AssetDetails", ""),
                    "AssetClass": productFields.get("AssetClass", ""),
                    "AssetService": productFields.get("AssetService", ""),
                    "AssetComponent": productFields.get("AssetComponent", ""),
                    "InformationalSeverityFindings": infoSevFindings,
                    "LowSeverityFindings": lowSevFindings,
                    "MediumSeverityFindings": medSevFindings,
                    "HighSeverityFindings": highSevFindings,
                    "CriticalSeverityFindings": critSevFindings
                }
            )

        del findings
        del data
        del uniqueIds
        del subData

        return cloudAssetManagementFindings