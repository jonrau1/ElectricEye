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
import base64
import json

@ElectricEyeOutput
class StdoutProvider(object):
    __provider__ = "stdout"

    def write_findings(self, findings: list, output_file: str, **kwargs):
        checkedIds = []

        """
        noDetails = [
            {**d, "ProductFields": {k: v for k, v in d["ProductFields"].items() if k != "AssetDetails"}} for d in findings
        ]
        del findings

        for finding in noDetails:
        """

        decodedFindings = [
            {**d, "ProductFields": {**d["ProductFields"], "AssetDetails": base64.b64decode(json.loads(d["ProductFields"]["AssetDetails"])).decode("utf-8")}}
            if "AssetDetails" in d["ProductFields"]
            else d
            for d in findings
        ]

        for finding in decodedFindings:
            parsedFinding = json.loads(json.dumps(finding, default=str))
            if parsedFinding["Id"] not in checkedIds:
                checkedIds.append(parsedFinding["Id"])
                print(json.dumps(finding, default=str))
            else:
                del parsedFinding
                continue
    
        del checkedIds
        
        return True