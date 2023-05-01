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

import json
from processor.outputs.output_base import ElectricEyeOutput

@ElectricEyeOutput
class JsonProvider(object):
    __provider__ = "json"

    def write_findings(self, findings: list, output_file: str, **kwargs):
        print(f"Writing {len(findings)} findings to JSON file")

        # Use another list comprehension to remove `ProductFields.AssetDetails` from non-Asset reporting outputs
        newFindings = [
            {**d, "ProductFields": {k: v for k, v in d["ProductFields"].items() if k != "AssetDetails"}} for d in findings
        ]

        del findings
        
        # create output file based on inputs
        jsonfile = f"{output_file}.json"
        print(f"Output file named: {jsonfile}")
        
        with open(jsonfile, "w") as jsonfile:
            json.dump(
                newFindings,
                jsonfile,
                indent=4,
                default=str
            )
            
        return True