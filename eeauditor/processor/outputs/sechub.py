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
from processor.outputs.output_base import ElectricEyeOutput

@ElectricEyeOutput
class SecHubProvider(object):
    __provider__ = "sechub"

    def write_findings(self, findings: list, **kwargs):
        print(f"Writing {len(findings)} results to AWS Security Hub")
        if findings:
            sechub = boto3.client("securityhub")

            # Use a list comprehension to flatten the Description if the length exceeds Security Hub's upper-limit of 1024
            maxDescriptionLength = 1018
            modifiedDescriptionFindings = [
                {k: (v[:maxDescriptionLength] + '...' if isinstance(v, str) and len(v) > maxDescriptionLength else v) for k, v in d.items()} for d in findings
            ]
            # Use another list comprehension to remove `ProductFields.AssetDetails` from non-Asset reporting outputs
            newFindings = [
                {k: v for k, v in d.items() if k != ["ProductFields"]["AssetDetails"]} for d in modifiedDescriptionFindings
            ]

            del findings
            del modifiedDescriptionFindings

            # Security Hub supports batches of up to 100 findings for the "BIF" API
            for i in range(0, len(newFindings), 100):
                sechub.batch_import_findings(
                    Findings=newFindings[i : i + 100]
                )
        
        return True