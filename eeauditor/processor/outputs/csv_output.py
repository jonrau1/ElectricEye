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

import csv
from functools import reduce
from processor.outputs.output_base import ElectricEyeOutput
from os import path

here = path.abspath(path.dirname(__file__))

@ElectricEyeOutput
class CsvProvider(object):
    __provider__ = "csv"

    def write_findings(self, findings: list, output_file: str, **kwargs):
        csv_columns = [
            {"name": "Id", "path": "Id"},
            {"name": "Title", "path": "Title"},
            {"name": "ProductArn", "path": "ProductArn"},
            {"name": "AwsAccountId", "path": "AwsAccountId"},
            {"name": "Severity", "path": "Severity.Label"},
            {"name": "Confidence", "path": "Confidence"},
            {"name": "Description", "path": "Description"},
            {"name": "RecordState", "path": "RecordState"},
            {"name": "Compliance Status", "path": "Compliance.Status"},
            {"name": "Remediation Recommendation", "path": "Remediation.Recommendation.Text",},
            {"name": "Remediation Recommendation Link", "path": "Remediation.Recommendation.Url",},
        ]

        csvOutputName = f"{here}/{output_file}.csv"

        try:
            with open(csvOutputName, "w") as csvfile:
                print(f"Writing {len(findings)} findings to {csvOutputName}")
                writer = csv.writer(csvfile, dialect="excel")
                writer.writerow(item["name"] for item in csv_columns)
                for finding in findings:
                    row_data = []
                    for column_dict in csv_columns:
                        row_data.append(self.deep_get(finding, column_dict["path"]))
                    writer.writerow(row_data)
            csvfile.close()
        except IOError as e:
            print(f"Error writing to file {output_file} with exception {e}")
            return False
        return True

    # Return nested dictionary values by passing in dictionary and keys separated by "."
    def deep_get(self, dictionary, keys):
        return reduce(
            lambda d, key: d.get(key) if isinstance(d, dict) else None,
            keys.split("."),
            dictionary,
        )
