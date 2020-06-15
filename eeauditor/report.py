# This file is part of ElectricEye.

# ElectricEye is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# ElectricEye is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with ElectricEye.
# If not, see https://github.com/jonrau1/ElectricEye/blob/master/LICENSE.

import csv
import json
from functools import reduce

# Return nested dictionary values by passing in dictionary and keys separated by "."
def deep_get(dictionary, keys):
    return reduce(
        lambda d, key: d.get(key) if isinstance(d, dict) else None, keys.split("."), dictionary,
    )


def csv_output(input_file, output_file):
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
    csv_file = output_file
    try:
        with open(input_file) as f:
            findings_file = json.load(f)
            findings = findings_file["Findings"]
            with open(csv_file, "w") as csvfile:
                writer = csv.writer(csvfile, dialect="excel")
                writer.writerow(item["name"] for item in csv_columns)
                for finding in findings:
                    row_data = []
                    for column_dict in csv_columns:
                        row_data.append(deep_get(finding, column_dict["path"]))
                    writer.writerow(row_data)
            csvfile.close()
        f.close()
    except IOError:
        print("I/O error")
