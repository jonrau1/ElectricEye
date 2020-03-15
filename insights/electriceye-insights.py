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

import boto3

securityhub = boto3.client('securityhub')

try:
    activeInsight = securityhub.create_insight(
        Name='ElectricEye Active Findings',
        Filters={
            'ProductFields': [
                {
                    'Key': 'Product Name',
                    'Value': 'ElectricEye',
                    'Comparison': 'EQUALS'
                },
            ],
            'RecordState': [
                {
                    'Value': 'ACTIVE',
                    'Comparison': 'EQUALS'
                },
            ]
        },
        GroupByAttribute='ResourceType'
    )
    print(activeInsight)
except Exception as e:
    print(e)

try:
    remediatedInsight = securityhub.create_insight(
        Name='ElectricEye Remediated Findings',
        Filters={
            'ProductFields': [
                {
                    'Key': 'Product Name',
                    'Value': 'ElectricEye',
                    'Comparison': 'EQUALS'
                },
            ],
            'RecordState': [
                {
                    'Value': 'ARCHIVED',
                    'Comparison': 'EQUALS'
                },
            ]
        },
        GroupByAttribute='ResourceType'
    )
    print(remediatedInsight)
except Exception as e:
    print(e)

try:
    shodanInsight = securityhub.create_insight(
        Name='ElectricEye Shodan Findings',
        Filters={
            'ProductFields': [
                {
                    'Key': 'Product Name',
                    'Value': 'ElectricEye',
                    'Comparison': 'EQUALS'
                },
            ],
            'ThreatIntelIndicatorSource': [
                {
                    'Value': 'Shodan.io',
                    'Comparison': 'EQUALS'
                }
            ],
            'RecordState': [
                {
                    'Value': 'ACTIVE',
                    'Comparison': 'EQUALS'
                },
            ]
        },
        GroupByAttribute='ResourceType'
    )
    print(shodanInsight)
except Exception as e:
    print(e)