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
import datetime
import json
import os
from auditors.Auditor import Auditor

# import boto3 clients
sts = boto3.client("sts")
kms = boto3.client("kms")
# create env vars
awsRegion = os.environ["AWS_REGION"]


class KMSKeyRotationCheck(Auditor):
   def execute(self):


class KMSKeyExposedCheck(Auditor):
    def execute(self):
        awsAccountId = sts.get_caller_identity()["Account"]
        response = kms.list_aliases()
        aliasList = response["Aliases"]
        for alias in aliasList:
            if "TargetKeyId" in alias:
                aliasArn = alias["AliasArn"]
                keyid = alias["TargetKeyId"]
                policyString = kms.get_key_policy(KeyId=keyid, PolicyName="default")
                fail = False
                policy_json = policyString["Policy"]
                policy = json.loads(policy_json)
                iso8601Time = (
                    datetime.datetime.utcnow()
                    .replace(tzinfo=datetime.timezone.utc)
                    .isoformat()
                )
                for sid in policy["Statement"]:
                    access = sid["Principal"].get("AWS", None)
                    if access != "*" or (access == "*" and "Condition" in sid):
                        continue
                    else:
                        fail = True
                        break
                if not fail:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": aliasArn + "/kms-key-exposed-check",
                        "ProductArn": "arn:aws:securityhub:"
                        + awsRegion
                        + ":"
                        + awsAccountId
                        + ":product/"
                        + awsAccountId
                        + "/default",
                        "GeneratorId": aliasArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "Effects/Data Exposure",
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 75,  # The Condition may not effectively limit access
                        "Title": "[KMS.2] KMS keys should not have public access",
                        "Description": "KMS key "
                        + keyid
                        + " does not have public access or limited by a Condition. Refer to the remediation instructions to review kms access policy",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on AWS KMS key policies refer to Using key policies in AWS KMS section of the AWS KMS Developer Guide.",
                                "Url": "https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsKmsAlias",
                                "Id": aliasArn,
                                "Partition": "aws",
                                "Region": awsRegion,
                            }
                        ],
                        "Compliance": {"Status": "PASSED"},
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": aliasArn + "/kms-key-exposed-check",
                        "ProductArn": "arn:aws:securityhub:"
                        + awsRegion
                        + ":"
                        + awsAccountId
                        + ":product/"
                        + awsAccountId
                        + "/default",
                        "GeneratorId": aliasArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "Effects/Data Exposure",
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "HIGH"},
                        "Confidence": 99,
                        "Title": "[KMS.2] KMS keys should not have public access",
                        "Description": "KMS key "
                        + keyid
                        + " has public access. Refer to the remediation instructions to review kms access policy",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on AWS KMS key policies refer to Using key policies in AWS KMS section of the AWS KMS Developer Guide.",
                                "Url": "https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsKmsAlias",
                                "Id": aliasArn,
                                "Partition": "aws",
                                "Region": awsRegion,
                            }
                        ],
                        "Compliance": {"Status": "FAILED"},
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
