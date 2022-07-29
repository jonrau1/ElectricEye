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
import datetime
from check_register import CheckRegister

registry = CheckRegister()
# import boto3 clients
iamra = boto3.client("rolesanywhere")

# Cache Trust Anchors
def list_trust_anchors(cache):
    response = cache.get("list_trust_anchors")
    if response:
        return response
    cache["list_trust_anchors"] = iamra.list_trust_anchors()
    return cache["list_trust_anchors"]

@registry.register_check("rolesanywhere")
def iamra_self_signed_trust_anchor_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAMRA.1] IAM Roles Anywhere Trust Anchors should not use self-signed certificates"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for ta in list_trust_anchors(cache=cache):
        try:
            taArn = ta['trustAnchorArn']
            taId = ta['trustAnchorId']
            taCertSourceType = ta['source']['sourceType']
            # This is a failing check
            if taCertSourceType == "SELF_SIGNED_REPOSITORY":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{taArn}/iamra-ta-self-signed-cert-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": taArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[IAM.1] IAM Access Keys should be rotated every 90 days",
                    "Description": f"IAM Roles Anywhere Trust Anchor {taId} uses a self-signed certificate. Self-signed certificates are a viable option for IAM Roles Anywhere Trust Anchors but are natively untrusted and can be easily manipulated by adveseraries. Consider using a trusted Certificate Authority or AWS Certificate Manager (ACM) Private Certificate Authority (PCA) to sign your X509 certificates in used by IAM Roles Anywhere. Refer to the remediation section for more information.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on IAMRA Trust Anchors refer to the Establish trust section of the AWS IAM Roles Anywhere User Guide",
                            "Url": "https://docs.aws.amazon.com/rolesanywhere/latest/userguide/getting-started.html#getting-started-step1"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsIamAccessKey",
                            "Id": taArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "TrustAnchorId": taId,
                                    "TrustAnchorSourceType": taCertSourceType
                                }
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF PR.DS-2",
                            "NIST SP 800-53 SC-8",
                            "NIST SP 800-53 SC-11",
                            "NIST SP 800-53 SC-12",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.8.2.3",
                            "ISO 27001:2013 A.13.1.1",
                            "ISO 27001:2013 A.13.2.1",
                            "ISO 27001:2013 A.13.2.3",
                            "ISO 27001:2013 A.14.1.2",
                            "ISO 27001:2013 A.14.1.3"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            # this is a passing check
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{taArn}/iamra-ta-self-signed-cert-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": taArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[IAM.1] IAM Access Keys should be rotated every 90 days",
                    "Description": f"IAM Roles Anywhere Trust Anchor {taId} does not use a self-signed certificate.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on IAMRA Trust Anchors refer to the Establish trust section of the AWS IAM Roles Anywhere User Guide",
                            "Url": "https://docs.aws.amazon.com/rolesanywhere/latest/userguide/getting-started.html#getting-started-step1"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsIamAccessKey",
                            "Id": taArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "TrustAnchorId": taId,
                                    "TrustAnchorSourceType": taCertSourceType
                                }
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF PR.DS-2",
                            "NIST SP 800-53 SC-8",
                            "NIST SP 800-53 SC-11",
                            "NIST SP 800-53 SC-12",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.8.2.3",
                            "ISO 27001:2013 A.13.1.1",
                            "ISO 27001:2013 A.13.2.1",
                            "ISO 27001:2013 A.13.2.3",
                            "ISO 27001:2013 A.14.1.2",
                            "ISO 27001:2013 A.14.1.3"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
        except Exception as e:
            print(e)

@registry.register_check("rolesanywhere")
def iamra_trust_anchor_crl_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAMRA.2] IAM Roles Anywhere Trust Anchors should have a CRL associated"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    # Write a list of IAMRA TA ARNs that are associated with CRLs to another list to compare to the main list of ARNs
    iamraCrlTaArnList = []
    for crl in iamra.list_crls()['crls']:
        crlTaArn = crl['trustAnchorArn']
        # this is a failing check
        if crlTaArn not in iamraCrlTaArnList:
            iamraCrlTaArnList.append(crlTaArn)
    # Assess if the TA ARNs are associated with CRLs
    try:
        for ta in list_trust_anchors(cache=cache):
            taArn = ta['trustAnchorArn']
            taId = ta['trustAnchorId']
            # this is a failing check
            if taArn not in iamraCrlTaArnList:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{taArn}/iamra-ta-crl-association-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": taArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[IAMRA.2] IAM Roles Anywhere Trust Anchors should have a CRL associated",
                    "Description": f"IAM Roles Anywhere Trust Anchor {taId} does not have a Certificate Revocation List (CRL) associated with it. Certificate revocation is supported through the use of imported certificate revocation lists (CRLs). For more information refer to the remediation guidance.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on CRLs refer to the Revocation section of the AWS IAM Roles Anywhere User Guide",
                            "Url": "https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html#revocation"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsIamAccessKey",
                            "Id": taArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "TrustAnchorId": taId
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF PR.MA-1",
                            "NIST SP 800-53 MA-2",
                            "NIST SP 800-53 MA-3",
                            "NIST SP 800-53 MA-5",
                            "NIST SP 800-53 MA-6",
                            "AICPA TSC CC8.1",
                            "ISO 27001:2013 A.11.1.2",
                            "ISO 27001:2013 A.11.2.4",
                            "ISO 27001:2013 A.11.2.5",
                            "ISO 27001:2013 A.11.2.6"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            # this is a passing check
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{taArn}/iamra-ta-crl-association-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": taArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[IAMRA.2] IAM Roles Anywhere Trust Anchors should have a CRL associated",
                    "Description": f"IAM Roles Anywhere Trust Anchor {taId} has a Certificate Revocation List (CRL) associated with it.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on CRLs refer to the Revocation section of the AWS IAM Roles Anywhere User Guide",
                            "Url": "https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html#revocation"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsIamAccessKey",
                            "Id": taArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "TrustAnchorId": taId
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF PR.MA-1",
                            "NIST SP 800-53 MA-2",
                            "NIST SP 800-53 MA-3",
                            "NIST SP 800-53 MA-5",
                            "NIST SP 800-53 MA-6",
                            "AICPA TSC CC8.1",
                            "ISO 27001:2013 A.11.1.2",
                            "ISO 27001:2013 A.11.2.4",
                            "ISO 27001:2013 A.11.2.5",
                            "ISO 27001:2013 A.11.2.6"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
    except Exception as e:
        print(e)



###