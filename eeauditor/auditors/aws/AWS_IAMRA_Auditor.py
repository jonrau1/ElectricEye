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

import datetime
import json
from check_register import CheckRegister

registry = CheckRegister()

def list_trust_anchors(cache, session):
    iamra = session.client("rolesanywhere")
    response = cache.get("list_trust_anchors")
    if response:
        return response
    cache["list_trust_anchors"] = iamra.list_trust_anchors()
    return cache["list_trust_anchors"]

def list_profiles(cache, session):
    iamra = session.client("rolesanywhere")
    response = cache.get("list_profiles")
    if response:
        return response
    cache["list_profiles"] = iamra.list_profiles()
    return cache["list_profiles"]

@registry.register_check("rolesanywhere")
def iamra_self_signed_trust_anchor_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAMRA.1] IAM Roles Anywhere Trust Anchors should not use self-signed certificates"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for ta in list_trust_anchors(cache, session)["trustAnchors"]:
        taArn = ta["trustAnchorArn"]
        taId = ta["trustAnchorId"]
        taCertSourceType = ta["source"]["sourceType"]
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
                "Title": "[IAMRA.1] IAM Roles Anywhere Trust Anchors should not use self-signed certificates",
                "Description": f"IAM Roles Anywhere Trust Anchor {taId} uses a self-signed certificate. Self-signed certificates are a viable option for IAM Roles Anywhere Trust Anchors but are natively untrusted and can be easily manipulated by adveseraries. Consider using a trusted Certificate Authority or AWS Certificate Manager (ACM) Private Certificate Authority (PCA) to sign your X509 certificates in used by IAM Roles Anywhere. Refer to the remediation section if this behavior is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on IAMRA Trust Anchors refer to the Establish trust section of the AWS IAM Roles Anywhere User Guide",
                        "Url": "https://docs.aws.amazon.com/rolesanywhere/latest/userguide/getting-started.html#getting-started-step1"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM Roles Anywhere",
                    "AssetType": "Trust Anchor"
                },
                "Resources": [
                    {
                        "Type": "AwsIamRolesAnywhereTrustAnchor",
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
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
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
                "Title": "[IAMRA.1] IAM Roles Anywhere Trust Anchors should not use self-signed certificates",
                "Description": f"IAM Roles Anywhere Trust Anchor {taId} does not use a self-signed certificate.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on IAMRA Trust Anchors refer to the Establish trust section of the AWS IAM Roles Anywhere User Guide",
                        "Url": "https://docs.aws.amazon.com/rolesanywhere/latest/userguide/getting-started.html#getting-started-step1"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM Roles Anywhere",
                    "AssetType": "Trust Anchor"
                },
                "Resources": [
                    {
                        "Type": "AwsIamRolesAnywhereTrustAnchor",
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
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
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

@registry.register_check("rolesanywhere")
def iamra_trust_anchor_crl_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAMRA.2] IAM Roles Anywhere Trust Anchors should have a CRL associated"""
    iamra = session.client("rolesanywhere")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    # Write a list of IAMRA TA ARNs that are associated with CRLs to another list to compare to the main list of ARNs
    iamraCrlTaArnList = []
    for crl in iamra.list_crls()["crls"]:
        crlTaArn = crl["trustAnchorArn"]
        # this is a failing check
        if crlTaArn not in iamraCrlTaArnList:
            iamraCrlTaArnList.append(crlTaArn)
    # Assess if the TA ARNs are associated with CRLs
    for ta in list_trust_anchors(cache, session)["trustAnchors"]:
        taArn = ta["trustAnchorArn"]
        taId = ta["trustAnchorId"]
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
                "Description": f"IAM Roles Anywhere Trust Anchor {taId} does not have a Certificate Revocation List (CRL) associated with it. Certificate revocation is supported through the use of imported certificate revocation lists (CRLs). Refer to the remediation section if this behavior is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on CRLs refer to the Revocation section of the AWS IAM Roles Anywhere User Guide",
                        "Url": "https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html#revocation"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM Roles Anywhere",
                    "AssetType": "Trust Anchor"
                },
                "Resources": [
                    {
                        "Type": "AwsIamRolesAnywhereTrustAnchor",
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
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM Roles Anywhere",
                    "AssetType": "Trust Anchor"
                },
                "Resources": [
                    {
                        "Type": "AwsIamRolesAnywhereTrustAnchor",
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
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
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

@registry.register_check("rolesanywhere")
def iamra_profiles_session_policy_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAMRA.3] IAM Roles Anywhere Profiles should contain a Session Policy"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for profile in list_profiles(cache, session)["profiles"]:
        profileArn = profile["profileArn"]
        profileName = profile["name"]
        profileId = profile["profileId"]
        # determine if a session policy exists, this field is not always available
        try:
            sessionPolicy = profile["sessionPolicy"]
            policySesh = True
            del sessionPolicy
        except KeyError:
            policySesh = False
        # this is a failing check
        if policySesh == False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{profileArn}/iamra-profile-session-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": profileArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[IAMRA.3] IAM Roles Anywhere Profiles should contain a Session Policy",
                "Description": f"IAM Roles Anywhere Profile {profileName} does not have a Session Policy associated with it. A session policy applies to the trust boundary of the vended session credentials for further restriction and scopes-down the effective permissions granted to the session. Refer to the remediation section if this behavior is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on Session Policies refer to the Session policies section of the AWS Identity and Access Management User Guide",
                        "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#policies_session"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM Roles Anywhere",
                    "AssetType": "Profile"
                },
                "Resources": [
                    {
                        "Type": "AwsIamRolesAnywhereProfile",
                        "Id": profileArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": profileName,
                                "ProfileId": profileId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "AICPA TSC CC6.3",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5"
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
                "Id": f"{profileArn}/iamra-profile-session-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": profileArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[IAMRA.3] IAM Roles Anywhere Profiles should contain a Session Policy",
                "Description": f"IAM Roles Anywhere Profile {profileName} has a Session Policy associated with it.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on Session Policies refer to the Session policies section of the AWS Identity and Access Management User Guide",
                        "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#policies_session"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM Roles Anywhere",
                    "AssetType": "Profile"
                },
                "Resources": [
                    {
                        "Type": "AwsIamRolesAnywhereProfile",
                        "Id": profileArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": profileName,
                                "ProfileId": profileId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "AICPA TSC CC6.3",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("rolesanywhere")
def iamra_profiles_managed_policy_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAMRA.4] IAM Roles Anywhere Profiles should contain Managed Policies"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for profile in list_profiles(cache, session)["profiles"]:
        profileArn = profile["profileArn"]
        profileName = profile["name"]
        profileId = profile["profileId"]
        # list comprehension used to detect if List is empty which means no managed scope down policy
        # this is a failing check
        if not profile["managedPolicyArns"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{profileArn}/iamra-profile-managed-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": profileArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[IAMRA.4] IAM Roles Anywhere Profiles should contain Managed Policies",
                "Description": f"IAM Roles Anywhere Profile {profileName} does not have any Managed Policies associated with it. A managed policy applies to the trust boundary of the vended session credentials for further restriction and scopes-down the effective permissions granted to the session. Rather than using an in-line Session Policy, Managed Policies are simply associations with AWS IAM Policies. Refer to the remediation section if this behavior is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on Session Policies refer to the Session policies section of the AWS Identity and Access Management User Guide",
                        "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#policies_session"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM Roles Anywhere",
                    "AssetType": "Profile"
                },
                "Resources": [
                    {
                        "Type": "AwsIamRolesAnywhereProfile",
                        "Id": profileArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": profileName,
                                "ProfileId": profileId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "AICPA TSC CC6.3",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5"
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
                "Id": f"{profileArn}/iamra-profile-managed-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": profileArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[IAMRA.4] IAM Roles Anywhere Profiles should contain Managed Policies",
                "Description": f"IAM Roles Anywhere Profile {profileName} does not have any Managed Policies associated with it. A managed policy applies to the trust boundary of the vended session credentials for further restriction and scopes-down the effective permissions granted to the session. Rather than using an in-line Session Policy, Managed Policies are simply associations with AWS IAM Policies. Refer to the remediation section if this behavior is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on Session Policies refer to the Session policies section of the AWS Identity and Access Management User Guide",
                        "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#policies_session"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM Roles Anywhere",
                    "AssetType": "Profile"
                },
                "Resources": [
                    {
                        "Type": "AwsIamRolesAnywhereProfile",
                        "Id": profileArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": profileName,
                                "ProfileId": profileId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "AICPA TSC CC6.3",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("rolesanywhere")
def iamra_role_trust_policy_condition_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAMRA.5] IAM Roles used with IAM Roles Anywhere Policies should contain a condition statement in the Trust Policy"""
    iam = session.client("iam")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Create an empty list to add the Role Arns already evaluated as to avoid duplicative runs
    seenRoles = []
    for profile in list_profiles(cache, session)["profiles"]:
        profileName = profile["name"]
        # loop through IAM Roles
        for role in profile["roleArns"]:
            if role not in seenRoles:
                seenRoles.append(role)
                roleArn = role
                # Parse the name of the role by splitting it out of the ARN
                roleName = role.split("/")[1]
                # Get Role info
                r = iam.get_role(RoleName=roleName)
                trustPolicy = json.loads(json.dumps(r["Role"]["AssumeRolePolicyDocument"]))
                for statement in trustPolicy["Statement"]:
                    # this is a failing check
                    if statement.get("Condition") == None:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{roleArn}/iamra-role-trust-policy-condition-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": roleArn,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "HIGH"},
                            "Confidence": 99,
                            "Title": "[IAMRA.5] IAM Roles used with IAM Roles Anywhere Policies should contain a condition statement in the Trust Policy",
                            "Description": f"IAM Role {roleName} associated with IAM Roles Anywhere Profile {profileName} does not contain a Condition statement within its Trust Policy. AWS strongly recommendeds that trust policies include Condition statements to further refine access to the role such as via the aws:PrincipalTag/x509Subject condition. Refer to the remediation section if this behavior is not intended.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For information on using Condition statements with IAM Roles Anywhere Trust Policies refer to the Mapping identities to your workloads with AWS Identity and Access Management Roles Anywhere section of the AWS IAM Roles Anywhere User Guide",
                                    "Url": "https://docs.aws.amazon.com/rolesanywhere/latest/userguide/workload-identities.html",
                                }
                            },
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "AssetClass": "Identity & Access Management",
                                "AssetService": "AWS IAM",
                                "AssetType": "Role"
                            },
                            "Resources": [
                                {
                                    "Type": "AwsIamRole",
                                    "Id": roleArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsIamRole": {
                                            "RoleName": roleName
                                        },
                                        "Other": {
                                            "ProfileName": profileName
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 PR.AC-3",
                                    "NIST SP 800-53 Rev. 4 AC-1",
                                    "NIST SP 800-53 Rev. 4 AC-17",
                                    "NIST SP 800-53 Rev. 4 AC-19",
                                    "NIST SP 800-53 Rev. 4 AC-20",
                                    "NIST SP 800-53 Rev. 4 SC-15",
                                    "AICPA TSC CC6.6",
                                    "ISO 27001:2013 A.6.2.1",
                                    "ISO 27001:2013 A.6.2.2",
                                    "ISO 27001:2013 A.11.2.6",
                                    "ISO 27001:2013 A.13.1.1",
                                    "ISO 27001:2013 A.13.2.1"
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
                            "Id": f"{roleArn}/iamra-role-trust-policy-condition-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": roleArn,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[IAMRA.5] IAM Roles used with IAM Roles Anywhere Policies should contain a condition statement in the Trust Policy",
                            "Description": f"IAM Role {roleName} associated with IAM Roles Anywhere Profile {profileName} does not contain a Condition statement within its Trust Policy. AWS strongly recommendeds that trust policies include Condition statements to further refine access to the role such as via the aws:PrincipalTag/x509Subject condition. Refer to the remediation section if this behavior is not intended.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For information on using Condition statements with IAM Roles Anywhere Trust Policies refer to the Mapping identities to your workloads with AWS Identity and Access Management Roles Anywhere section of the AWS IAM Roles Anywhere User Guide",
                                    "Url": "https://docs.aws.amazon.com/rolesanywhere/latest/userguide/workload-identities.html",
                                }
                            },
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "AssetClass": "Identity & Access Management",
                                "AssetService": "AWS IAM",
                                "AssetType": "Role"
                            },
                            "Resources": [
                                {
                                    "Type": "AwsIamRole",
                                    "Id": roleArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsIamRole": {
                                            "RoleName": roleName
                                        },
                                        "Other": {
                                            "ProfileName": profileName
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 PR.AC-3",
                                    "NIST SP 800-53 Rev. 4 AC-1",
                                    "NIST SP 800-53 Rev. 4 AC-17",
                                    "NIST SP 800-53 Rev. 4 AC-19",
                                    "NIST SP 800-53 Rev. 4 AC-20",
                                    "NIST SP 800-53 Rev. 4 SC-15",
                                    "AICPA TSC CC6.6",
                                    "ISO 27001:2013 A.6.2.1",
                                    "ISO 27001:2013 A.6.2.2",
                                    "ISO 27001:2013 A.11.2.6",
                                    "ISO 27001:2013 A.13.1.1",
                                    "ISO 27001:2013 A.13.2.1"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
            else:
                # ignore Roles we have already evaluated - regardless how many profiles they're associated with
                continue           