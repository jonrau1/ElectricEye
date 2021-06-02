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
import os
from check_register import CheckRegister

registry = CheckRegister()
# import boto3 clients
licensemanager = boto3.client("license-manager")

@registry.register_check("license-manager")
def license_manager_hard_count_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[LicenseManager.1] License Manager license configurations should be configured to enforce a hard limit"""
    try:
        # TODO: need to catch the case that License Manager is not setup
        response = licensemanager.list_license_configurations()
        lmCheck = str(response["LicenseConfigurations"])
        if lmCheck == "[]":
            pass
        else:
            myLiscMgrConfigs = response["LicenseConfigurations"]
            for lmconfigs in myLiscMgrConfigs:
                liscConfigArn = str(lmconfigs["LicenseConfigurationArn"])
                # ISO Time
                iso8601Time = (
                    datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                )
                try:
                    response = licensemanager.get_license_configuration(
                        LicenseConfigurationArn=liscConfigArn
                    )
                    liscConfigId = str(response["LicenseConfigurationId"])
                    liscConfigName = str(response["Name"])
                    hardLimitCheck = str(response["LicenseCountHardLimit"])
                    if hardLimitCheck == "False":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": liscConfigArn + "/license-manager-enforce-hard-limit-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": liscConfigArn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "LOW"},
                            "Confidence": 99,
                            "Title": "[LicenseManager.1] License Manager license configurations should be configured to enforce a hard limit",
                            "Description": "License Manager license configuration "
                            + liscConfigName
                            + " does not enforce a hard limit. Enforcing a hard limit prevents new instances from being created that if you have already provisioned all available licenses. Refer to the remediation instructions to remediate this behavior",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For information on hard limits refer to the License Configuration Parameters and Rules section of the AWS License Manager User Guide",
                                    "Url": "https://docs.aws.amazon.com/license-manager/latest/userguide/config-overview.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsLicenseManagerLicenseConfiguration",
                                    "Id": liscConfigArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {
                                            "licenseConfigurationId": liscConfigId,
                                            "licenseConfigurationName": liscConfigName,
                                        }
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF ID.AM-2",
                                    "NIST SP 800-53 CM-8",
                                    "NIST SP 800-53 PM-5",
                                    "AICPA TSC CC3.2",
                                    "AICPA TSC CC6.1",
                                    "ISO 27001:2013 A.8.1.1",
                                    "ISO 27001:2013 A.8.1.2",
                                    "ISO 27001:2013 A.12.5.1",
                                ],
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE",
                        }
                        yield finding
                    else:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": liscConfigArn + "/license-manager-enforce-hard-limit-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": liscConfigArn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[LicenseManager.1] License Manager license configurations should be configured to enforce a hard limit",
                            "Description": "License Manager license configuration "
                            + liscConfigName
                            + " enforces a hard limit.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For information on hard limits refer to the License Configuration Parameters and Rules section of the AWS License Manager User Guide",
                                    "Url": "https://docs.aws.amazon.com/license-manager/latest/userguide/config-overview.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsLicenseManagerLicenseConfiguration",
                                    "Id": liscConfigArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {
                                            "licenseConfigurationId": liscConfigId,
                                            "licenseConfigurationName": liscConfigName,
                                        }
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF ID.AM-2",
                                    "NIST SP 800-53 CM-8",
                                    "NIST SP 800-53 PM-5",
                                    "AICPA TSC CC3.2",
                                    "AICPA TSC CC6.1",
                                    "ISO 27001:2013 A.8.1.1",
                                    "ISO 27001:2013 A.8.1.2",
                                    "ISO 27001:2013 A.12.5.1",
                                ],
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED",
                        }
                        yield finding
                except Exception as e:
                    print(e)
    except Exception as e:
        print(e)

@registry.register_check("license-manager")
def license_manager_disassociation_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[LicenseManager.2] License Manager license configurations should disassociate hosts when license in scope is not found"""
    try:
        # TODO: need to catch the case that License Manager is not setup
        response = licensemanager.list_license_configurations()
        lmCheck = str(response["LicenseConfigurations"])
        if lmCheck == "[]":
            pass
        else:
            myLiscMgrConfigs = response["LicenseConfigurations"]
            for lmconfigs in myLiscMgrConfigs:
                liscConfigArn = str(lmconfigs["LicenseConfigurationArn"])
                # ISO Time
                iso8601Time = (
                    datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                )
                try:
                    response = licensemanager.get_license_configuration(
                        LicenseConfigurationArn=liscConfigArn
                    )
                    liscConfigId = str(response["LicenseConfigurationId"])
                    liscConfigName = str(response["Name"])
                    disassocCheck = str(response["DisassociateWhenNotFound"])
                    if disassocCheck == "False":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": liscConfigArn + "/license-manager-disassociation-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": liscConfigArn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "LOW"},
                            "Confidence": 99,
                            "Title": "[LicenseManager.2] License Manager license configurations should disassociate hosts when license in scope is not found",
                            "Description": "License Manager license configuration "
                            + liscConfigName
                            + " does not enforce automatic disassociation. Refer to the remediation instructions to remediate this behavior.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For information on disassociation refer to the Disassociating license configurations and AMIs section of the AWS License Manager User Guide",
                                    "Url": "https://docs.aws.amazon.com/license-manager/latest/userguide/license-rules.html#ami-disassociation",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsLicenseManagerLicenseConfiguration",
                                    "Id": liscConfigArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {
                                            "LicenseConfigurationId": liscConfigId,
                                            "LicenseConfigurationName": liscConfigName,
                                        }
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF ID.AM-2",
                                    "NIST SP 800-53 CM-8",
                                    "NIST SP 800-53 PM-5",
                                    "AICPA TSC CC3.2",
                                    "AICPA TSC CC6.1",
                                    "ISO 27001:2013 A.8.1.1",
                                    "ISO 27001:2013 A.8.1.2",
                                    "ISO 27001:2013 A.12.5.1",
                                ],
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE",
                        }
                        yield finding
                    else:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": liscConfigArn + "/license-manager-disassociation-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": liscConfigArn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[LicenseManager.2] License Manager license configurations should disassociate hosts when license in scope is not found",
                            "Description": "License Manager license configuration "
                            + liscConfigName
                            + " enforces automatic disassociation.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For information on disassociation refer to the Disassociating license configurations and AMIs section of the AWS License Manager User Guide",
                                    "Url": "https://docs.aws.amazon.com/license-manager/latest/userguide/license-rules.html#ami-disassociation",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsLicenseManagerLicenseConfiguration",
                                    "Id": liscConfigArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {
                                            "LicenseConfigurationId": liscConfigId,
                                            "LicenseConfigurationName": liscConfigName,
                                        }
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF ID.AM-2",
                                    "NIST SP 800-53 CM-8",
                                    "NIST SP 800-53 PM-5",
                                    "AICPA TSC CC3.2",
                                    "AICPA TSC CC6.1",
                                    "ISO 27001:2013 A.8.1.1",
                                    "ISO 27001:2013 A.8.1.2",
                                    "ISO 27001:2013 A.12.5.1"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED",
                        }
                        yield finding
                except Exception as e:
                    print(e)
    except Exception as e:
        print(e)