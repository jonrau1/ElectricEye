import boto3
import datetime
from check_register import CheckRegister

registry = CheckRegister()
# import boto3 clients
cloudtrail = boto3.client("cloudtrail")
# loop through trails
def list_trails(cache):
    response = cache.get("list_trails")
    if response:
        return response
    cache["list_trails"] = cloudtrail.list_trails()
    return cache["list_trails"]


@registry.register_check("cloudtrail")
def cloudtrail_multi_region_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    trail = list_trails(cache=cache)
    myCloudTrails = trail["Trails"]
    for trails in myCloudTrails:
        trailArn = str(trails["TrailARN"])
        trailName = str(trails["Name"])
        response = cloudtrail.describe_trails(trailNameList=[trailArn], includeShadowTrails=False)
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        for details in response["trailList"]:
            multiRegionCheck = str(details["IsMultiRegionTrail"])
            if multiRegionCheck == "False":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": trailArn + "/cloudtrail-multi-region-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": trailArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[CloudTrail.1] CloudTrail trails should be multi-region",
                    "Description": "CloudTrail trail "
                    + trailName
                    + " is not a multi-region trail. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your trail should be multi-region refer to the Receiving CloudTrail Log Files from Multiple Regions section of the AWS CloudTrail User Guide",
                            "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html",
                        }
                    },
                    "ProductFields": {"Product Name": "Day2SecurityBot"},
                    "Resources": [
                        {
                            "Type": "AwsCloudTrailTrail",
                            "Id": trailArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF DE.AE-3",
                            "NIST SP 800-53 AU-6",
                            "NIST SP 800-53 CA-7",
                            "NIST SP 800-53 IR-4",
                            "NIST SP 800-53 IR-5",
                            "NIST SP 800-53 IR-8",
                            "NIST SP 800-53 SI-4",
                            "AICPA TSC CC7.2",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.7",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": trailArn + "/cloudtrail-multi-region-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": trailArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[CloudTrail.1] CloudTrail trails should be multi-region",
                    "Description": "CloudTrail trail " + trailName + " is a multi-region trail.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your trail should be multi-region refer to the Receiving CloudTrail Log Files from Multiple Regions section of the AWS CloudTrail User Guide",
                            "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html",
                        }
                    },
                    "ProductFields": {"Product Name": "Day2SecurityBot"},
                    "Resources": [
                        {
                            "Type": "AwsCloudTrailTrail",
                            "Id": trailArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF DE.AE-3",
                            "NIST SP 800-53 AU-6",
                            "NIST SP 800-53 CA-7",
                            "NIST SP 800-53 IR-4",
                            "NIST SP 800-53 IR-5",
                            "NIST SP 800-53 IR-8",
                            "NIST SP 800-53 SI-4",
                            "AICPA TSC CC7.2",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.7",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding


@registry.register_check("cloudtrail")
def cloudtrail_cloudwatch_logging_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    trail = list_trails(cache=cache)
    myCloudTrails = trail["Trails"]
    for trails in myCloudTrails:
        trailArn = str(trails["TrailARN"])
        trailName = str(trails["Name"])
        response = cloudtrail.describe_trails(trailNameList=[trailArn], includeShadowTrails=False)
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        for details in response["trailList"]:
            try:
                # this is a passing check
                cloudwatchLogCheck = str(details["CloudWatchLogsLogGroupArn"])
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": trailArn + "/cloudtrail-cloudwatch-logging-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": trailArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[CloudTrail.2] CloudTrail trails should have CloudWatch logging configured",
                    "Description": "CloudTrail trail "
                    + trailName
                    + " has CloudWatch Logging configured.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your trail should send logs to CloudWatch refer to the Monitoring CloudTrail Log Files with Amazon CloudWatch Logs section of the AWS CloudTrail User Guide",
                            "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/monitor-cloudtrail-log-files-with-cloudwatch-logs.html",
                        }
                    },
                    "ProductFields": {"Product Name": "Day2SecurityBot"},
                    "Resources": [
                        {
                            "Type": "AwsCloudTrailTrail",
                            "Id": trailArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF DE.AE-3",
                            "NIST SP 800-53 AU-6",
                            "NIST SP 800-53 CA-7",
                            "NIST SP 800-53 IR-4",
                            "NIST SP 800-53 IR-5",
                            "NIST SP 800-53 IR-8",
                            "NIST SP 800-53 SI-4",
                            "AICPA TSC CC7.2",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.7",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
            except Exception as e:
                if str(e) == "'CloudWatchLogsLogGroupArn'":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": trailArn + "/cloudtrail-cloudwatch-logging-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": trailArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "MEDIUM"},
                        "Confidence": 99,
                        "Title": "[CloudTrail.2] CloudTrail trails should have CloudWatch logging configured",
                        "Description": "CloudTrail trail "
                        + trailName
                        + " does not have CloudWatch Logging configured. Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "If your trail should send logs to CloudWatch refer to the Monitoring CloudTrail Log Files with Amazon CloudWatch Logs section of the AWS CloudTrail User Guide",
                                "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/monitor-cloudtrail-log-files-with-cloudwatch-logs.html",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "AwsCloudTrailTrail",
                                "Id": trailArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF DE.AE-3",
                                "NIST SP 800-53 AU-6",
                                "NIST SP 800-53 CA-7",
                                "NIST SP 800-53 IR-4",
                                "NIST SP 800-53 IR-5",
                                "NIST SP 800-53 IR-8",
                                "NIST SP 800-53 SI-4",
                                "AICPA TSC CC7.2",
                                "ISO 27001:2013 A.12.4.1",
                                "ISO 27001:2013 A.16.1.7",
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
                else:
                    print(e)


@registry.register_check("cloudtrail")
def cloudtrail_encryption_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    trail = list_trails(cache=cache)
    myCloudTrails = trail["Trails"]
    for trails in myCloudTrails:
        trailArn = str(trails["TrailARN"])
        trailName = str(trails["Name"])
        response = cloudtrail.describe_trails(trailNameList=[trailArn], includeShadowTrails=False)
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        for details in response["trailList"]:
            try:
                # this is a passing check
                encryptionCheck = str(details["KmsKeyId"])
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": trailArn + "/cloudtrail-kms-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": trailArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                        "Effects/Data Exposure",
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[CloudTrail.3] CloudTrail trails should be encrypted by KMS",
                    "Description": "CloudTrail trail " + trailName + " is encrypted by KMS.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your trail should be encrypted with SSE-KMS refer to the Encrypting CloudTrail Log Files with AWS KMS–Managed Keys (SSE-KMS) section of the AWS CloudTrail User Guide",
                            "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html",
                        }
                    },
                    "ProductFields": {"Product Name": "Day2SecurityBot"},
                    "Resources": [
                        {
                            "Type": "AwsCloudTrailTrail",
                            "Id": trailArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF PR.DS-1",
                            "NIST SP 800-53 MP-8",
                            "NIST SP 800-53 SC-12",
                            "NIST SP 800-53 SC-28",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.8.2.3",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
            except Exception as e:
                if str(e) == "'KmsKeyId'":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": trailArn + "/cloudtrail-kms-encryption-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": trailArn,
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
                        "Title": "[CloudTrail.3] CloudTrail trails should be encrypted by KMS",
                        "Description": "CloudTrail trail "
                        + trailName
                        + " is not encrypted by KMS. Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "If your trail should be encrypted with SSE-KMS refer to the Encrypting CloudTrail Log Files with AWS KMS–Managed Keys (SSE-KMS) section of the AWS CloudTrail User Guide",
                                "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html",
                            }
                        },
                        "ProductFields": {"Product Name": "Day2SecurityBot"},
                        "Resources": [
                            {
                                "Type": "AwsCloudTrailTrail",
                                "Id": trailArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF PR.DS-1",
                                "NIST SP 800-53 MP-8",
                                "NIST SP 800-53 SC-12",
                                "NIST SP 800-53 SC-28",
                                "AICPA TSC CC6.1",
                                "ISO 27001:2013 A.8.2.3",
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
                else:
                    print(e)


@registry.register_check("cloudtrail")
def cloudtrail_global_services_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    trail = list_trails(cache=cache)
    myCloudTrails = trail["Trails"]
    for trails in myCloudTrails:
        trailArn = str(trails["TrailARN"])
        trailName = str(trails["Name"])
        response = cloudtrail.describe_trails(trailNameList=[trailArn], includeShadowTrails=False)
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        for details in response["trailList"]:
            globalServiceEventCheck = str(details["IncludeGlobalServiceEvents"])
            if globalServiceEventCheck == "False":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": trailArn + "/cloudtrail-global-services-logging-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": trailArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[CloudTrail.4] CloudTrail trails should log management events",
                    "Description": "CloudTrail trail "
                    + trailName
                    + " does not log management events. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your trail should log management events refer to the Management Events section of the AWS CloudTrail User Guide",
                            "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html#logging-management-events",
                        }
                    },
                    "ProductFields": {"Product Name": "Day2SecurityBot"},
                    "Resources": [
                        {
                            "Type": "AwsCloudTrailTrail",
                            "Id": trailArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF DE.AE-3",
                            "NIST SP 800-53 AU-6",
                            "NIST SP 800-53 CA-7",
                            "NIST SP 800-53 IR-4",
                            "NIST SP 800-53 IR-5",
                            "NIST SP 800-53 IR-8",
                            "NIST SP 800-53 SI-4",
                            "AICPA TSC CC7.2",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.7",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": trailArn + "/cloudtrail-global-services-logging-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": trailArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[CloudTrail.4] CloudTrail trails should log management events",
                    "Description": "CloudTrail trail " + trailName + " logs management events.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your trail should log management events refer to the Management Events section of the AWS CloudTrail User Guide",
                            "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html#logging-management-events",
                        }
                    },
                    "ProductFields": {"Product Name": "Day2SecurityBot"},
                    "Resources": [
                        {
                            "Type": "AwsCloudTrailTrail",
                            "Id": trailArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF DE.AE-3",
                            "NIST SP 800-53 AU-6",
                            "NIST SP 800-53 CA-7",
                            "NIST SP 800-53 IR-4",
                            "NIST SP 800-53 IR-5",
                            "NIST SP 800-53 IR-8",
                            "NIST SP 800-53 SI-4",
                            "AICPA TSC CC7.2",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.7",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding


@registry.register_check("cloudtrail")
def cloudtrail_log_file_validation_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    trail = list_trails(cache=cache)
    myCloudTrails = trail["Trails"]
    for trails in myCloudTrails:
        trailArn = str(trails["TrailARN"])
        trailName = str(trails["Name"])
        response = cloudtrail.describe_trails(trailNameList=[trailArn], includeShadowTrails=False)
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        for details in response["trailList"]:
            fileValidationCheck = str(details["LogFileValidationEnabled"])
            if fileValidationCheck == "False":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": trailArn + "/cloudtrail-log-file-validation-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": trailArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[CloudTrail.5] CloudTrail log file validation should be enabled",
                    "Description": "CloudTrail trail "
                    + trailName
                    + " does not log management events. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your trail should have log file validation enabled refer to the Validating CloudTrail Log File Integrity section of the AWS CloudTrail User Guide",
                            "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html",
                        }
                    },
                    "ProductFields": {"Product Name": "Day2SecurityBot"},
                    "Resources": [
                        {
                            "Type": "AwsCloudTrailTrail",
                            "Id": trailArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF PR.DS-6",
                            "NIST SP 800-53 SC-16",
                            "NIST SP 800-53 SI-7",
                            "AICPA TSC CC7.1",
                            "ISO 27001:2013 A.12.2.1",
                            "ISO 27001:2013 A.12.5.1",
                            "ISO 27001:2013 A.14.1.2",
                            "ISO 27001:2013 A.14.1.3",
                            "ISO 27001:2013 A.14.2.4",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": trailArn + "/cloudtrail-log-file-validation-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": trailArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[CloudTrail.5] CloudTrail log file validation should be enabled",
                    "Description": "CloudTrail trail "
                    + trailName
                    + " does not log management events. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your trail should have log file validation enabled refer to the Validating CloudTrail Log File Integrity section of the AWS CloudTrail User Guide",
                            "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html",
                        }
                    },
                    "ProductFields": {"Product Name": "Day2SecurityBot"},
                    "Resources": [
                        {
                            "Type": "AwsCloudTrailTrail",
                            "Id": trailArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF PR.DS-6",
                            "NIST SP 800-53 SC-16",
                            "NIST SP 800-53 SI-7",
                            "AICPA TSC CC7.1",
                            "ISO 27001:2013 A.12.2.1",
                            "ISO 27001:2013 A.12.5.1",
                            "ISO 27001:2013 A.14.1.2",
                            "ISO 27001:2013 A.14.1.3",
                            "ISO 27001:2013 A.14.2.4",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding

