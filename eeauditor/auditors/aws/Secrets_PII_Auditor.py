import boto3
import datetime
import time
import os
import json
from check_register import CheckRegister

registry = CheckRegister()
# import boto3 clients

codebuild = boto3.client("codebuild")
lambdas = boto3.client("lambda")
ec2 = boto3.client("ec2")
cloudformation = boto3.client("cloudformation")
ecs = boto3.client("ecs")

@registry.register_check("support")
def secret_scan_codebuild_envvar_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Secrets.CodeBuild.1] CodeBuild environments should not have secrets stored in Plaintext"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # setup some reusable variables
    scanFile = "./codebuild-data-sample.json"
    resultsFile = "./codebuild-scan-result.json"
    scanCommand = "detect-secrets scan " + scanFile + " > " + resultsFile
    # Collect all CodeBuild Projects and send to the Batch API
    cbList = []
    for p in codebuild.list_projects()["projects"]:
        cbList.append(str(p))
    # Submit batch request
    for proj in codebuild.batch_get_projects(names=cbList)["projects"]:
        # Create an empty list per loop to put "Plaintext" env vars as the SSM and Secrets Manager types will just be a name
        envvarList = []
        cbName = str(proj["name"])
        cbArn = str(proj["arn"])
        sourceType = str(proj["source"]["type"])
        for e in proj["environment"]["environmentVariables"]:
            if str(e["type"]) == "PLAINTEXT":
                # Append a dict into the envvarlist - this will be written into a new file
                envvarList.append({"name": str(e["name"]),"value": str(e["value"])})
            else:
                continue
        # Write the results out to a file
        with open(scanFile, 'w') as writejson:
            json.dump(envvarList, writejson, indent=2, default=str)
        # execute command
        os.system(scanCommand)
        time.sleep(1)
        # read the results file
        with open(resultsFile, 'r') as readjson:
            data = json.load(readjson)
        # if results is an empty dict then there are no secrets found!
        if str(data["results"]) == "{}":
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": cbArn + "/codebuild-env-var-secrets-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": cbArn,
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
                "Title": "[Secrets.CodeBuild.1] CodeBuild environments should not have secrets stored in Plaintext",
                "Description": "CodeBuild Project "
                + cbName
                + " does not have any secrets in Plaintext environment variables.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your project should not contain plaintext environment variables refer to the Buildspec File Name and Storage Location section of the AWS CodeBuild User Guide.",
                        "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html#build-spec-ref-syntax",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "SourceUrl": "https://console.aws.amazon.com/trustedadvisor/home?region=us-east-1#/category/security",
                "Resources": [
                    {
                        "Type": "AwsCodeBuildProject",
                        "Id": cbArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {
                            "AwsCodeBuildProject": {
                                "Name": cbName,
                                "Source": {
                                    "Type": sourceType
                                }
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-3",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-17",
                        "NIST SP 800-53 AC-19",
                        "NIST SP 800-53 AC-20",
                        "NIST SP 800-53 SC-15",
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
            # this is a failing check - we won't actually parse the full payload of potential secrets
            # otherwise we would break the mutability of a finding...so we will sample the first one
            # and note that in the finding itself
            secretType = str(data["results"]["scan-result.json"][0]["type"])
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": cbArn + "/codebuild-env-var-secrets-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": cbArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "CRITICAL"},
                "Confidence": 99,
                "Title": "[Secrets.CodeBuild.1] CodeBuild environments should not have secrets stored in Plaintext",
                "Description": "CodeBuild Project "
                + cbName
                + " has at least one secret in Plaintext environment variables. Detect-secrets is reporting it as "
                + secretType
                + " secrets in plaintext can be leaked or exploited by unauthroized personnel who have permissions to access CodeBuild Projects and read the environment varialbes. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your project should not contain plaintext environment variables refer to the Buildspec File Name and Storage Location section of the AWS CodeBuild User Guide.",
                        "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html#build-spec-ref-syntax",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "SourceUrl": "https://console.aws.amazon.com/trustedadvisor/home?region=us-east-1#/category/security",
                "Resources": [
                    {
                        "Type": "AwsCodeBuildProject",
                        "Id": cbArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {
                            "AwsCodeBuildProject": {
                                "Name": cbName,
                                "Source": {
                                    "Type": sourceType
                                }
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-3",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-17",
                        "NIST SP 800-53 AC-19",
                        "NIST SP 800-53 AC-20",
                        "NIST SP 800-53 SC-15",
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
        # clear out memory and prevent duplicates from being cached
        os.system("rm " + scanFile)
        os.system("rm " + resultsFile)
        del envvarList
        del writejson
        del readjson
        del data