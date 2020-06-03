import boto3
import datetime
import time
import os

lambda_client = boto3.client("lambda")
cloudwatch_client = boto3.client("cloudwatch")
securityHub_client = boto3.client("securityhub")
sts = boto3.client("sts")

response = lambda_client.list_functions()
functions = response["Functions"]

# create env vars
awsAccountId = sts.get_caller_identity()["Account"]
awsRegion = os.environ["AWS_REGION"]


def function_expiration_check():
    for function in functions:
        Function_Name = str(function["FunctionName"])
        lambdaArn = str(function["FunctionArn"])
        metric_response = cloudwatch_client.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "m1",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/Lambda",
                            "MetricName": "Invocations",
                            "Dimensions": [
                                {"Name": "FunctionName", "Value": Function_Name},
                            ],
                        },
                        "Period": 300,
                        "Stat": "Sum",
                    },
                }
            ],
            StartTime=time.time() - 30 * 24 * 360,
            EndTime=time.time(),
        )

        try:
            metrics = metric_response["MetricDataResults"]
            for metric in metrics:
                try:
                    invocations = metric["Values"][0]
                    iso8601Time = (
                        datetime.datetime.utcnow()
                        .replace(tzinfo=datetime.timezone.utc)
                        .isoformat()
                    )
                    response = securityHub_client.batch_import_findings(
                        Findings=[
                            {
                                "SchemaVersion": "2018-10-08",
                                "Id": lambdaArn + "/lambda-function-unused-check",
                                "ProductArn": "arn:aws:securityhub:"
                                + awsRegion
                                + ":"
                                + awsAccountId
                                + ":product/"
                                + awsAccountId
                                + "/default",
                                "GeneratorId": lambdaArn,
                                "AwsAccountId": awsAccountId,
                                "Types": [
                                    "Software and Configuration Checks/AWS Security Best Practices"
                                ],
                                "FirstObservedAt": iso8601Time,
                                "CreatedAt": iso8601Time,
                                "UpdatedAt": iso8601Time,
                                "Severity": {"Label": "INFORMATIONAL"},
                                "Confidence": 99,
                                "Title": "[Lambda] Lambda functions should be deleted after 30 days of no use",
                                "Description": "Lambda function "
                                + Function_Name
                                + " has been used in the last 30 days.",
                                "Remediation": {
                                    "Recommendation": {
                                        "Text": "For more information on best practices for lambda functions refer to the Best Practices for Working with AWS Lambda Functions section of the Amazon Lambda Developer Guide",
                                        "Url": "https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html#function-configuration",
                                    }
                                },
                                "ProductFields": {"Product Name": "ElectricEye"},
                                "Resources": [
                                    {
                                        "Type": "AwsLambda",
                                        "Id": lambdaArn,
                                        "Partition": "aws",
                                        "Region": awsRegion,
                                    }
                                ],
                                "Workflow": {"Status": "RESOLVED"},
                                "RecordState": "ARCHIVED",
                            }
                        ]
                    )
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)


function_expiration_check()
