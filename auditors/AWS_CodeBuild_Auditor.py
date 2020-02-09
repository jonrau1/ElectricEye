import boto3
import os
import datetime
# import boto3 clients
sts = boto3.client('sts')
codebuild = boto3.client('codebuild')
securityhub = boto3.client('securityhub')
# create env vars
awsAccountId = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']
# loop through all CodeBuild projects and list their attributes
response = codebuild.list_projects()
allCodebuildProjects = response['projects']
response = codebuild.batch_get_projects(names=allCodebuildProjects)
myCodeBuildProjects = response['projects']

def artifact_encryption_check(): 
    for projects in myCodeBuildProjects:
        buildProjectName = str(projects['name'])
        buildProjectArn = str(projects['arn'])
        # check if this project supports artifacts
        artifactCheck = str(projects['artifacts']['type'])
        # skip projects without artifacts
        if artifactCheck == 'NO_ARTIFACTS':
            print('No artifacts supported, skipping this check')
            pass
        else:
            # check if encryption for artifacts is disabled
            artifactEncryptionCheck = str(projects['artifacts']['encryptionDisabled'])
            if artifactEncryptionCheck == 'True':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    # create Sec Hub finding
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': buildProjectArn + '/unencrypted-artifacts',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': buildProjectArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [
                                    'Software and Configuration Checks/AWS Security Best Practices',
                                    'Effects/Data Exposure'
                                ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 40 },
                                'Confidence': 99,
                                'Title': '[CodeBuild.1] CodeBuild projects should not have artifact encryption disabled',
                                'Description': 'CodeBuild project ' + buildProjectName + ' has artifact encryption disabled. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your project should have artifact encryption enabled scroll down to item 8 in the Create a Build Project (Console) section of the AWS CodeBuild User Guide',
                                        'Url': 'https://docs.aws.amazon.com/codebuild/latest/userguide/create-project.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsCodeBuildProject',
                                        'Id': buildProjectArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'AwsCodeBuildProject': { 'Name': buildProjectName }
                                        }
                                    }
                                ],
                                'Compliance': { 'Status': 'FAILED' },
                                'RecordState': 'ACTIVE'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
            else:
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    # create Sec Hub finding
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': buildProjectArn + '/unencrypted-artifacts',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': buildProjectArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [
                                    'Software and Configuration Checks/AWS Security Best Practices',
                                    'Effects/Data Exposure'
                                ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 0 },
                                'Confidence': 99,
                                'Title': '[CodeBuild.1] CodeBuild projects should not have artifact encryption disabled',
                                'Description': 'CodeBuild project ' + buildProjectName + ' has artifact encryption enabled.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your project should have artifact encryption enabled scroll down to item 8 in the Create a Build Project (Console) section of the AWS CodeBuild User Guide',
                                        'Url': 'https://docs.aws.amazon.com/codebuild/latest/userguide/create-project.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsCodeBuildProject',
                                        'Id': buildProjectArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'AwsCodeBuildProject': { 'Name': buildProjectName }
                                        }
                                    }
                                ],
                                'Compliance': { 'Status': 'PASSED' },
                                'RecordState': 'ARCHIVED'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)

def insecure_ssl_check():
    for projects in myCodeBuildProjects:
        buildProjectName = str(projects['name'])
        buildProjectArn = str(projects['arn'])
        # check if Insecure SSL is enabled for your Source
        sourceInsecureSslCheck = str(projects['source']['insecureSsl'])
        if sourceInsecureSslCheck != 'False':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': buildProjectArn + '/insecure-ssl',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': buildProjectArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 40 },
                            'Confidence': 99,
                            'Title': '[CodeBuild.2] CodeBuild projects should not have insecure SSL configured',
                            'Description': 'CodeBuild project ' + buildProjectName + ' has insecure SSL configured. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your project should not have insecure SSL configured refer to the Troubleshooting CodeBuild section of the AWS CodeBuild User Guide',
                                    'Url': 'https://docs.aws.amazon.com/codebuild/latest/userguide/troubleshooting.html#troubleshooting-self-signed-certificate'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsCodeBuildProject',
                                    'Id': buildProjectArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsCodeBuildProject': { 'Name': buildProjectName }
                                    }
                                }
                            ],
                            'Compliance': { 'Status': 'FAILED' },
                            'RecordState': 'ACTIVE'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
        else:
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': buildProjectArn + '/insecure-ssl',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': buildProjectArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[CodeBuild.2] CodeBuild projects should not have insecure SSL configured',
                            'Description': 'CodeBuild project ' + buildProjectName + ' doesnt have insecure SSL configured.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your project should not have insecure SSL configured refer to the Troubleshooting CodeBuild section of the AWS CodeBuild User Guide',
                                    'Url': 'https://docs.aws.amazon.com/codebuild/latest/userguide/troubleshooting.html#troubleshooting-self-signed-certificate'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsCodeBuildProject',
                                    'Id': buildProjectArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsCodeBuildProject': { 'Name': buildProjectName }
                                    }
                                }
                            ],
                            'Compliance': { 'Status': 'PASSED' },
                            'RecordState': 'ARCHIVED'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)

def plaintext_env_var_check():
    for projects in myCodeBuildProjects:
        buildProjectName = str(projects['name'])
        buildProjectArn = str(projects['arn'])
        # check if this project has any env vars
        envVarCheck = str(projects['environment']['environmentVariables'])
        if envVarCheck == '[]':
            print('No env vars, skipping this check')
            pass
        else:
            # loop through env vars
            codeBuildEnvVars = projects['environment']['environmentVariables']
            for envvar in codeBuildEnvVars:
                plaintextCheck = str(envvar['type'])
                # identify projects that don't use parameter store or AWS secrets manager
                if plaintextCheck == 'PLAINTEXT':
                    try:
                        # ISO Time
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        # create Sec Hub finding
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': buildProjectArn + '/plaintext-env-vars',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': buildProjectArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure',
                                        'Sensitive Data Identifications'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Normalized': 40 },
                                    'Confidence': 99,
                                    'Title': '[CodeBuild.3] CodeBuild projects should not have plaintext environment variables',
                                    'Description': 'CodeBuild project ' + buildProjectName + ' contains plaintext environment variables. Refer to the remediation instructions if this configuration is not intended',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'If your project should not contain plaintext environment variables refer to the Buildspec File Name and Storage Location section of the AWS CodeBuild User Guide',
                                            'Url': 'https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html#build-spec-ref-syntax'
                                        }
                                    },
                                    'ProductFields': {
                                        'Product Name': 'ElectricEye'
                                    },
                                    'Resources': [
                                        {
                                            'Type': 'AwsCodeBuildProject',
                                            'Id': buildProjectArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsCodeBuildProject': { 'Name': buildProjectName }
                                            }
                                        }
                                    ],
                                    'Compliance': { 'Status': 'FAILED' },
                                    'RecordState': 'ACTIVE'
                                }
                            ]
                        )
                        print(response)
                    except Exception as e:
                        print(e)
                else:
                    try:
                        # ISO Time
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        # create Sec Hub finding
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': buildProjectArn + '/plaintext-env-vars',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': buildProjectArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure',
                                        'Sensitive Data Identifications'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Normalized': 0 },
                                    'Confidence': 99,
                                    'Title': '[CodeBuild.3] CodeBuild projects should not have plaintext environment variables',
                                    'Description': 'CodeBuild project ' + buildProjectName + ' does not contain plaintext environment variables.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'If your project should not contain plaintext environment variables refer to the Buildspec File Name and Storage Location section of the AWS CodeBuild User Guide',
                                            'Url': 'https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html#build-spec-ref-syntax'
                                        }
                                    },
                                    'ProductFields': {
                                        'Product Name': 'ElectricEye'
                                    },
                                    'Resources': [
                                        {
                                            'Type': 'AwsCodeBuildProject',
                                            'Id': buildProjectArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsCodeBuildProject': { 'Name': buildProjectName }
                                            }
                                        }
                                    ],
                                    'Compliance': { 'Status': 'PASSED' },
                                    'RecordState': 'ARCHIVED'
                                }
                            ]
                        )
                        print(response)
                    except Exception as e:
                        print(e)

def s3_logging_encryption_check():
    for projects in myCodeBuildProjects:
        buildProjectName = str(projects['name'])
        buildProjectArn = str(projects['arn'])
        # check if this project disabled s3 log encryption
        s3EncryptionCheck = str(projects['logsConfig']['s3Logs']['encryptionDisabled'])
        if s3EncryptionCheck == 'True':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': buildProjectArn + '/s3-encryption',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': buildProjectArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 40 },
                            'Confidence': 99,
                            'Title': '[CodeBuild.4] CodeBuild projects should not have S3 log encryption disabled',
                            'Description': 'CodeBuild project ' + buildProjectName + ' has S3 log encryption disabled. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your project should not have S3 log encryption disabled refer to #20 in the Change a Build Projects Settings (AWS CLI) section of the AWS CodeBuild User Guide',
                                    'Url': 'https://docs.aws.amazon.com/codebuild/latest/userguide/change-project.html#change-project-console'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsCodeBuildProject',
                                    'Id': buildProjectArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsCodeBuildProject': { 'Name': buildProjectName }
                                    }
                                }
                            ],
                            'Compliance': { 'Status': 'FAILED' },
                            'RecordState': 'ACTIVE'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
        else:
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': buildProjectArn + '/s3-encryption',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': buildProjectArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[CodeBuild.4] CodeBuild projects should not have S3 log encryption disabled',
                            'Description': 'CodeBuild project ' + buildProjectName + ' has S3 log encryption enabled.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your project should not have S3 log encryption disabled refer to #20 in the Change a Build Projects Settings (AWS CLI) section of the AWS CodeBuild User Guide',
                                    'Url': 'https://docs.aws.amazon.com/codebuild/latest/userguide/change-project.html#change-project-console'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsCodeBuildProject',
                                    'Id': buildProjectArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsCodeBuildProject': { 'Name': buildProjectName }
                                    }
                                }
                            ],
                            'Compliance': { 'Status': 'PASSED' },
                            'RecordState': 'ARCHIVED'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)

def cloudwatch_logging_check():
    for projects in myCodeBuildProjects:
        buildProjectName = str(projects['name'])
        buildProjectArn = str(projects['arn'])
        # check if this project logs to cloudwatch
        codeBuildLoggingCheck = str(projects['logsConfig']['cloudWatchLogs']['status'])
        if codeBuildLoggingCheck != 'ENABLED':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': buildProjectArn + '/cloudwatch-logging',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': buildProjectArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 40 },
                            'Confidence': 99,
                            'Title': '[CodeBuild.5] CodeBuild projects should have CloudWatch logging enabled',
                            'Description': 'CodeBuild project ' + buildProjectName + ' has CloudWatch logging disabled. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your project should not have CloudWatch logging disabled refer to #20 in the Change a Build Projects Settings (AWS CLI) section of the AWS CodeBuild User Guide',
                                    'Url': 'https://docs.aws.amazon.com/codebuild/latest/userguide/change-project.html#change-project-console'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsCodeBuildProject',
                                    'Id': buildProjectArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsCodeBuildProject': { 'Name': buildProjectName }
                                    }
                                }
                            ],
                            'Compliance': { 'Status': 'FAILED' },
                            'RecordState': 'ACTIVE'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
        else:
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': buildProjectArn + '/cloudwatch-logging',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': buildProjectArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[CodeBuild.5] CodeBuild projects should have CloudWatch logging enabled',
                            'Description': 'CodeBuild project ' + buildProjectName + ' has CloudWatch logging enabled.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your project should not have CloudWatch logging disabled refer to #20 in the Change a Build Projects Settings (AWS CLI) section of the AWS CodeBuild User Guide',
                                    'Url': 'https://docs.aws.amazon.com/codebuild/latest/userguide/change-project.html#change-project-console'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsCodeBuildProject',
                                    'Id': buildProjectArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsCodeBuildProject': { 'Name': buildProjectName }
                                    }
                                }
                            ],
                            'Compliance': { 'Status': 'PASSED' },
                            'RecordState': 'ARCHIVED'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)

def codebuild_auditor():
    artifact_encryption_check()
    insecure_ssl_check()
    plaintext_env_var_check()
    s3_logging_encryption_check()
    cloudwatch_logging_check()

codebuild_auditor()