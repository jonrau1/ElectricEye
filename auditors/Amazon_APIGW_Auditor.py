import boto3
import datetime
import os
# import boto3 clients
securityhub = boto3.client('securityhub')
apigateway = boto3.client('apigateway')
sts = boto3.client('sts')
# create account id & region variables
awsAccountId = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']
# loop through API Gateway rest apis
response = apigateway.get_rest_apis(limit=500)
myRestApis = response['items']

def api_gateway_stage_metrics_enabled_check():
    for restapi in myRestApis:
        apiGwApiId = str(restapi['id'])
        apiGwApiName = str(restapi['name'])
        response = apigateway.get_stages(restApiId=apiGwApiId)
        for apistages in response['item']:
            apiStageName = str(apistages['stageName'])
            apiStageDeploymentId = str(apistages['deploymentId'])
            apiStageArn = 'arn:aws:apigateway:' + awsRegion + '::/restapis/' + apiGwApiId + '/stages/' + apiStageName
            metricsCheck = str(apistages['methodSettings']['*/*']['metricsEnabled'])
            if metricsCheck == 'False':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': apiStageArn + '/apigateway-stage-metrics-enabled-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': apiStageArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 20 },
                                'Confidence': 99,
                                'Title': '[APIGateway.1] API Gateway Rest API Stages should have CloudWatch Metrics enabled',
                                'Description': 'API Gateway stage ' + apiStageName + ' for Rest API ' + apiGwApiName + ' does not have CloudWatch metrics enabled. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your API Gateway stage should have CloudWatch Metrics enabled refer to the Monitor API Execution with Amazon CloudWatch section of the Amazon API Gateway Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/apigateway/latest/developerguide/monitoring-cloudwatch.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': apiStageArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'deploymentId': apiStageDeploymentId,
                                                'stageName': apiStageName
                                            }
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
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': apiStageArn + '/apigateway-stage-metrics-enabled-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': apiStageArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 0 },
                                'Confidence': 99,
                                'Title': '[APIGateway.1] API Gateway Rest API Stages should have CloudWatch Metrics enabled',
                                'Description': 'API Gateway stage ' + apiStageName + ' for Rest API ' + apiGwApiName + ' has CloudWatch metrics enabled.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your API Gateway stage should have CloudWatch Metrics enabled refer to the Monitor API Execution with Amazon CloudWatch section of the Amazon API Gateway Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/apigateway/latest/developerguide/monitoring-cloudwatch.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': apiStageArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'deploymentId': apiStageDeploymentId,
                                                'stageName': apiStageName
                                            }
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

def api_gateway_stage_logging_check():
    for restapi in myRestApis:
        apiGwApiId = str(restapi['id'])
        apiGwApiName = str(restapi['name'])
        response = apigateway.get_stages(restApiId=apiGwApiId)
        for apistages in response['item']:
            apiStageName = str(apistages['stageName'])
            apiStageDeploymentId = str(apistages['deploymentId'])
            apiStageArn = 'arn:aws:apigateway:' + awsRegion + '::/restapis/' + apiGwApiId + '/stages/' + apiStageName
            loggingCheck = str(apistages['methodSettings']['*/*']['loggingLevel'])
            if loggingCheck == 'OFF':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': apiStageArn + '/apigateway-stage-api-logging-enabled-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': apiStageArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 20 },
                                'Confidence': 99,
                                'Title': '[APIGateway.2] API Gateway Rest API Stages should have CloudWatch API Logging enabled',
                                'Description': 'API Gateway stage ' + apiStageName + ' for Rest API ' + apiGwApiName + ' does not have CloudWatch API Logging enabled. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your API Gateway stage should have CloudWatch API Logging enabled refer to the Set Up CloudWatch API Logging in API Gateway section of the Amazon API Gateway Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': apiStageArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'deploymentId': apiStageDeploymentId,
                                                'stageName': apiStageName
                                            }
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
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': apiStageArn + '/apigateway-stage-api-logging-enabled-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': apiStageArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 0 },
                                'Confidence': 99,
                                'Title': '[APIGateway.2] API Gateway Rest API Stages should have CloudWatch API Logging enabled',
                                'Description': 'API Gateway stage ' + apiStageName + ' for Rest API ' + apiGwApiName + ' has CloudWatch API Logging enabled.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your API Gateway stage should have CloudWatch API Logging enabled refer to the Set Up CloudWatch API Logging in API Gateway section of the Amazon API Gateway Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': apiStageArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'deploymentId': apiStageDeploymentId,
                                                'stageName': apiStageName
                                            }
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

def api_gateway_stage_caching_enabled_check():
    for restapi in myRestApis:
        apiGwApiId = str(restapi['id'])
        apiGwApiName = str(restapi['name'])
        response = apigateway.get_stages(restApiId=apiGwApiId)
        for apistages in response['item']:
            apiStageName = str(apistages['stageName'])
            apiStageDeploymentId = str(apistages['deploymentId'])
            apiStageArn = 'arn:aws:apigateway:' + awsRegion + '::/restapis/' + apiGwApiId + '/stages/' + apiStageName
            cachingCheck = str(apistages['methodSettings']['*/*']['cachingEnabled'])
            if cachingCheck == 'False':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': apiStageArn + '/apigateway-stage-caching-enabled-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': apiStageArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 20 },
                                'Confidence': 99,
                                'Title': '[APIGateway.3] API Gateway Rest API Stages should have Caching enabled',
                                'Description': 'API Gateway stage ' + apiStageName + ' for Rest API ' + apiGwApiName + ' does not have Caching enabled. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your API Gateway stage should have caching enabled refer to the Enable API Caching to Enhance Responsiveness section of the Amazon API Gateway Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': apiStageArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'deploymentId': apiStageDeploymentId,
                                                'stageName': apiStageName
                                            }
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
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': apiStageArn + '/apigateway-stage-caching-enabled-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': apiStageArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 0 },
                                'Confidence': 99,
                                'Title': '[APIGateway.3] API Gateway Rest API Stages should have Caching enabled',
                                'Description': 'API Gateway stage ' + apiStageName + ' for Rest API ' + apiGwApiName + ' has Caching enabled.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your API Gateway stage should have caching enabled refer to the Enable API Caching to Enhance Responsiveness section of the Amazon API Gateway Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': apiStageArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'deploymentId': apiStageDeploymentId,
                                                'stageName': apiStageName
                                            }
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

def api_gateway_stage_cache_encryption_check():
    for restapi in myRestApis:
        apiGwApiId = str(restapi['id'])
        apiGwApiName = str(restapi['name'])
        response = apigateway.get_stages(restApiId=apiGwApiId)
        for apistages in response['item']:
            apiStageName = str(apistages['stageName'])
            apiStageDeploymentId = str(apistages['deploymentId'])
            apiStageArn = 'arn:aws:apigateway:' + awsRegion + '::/restapis/' + apiGwApiId + '/stages/' + apiStageName
            cachingEncryptionCheck = str(apistages['methodSettings']['*/*']['cacheDataEncrypted'])
            if cachingEncryptionCheck == 'False':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': apiStageArn + '/apigateway-stage-cache-encryption-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': apiStageArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [
                                    'Software and Configuration Checks/AWS Security Best Practices',
                                    'Effects/Data Exposure'
                                ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 80 },
                                'Confidence': 99,
                                'Title': '[APIGateway.4] API Gateway Rest API Stages should have cache encryption enabled',
                                'Description': 'API Gateway stage ' + apiStageName + ' for Rest API ' + apiGwApiName + ' does not have cache encryption enabled. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your API Gateway stage should have caching encryption enabled refer to the Override API Gateway Stage-Level Caching for Method Caching section of the Amazon API Gateway Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html#override-api-gateway-stage-cache-for-method-cache'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': apiStageArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'deploymentId': apiStageDeploymentId,
                                                'stageName': apiStageName
                                            }
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
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': apiStageArn + '/apigateway-stage-cache-encryption-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': apiStageArn,
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
                                'Title': '[APIGateway.4] API Gateway Rest API Stages should have cache encryption enabled',
                                'Description': 'API Gateway stage ' + apiStageName + ' for Rest API ' + apiGwApiName + ' has cache encryption enabled.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your API Gateway stage should have caching encryption enabled refer to the Override API Gateway Stage-Level Caching for Method Caching section of the Amazon API Gateway Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html#override-api-gateway-stage-cache-for-method-cache'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': apiStageArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'deploymentId': apiStageDeploymentId,
                                                'stageName': apiStageName
                                            }
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

def api_gateway_stage_xray_tracing_check():
    for restapi in myRestApis:
        apiGwApiId = str(restapi['id'])
        apiGwApiName = str(restapi['name'])
        response = apigateway.get_stages(restApiId=apiGwApiId)
        for apistages in response['item']:
            apiStageName = str(apistages['stageName'])
            apiStageDeploymentId = str(apistages['deploymentId'])
            apiStageArn = 'arn:aws:apigateway:' + awsRegion + '::/restapis/' + apiGwApiId + '/stages/' + apiStageName
            xrayTracingCheck = str(apistages['tracingEnabled'])
            if xrayTracingCheck == 'False':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': apiStageArn + '/apigateway-stage-xray-tracing-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': apiStageArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 20 },
                                'Confidence': 99,
                                'Title': '[APIGateway.5] API Gateway Rest API Stages should have tracing enabled',
                                'Description': 'API Gateway stage ' + apiStageName + ' for Rest API ' + apiGwApiName + ' does not have tracing enabled. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your API Gateway stage should have tracing enabled refer to the Set Up X-Ray Tracing in API Gateway section of the Amazon API Gateway Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-set-up-tracing.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': apiStageArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'deploymentId': apiStageDeploymentId,
                                                'stageName': apiStageName
                                            }
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
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': apiStageArn + '/apigateway-stage-xray-tracing-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': apiStageArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 0 },
                                'Confidence': 99,
                                'Title': '[APIGateway.5] API Gateway Rest API Stages should have tracing enabled',
                                'Description': 'API Gateway stage ' + apiStageName + ' for Rest API ' + apiGwApiName + ' has tracing enabled.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your API Gateway stage should have tracing enabled refer to the Set Up X-Ray Tracing in API Gateway section of the Amazon API Gateway Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-set-up-tracing.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': apiStageArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'deploymentId': apiStageDeploymentId,
                                                'stageName': apiStageName
                                            }
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

def api_gateway_stage_waf_check_check():
    for restapi in myRestApis:
        apiGwApiId = str(restapi['id'])
        apiGwApiName = str(restapi['name'])
        response = apigateway.get_stages(restApiId=apiGwApiId)
        for apistages in response['item']:
            apiStageName = str(apistages['stageName'])
            apiStageDeploymentId = str(apistages['deploymentId'])
            apiStageArn = 'arn:aws:apigateway:' + awsRegion + '::/restapis/' + apiGwApiId + '/stages/' + apiStageName
            try:
                wafCheck = str(apistages['webAclArn'])
                # this is a passing check
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': apiStageArn + '/apigateway-stage-waf-protection-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': apiStageArn,
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
                                'Title': '[APIGateway.6] API Gateway Rest API Stages should be protected by an AWS WAF Web ACL',
                                'Description': 'API Gateway stage ' + apiStageName + ' for Rest API ' + apiGwApiName + ' is protected by an AWS WAF Web ACL.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your API Gateway stage should be protected by WAF refer to the Set Up AWS WAF in API Gateway section of the Amazon API Gateway Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-setup-waf.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': apiStageArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'deploymentId': apiStageDeploymentId,
                                                'stageName': apiStageName
                                            }
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
            except Exception as e:
                if str(e) == "'webAclArn'":
                    try:
                        # ISO Time
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': apiStageArn + '/apigateway-stage-waf-protection-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': apiStageArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Normalized': 80 },
                                    'Confidence': 99,
                                    'Title': '[APIGateway.6] API Gateway Rest API Stages should be protected by an AWS WAF Web ACL',
                                    'Description': 'API Gateway stage ' + apiStageName + ' for Rest API ' + apiGwApiName + ' is not protected by an AWS WAF Web ACL. Refer to the remediation instructions if this configuration is not intended',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'If your API Gateway stage should be protected by WAF refer to the Set Up AWS WAF in API Gateway section of the Amazon API Gateway Developer Guide',
                                            'Url': 'https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-setup-waf.html'
                                        }
                                    },
                                    'ProductFields': {
                                        'Product Name': 'ElectricEye'
                                    },
                                    'Resources': [
                                        {
                                            'Type': 'Other',
                                            'Id': apiStageArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'Other': { 
                                                    'deploymentId': apiStageDeploymentId,
                                                    'stageName': apiStageName
                                                }
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
                    print(e)

def api_gateway_auditor():
    api_gateway_stage_metrics_enabled_check()
    api_gateway_stage_logging_check()
    api_gateway_stage_caching_enabled_check()
    api_gateway_stage_cache_encryption_check()
    api_gateway_stage_xray_tracing_check()
    api_gateway_stage_waf_check_check()

api_gateway_auditor()