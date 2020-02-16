import boto3
import os
import datetime
# import boto3 clients
sts = boto3.client('sts')
kinesis = boto3.client('kinesis')
securityhub = boto3.client('securityhub')
# create env vars
awsRegion = os.environ['AWS_REGION']
awsAccountId = sts.get_caller_identity()['Account']
# loop through kinesis streams
response = kinesis.list_streams(Limit=100)
myKinesisStreams = response['StreamNames']

def kinesis_stream_encryption_check():
    for streams in myKinesisStreams:
        response = kinesis.describe_stream(StreamName=streams)
        streamArn = str(response['StreamDescription']['StreamARN'])
        streamName = str(response['StreamDescription']['StreamName'])
        streamEncryptionCheck = str(response['StreamDescription']['EncryptionType'])
        if streamEncryptionCheck == 'NONE':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': streamArn + '/kinesis-streams-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': streamArn,
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
                            'Title': '[Kinesis.1] Kinesis Data Streams should be encrypted',
                            'Description': 'Kinesis data stream ' + streamName + ' is not encrypted. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Kinesis Data Stream encryption refer to the How Do I Get Started with Server-Side Encryption? section of the Amazon Kinesis Data Streams Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/streams/latest/dev/getting-started-with-sse.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': streamArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'StreamName': streamName
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
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': streamArn + '/kinesis-streams-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': streamArn,
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
                            'Title': '[Kinesis.1] Kinesis Data Streams should be encrypted',
                            'Description': 'Kinesis data stream ' + streamName + ' is encrypted.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Kinesis Data Stream encryption refer to the How Do I Get Started with Server-Side Encryption? section of the Amazon Kinesis Data Streams Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/streams/latest/dev/getting-started-with-sse.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': streamArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'StreamName': streamName
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

def kinesis_enhanced_monitoring_check():
    for streams in myKinesisStreams:
        response = kinesis.describe_stream(StreamName=streams)
        streamArn = str(response['StreamDescription']['StreamARN'])
        streamName = str(response['StreamDescription']['StreamName'])
        streamEnhancedMonitoring = response['StreamDescription']['EnhancedMonitoring']
        for enhancedmonitors in streamEnhancedMonitoring:
            shardLevelMetricCheck = str(enhancedmonitors['ShardLevelMetrics'])
            if shardLevelMetricCheck == '[]':
                try:
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': streamArn + '/kinesis-streams-enhanced-monitoring-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': streamArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 10 },
                                'Confidence': 99,
                                'Title': '[Kinesis.2] Business-critical Kinesis Data Streams should have detailed monitoring configured',
                                'Description': 'Kinesis data stream ' + streamName + ' does not have detailed monitoring configured, detailed monitoring allows shard-level metrics to be delivered every minute at additional cost. Business-critical streams should be considered for this configuration. Refer to the remediation instructions for information on this configuration',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on Kinesis Data Stream enhanced monitoring refer to the Monitoring the Amazon Kinesis Data Streams Service with Amazon CloudWatch section of the Amazon Kinesis Data Streams Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/streams/latest/dev/monitoring-with-cloudwatch.html'
                                    }
                                },
                                'ProductFields': { 'Product Name': 'ElectricEye' },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': streamArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': {
                                                'StreamName': streamName
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
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': streamArn + '/kinesis-streams-enhanced-monitoring-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': streamArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 0 },
                                'Confidence': 99,
                                'Title': '[Kinesis.2] Business-critical Kinesis Data Streams should have detailed monitoring configured',
                                'Description': 'Kinesis data stream ' + streamName + ' has detailed monitoring configured.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on Kinesis Data Stream enhanced monitoring refer to the Monitoring the Amazon Kinesis Data Streams Service with Amazon CloudWatch section of the Amazon Kinesis Data Streams Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/streams/latest/dev/monitoring-with-cloudwatch.html'
                                    }
                                },
                                'ProductFields': { 'Product Name': 'ElectricEye' },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': streamArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': {
                                                'StreamName': streamName
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

def kinesis_data_streams_auditor():
    kinesis_stream_encryption_check()
    kinesis_enhanced_monitoring_check()

kinesis_data_streams_auditor()