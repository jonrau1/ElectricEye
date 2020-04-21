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
# import boto3 clients
securityhub = boto3.client('securityhub')
amzmq = boto3.client('mq')
sts = boto3.client('sts')
# create account id & region variables
awsAccountId = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']
# loop through Amazon MQ Brokers
try:
    response = amzmq.list_brokers(MaxResults=100)
    myBrokers = response['BrokerSummaries']
except Exception as e:
    print(e)

def broker_kms_cmk_check():
    for broker in myBrokers:
        brokerName = str(broker['BrokerName'])
        try:
            response = amzmq.describe_broker(BrokerId=brokerName)
            brokerArn = str(response['BrokerArn'])
            brokerId = str(response['BrokerId'])
            kmsCmkCheck = str(response['EncryptionOptions']['UseAwsOwnedKey'])
            if kmsCmkCheck == 'True':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': brokerArn + '/amazonmq-broker-kms-cmk-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': brokerArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'LOW' },
                                'Confidence': 99,
                                'Title': '[AmazonMQ.1] AmazonMQ message brokers should use customer-managed KMS CMKs for encryption',
                                'Description': 'AmazonMQ broker ' + brokerName + ' does not use a customer-managed KMS CMK for encryption. Customer managed CMKs are CMKs in your AWS account that you create, own, and manage. You have full control over these CMKs, including establishing and maintaining their key policies, IAM policies, and grants, enabling and disabling them, rotating their cryptographic material, adding tags, creating aliases that refer to the CMK, and scheduling the CMKs for deletion. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on encryption at rest considerations for Amazon MQ refer to the Encryption at Rest section of the Amazon MQ Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-encryption.html#encryption-at-rest'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsMqMessageBroker',
                                        'Id': brokerArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'brokerName': brokerName,
                                                'brokerId': brokerId
                                            }
                                        }
                                    }
                                ],
                                'Compliance': { 
                                    'Status': 'FAILED',
                                    'RelatedRequirements': [
                                        'NIST CSF PR.DS-1', 
                                        'NIST SP 800-53 MP-8',
                                        'NIST SP 800-53 SC-12',
                                        'NIST SP 800-53 SC-28',
                                        'AICPA TSC CC6.1',
                                        'ISO 27001:2013 A.8.2.3'
                                    ]
                                },
                                'Workflow': {
                                    'Status': 'NEW'
                                },
                                'RecordState': 'ACTIVE'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
            else:
                kmsKeyId = str(response['EncryptionOptions']['KmsKeyId'])
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': brokerArn + '/amazonmq-broker-kms-cmk-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': brokerArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'INFORMATIONAL' },
                                'Confidence': 99,
                                'Title': '[AmazonMQ.1] AmazonMQ message brokers should use customer-managed KMS CMKs for encryption',
                                'Description': 'AmazonMQ broker ' + brokerName + ' uses a customer-managed KMS CMK for encryption.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on encryption at rest considerations for Amazon MQ refer to the Encryption at Rest section of the Amazon MQ Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-encryption.html#encryption-at-rest'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsMqMessageBroker',
                                        'Id': brokerArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'brokerName': brokerName,
                                                'brokerId': brokerId,
                                                'kmsKeyId': kmsKeyId
                                            }
                                        }
                                    }
                                ],
                                'Compliance': { 
                                    'Status': 'PASSED',
                                    'RelatedRequirements': [
                                        'NIST CSF PR.DS-1', 
                                        'NIST SP 800-53 MP-8',
                                        'NIST SP 800-53 SC-12',
                                        'NIST SP 800-53 SC-28',
                                        'AICPA TSC CC6.1',
                                        'ISO 27001:2013 A.8.2.3'
                                    ]
                                },
                                'Workflow': {
                                    'Status': 'RESOLVED'
                                },
                                'RecordState': 'ARCHIVED'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)

def broker_audit_logging_check():
    for broker in myBrokers:
        brokerName = str(broker['BrokerName'])
        try:
            response = amzmq.describe_broker(BrokerId=brokerName)
            brokerArn = str(response['BrokerArn'])
            brokerId = str(response['BrokerId'])
            auditLogCheck = str(response['Logs']['Audit'])
            if auditLogCheck == 'False':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': brokerArn + '/amazonmq-broker-audit-logging-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': brokerArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'LOW' },
                                'Confidence': 99,
                                'Title': '[AmazonMQ.2] AmazonMQ message brokers should have audit logging enabled',
                                'Description': 'AmazonMQ broker ' + brokerName + ' does not have audit logging enabled. Audit logging enables logging of management actions taken using JMX or using the ActiveMQ Web Console and publishes audit.log to a log group in CloudWatch. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on message broker logging refer to the Understanding the Structure of Logging in CloudWatch Logs section of the Amazon MQ Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-configuring-cloudwatch-logs.html#structure-of-logging-cloudwatch-logs'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsMqMessageBroker',
                                        'Id': brokerArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'brokerName': brokerName,
                                                'brokerId': brokerId
                                            }
                                        }
                                    }
                                ],
                                'Compliance': { 
                                    'Status': 'FAILED',
                                    'RelatedRequirements': [
                                        'NIST CSF DE.AE-3',
                                        'NIST SP 800-53 AU-6',
                                        'NIST SP 800-53 CA-7',
                                        'NIST SP 800-53 IR-4',
                                        'NIST SP 800-53 IR-5',
                                        'NIST SP 800-53 IR-8', 
                                        'NIST SP 800-53 SI-4',
                                        'AICPA TSC CC7.2',
                                        'ISO 27001:2013 A.12.4.1',
                                        'ISO 27001:2013 A.16.1.7'
                                    ]
                                },
                                'Workflow': {
                                    'Status': 'NEW'
                                },
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
                                'Id': brokerArn + '/amazonmq-broker-audit-logging-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': brokerArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'INFORMATIONAL' },
                                'Confidence': 99,
                                'Title': '[AmazonMQ.2] AmazonMQ message brokers should have audit logging enabled',
                                'Description': 'AmazonMQ broker ' + brokerName + ' has audit logging enabled.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on message broker logging refer to the Understanding the Structure of Logging in CloudWatch Logs section of the Amazon MQ Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-configuring-cloudwatch-logs.html#structure-of-logging-cloudwatch-logs'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsMqMessageBroker',
                                        'Id': brokerArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'brokerName': brokerName,
                                                'brokerId': brokerId
                                            }
                                        }
                                    }
                                ],
                                'Compliance': { 
                                    'Status': 'PASSED',
                                    'RelatedRequirements': [
                                        'NIST CSF DE.AE-3',
                                        'NIST SP 800-53 AU-6',
                                        'NIST SP 800-53 CA-7',
                                        'NIST SP 800-53 IR-4',
                                        'NIST SP 800-53 IR-5',
                                        'NIST SP 800-53 IR-8', 
                                        'NIST SP 800-53 SI-4',
                                        'AICPA TSC CC7.2',
                                        'ISO 27001:2013 A.12.4.1',
                                        'ISO 27001:2013 A.16.1.7'
                                    ]
                                },
                                'Workflow': {
                                    'Status': 'RESOLVED'
                                },
                                'RecordState': 'ARCHIVED'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)

def broker_general_logging_check():
    for broker in myBrokers:
        brokerName = str(broker['BrokerName'])
        try:
            response = amzmq.describe_broker(BrokerId=brokerName)
            brokerArn = str(response['BrokerArn'])
            brokerId = str(response['BrokerId'])
            genLogCheck = str(response['Logs']['General'])
            if genLogCheck == 'False':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': brokerArn + '/amazonmq-broker-general-logging-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': brokerArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'LOW' },
                                'Confidence': 99,
                                'Title': '[AmazonMQ.3] AmazonMQ message brokers should have general logging enabled',
                                'Description': 'AmazonMQ broker ' + brokerName + ' does not have general logging enabled. General logging enables the default INFO logging level (DEBUG logging isnt supported) and publishes activemq.log to a log group in CloudWatch. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on message broker logging refer to the Understanding the Structure of Logging in CloudWatch Logs section of the Amazon MQ Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-configuring-cloudwatch-logs.html#structure-of-logging-cloudwatch-logs'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsMqMessageBroker',
                                        'Id': brokerArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'brokerName': brokerName,
                                                'brokerId': brokerId
                                            }
                                        }
                                    }
                                ],
                                'Compliance': { 
                                    'Status': 'FAILED',
                                    'RelatedRequirements': [
                                        'NIST CSF DE.AE-3',
                                        'NIST SP 800-53 AU-6',
                                        'NIST SP 800-53 CA-7',
                                        'NIST SP 800-53 IR-4',
                                        'NIST SP 800-53 IR-5',
                                        'NIST SP 800-53 IR-8', 
                                        'NIST SP 800-53 SI-4',
                                        'AICPA TSC CC7.2',
                                        'ISO 27001:2013 A.12.4.1',
                                        'ISO 27001:2013 A.16.1.7'
                                    ]
                                },
                                'Workflow': {
                                    'Status': 'NEW'
                                },
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
                                'Id': brokerArn + '/amazonmq-broker-general-logging-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': brokerArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'INFORMATIONAL' },
                                'Confidence': 99,
                                'Title': '[AmazonMQ.3] AmazonMQ message brokers should have general logging enabled',
                                'Description': 'AmazonMQ broker ' + brokerName + ' has general logging enabled.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on message broker logging refer to the Understanding the Structure of Logging in CloudWatch Logs section of the Amazon MQ Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-configuring-cloudwatch-logs.html#structure-of-logging-cloudwatch-logs'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsMqMessageBroker',
                                        'Id': brokerArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'brokerName': brokerName,
                                                'brokerId': brokerId
                                            }
                                        }
                                    }
                                ],
                                'Compliance': { 
                                    'Status': 'PASSED',
                                    'RelatedRequirements': [
                                        'NIST CSF DE.AE-3',
                                        'NIST SP 800-53 AU-6',
                                        'NIST SP 800-53 CA-7',
                                        'NIST SP 800-53 IR-4',
                                        'NIST SP 800-53 IR-5',
                                        'NIST SP 800-53 IR-8', 
                                        'NIST SP 800-53 SI-4',
                                        'AICPA TSC CC7.2',
                                        'ISO 27001:2013 A.12.4.1',
                                        'ISO 27001:2013 A.16.1.7'
                                    ]
                                },
                                'Workflow': {
                                    'Status': 'RESOLVED'
                                },
                                'RecordState': 'ARCHIVED'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)

def broker_public_access_check():
    for broker in myBrokers:
        brokerName = str(broker['BrokerName'])
        try:
            response = amzmq.describe_broker(BrokerId=brokerName)
            brokerArn = str(response['BrokerArn'])
            brokerId = str(response['BrokerId'])
            publicAccessCheck = str(response['PubliclyAccessible'])
            if publicAccessCheck == 'True':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': brokerArn + '/amazonmq-public-accessible-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': brokerArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 
                                    'Software and Configuration Checks/AWS Security Best Practices',
                                    'Effects/Data Exposure' 
                                ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'CRITICAL' },
                                'Confidence': 99,
                                'Title': '[AmazonMQ.4] AmazonMQ message brokers should not be publicly accessible',
                                'Description': 'AmazonMQ broker ' + brokerName + ' is publicly accessible. Brokers created without public accessibility cannot be accessed from outside of your VPC. This greatly reduces your susceptibility to Distributed Denial of Service (DDoS) attacks from the public internet. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on message broker accessibility through a VPC refer to the Accessing the ActiveMQ Web Console of a Broker without Public Accessibility section of the Amazon MQ Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/accessing-web-console-of-broker-without-private-accessibility.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsMqMessageBroker',
                                        'Id': brokerArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'brokerName': brokerName,
                                                'brokerId': brokerId
                                            }
                                        }
                                    }
                                ],
                                'Compliance': { 
                                    'Status': 'FAILED',
                                    'RelatedRequirements': [
                                        'NIST CSF PR.AC-3',
                                        'NIST SP 800-53 AC-1',
                                        'NIST SP 800-53 AC-17',
                                        'NIST SP 800-53 AC-19',
                                        'NIST SP 800-53 AC-20',
                                        'NIST SP 800-53 SC-15',
                                        'AICPA TSC CC6.6',
                                        'ISO 27001:2013 A.6.2.1',
                                        'ISO 27001:2013 A.6.2.2',
                                        'ISO 27001:2013 A.11.2.6',
                                        'ISO 27001:2013 A.13.1.1',
                                        'ISO 27001:2013 A.13.2.1'
                                    ]
                                },
                                'Workflow': {
                                    'Status': 'NEW'
                                },
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
                                'Id': brokerArn + '/amazonmq-public-accessible-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': brokerArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 
                                    'Software and Configuration Checks/AWS Security Best Practices',
                                    'Effects/Data Exposure' 
                                ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'INFORMATIONAL' },
                                'Confidence': 99,
                                'Title': '[AmazonMQ.4] AmazonMQ message brokers should not be publicly accessible',
                                'Description': 'AmazonMQ broker ' + brokerName + ' is not publicly accessible.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on message broker accessibility through a VPC refer to the Accessing the ActiveMQ Web Console of a Broker without Public Accessibility section of the Amazon MQ Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/accessing-web-console-of-broker-without-private-accessibility.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsMqMessageBroker',
                                        'Id': brokerArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'brokerName': brokerName,
                                                'brokerId': brokerId
                                            }
                                        }
                                    }
                                ],
                                'Compliance': { 
                                    'Status': 'PASSED',
                                    'RelatedRequirements': [
                                        'NIST CSF PR.AC-3',
                                        'NIST SP 800-53 AC-1',
                                        'NIST SP 800-53 AC-17',
                                        'NIST SP 800-53 AC-19',
                                        'NIST SP 800-53 AC-20',
                                        'NIST SP 800-53 SC-15',
                                        'AICPA TSC CC6.6',
                                        'ISO 27001:2013 A.6.2.1',
                                        'ISO 27001:2013 A.6.2.2',
                                        'ISO 27001:2013 A.11.2.6',
                                        'ISO 27001:2013 A.13.1.1',
                                        'ISO 27001:2013 A.13.2.1'
                                    ]
                                },
                                'Workflow': {
                                    'Status': 'RESOLVED'
                                },
                                'RecordState': 'ARCHIVED'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)

def broker_minor_version_auto_upgrade_check():
    for broker in myBrokers:
        brokerName = str(broker['BrokerName'])
        try:
            response = amzmq.describe_broker(BrokerId=brokerName)
            brokerArn = str(response['BrokerArn'])
            brokerId = str(response['BrokerId'])
            autoUpgrMinorVersionCheck = str(response['AutoMinorVersionUpgrade'])
            if autoUpgrMinorVersionCheck == 'False':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': brokerArn + '/amazonmq-auto-minor-version-upgrade-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': brokerArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'LOW' },
                                'Confidence': 99,
                                'Title': '[AmazonMQ.5] AmazonMQ message brokers should be configured to automatically upgrade to the latest minor version',
                                'Description': 'AmazonMQ broker ' + brokerName + ' is not configured to automatically upgrade to the latest minor version. To upgrade the broker to new versions as AWS releases them, choose Enable automatic minor version upgrades. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on message broker auto upgrades refer to the Tutorial: Editing Broker Engine Version, Instance Type, CloudWatch Logs, and Maintenance Preferences section of the Amazon MQ Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-editing-broker-preferences.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsMqMessageBroker',
                                        'Id': brokerArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'brokerName': brokerName,
                                                'brokerId': brokerId
                                            }
                                        }
                                    }
                                ],
                                'Compliance': { 
                                    'Status': 'FAILED',
                                    'RelatedRequirements': [
                                        'NIST CSF PR.MA-1',
                                        'NIST SP 800-53 MA-2',
                                        'NIST SP 800-53 MA-3',
                                        'NIST SP 800-53 MA-5',
                                        'NIST SP 800-53 MA-6',
                                        'AICPA TSC CC8.1',
                                        'ISO 27001:2013 A.11.1.2',
                                        'ISO 27001:2013 A.11.2.4',
                                        'ISO 27001:2013 A.11.2.5',
                                        'ISO 27001:2013 A.11.2.6'
                                    ]
                                },
                                'Workflow': {
                                    'Status': 'NEW'
                                },
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
                                'Id': brokerArn + '/amazonmq-auto-minor-version-upgrade-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': brokerArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'INFORMATIONAL' },
                                'Confidence': 99,
                                'Title': '[AmazonMQ.5] AmazonMQ message brokers should be configured to automatically upgrade to the latest minor version',
                                'Description': 'AmazonMQ broker ' + brokerName + ' is configured to automatically upgrade to the latest minor version.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on message broker auto upgrades refer to the Tutorial: Editing Broker Engine Version, Instance Type, CloudWatch Logs, and Maintenance Preferences section of the Amazon MQ Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-editing-broker-preferences.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsMqMessageBroker',
                                        'Id': brokerArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 
                                                'brokerName': brokerName,
                                                'brokerId': brokerId
                                            }
                                        }
                                    }
                                ],
                                'Compliance': { 
                                    'Status': 'PASSED',
                                    'RelatedRequirements': [
                                        'NIST CSF PR.MA-1',
                                        'NIST SP 800-53 MA-2',
                                        'NIST SP 800-53 MA-3',
                                        'NIST SP 800-53 MA-5',
                                        'NIST SP 800-53 MA-6',
                                        'AICPA TSC CC8.1',
                                        'ISO 27001:2013 A.11.1.2',
                                        'ISO 27001:2013 A.11.2.4',
                                        'ISO 27001:2013 A.11.2.5',
                                        'ISO 27001:2013 A.11.2.6'
                                    ]
                                },
                                'Workflow': {
                                    'Status': 'RESOLVED'
                                },
                                'RecordState': 'ARCHIVED'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)

def amazon_mq_auditor():
    broker_kms_cmk_check()
    broker_audit_logging_check()
    broker_general_logging_check()
    broker_public_access_check()
    broker_minor_version_auto_upgrade_check()

amazon_mq_auditor()