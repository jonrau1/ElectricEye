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
import os
import datetime
# import boto3 clients
sts = boto3.client('sts')
neptune = boto3.client('neptune')
securityhub = boto3.client('securityhub')
# create env vars
awsRegion = os.environ['AWS_REGION']
awsAccountId = sts.get_caller_identity()['Account']
# loop through neptune instances
neptune_instances = neptune.describe_db_instances(Filters=[ { 'Name': 'engine','Values': [ 'neptune' ] } ])

def neptune_instance_multi_az_check():
    for instances in neptune_instances['DBInstances']:
        neptuneInstanceArn = str(instances['DBInstanceArn'])
        neptuneDbId = str(instances['DBInstanceIdentifier'])
        mutliAzCheck = str(instances['MultiAZ'])
        if mutliAzCheck == 'False':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': neptuneInstanceArn + '/neptune-instance-ha-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': neptuneInstanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 20 },
                            'Confidence': 99,
                            'Title': '[Neptune.1] Neptune database instances should be configured to be highly available',
                            'Description': 'Neptune database instance ' + neptuneDbId + ' does not have Multi-AZ enabled and thus is not highly available. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Neptune High Availability and how to configure it refer to the High Availability for Neptune section of the Amazon Neptune User Guide',
                                    'Url': 'https://docs.aws.amazon.com/neptune/latest/userguide/feature-overview-availability.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': neptuneInstanceArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'InstanceId': neptuneDbId
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
                            'Id': neptuneInstanceArn + '/neptune-instance-ha-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': neptuneInstanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[Neptune.1] Neptune database instances should be configured to be highly available',
                            'Description': 'Neptune database instance ' + neptuneDbId + ' is highly available.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Neptune High Availability and how to configure it refer to the High Availability for Neptune section of the Amazon Neptune User Guide',
                                    'Url': 'https://docs.aws.amazon.com/neptune/latest/userguide/feature-overview-availability.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': neptuneInstanceArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'InstanceId': neptuneDbId
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

def neptune_instance_storage_encryption_check():
    for instances in neptune_instances['DBInstances']:
        neptuneInstanceArn = str(instances['DBInstanceArn'])
        neptuneDbId = str(instances['DBInstanceIdentifier'])
        storageEncryptionCheck = str(instances['StorageEncrypted'])
        if storageEncryptionCheck == 'False':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': neptuneInstanceArn + '/neptune-instance-storage-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': neptuneInstanceArn,
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
                            'Title': '[Neptune.2] Neptune database instace storage should be encrypted',
                            'Description': 'Neptune database instance ' + neptuneDbId + ' does not have storage encryption enabled. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Neptune storage encryption and how to configure it refer to the Enabling Encryption for a Neptune DB Instance section of the Amazon Neptune User Guide',
                                    'Url': 'https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html#encrypt-enable'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': neptuneInstanceArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'InstanceId': neptuneDbId
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
                            'Id': neptuneInstanceArn + '/neptune-instance-storage-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': neptuneInstanceArn,
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
                            'Title': '[Neptune.2] Neptune database instace storage should be encrypted',
                            'Description': 'Neptune database instance ' + neptuneDbId + ' has storage encryption enabled.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Neptune storage encryption and how to configure it refer to the Enabling Encryption for a Neptune DB Instance section of the Amazon Neptune User Guide',
                                    'Url': 'https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html#encrypt-enable'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': neptuneInstanceArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'InstanceId': neptuneDbId
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

def neptune_instance_iam_authentication_check():
    for instances in neptune_instances['DBInstances']:
        neptuneInstanceArn = str(instances['DBInstanceArn'])
        neptuneDbId = str(instances['DBInstanceIdentifier'])
        iamDbAuthCheck = str(instances['IAMDatabaseAuthenticationEnabled'])
        if iamDbAuthCheck == 'False':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': neptuneInstanceArn + '/neptune-instance-iam-db-auth-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': neptuneInstanceArn,
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
                            'Title': '[Neptune.3] Neptune database instaces storage should use IAM Database Authentication',
                            'Description': 'Neptune database instance ' + neptuneDbId + ' does not use IAM Database Authentication. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Neptune IAM Database Authentication and how to configure it refer to the Neptune Database Authentication Using IAM section of the Amazon Neptune User Guide',
                                    'Url': 'https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': neptuneInstanceArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'InstanceId': neptuneDbId
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
                            'Id': neptuneInstanceArn + '/neptune-instance-iam-db-auth-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': neptuneInstanceArn,
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
                            'Title': '[Neptune.3] Neptune database instaces storage should use IAM Database Authentication',
                            'Description': 'Neptune database instance ' + neptuneDbId + ' uses IAM Database Authentication.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Neptune IAM Database Authentication and how to configure it refer to the Neptune Database Authentication Using IAM section of the Amazon Neptune User Guide',
                                    'Url': 'https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': neptuneInstanceArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'InstanceId': neptuneDbId
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

def neptune_cluster_parameter_ssl_enforcement_check():
    response = neptune.describe_db_cluster_parameter_groups()
    for parametergroup in response['DBClusterParameterGroups']:
        parameterGroupName = str(parametergroup['DBClusterParameterGroupName'])
        parameterGroupArn = str(parametergroup['DBClusterParameterGroupArn'])
        response = neptune.describe_db_cluster_parameters(DBClusterParameterGroupName=parameterGroupName)
        for parameters in response['Parameters']:
            if str(parameters['ParameterName']) == 'neptune_enforce_ssl':
                sslEnforcementCheck = str(parameters['ParameterValue'])
                if sslEnforcementCheck == '0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': parameterGroupArn + '/neptune-cluster-param-group-ssl-enforcement-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': parameterGroupArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Normalized': 60 },
                                    'Confidence': 99,
                                    'Title': '[Neptune.4] Neptune cluster parameter groups should enforce SSL connections to Neptune databases',
                                    'Description': 'Neptune cluster parameter group ' + parameterGroupName + ' does not enforce SSL connections. Refer to the remediation instructions to remediate this behavior',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on enforcing SSL/HTTPS connections to Neptune instances refer to the Encryption in Transit: Connecting to Neptune Using SSL/HTTPS section of the Amazon Neptune User Guide.',
                                            'Url': 'https://docs.aws.amazon.com/neptune/latest/userguide/security-ssl.html'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'Other',
                                            'Id': parameterGroupArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'Other': { 'ParameterGroupName': parameterGroupName }
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
                                    'Id': parameterGroupArn + '/neptune-cluster-param-group-ssl-enforcement-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': parameterGroupArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Normalized': 0 },
                                    'Confidence': 99,
                                    'Title': '[Neptune.4] Neptune cluster parameter groups should enforce SSL connections to Neptune databases',
                                    'Description': 'Neptune cluster parameter group ' + parameterGroupName + ' enforces SSL connections.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on enforcing SSL/HTTPS connections to Neptune instances refer to the Encryption in Transit: Connecting to Neptune Using SSL/HTTPS section of the Amazon Neptune User Guide.',
                                            'Url': 'https://docs.aws.amazon.com/neptune/latest/userguide/security-ssl.html'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'Other',
                                            'Id': parameterGroupArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'Other': { 'ParameterGroupName': parameterGroupName }
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
            else:
                pass

def neptune_cluster_parameter_audit_log_check():
    response = neptune.describe_db_cluster_parameter_groups()
    for parametergroup in response['DBClusterParameterGroups']:
        parameterGroupName = str(parametergroup['DBClusterParameterGroupName'])
        parameterGroupArn = str(parametergroup['DBClusterParameterGroupArn'])
        response = neptune.describe_db_cluster_parameters(DBClusterParameterGroupName=parameterGroupName)
        for parameters in response['Parameters']:
            if str(parameters['ParameterName']) == 'neptune_enable_audit_log':
                auditLogCheck = str(parameters['ParameterValue'])
                if auditLogCheck == '0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': parameterGroupArn + '/neptune-cluster-param-group-audit-logging-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': parameterGroupArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Normalized': 40 },
                                    'Confidence': 99,
                                    'Title': '[Neptune.5] Neptune cluster parameter groups should enforce audit logging for Neptune databases',
                                    'Description': 'Neptune cluster parameter group ' + parameterGroupName + ' does not enforce audit logging. Refer to the remediation instructions to remediate this behavior',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on audit logging for Neptune instances refer to the Enabling Neptune Audit Logs section of the Amazon Neptune User Guide.',
                                            'Url': 'https://docs.aws.amazon.com/neptune/latest/userguide/auditing.html#auditing-enable'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'Other',
                                            'Id': parameterGroupArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'Other': { 'ParameterGroupName': parameterGroupName }
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
                                    'Id': parameterGroupArn + '/neptune-cluster-param-group-audit-logging-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': parameterGroupArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Normalized': 0 },
                                    'Confidence': 99,
                                    'Title': '[Neptune.5] Neptune cluster parameter groups should enforce audit logging for Neptune databases',
                                    'Description': 'Neptune cluster parameter group ' + parameterGroupName + ' enforces audit logging.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on audit logging for Neptune instances refer to the Enabling Neptune Audit Logs section of the Amazon Neptune User Guide.',
                                            'Url': 'https://docs.aws.amazon.com/neptune/latest/userguide/auditing.html#auditing-enable'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'Other',
                                            'Id': parameterGroupArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'Other': { 'ParameterGroupName': parameterGroupName }
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
            else:
                pass

def neptune_auditor():
    neptune_instance_multi_az_check()
    neptune_instance_storage_encryption_check()
    neptune_instance_iam_authentication_check()
    neptune_cluster_parameter_ssl_enforcement_check()
    neptune_cluster_parameter_audit_log_check()

neptune_auditor()