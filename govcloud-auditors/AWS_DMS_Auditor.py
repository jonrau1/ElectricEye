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
# create boto3 clients
sts = boto3.client('sts')
dms = boto3.client('dms')
securityhub = boto3.client('securityhub')
# creat env vars
awsAccountId = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']

def dms_replication_instance_public_access_check():
    # loop through dms replication instances
    response = dms.describe_replication_instances()
    for repinstances in response['ReplicationInstances']:
        dmsInstanceId = str(repinstances['ReplicationInstanceIdentifier'])
        dmsInstanceArn = str(repinstances['ReplicationInstanceArn'])
        publicAccessCheck = str(repinstances['PubliclyAccessible'])
        if publicAccessCheck == 'True':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': dmsInstanceArn + '/dms-replication-instance-public-access-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': dmsInstanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'HIGH' },
                            'Confidence': 99,
                            'Title': '[DMS.1] Database Migration Service instances should not be publicly accessible',
                            'Description': 'Database Migration Service instance ' + dmsInstanceId + ' is publicly accessible. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'Public access on DMS instances cannot be changed, however, you can change the subnets that are in the subnet group that is associated with the replication instance to private subnets. For more informaton see the AWS Premium Support post How can I disable public access for an AWS DMS replication instance?.',
                                    'Url': 'https://aws.amazon.com/premiumsupport/knowledge-center/dms-disable-public-access/'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsDmsReplicationInstance',
                                    'Id': dmsInstanceArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'replicationInstanceId': dmsInstanceId }
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
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': dmsInstanceArn + '/dms-replication-instance-public-access-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': dmsInstanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[DMS.1] Database Migration Service instances should not be publicly accessible',
                            'Description': 'Database Migration Service instance ' + dmsInstanceId + ' is not publicly accessible.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'Public access on DMS instances cannot be changed, however, you can change the subnets that are in the subnet group that is associated with the replication instance to private subnets. For more informaton see the AWS Premium Support post How can I disable public access for an AWS DMS replication instance?.',
                                    'Url': 'https://aws.amazon.com/premiumsupport/knowledge-center/dms-disable-public-access/'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsDmsReplicationInstance',
                                    'Id': dmsInstanceArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'replicationInstanceId': dmsInstanceId }
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

def dms_replication_instance_multi_az_check():
    # loop through dms replication instances
    response = dms.describe_replication_instances()
    for repinstances in response['ReplicationInstances']:
        dmsInstanceId = str(repinstances['ReplicationInstanceIdentifier'])
        dmsInstanceArn = str(repinstances['ReplicationInstanceArn'])
        mutltiAzCheck = str(repinstances['MultiAZ'])
        if mutltiAzCheck == 'False':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': dmsInstanceArn + '/dms-replication-instance-multi-az-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': dmsInstanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'LOW' },
                            'Confidence': 99,
                            'Title': '[DMS.2] Database Migration Service instances should have Multi-AZ configured',
                            'Description': 'Database Migration Service instance ' + dmsInstanceId + ' does not have Multi-AZ configured. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on configuring DMS instances for Multi-AZ refer to the Working with an AWS DMS Replication Instance section of the AWS Database Migration Service User Guide',
                                    'Url': 'https://docs.aws.amazon.com/dms/latest/userguide/CHAP_ReplicationInstance.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsDmsReplicationInstance',
                                    'Id': dmsInstanceArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'replicationInstanceId': dmsInstanceId }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'FAILED',
                                'RelatedRequirements': [
                                    'NIST CSF ID.BE-5', 
                                    'NIST CSF PR.PT-5',
                                    'NIST SP 800-53 CP-2',
                                    'NIST SP 800-53 CP-11',
                                    'NIST SP 800-53 SA-13',
                                    'NIST SP 800-53 SA14',
                                    'AICPA TSC CC3.1',
                                    'AICPA TSC A1.2',
                                    'ISO 27001:2013 A.11.1.4',
                                    'ISO 27001:2013 A.17.1.1',
                                    'ISO 27001:2013 A.17.1.2',
                                    'ISO 27001:2013 A.17.2.1'
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
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': dmsInstanceArn + '/dms-replication-instance-multi-az-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': dmsInstanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[DMS.2] Database Migration Service instances should have Multi-AZ configured',
                            'Description': 'Database Migration Service instance ' + dmsInstanceId + ' has Multi-AZ configured.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on configuring DMS instances for Multi-AZ refer to the Working with an AWS DMS Replication Instance section of the AWS Database Migration Service User Guide',
                                    'Url': 'https://docs.aws.amazon.com/dms/latest/userguide/CHAP_ReplicationInstance.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsDmsReplicationInstance',
                                    'Id': dmsInstanceArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'replicationInstanceId': dmsInstanceId }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'PASSED',
                                'RelatedRequirements': [
                                    'NIST CSF ID.BE-5', 
                                    'NIST CSF PR.PT-5',
                                    'NIST SP 800-53 CP-2',
                                    'NIST SP 800-53 CP-11',
                                    'NIST SP 800-53 SA-13',
                                    'NIST SP 800-53 SA14',
                                    'AICPA TSC CC3.1',
                                    'AICPA TSC A1.2',
                                    'ISO 27001:2013 A.11.1.4',
                                    'ISO 27001:2013 A.17.1.1',
                                    'ISO 27001:2013 A.17.1.2',
                                    'ISO 27001:2013 A.17.2.1'
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

def dms_replication_instance_minor_version_update_check():
    # loop through dms replication instances
    response = dms.describe_replication_instances()
    for repinstances in response['ReplicationInstances']:
        dmsInstanceId = str(repinstances['ReplicationInstanceIdentifier'])
        dmsInstanceArn = str(repinstances['ReplicationInstanceArn'])
        minorVersionUpgradeCheck = str(repinstances['AutoMinorVersionUpgrade'])
        if minorVersionUpgradeCheck == 'False':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': dmsInstanceArn + '/dms-replication-instance-minor-version-auto-update-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': dmsInstanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'LOW' },
                            'Confidence': 99,
                            'Title': '[DMS.2] Database Migration Service instances should be configured to have minor version updates be automatically applied',
                            'Description': 'Database Migration Service instance ' + dmsInstanceId + ' is not configured to have minor version updates be automatically applied. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on configuring DMS instances for minor version updates refer to the AWS DMS Maintenance section of the AWS Database Migration Service User Guide',
                                    'Url': 'https://docs.amazonaws.cn/en_us/dms/latest/userguide/CHAP_ReplicationInstance.html#CHAP_ReplicationInstance.Maintenance'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsDmsReplicationInstance',
                                    'Id': dmsInstanceArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'replicationInstanceId': dmsInstanceId }
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
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': dmsInstanceArn + '/dms-replication-instance-minor-version-auto-update-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': dmsInstanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[DMS.2] Database Migration Service instances should be configured to have minor version updates be automatically applied',
                            'Description': 'Database Migration Service instance ' + dmsInstanceId + ' is configured to have minor version updates be automatically applied.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on configuring DMS instances for minor version updates refer to the AWS DMS Maintenance section of the AWS Database Migration Service User Guide',
                                    'Url': 'https://docs.amazonaws.cn/en_us/dms/latest/userguide/CHAP_ReplicationInstance.html#CHAP_ReplicationInstance.Maintenance'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsDmsReplicationInstance',
                                    'Id': dmsInstanceArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'replicationInstanceId': dmsInstanceId }
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

def dms_auditor():
    dms_replication_instance_public_access_check()
    dms_replication_instance_multi_az_check()
    dms_replication_instance_minor_version_update_check()

dms_auditor()