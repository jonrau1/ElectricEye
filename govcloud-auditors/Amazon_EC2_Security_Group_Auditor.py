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
ec2 = boto3.client('ec2')
securityhub = boto3.client('securityhub')
# create env vars
awsRegion = os.environ['AWS_REGION']
awsAccountId = sts.get_caller_identity()['Account']
# loop through security groups
response = ec2.describe_security_groups()
mySgs = response['SecurityGroups']

def security_group_all_open_check():
    for secgroup in mySgs:
        sgName = str(secgroup['GroupName'])
        sgId = str(secgroup['GroupId'])
        sgArn = 'arn:aws-us-gov:ec2:' + awsRegion + ':' + awsAccountId + ':security-group/' + sgId
        for permissions in secgroup['IpPermissions']:
            try:
                fromPort = str(permissions['FromPort'])
            except Exception as e:
                if str(e) == "'FromPort'":
                    pass
                else:
                    print(e)
            try:
                toPort = str(permissions['ToPort'])
            except Exception as e:
                if str(e) == "'ToPort'":
                    pass
                else:
                    print(e)
            try:
                ipProtocol = str(permissions['IpProtocol'])
            except Exception as e:
                print(e)
            ipRanges = permissions['IpRanges']
            for cidrs in ipRanges:
                cidrIpRange = str(cidrs['CidrIp'])
                if ipProtocol == '-1' and cidrIpRange == '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-all-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.1] Security groups should not allow unrestricted access to all ports and protocols',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted access to all ports and protocols. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                elif ipProtocol == '-1' and cidrIpRange != '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-all-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.1] Security groups should not allow unrestricted access to all ports and protocols',
                                    'Description': 'Security group ' + sgName + ' does not allow unrestricted access to all ports and protocols. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                else:
                    pass

def security_group_open_ftp_check():
    for secgroup in mySgs:
        sgName = str(secgroup['GroupName'])
        sgId = str(secgroup['GroupId'])
        sgArn = 'arn:aws-us-gov:ec2:' + awsRegion + ':' + awsAccountId + ':security-group/' + sgId
        for permissions in secgroup['IpPermissions']:
            try:
                fromPort = str(permissions['FromPort'])
            except Exception as e:
                if str(e) == "'FromPort'":
                    pass
                else:
                    print(e)
            try:
                toPort = str(permissions['ToPort'])
            except Exception as e:
                if str(e) == "'ToPort'":
                    pass
                else:
                    print(e)
            try:
                ipProtocol = str(permissions['IpProtocol'])
            except Exception as e:
                print(e)
            ipRanges = permissions['IpRanges']
            for cidrs in ipRanges:
                cidrIpRange = str(cidrs['CidrIp'])
                if toPort =='20' and fromPort == '21' and cidrIpRange == '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-ftp-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'MEDIUM' },
                                    'Confidence': 99,
                                    'Title': '[SecurityGroup.2] Security groups should not allow unrestricted File Transfer Protocol (FTP) access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted File Transfer Protocol (FTP) access on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                elif toPort =='20' and fromPort == '21' and cidrIpRange != '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-ftp-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.2] Security groups should not allow unrestricted File Transfer Protocol (FTP) access',
                                    'Description': 'Security group ' + sgName + ' does not allow unrestricted File Transfer Protocol (FTP) access on ' + ipProtocol + '. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                else:
                    pass

def security_group_open_telnet_check():
    for secgroup in mySgs:
        sgName = str(secgroup['GroupName'])
        sgId = str(secgroup['GroupId'])
        sgArn = 'arn:aws-us-gov:ec2:' + awsRegion + ':' + awsAccountId + ':security-group/' + sgId
        for permissions in secgroup['IpPermissions']:
            try:
                fromPort = str(permissions['FromPort'])
            except Exception as e:
                if str(e) == "'FromPort'":
                    pass
                else:
                    print(e)
            try:
                toPort = str(permissions['ToPort'])
            except Exception as e:
                if str(e) == "'ToPort'":
                    pass
                else:
                    print(e)
            try:
                ipProtocol = str(permissions['IpProtocol'])
            except Exception as e:
                print(e)
            ipRanges = permissions['IpRanges']
            for cidrs in ipRanges:
                cidrIpRange = str(cidrs['CidrIp'])
                if toPort and fromPort == '23' and cidrIpRange == '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-telnet-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'MEDIUM' },
                                    'Confidence': 99,
                                    'Title': '[SecurityGroup.3] Security groups should not allow unrestricted TelNet access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted TelNet access on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                elif toPort and fromPort == '23' and cidrIpRange != '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-telnet-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.3] Security groups should not allow unrestricted TelNet access',
                                    'Description': 'Security group ' + sgName + ' does not allow unrestricted TelNet access on ' + ipProtocol + '. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                else:
                    pass

def security_group_open_dcom_rpc_check():
    for secgroup in mySgs:
        sgName = str(secgroup['GroupName'])
        sgId = str(secgroup['GroupId'])
        sgArn = 'arn:aws-us-gov:ec2:' + awsRegion + ':' + awsAccountId + ':security-group/' + sgId
        for permissions in secgroup['IpPermissions']:
            try:
                fromPort = str(permissions['FromPort'])
            except Exception as e:
                if str(e) == "'FromPort'":
                    pass
                else:
                    print(e)
            try:
                toPort = str(permissions['ToPort'])
            except Exception as e:
                if str(e) == "'ToPort'":
                    pass
                else:
                    print(e)
            try:
                ipProtocol = str(permissions['IpProtocol'])
            except Exception as e:
                print(e)
            ipRanges = permissions['IpRanges']
            for cidrs in ipRanges:
                cidrIpRange = str(cidrs['CidrIp'])
                if toPort and fromPort == '135' and cidrIpRange == '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-telnet-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'MEDIUM' },
                                    'Confidence': 99,
                                    'Title': '[SecurityGroup.4] Security groups should not allow unrestricted Windows RPC DCOM access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted Windows RPC DCOM access on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ThreatIntelIndicators': [
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Attack signature information, refer to Threatl Intel Source URL',
                                            'Source': 'Symantec Security Center',
                                            'SourceUrl': 'https://www.symantec.com/security_response/attacksignatures/detail.jsp?asid=20387'
                                        }
                                    ],
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                if toPort and fromPort == '135' and cidrIpRange != '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-wsrpc-dcom-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.4] Security groups should not allow unrestricted Windows RPC DCOM access',
                                    'Description': 'Security group ' + sgName + ' does not allow unrestricted Windows RPC DCOM access on ' + ipProtocol + '. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ThreatIntelIndicators': [
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Attack signature information, refer to Threatl Intel Source URL',
                                            'Source': 'Symantec Security Center',
                                            'SourceUrl': 'https://www.symantec.com/security_response/attacksignatures/detail.jsp?asid=20387'
                                        }
                                    ],
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                else:
                    pass

def security_group_open_smb_check():
    for secgroup in mySgs:
        sgName = str(secgroup['GroupName'])
        sgId = str(secgroup['GroupId'])
        sgArn = 'arn:aws-us-gov:ec2:' + awsRegion + ':' + awsAccountId + ':security-group/' + sgId
        for permissions in secgroup['IpPermissions']:
            try:
                fromPort = str(permissions['FromPort'])
            except Exception as e:
                if str(e) == "'FromPort'":
                    pass
                else:
                    print(e)
            try:
                toPort = str(permissions['ToPort'])
            except Exception as e:
                if str(e) == "'ToPort'":
                    pass
                else:
                    print(e)
            try:
                ipProtocol = str(permissions['IpProtocol'])
            except Exception as e:
                print(e)
            ipRanges = permissions['IpRanges']
            for cidrs in ipRanges:
                cidrIpRange = str(cidrs['CidrIp'])
                if toPort and fromPort == '445' and cidrIpRange == '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-smb-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'MEDIUM' },
                                    'Confidence': 99,
                                    'Title': '[SecurityGroup.5] Security groups should not allow unrestricted Server Message Blocks (SMB) access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted Server Message Blocks (SMB) access on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ThreatIntelIndicators': [
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption',
                                            'Source': 'Rapid7 Vulnerability & Exploit Database',
                                            'SourceUrl': 'https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue'
                                        },
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'How to use EternalBlue to Exploit SMB Port using Public Wi-Fi',
                                            'Source': 'Medium',
                                            'SourceUrl': 'https://medium.com/@melvinshb/how-to-use-eternalblue-to-exploit-smb-port-using-public-wi-fi-79a996821767'
                                        }
                                    ],
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                elif toPort and fromPort == '445' and cidrIpRange != '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-smb-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.5] Security groups should not allow unrestricted Server Message Blocks (SMB) access',
                                    'Description': 'Security group ' + sgName + ' does not allow unrestricted Server Message Blocks (SMB) access on ' + ipProtocol + '. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ThreatIntelIndicators': [
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption',
                                            'Source': 'Rapid7 Vulnerability & Exploit Database',
                                            'SourceUrl': 'https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue'
                                        },
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'How to use EternalBlue to Exploit SMB Port using Public Wi-Fi',
                                            'Source': 'Medium',
                                            'SourceUrl': 'https://medium.com/@melvinshb/how-to-use-eternalblue-to-exploit-smb-port-using-public-wi-fi-79a996821767'
                                        }
                                    ],
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                else:
                    pass

def security_group_open_mssql_check():
    for secgroup in mySgs:
        sgName = str(secgroup['GroupName'])
        sgId = str(secgroup['GroupId'])
        sgArn = 'arn:aws-us-gov:ec2:' + awsRegion + ':' + awsAccountId + ':security-group/' + sgId
        for permissions in secgroup['IpPermissions']:
            try:
                fromPort = str(permissions['FromPort'])
            except Exception as e:
                if str(e) == "'FromPort'":
                    pass
                else:
                    print(e)
            try:
                toPort = str(permissions['ToPort'])
            except Exception as e:
                if str(e) == "'ToPort'":
                    pass
                else:
                    print(e)
            try:
                ipProtocol = str(permissions['IpProtocol'])
            except Exception as e:
                print(e)
            ipRanges = permissions['IpRanges']
            for cidrs in ipRanges:
                cidrIpRange = str(cidrs['CidrIp'])
                if toPort and fromPort == '1433' and cidrIpRange == '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-mssql-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'MEDIUM' },
                                    'Confidence': 99,
                                    'Title': '[SecurityGroup.6] Security groups should not allow unrestricted Microsoft SQL Server (MSSQL) access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted Microsoft SQL Server (MSSQL) access on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ThreatIntelIndicators': [
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Microsoft CVE-2020-0618: Microsoft SQL Server Reporting Services Remote Code Execution Vulnerability',
                                            'Source': 'Rapid7 Vulnerability & Exploit Database',
                                            'SourceUrl': 'https://www.rapid7.com/db/vulnerabilities/msft-cve-2020-0618'
                                        },
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Microsoft CVE-2019-0819: Microsoft SQL Server Analysis Services Information Disclosure Vulnerability',
                                            'Source': 'Rapid7 Vulnerability & Exploit Database',
                                            'SourceUrl': 'https://www.rapid7.com/db/vulnerabilities/msft-cve-2019-0819'
                                        },
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Microsoft CVE-2018-8273: Microsoft SQL Server Remote Code Execution Vulnerability',
                                            'Source': 'Rapid7 Vulnerability & Exploit Database',
                                            'SourceUrl': 'https://www.rapid7.com/db/vulnerabilities/msft-cve-2018-8273'
                                        }
                                    ],
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                elif toPort and fromPort == '1433' and cidrIpRange != '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-mssql-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.6] Security groups should not allow unrestricted Microsoft SQL Server (MSSQL) access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted Microsoft SQL Server (MSSQL) access on ' + ipProtocol + '. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ThreatIntelIndicators': [
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Microsoft CVE-2020-0618: Microsoft SQL Server Reporting Services Remote Code Execution Vulnerability',
                                            'Source': 'Rapid7 Vulnerability & Exploit Database',
                                            'SourceUrl': 'https://www.rapid7.com/db/vulnerabilities/msft-cve-2020-0618'
                                        },
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Microsoft CVE-2019-0819: Microsoft SQL Server Analysis Services Information Disclosure Vulnerability',
                                            'Source': 'Rapid7 Vulnerability & Exploit Database',
                                            'SourceUrl': 'https://www.rapid7.com/db/vulnerabilities/msft-cve-2019-0819'
                                        },
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Microsoft CVE-2018-8273: Microsoft SQL Server Remote Code Execution Vulnerability',
                                            'Source': 'Rapid7 Vulnerability & Exploit Database',
                                            'SourceUrl': 'https://www.rapid7.com/db/vulnerabilities/msft-cve-2018-8273'
                                        }
                                    ],
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                else:
                    pass

def security_group_open_oracle_check():
    for secgroup in mySgs:
        sgName = str(secgroup['GroupName'])
        sgId = str(secgroup['GroupId'])
        sgArn = 'arn:aws-us-gov:ec2:' + awsRegion + ':' + awsAccountId + ':security-group/' + sgId
        for permissions in secgroup['IpPermissions']:
            try:
                fromPort = str(permissions['FromPort'])
            except Exception as e:
                if str(e) == "'FromPort'":
                    pass
                else:
                    print(e)
            try:
                toPort = str(permissions['ToPort'])
            except Exception as e:
                if str(e) == "'ToPort'":
                    pass
                else:
                    print(e)
            try:
                ipProtocol = str(permissions['IpProtocol'])
            except Exception as e:
                print(e)
            ipRanges = permissions['IpRanges']
            for cidrs in ipRanges:
                cidrIpRange = str(cidrs['CidrIp'])
                if toPort and fromPort == '1521' and cidrIpRange == '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-oracledb-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'MEDIUM' },
                                    'Confidence': 99,
                                    'Title': '[SecurityGroup.7] Security groups should not allow unrestricted Oracle database (TCP 1521) access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted Oracle database (TCP 1521) access on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                elif toPort and fromPort == '1521' and cidrIpRange != '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-oracledb-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.7] Security groups should not allow unrestricted Oracle database (TCP 1521) access',
                                    'Description': 'Security group ' + sgName + ' does not allow unrestricted Oracle database (TCP 1521) access on ' + ipProtocol + '. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                else:
                    pass

def security_group_open_mysql_mariadb_check():
    for secgroup in mySgs:
        sgName = str(secgroup['GroupName'])
        sgId = str(secgroup['GroupId'])
        sgArn = 'arn:aws-us-gov:ec2:' + awsRegion + ':' + awsAccountId + ':security-group/' + sgId
        for permissions in secgroup['IpPermissions']:
            try:
                fromPort = str(permissions['FromPort'])
            except Exception as e:
                if str(e) == "'FromPort'":
                    pass
                else:
                    print(e)
            try:
                toPort = str(permissions['ToPort'])
            except Exception as e:
                if str(e) == "'ToPort'":
                    pass
                else:
                    print(e)
            try:
                ipProtocol = str(permissions['IpProtocol'])
            except Exception as e:
                print(e)
            ipRanges = permissions['IpRanges']
            for cidrs in ipRanges:
                cidrIpRange = str(cidrs['CidrIp'])
                if toPort and fromPort == '3306' and cidrIpRange == '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-mysql-mariadb-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'MEDIUM' },
                                    'Confidence': 99,
                                    'Title': '[SecurityGroup.8] Security groups should not allow unrestricted MySQL or MariaDB database (TCP 3306) access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted MySQL or MariaDB database (TCP 3306) access on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                if toPort and fromPort == '3306' and cidrIpRange != '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-mysql-mariadb-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.8] Security groups should not allow unrestricted MySQL or MariaDB database (TCP 3306) access',
                                    'Description': 'Security group ' + sgName + ' does not allow unrestricted MySQL or MariaDB database (TCP 3306) access on ' + ipProtocol + '. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                else:
                    pass

def security_group_open_rdp_check():
    for secgroup in mySgs:
        sgName = str(secgroup['GroupName'])
        sgId = str(secgroup['GroupId'])
        sgArn = 'arn:aws-us-gov:ec2:' + awsRegion + ':' + awsAccountId + ':security-group/' + sgId
        for permissions in secgroup['IpPermissions']:
            try:
                fromPort = str(permissions['FromPort'])
            except Exception as e:
                if str(e) == "'FromPort'":
                    pass
                else:
                    print(e)
            try:
                toPort = str(permissions['ToPort'])
            except Exception as e:
                if str(e) == "'ToPort'":
                    pass
                else:
                    print(e)
            try:
                ipProtocol = str(permissions['IpProtocol'])
            except Exception as e:
                print(e)
            ipRanges = permissions['IpRanges']
            for cidrs in ipRanges:
                cidrIpRange = str(cidrs['CidrIp'])
                if toPort and fromPort == '3389' and cidrIpRange == '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-rdp-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.9] Security groups should not allow unrestricted Remote Desktop Protocol (RDP) access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted Remote Desktop Protocol (RDP) access on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'ThreatIntelIndicators': [
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Microsoft CVE-2020-0660: Windows Remote Desktop Protocol (RDP) Denial of Service Vulnerability',
                                            'Source': 'Rapid7 Vulnerability & Exploit Database',
                                            'SourceUrl': 'https://www.rapid7.com/db/vulnerabilities/msft-cve-2020-0660'
                                        },
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Microsoft CVE-2020-0610: Windows Remote Desktop Gateway (RD Gateway) Remote Code Execution Vulnerability',
                                            'Source': 'Rapid7 Vulnerability & Exploit Database',
                                            'SourceUrl': 'https://www.rapid7.com/db/vulnerabilities/msft-cve-2020-0610'
                                        }
                                    ],
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                elif toPort and fromPort == '3389' and cidrIpRange != '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-rdp-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.9] Security groups should not allow unrestricted Remote Desktop Protocol (RDP) access',
                                    'Description': 'Security group ' + sgName + ' does not allow unrestricted Remote Desktop Protocol (RDP) access on ' + ipProtocol + '. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'ThreatIntelIndicators': [
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Microsoft CVE-2020-0660: Windows Remote Desktop Protocol (RDP) Denial of Service Vulnerability',
                                            'Source': 'Rapid7 Vulnerability & Exploit Database',
                                            'SourceUrl': 'https://www.rapid7.com/db/vulnerabilities/msft-cve-2020-0660'
                                        },
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Microsoft CVE-2020-0610: Windows Remote Desktop Gateway (RD Gateway) Remote Code Execution Vulnerability',
                                            'Source': 'Rapid7 Vulnerability & Exploit Database',
                                            'SourceUrl': 'https://www.rapid7.com/db/vulnerabilities/msft-cve-2020-0610'
                                        }
                                    ],
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                else:
                    pass

def security_group_open_postgresql_check():
    for secgroup in mySgs:
        sgName = str(secgroup['GroupName'])
        sgId = str(secgroup['GroupId'])
        sgArn = 'arn:aws-us-gov:ec2:' + awsRegion + ':' + awsAccountId + ':security-group/' + sgId
        for permissions in secgroup['IpPermissions']:
            try:
                fromPort = str(permissions['FromPort'])
            except Exception as e:
                if str(e) == "'FromPort'":
                    pass
                else:
                    print(e)
            try:
                toPort = str(permissions['ToPort'])
            except Exception as e:
                if str(e) == "'ToPort'":
                    pass
                else:
                    print(e)
            try:
                ipProtocol = str(permissions['IpProtocol'])
            except Exception as e:
                print(e)
            ipRanges = permissions['IpRanges']
            for cidrs in ipRanges:
                cidrIpRange = str(cidrs['CidrIp'])
                if toPort and fromPort == '5432' and cidrIpRange == '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-postgresql-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'MEDIUM' },
                                    'Confidence': 99,
                                    'Title': '[SecurityGroup.10] Security groups should not allow unrestricted PostgreSQL datbase (TCP 5432) access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted PostgreSQL datbase (TCP 5432) access on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                elif toPort and fromPort == '5432' and cidrIpRange != '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-postgresql-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.10] Security groups should not allow unrestricted PostgreSQL datbase (TCP 5432) access',
                                    'Description': 'Security group ' + sgName + ' does not allow unrestricted PostgreSQL datbase (TCP 5432) access on ' + ipProtocol + '. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                else:
                    pass

def security_group_open_kibana_check():
    for secgroup in mySgs:
        sgName = str(secgroup['GroupName'])
        sgId = str(secgroup['GroupId'])
        sgArn = 'arn:aws-us-gov:ec2:' + awsRegion + ':' + awsAccountId + ':security-group/' + sgId
        for permissions in secgroup['IpPermissions']:
            try:
                fromPort = str(permissions['FromPort'])
            except Exception as e:
                if str(e) == "'FromPort'":
                    pass
                else:
                    print(e)
            try:
                toPort = str(permissions['ToPort'])
            except Exception as e:
                if str(e) == "'ToPort'":
                    pass
                else:
                    print(e)
            try:
                ipProtocol = str(permissions['IpProtocol'])
            except Exception as e:
                print(e)
            ipRanges = permissions['IpRanges']
            for cidrs in ipRanges:
                cidrIpRange = str(cidrs['CidrIp'])
                if toPort and fromPort == '5601' and cidrIpRange == '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-kibana-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'MEDIUM' },
                                    'Confidence': 99,
                                    'Title': '[SecurityGroup.11] Security groups should not allow unrestricted access to Kibana (TCP 5601)',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted access to Kibana (TCP 5601) on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'ThreatIntelIndicators': [
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'CVE-2019-7609: Exploit Script Available for Kibana Remote Code Execution Vulnerability',
                                            'Source': 'Tenable Blog',
                                            'SourceUrl': 'https://www.rapid7.com/db/vulnerabilities/msft-cve-2020-0660'
                                        },
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Red Hat OpenShift: CVE-2019-7608: kibana: Cross-site scripting vulnerability permits perform destructive actions on behalf of other Kibana users',
                                            'Source': 'Rapid7 Vulnerability & Exploit Database',
                                            'SourceUrl': 'https://www.rapid7.com/db/vulnerabilities/redhat-openshift-cve-2019-7608'
                                        }
                                    ],
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                elif toPort and fromPort == '5601' and cidrIpRange != '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-kibana-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.11] Security groups should not allow unrestricted access to Kibana (TCP 5601)',
                                    'Description': 'Security group ' + sgName + ' does not allow unrestricted access to Kibana (TCP 5601) on ' + ipProtocol + '. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'ThreatIntelIndicators': [
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'CVE-2019-7609: Exploit Script Available for Kibana Remote Code Execution Vulnerability',
                                            'Source': 'Tenable Blog',
                                            'SourceUrl': 'https://www.rapid7.com/db/vulnerabilities/msft-cve-2020-0660'
                                        },
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Red Hat OpenShift: CVE-2019-7608: kibana: Cross-site scripting vulnerability permits perform destructive actions on behalf of other Kibana users',
                                            'Source': 'Rapid7 Vulnerability & Exploit Database',
                                            'SourceUrl': 'https://www.rapid7.com/db/vulnerabilities/redhat-openshift-cve-2019-7608'
                                        }
                                    ],
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                else:
                    pass

def security_group_open_redis_check():
    for secgroup in mySgs:
        sgName = str(secgroup['GroupName'])
        sgId = str(secgroup['GroupId'])
        sgArn = 'arn:aws-us-gov:ec2:' + awsRegion + ':' + awsAccountId + ':security-group/' + sgId
        for permissions in secgroup['IpPermissions']:
            try:
                fromPort = str(permissions['FromPort'])
            except Exception as e:
                if str(e) == "'FromPort'":
                    pass
                else:
                    print(e)
            try:
                toPort = str(permissions['ToPort'])
            except Exception as e:
                if str(e) == "'ToPort'":
                    pass
                else:
                    print(e)
            try:
                ipProtocol = str(permissions['IpProtocol'])
            except Exception as e:
                print(e)
            ipRanges = permissions['IpRanges']
            for cidrs in ipRanges:
                cidrIpRange = str(cidrs['CidrIp'])
                if toPort and fromPort == '6379' and cidrIpRange == '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-redis-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'MEDIUM' },
                                    'Confidence': 99,
                                    'Title': '[SecurityGroup.12] Security groups should not allow unrestricted Redis (TCP 6379) access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted Redis (TCP 6379) access on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'ThreatIntelIndicators': [
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Redis 4.x / 5.x - Unauthenticated Code Execution (Metasploit)',
                                            'Source': 'ExploitDB',
                                            'SourceUrl': 'https://www.exploit-db.com/exploits/47195'
                                        },
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Redis: Improper Input Validation (CVE-2013-0178)',
                                            'Source': 'Rapid7 Vulnerability & Exploit Database',
                                            'SourceUrl': 'https://www.rapid7.com/db/vulnerabilities/redislabs-redis-cve-2013-0178'
                                        }
                                    ],
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                elif toPort and fromPort == '6379' and cidrIpRange != '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-redis-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.12] Security groups should not allow unrestricted Redis (TCP 6379) access',
                                    'Description': 'Security group ' + sgName + ' does not allow unrestricted Redis (TCP 6379) access on ' + ipProtocol + '. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'ThreatIntelIndicators': [
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Redis 4.x / 5.x - Unauthenticated Code Execution (Metasploit)',
                                            'Source': 'ExploitDB',
                                            'SourceUrl': 'https://www.exploit-db.com/exploits/47195'
                                        },
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Redis: Improper Input Validation (CVE-2013-0178)',
                                            'Source': 'Rapid7 Vulnerability & Exploit Database',
                                            'SourceUrl': 'https://www.rapid7.com/db/vulnerabilities/redislabs-redis-cve-2013-0178'
                                        }
                                    ],
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                else:
                    pass

def security_group_open_splunkd_check():
    for secgroup in mySgs:
        sgName = str(secgroup['GroupName'])
        sgId = str(secgroup['GroupId'])
        sgArn = 'arn:aws-us-gov:ec2:' + awsRegion + ':' + awsAccountId + ':security-group/' + sgId
        for permissions in secgroup['IpPermissions']:
            try:
                fromPort = str(permissions['FromPort'])
            except Exception as e:
                if str(e) == "'FromPort'":
                    pass
                else:
                    print(e)
            try:
                toPort = str(permissions['ToPort'])
            except Exception as e:
                if str(e) == "'ToPort'":
                    pass
                else:
                    print(e)
            try:
                ipProtocol = str(permissions['IpProtocol'])
            except Exception as e:
                print(e)
            ipRanges = permissions['IpRanges']
            for cidrs in ipRanges:
                cidrIpRange = str(cidrs['CidrIp'])
                if toPort and fromPort == '8089' and cidrIpRange == '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-splunkd-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'MEDIUM' },
                                    'Confidence': 99,
                                    'Title': '[SecurityGroup.13] Security groups should not allow unrestricted Splunkd (TCP 8089) access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted Splunkd (TCP 8089) access on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'ThreatIntelIndicators': [
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Splunk - Remote Command Execution',
                                            'Source': 'ExploitDB',
                                            'SourceUrl': 'https://www.exploit-db.com/exploits/18245'
                                        },
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Splunk Web Interface Login Utility',
                                            'Source': 'Rapid7 Vulnerability & Exploit Database',
                                            'SourceUrl': 'https://www.rapid7.com/db/modules/auxiliary/scanner/http/splunk_web_login'
                                        }
                                    ],
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                elif toPort and fromPort == '8089' and cidrIpRange != '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-splunkd-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.13] Security groups should not allow unrestricted Splunkd (TCP 8089) access',
                                    'Description': 'Security group ' + sgName + ' does not allow unrestricted Splunkd (TCP 8089) access on ' + ipProtocol + '. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'ThreatIntelIndicators': [
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Splunk - Remote Command Execution',
                                            'Source': 'ExploitDB',
                                            'SourceUrl': 'https://www.exploit-db.com/exploits/18245'
                                        },
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Splunk Web Interface Login Utility',
                                            'Source': 'Rapid7 Vulnerability & Exploit Database',
                                            'SourceUrl': 'https://www.rapid7.com/db/modules/auxiliary/scanner/http/splunk_web_login'
                                        }
                                    ],
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                else:
                    pass

def security_group_open_elasticsearch1_check():
    for secgroup in mySgs:
        sgName = str(secgroup['GroupName'])
        sgId = str(secgroup['GroupId'])
        sgArn = 'arn:aws-us-gov:ec2:' + awsRegion + ':' + awsAccountId + ':security-group/' + sgId
        for permissions in secgroup['IpPermissions']:
            try:
                fromPort = str(permissions['FromPort'])
            except Exception as e:
                if str(e) == "'FromPort'":
                    pass
                else:
                    print(e)
            try:
                toPort = str(permissions['ToPort'])
            except Exception as e:
                if str(e) == "'ToPort'":
                    pass
                else:
                    print(e)
            try:
                ipProtocol = str(permissions['IpProtocol'])
            except Exception as e:
                print(e)
            ipRanges = permissions['IpRanges']
            for cidrs in ipRanges:
                cidrIpRange = str(cidrs['CidrIp'])
                if toPort and fromPort == '9200' and cidrIpRange == '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-elasticsearch-9200-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'MEDIUM' },
                                    'Confidence': 99,
                                    'Title': '[SecurityGroup.14] Security groups should not allow unrestricted Elasticsearch (TCP 9200) access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted Elasticsearch (TCP 9200) access on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                elif toPort and fromPort == '9200' and cidrIpRange != '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-elasticsearch-9200-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.14] Security groups should not allow unrestricted Elasticsearch (TCP 9200) access',
                                    'Description': 'Security group ' + sgName + ' does not allow unrestricted Elasticsearch (TCP 9200) access on ' + ipProtocol + '. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                else:
                    pass

def security_group_open_elasticsearch2_check():
    for secgroup in mySgs:
        sgName = str(secgroup['GroupName'])
        sgId = str(secgroup['GroupId'])
        sgArn = 'arn:aws-us-gov:ec2:' + awsRegion + ':' + awsAccountId + ':security-group/' + sgId
        for permissions in secgroup['IpPermissions']:
            try:
                fromPort = str(permissions['FromPort'])
            except Exception as e:
                if str(e) == "'FromPort'":
                    pass
                else:
                    print(e)
            try:
                toPort = str(permissions['ToPort'])
            except Exception as e:
                if str(e) == "'ToPort'":
                    pass
                else:
                    print(e)
            try:
                ipProtocol = str(permissions['IpProtocol'])
            except Exception as e:
                print(e)
            ipRanges = permissions['IpRanges']
            for cidrs in ipRanges:
                cidrIpRange = str(cidrs['CidrIp'])
                if toPort and fromPort == '9300' and cidrIpRange == '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-elasticsearch-9300-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'MEDIUM' },
                                    'Confidence': 99,
                                    'Title': '[SecurityGroup.15] Security groups should not allow unrestricted Elasticsearch (TCP 9300) access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted Elasticsearch (TCP 9300) access on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                elif toPort and fromPort == '9300' and cidrIpRange != '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-elasticsearch-9300-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.15] Security groups should not allow unrestricted Elasticsearch (TCP 9300) access',
                                    'Description': 'Security group ' + sgName + ' does not allow unrestricted Elasticsearch (TCP 9300) access on ' + ipProtocol + '. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                else:
                    pass

def security_group_open_memcached_check():
    for secgroup in mySgs:
        sgName = str(secgroup['GroupName'])
        sgId = str(secgroup['GroupId'])
        sgArn = 'arn:aws-us-gov:ec2:' + awsRegion + ':' + awsAccountId + ':security-group/' + sgId
        for permissions in secgroup['IpPermissions']:
            try:
                fromPort = str(permissions['FromPort'])
            except Exception as e:
                if str(e) == "'FromPort'":
                    pass
                else:
                    print(e)
            try:
                toPort = str(permissions['ToPort'])
            except Exception as e:
                if str(e) == "'ToPort'":
                    pass
                else:
                    print(e)
            try:
                ipProtocol = str(permissions['IpProtocol'])
            except Exception as e:
                print(e)
            ipRanges = permissions['IpRanges']
            for cidrs in ipRanges:
                cidrIpRange = str(cidrs['CidrIp'])
                if toPort and fromPort == '11211' and ipProtocol == 'udp' and cidrIpRange == '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-memcached-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'MEDIUM' },
                                    'Confidence': 99,
                                    'Title': '[SecurityGroup.16] Security groups should not allow unrestricted Memcached (UDP 11211) access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted Memcached (UDP 11211) access on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'ThreatIntelIndicators': [
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'memcached 1.4.2 - Memory Consumption Remote Denial of Service',
                                            'Source': 'ExploitDB',
                                            'SourceUrl': 'https://www.exploit-db.com/exploits/33850'
                                        },
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Ubuntu: USN-4125-1 (CVE-2019-15026): Memcached vulnerability',
                                            'Source': 'Rapid7 Vulnerability & Exploit Database',
                                            'SourceUrl': 'https://www.rapid7.com/db/vulnerabilities/ubuntu-cve-2019-15026'
                                        }
                                    ],
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                elif toPort and fromPort == '11211' and ipProtocol == 'udp' and cidrIpRange != '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-memcached-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.16] Security groups should not allow unrestricted Memcached (UDP 11211) access',
                                    'Description': 'Security group ' + sgName + ' does not allow unrestricted Memcached (UDP 11211) access on ' + ipProtocol + '. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'ThreatIntelIndicators': [
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'memcached 1.4.2 - Memory Consumption Remote Denial of Service',
                                            'Source': 'ExploitDB',
                                            'SourceUrl': 'https://www.exploit-db.com/exploits/33850'
                                        },
                                        {
                                            'Category': 'BACKDOOR',
                                            'Value': 'Ubuntu: USN-4125-1 (CVE-2019-15026): Memcached vulnerability',
                                            'Source': 'Rapid7 Vulnerability & Exploit Database',
                                            'SourceUrl': 'https://www.rapid7.com/db/vulnerabilities/ubuntu-cve-2019-15026'
                                        }
                                    ],
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                else:
                    pass

def security_group_open_redshift_check():
    for secgroup in mySgs:
        sgName = str(secgroup['GroupName'])
        sgId = str(secgroup['GroupId'])
        sgArn = 'arn:aws-us-gov:ec2:' + awsRegion + ':' + awsAccountId + ':security-group/' + sgId
        for permissions in secgroup['IpPermissions']:
            try:
                fromPort = str(permissions['FromPort'])
            except Exception as e:
                if str(e) == "'FromPort'":
                    pass
                else:
                    print(e)
            try:
                toPort = str(permissions['ToPort'])
            except Exception as e:
                if str(e) == "'ToPort'":
                    pass
                else:
                    print(e)
            try:
                ipProtocol = str(permissions['IpProtocol'])
            except Exception as e:
                print(e)
            ipRanges = permissions['IpRanges']
            for cidrs in ipRanges:
                cidrIpRange = str(cidrs['CidrIp'])
                if toPort and fromPort == '5439' and cidrIpRange == '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-redshift-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'MEDIUM' },
                                    'Confidence': 99,
                                    'Title': '[SecurityGroup.17] Security groups should not allow unrestricted Redshift (TCP 5439) access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted Redshift (TCP 5439) access on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                elif toPort and fromPort == '5439' and cidrIpRange != '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-redshift-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.17] Security groups should not allow unrestricted Redshift (TCP 5439) access',
                                    'Description': 'Security group ' + sgName + ' does not allow unrestricted Redshift (TCP 5439) access on ' + ipProtocol + '. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                else:
                    pass

def security_group_open_documentdb_check():
    for secgroup in mySgs:
        sgName = str(secgroup['GroupName'])
        sgId = str(secgroup['GroupId'])
        sgArn = 'arn:aws-us-gov:ec2:' + awsRegion + ':' + awsAccountId + ':security-group/' + sgId
        for permissions in secgroup['IpPermissions']:
            try:
                fromPort = str(permissions['FromPort'])
            except Exception as e:
                if str(e) == "'FromPort'":
                    pass
                else:
                    print(e)
            try:
                toPort = str(permissions['ToPort'])
            except Exception as e:
                if str(e) == "'ToPort'":
                    pass
                else:
                    print(e)
            try:
                ipProtocol = str(permissions['IpProtocol'])
            except Exception as e:
                print(e)
            ipRanges = permissions['IpRanges']
            for cidrs in ipRanges:
                cidrIpRange = str(cidrs['CidrIp'])
                if toPort and fromPort == '27017' and cidrIpRange == '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-documentdb-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'MEDIUM' },
                                    'Confidence': 99,
                                    'Title': '[SecurityGroup.18] Security groups should not allow unrestricted DocumentDB (TCP 27017) access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted DocumentDB (TCP 27017) access on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                elif toPort and fromPort == '27017' and cidrIpRange != '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-documentdb-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.18] Security groups should not allow unrestricted DocumentDB (TCP 27017) access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted DocumentDB (TCP 27017) access on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                else:
                    pass
def security_group_open_cassandra_check():
    for secgroup in mySgs:
        sgName = str(secgroup['GroupName'])
        sgId = str(secgroup['GroupId'])
        sgArn = 'arn:aws-us-gov:ec2:' + awsRegion + ':' + awsAccountId + ':security-group/' + sgId
        for permissions in secgroup['IpPermissions']:
            try:
                fromPort = str(permissions['FromPort'])
            except Exception as e:
                if str(e) == "'FromPort'":
                    pass
                else:
                    print(e)
            try:
                toPort = str(permissions['ToPort'])
            except Exception as e:
                if str(e) == "'ToPort'":
                    pass
                else:
                    print(e)
            try:
                ipProtocol = str(permissions['IpProtocol'])
            except Exception as e:
                print(e)
            ipRanges = permissions['IpRanges']
            for cidrs in ipRanges:
                cidrIpRange = str(cidrs['CidrIp'])
                if toPort and fromPort == '9142' and cidrIpRange == '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-cassandra-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'MEDIUM' },
                                    'Confidence': 99,
                                    'Title': '[SecurityGroup.19] Security groups should not allow unrestricted Cassandra (TCP 9142) access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted Cassandra (TCP 9142) access on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                elif toPort and fromPort == '9142' and cidrIpRange != '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-cassandra-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.19] Security groups should not allow unrestricted Cassandra (TCP 9142) access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted Cassandra (TCP 9142) access on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                else:
                    pass

def security_group_open_kafka_check():
    for secgroup in mySgs:
        sgName = str(secgroup['GroupName'])
        sgId = str(secgroup['GroupId'])
        sgArn = 'arn:aws-us-gov:ec2:' + awsRegion + ':' + awsAccountId + ':security-group/' + sgId
        for permissions in secgroup['IpPermissions']:
            try:
                fromPort = str(permissions['FromPort'])
            except Exception as e:
                if str(e) == "'FromPort'":
                    pass
                else:
                    print(e)
            try:
                toPort = str(permissions['ToPort'])
            except Exception as e:
                if str(e) == "'ToPort'":
                    pass
                else:
                    print(e)
            try:
                ipProtocol = str(permissions['IpProtocol'])
            except Exception as e:
                print(e)
            ipRanges = permissions['IpRanges']
            for cidrs in ipRanges:
                cidrIpRange = str(cidrs['CidrIp'])
                if toPort and fromPort == '9092' and cidrIpRange == '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-kafka-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'MEDIUM' },
                                    'Confidence': 99,
                                    'Title': '[SecurityGroup.20] Security groups should not allow unrestricted Kafka streams (TCP 9092) access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted Kafka streams (TCP 9092) access on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                elif toPort and fromPort == '9092' and cidrIpRange != '0.0.0.0/0':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': sgArn + '/' + ipProtocol + '/security-group-kafka-open-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': sgArn,
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
                                    'Title': '[SecurityGroup.20] Security groups should not allow unrestricted Kafka streams (TCP 9092) access',
                                    'Description': 'Security group ' + sgName + ' allows unrestricted Kafka streams (TCP 9092) access on ' + ipProtocol + '. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2SecurityGroup',
                                            'Id': sgArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2SecurityGroup': {
                                                    'GroupName': sgName,
                                                    'GroupId': sgId
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
                else:
                    pass

def security_group_auditor():
    security_group_all_open_check()
    security_group_open_ftp_check()
    security_group_open_telnet_check()
    security_group_open_dcom_rpc_check()
    security_group_open_smb_check()
    security_group_open_mssql_check()
    security_group_open_oracle_check()
    security_group_open_mysql_mariadb_check()
    security_group_open_rdp_check()
    security_group_open_postgresql_check()
    security_group_open_kibana_check()
    security_group_open_redis_check()
    security_group_open_splunkd_check()
    security_group_open_elasticsearch1_check()
    security_group_open_elasticsearch2_check()
    security_group_open_memcached_check()
    security_group_open_redshift_check()
    security_group_open_documentdb_check()
    security_group_open_cassandra_check()
    security_group_open_kafka_check()

security_group_auditor()