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
elbv2 = boto3.client('elbv2')
securityhub = boto3.client('securityhub')
# create env vars
awsRegion = os.environ['AWS_REGION']
awsAccountId = sts.get_caller_identity()['Account']
# loop through ELBv2 load balancers
response = elbv2.describe_load_balancers()
myElbv2LoadBalancers = response['LoadBalancers']

def elbv2_logging_check():
    for loadbalancers in myElbv2LoadBalancers:
        elbv2Arn = str(loadbalancers['LoadBalancerArn'])
        elbv2Name = str(loadbalancers['LoadBalancerName'])
        elbv2DnsName = str(loadbalancers['DNSName'])
        elbv2LbType = str(loadbalancers['Type']) 
        elbv2Scheme = str(loadbalancers['Scheme']) 
        elbv2VpcId = str(loadbalancers['VpcId'])
        elbv2IpAddressType = str(loadbalancers['IpAddressType'])
        try:
            response = elbv2.describe_load_balancer_attributes(LoadBalancerArn=elbv2Arn)
            elbv2Attributes = response['Attributes']
            for attributes in elbv2Attributes:
                if str(attributes['Key']) == 'access_logs.s3.enabled':
                    elbv2LoggingCheck = str(attributes['Value'])
                    if elbv2LoggingCheck == 'false':
                        try:
                            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                            response = securityhub.batch_import_findings(
                                Findings=[
                                    {
                                        'SchemaVersion': '2018-10-08',
                                        'Id': elbv2Arn + '/elbv2-logging-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': elbv2Arn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Normalized': 20 },
                                        'Confidence': 99,
                                        'Title': '[ELBv2.1] Application and Network Load Balancers should have access logging enabled',
                                        'Description': 'ELB ' + elbv2LbType + ' load balancer ' + elbv2Name + ' does not have access logging enabled. Refer to the remediation instructions to remediate this behavior',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'For more information on ELBv2 Access Logging and how to configure it refer to the Access Logs for Your Application Load Balancer section of the Application Load Balancers User Guide. For Network Load Balancer logging please refer to the NLB User Guide',
                                                'Url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html'
                                            }
                                        },
                                        'ProductFields': { 'Product Name': 'ElectricEye' },
                                        'Resources': [
                                            {
                                                'Type': 'AwsElbv2LoadBalancer',
                                                'Id': elbv2Arn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'AwsElbv2LoadBalancer': {
                                                        'DNSName': elbv2DnsName,
                                                        'IpAddressType': elbv2IpAddressType,
                                                        'Scheme': elbv2Scheme,
                                                        'Type': elbv2LbType,
                                                        'VpcId': elbv2VpcId
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
                                        'Id': elbv2Arn + '/elbv2-logging-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': elbv2Arn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Normalized': 0 },
                                        'Confidence': 99,
                                        'Title': '[ELBv2.1] Application and Network Load Balancers should have access logging enabled',
                                        'Description': 'ELB ' + elbv2LbType + ' load balancer ' + elbv2Name + ' has access logging enabled.',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'For more information on ELBv2 Access Logging and how to configure it refer to the Access Logs for Your Application Load Balancer section of the Application Load Balancers User Guide. For Network Load Balancer logging please refer to the NLB User Guide',
                                                'Url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html'
                                            }
                                        },
                                        'ProductFields': { 'Product Name': 'ElectricEye' },
                                        'Resources': [
                                            {
                                                'Type': 'AwsElbv2LoadBalancer',
                                                'Id': elbv2Arn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'AwsElbv2LoadBalancer': {
                                                        'DNSName': elbv2DnsName,
                                                        'IpAddressType': elbv2IpAddressType,
                                                        'Scheme': elbv2Scheme,
                                                        'Type': elbv2LbType,
                                                        'VpcId': elbv2VpcId
                                                    },
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
                    print('skipping non logging attribute')
                    pass
        except Exception as e:
            print(e)

def elbv2_deletion_protection_check():
    for loadbalancers in myElbv2LoadBalancers:
        elbv2Arn = str(loadbalancers['LoadBalancerArn'])
        elbv2Name = str(loadbalancers['LoadBalancerName'])
        elbv2DnsName = str(loadbalancers['DNSName'])
        elbv2LbType = str(loadbalancers['Type']) 
        elbv2Scheme = str(loadbalancers['Scheme']) 
        elbv2VpcId = str(loadbalancers['VpcId'])
        elbv2IpAddressType = str(loadbalancers['IpAddressType'])
        try:
            response = elbv2.describe_load_balancer_attributes(LoadBalancerArn=elbv2Arn)
            elbv2Attributes = response['Attributes']
            for attributes in elbv2Attributes:
                if str(attributes['Key']) == 'deletion_protection.enabled':
                    elbv2LoggingCheck = str(attributes['Value'])
                    if elbv2LoggingCheck == 'false':
                        try:
                            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                            response = securityhub.batch_import_findings(
                                Findings=[
                                    {
                                        'SchemaVersion': '2018-10-08',
                                        'Id': elbv2Arn + '/elbv2-deletion-protection-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': elbv2Arn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Normalized': 20 },
                                        'Confidence': 99,
                                        'Title': '[ELBv2.2] Application and Network Load Balancers should have deletion protection enabled',
                                        'Description': 'ELB ' + elbv2LbType + ' load balancer ' + elbv2Name + ' does not have deletion protection enabled. Refer to the remediation instructions to remediate this behavior',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'For more information on ELBv2 Access Logging and how to configure it refer to the Deletion Protection section of the Application Load Balancers User Guide. For Network Load Balancer logging please refer to the NLB User Guide',
                                                'Url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#deletion-protection'
                                            }
                                        },
                                        'ProductFields': { 'Product Name': 'ElectricEye' },
                                        'Resources': [
                                            {
                                                'Type': 'AwsElbv2LoadBalancer',
                                                'Id': elbv2Arn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'AwsElbv2LoadBalancer': {
                                                        'DNSName': elbv2DnsName,
                                                        'IpAddressType': elbv2IpAddressType,
                                                        'Scheme': elbv2Scheme,
                                                        'Type': elbv2LbType,
                                                        'VpcId': elbv2VpcId
                                                    },
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
                                        'Id': elbv2Arn + '/elbv2-deletion-protection-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': elbv2Arn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Normalized': 0 },
                                        'Confidence': 99,
                                        'Title': '[ELBv2.2] Application and Network Load Balancers should have deletion protection enabled',
                                        'Description': 'ELB ' + elbv2LbType + ' load balancer ' + elbv2Name + ' has deletion protection enabled.',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'For more information on ELBv2 Access Logging and how to configure it refer to the Deletion Protection section of the Application Load Balancers User Guide. For Network Load Balancer logging please refer to the NLB User Guide',
                                                'Url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#deletion-protection'
                                            }
                                        },
                                        'ProductFields': { 'Product Name': 'ElectricEye' },
                                        'Resources': [
                                            {
                                                'Type': 'AwsElbv2LoadBalancer',
                                                'Id': elbv2Arn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'AwsElbv2LoadBalancer': {
                                                        'DNSName': elbv2DnsName,
                                                        'IpAddressType': elbv2IpAddressType,
                                                        'Scheme': elbv2Scheme,
                                                        'Type': elbv2LbType,
                                                        'VpcId': elbv2VpcId
                                                    },
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
                    print('skipping non logging attribute')
                    pass
        except Exception as e:
            print(e)

def elbv2_internet_facing_secure_listeners_check():
    for loadbalancers in myElbv2LoadBalancers:
        elbv2Arn = str(loadbalancers['LoadBalancerArn'])
        elbv2Name = str(loadbalancers['LoadBalancerName'])
        elbv2DnsName = str(loadbalancers['DNSName'])
        elbv2LbType = str(loadbalancers['Type']) 
        elbv2Scheme = str(loadbalancers['Scheme']) 
        elbv2VpcId = str(loadbalancers['VpcId'])
        elbv2IpAddressType = str(loadbalancers['IpAddressType'])
        try:
            response = elbv2.describe_listeners(LoadBalancerArn=elbv2Arn)
            myElbv2Listeners = response['Listeners']
            for listeners in myElbv2Listeners:
                listenerProtocol = str(listeners['Protocol'])
                if elbv2Scheme == 'internet-facing' and listenerProtocol != 'HTTPS' or 'TLS':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': elbv2Arn + '/internet-facing-secure-listeners-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': elbv2Arn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Normalized': 70 },
                                    'Confidence': 99,
                                    'Title': '[ELBv2.3] Internet-facing Application and Network Load Balancers should have secure listeners configured',
                                    'Description': 'ELB ' + elbv2LbType + ' load balancer ' + elbv2Name + ' does not have a secure listener configured. Refer to the remediation instructions to remediate this behavior',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on ELBv2 Access Logging and how to configure it refer to the Create an HTTPS Listener for Your Application Load Balancer section of the Application Load Balancers User Guide. For Network Load Balancer logging please refer to the NLB User Guide',
                                            'Url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsElbv2LoadBalancer',
                                            'Id': elbv2Arn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsElbv2LoadBalancer': {
                                                    'DNSName': elbv2DnsName,
                                                    'IpAddressType': elbv2IpAddressType,
                                                    'Scheme': elbv2Scheme,
                                                    'Type': elbv2LbType,
                                                    'VpcId': elbv2VpcId
                                                },
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
                                    'Id': elbv2Arn + '/internet-facing-secure-listeners-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': elbv2Arn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Normalized': 0 },
                                    'Confidence': 99,
                                    'Title': '[ELBv2.3] Internet-facing Application and Network Load Balancers should have secure listeners configured',
                                    'Description': 'ELB ' + elbv2LbType + ' load balancer ' + elbv2Name + ' has a secure listener configured.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on ELBv2 Access Logging and how to configure it refer to the Create an HTTPS Listener for Your Application Load Balancer section of the Application Load Balancers User Guide. For Network Load Balancer logging please refer to the NLB User Guide',
                                            'Url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsElbv2LoadBalancer',
                                            'Id': elbv2Arn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsElbv2LoadBalancer': {
                                                    'DNSName': elbv2DnsName,
                                                    'IpAddressType': elbv2IpAddressType,
                                                    'Scheme': elbv2Scheme,
                                                    'Type': elbv2LbType,
                                                    'VpcId': elbv2VpcId
                                                },
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
            print(e)

def elbv2_tls12_listener_policy_check():
    for loadbalancers in myElbv2LoadBalancers:
        elbv2Arn = str(loadbalancers['LoadBalancerArn'])
        elbv2Name = str(loadbalancers['LoadBalancerName'])
        elbv2DnsName = str(loadbalancers['DNSName'])
        elbv2LbType = str(loadbalancers['Type']) 
        elbv2Scheme = str(loadbalancers['Scheme']) 
        elbv2VpcId = str(loadbalancers['VpcId'])
        elbv2IpAddressType = str(loadbalancers['IpAddressType'])
        try:
            response = elbv2.describe_listeners(LoadBalancerArn=elbv2Arn)
            myElbv2Listeners = response['Listeners']
            for listeners in myElbv2Listeners:
                listenerProtocol = str(listeners['Protocol'])
                if listenerProtocol == 'HTTPS' or 'TLS':
                    listenerTlsPolicyCheck = str(listeners['SslPolicy'])
                    if listenerTlsPolicyCheck != 'ELBSecurityPolicy-TLS-1-2-2017-01' or 'ELBSecurityPolicy-TLS-1-2-Ext-2018-06' or 'ELBSecurityPolicy-FS-1-2-2019-08' or 'ELBSecurityPolicy-FS-1-2-Res-2019-08':
                        try:
                            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                            response = securityhub.batch_import_findings(
                                Findings=[
                                    {
                                        'SchemaVersion': '2018-10-08',
                                        'Id': elbv2Arn + '/secure-listener-tls12-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': elbv2Arn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Normalized': 70 },
                                        'Confidence': 99,
                                        'Title': '[ELBv2.4] Application and Network Load Balancers with HTTPS or TLS listeners should enforce TLS 1.2 policies',
                                        'Description': 'ELB ' + elbv2LbType + ' load balancer ' + elbv2Name + ' does not enforce a TLS 1.2 policy. Refer to the remediation instructions to remediate this behavior',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'For more information on ELBv2 Access Logging and how to configure it refer to the Security Policies section of the Application Load Balancers User Guide. For Network Load Balancer logging please refer to the NLB User Guide',
                                                'Url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#describe-ssl-policies'
                                            }
                                        },
                                        'ProductFields': { 'Product Name': 'ElectricEye' },
                                        'Resources': [
                                            {
                                                'Type': 'AwsElbv2LoadBalancer',
                                                'Id': elbv2Arn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'AwsElbv2LoadBalancer': {
                                                        'DNSName': elbv2DnsName,
                                                        'IpAddressType': elbv2IpAddressType,
                                                        'Scheme': elbv2Scheme,
                                                        'Type': elbv2LbType,
                                                        'VpcId': elbv2VpcId
                                                    },
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
                                        'Id': elbv2Arn + '/secure-listener-tls12-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': elbv2Arn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Normalized': 0 },
                                        'Confidence': 99,
                                        'Title': '[ELBv2.4] Application and Network Load Balancers with HTTPS or TLS listeners should enforce TLS 1.2 policies',
                                        'Description': 'ELB ' + elbv2LbType + ' load balancer ' + elbv2Name + ' enforces a TLS 1.2 policy.',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'For more information on ELBv2 Access Logging and how to configure it refer to the Security Policies section of the Application Load Balancers User Guide. For Network Load Balancer logging please refer to the NLB User Guide',
                                                'Url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#describe-ssl-policies'
                                            }
                                        },
                                        'ProductFields': { 'Product Name': 'ElectricEye' },
                                        'Resources': [
                                            {
                                                'Type': 'AwsElbv2LoadBalancer',
                                                'Id': elbv2Arn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'AwsElbv2LoadBalancer': {
                                                        'DNSName': elbv2DnsName,
                                                        'IpAddressType': elbv2IpAddressType,
                                                        'Scheme': elbv2Scheme,
                                                        'Type': elbv2LbType,
                                                        'VpcId': elbv2VpcId
                                                    },
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
                    print('This load balancer doesnt have a secure listener')
                    pass
        except Exception as e:
            print(e)

def elbv2_drop_invalid_header_check():
    for loadbalancers in myElbv2LoadBalancers:
        elbv2Arn = str(loadbalancers['LoadBalancerArn'])
        elbv2Name = str(loadbalancers['LoadBalancerName'])
        elbv2DnsName = str(loadbalancers['DNSName'])
        elbv2LbType = str(loadbalancers['Type']) 
        elbv2Scheme = str(loadbalancers['Scheme']) 
        elbv2VpcId = str(loadbalancers['VpcId'])
        elbv2IpAddressType = str(loadbalancers['IpAddressType'])
        response = elbv2.describe_load_balancer_attributes(LoadBalancerArn=elbv2Arn)
        elbv2Attributes = response['Attributes']
        for attributes in elbv2Attributes:
            if str(attributes['Key']) == 'routing.http.drop_invalid_header_fields.enabled':
                elbv2DropInvalidHeaderCheck = str(attributes['Value'])
                if elbv2DropInvalidHeaderCheck == 'false':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': elbv2Arn + '/elbv2-drop-invalid-header-fields-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': elbv2Arn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Normalized': 60 },
                                    'Confidence': 99,
                                    'Title': '[ELBv2.5] Application Load Balancers should drop invalid HTTP header fields',
                                    'Description': 'ELB ' + elbv2LbType + ' load balancer ' + elbv2Name + ' does not drop invalid HTTP header fields. Refer to the remediation instructions to remediate this behavior',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on dropping invalid HTTP headers refer to the routing.http.drop_invalid_header_fields.enabled section of the Application Load Balancers User Guide.',
                                            'Url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#load-balancer-attributes'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsElbv2LoadBalancer',
                                            'Id': elbv2Arn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsElbv2LoadBalancer': {
                                                    'DNSName': elbv2DnsName,
                                                    'IpAddressType': elbv2IpAddressType,
                                                    'Scheme': elbv2Scheme,
                                                    'Type': elbv2LbType,
                                                    'VpcId': elbv2VpcId
                                                },
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
                                    'Id': elbv2Arn + '/elbv2-drop-invalid-header-fields-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': elbv2Arn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Normalized': 0 },
                                    'Confidence': 99,
                                    'Title': '[ELBv2.5] Application Load Balancers should drop invalid HTTP header fields',
                                    'Description': 'ELB ' + elbv2LbType + ' load balancer ' + elbv2Name + ' drops invalid HTTP header fields.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on dropping invalid HTTP headers refer to the routing.http.drop_invalid_header_fields.enabled section of the Application Load Balancers User Guide.',
                                            'Url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#load-balancer-attributes'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsElbv2LoadBalancer',
                                            'Id': elbv2Arn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsElbv2LoadBalancer': {
                                                    'DNSName': elbv2DnsName,
                                                    'IpAddressType': elbv2IpAddressType,
                                                    'Scheme': elbv2Scheme,
                                                    'Type': elbv2LbType,
                                                    'VpcId': elbv2VpcId
                                                },
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

def elbv2_auditor():
    elbv2_logging_check()
    elbv2_deletion_protection_check()
    elbv2_internet_facing_secure_listeners_check()
    elbv2_tls12_listener_policy_check()
    elbv2_drop_invalid_header_check()

elbv2_auditor()