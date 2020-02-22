import boto3
import os
import datetime
# create boto3 clients
sts = boto3.client('sts')
elb = boto3.client('elb')
securityhub = boto3.client('securityhub')
# creat env vars
awsAccountId = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']

def internet_facing_clb_https_listener_check():
    # loop through classic load balancers
    response = elb.describe_load_balancers()
    for classicbalancer in response['LoadBalancerDescriptions']:
        clbName = str(classicbalancer['LoadBalancerName'])
        clbArn = 'arn:aws:elasticloadbalancing:' + awsRegion + ':' + awsAccountId + ':loadbalancer/' + clbName
        clbScheme = str(classicbalancer['Scheme'])
        if clbScheme == 'internet-facing':
            for listeners in classicbalancer['ListenerDescriptions']:
                listenerProtocol = str(listeners['Listener']['Protocol'])
                if listenerProtocol != 'HTTPS' or 'SSL':
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': clbArn + '/classic-loadbalancer-secure-listener-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': clbArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Normalized': 60 },
                                    'Confidence': 99,
                                    'Title': '[ELB.1] Classic load balancers that are internet-facing should use secure listeners',
                                    'Description': 'Classic load balancer ' + clbName + ' does not use a secure listener (HTTPS or SSL). Refer to the remediation instructions to remediate this behavior',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on classic load balancer HTTPS listeners refer to the Create a Classic Load Balancer with an HTTPS Listener section of the Classic Load Balancers User Guide.',
                                            'Url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-create-https-ssl-load-balancer.html'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'Other',
                                            'Id': clbArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'Other': { 'LoadBalancerName': clbName }
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
                                    'Id': clbArn + '/classic-loadbalancer-secure-listener-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': clbArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Normalized': 0 },
                                    'Confidence': 99,
                                    'Title': '[ELB.1] Classic load balancers that are internet-facing should use secure listeners',
                                    'Description': 'Classic load balancer ' + clbName + ' uses a secure listener (HTTPS or SSL).',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on classic load balancer HTTPS listeners refer to the Create a Classic Load Balancer with an HTTPS Listener section of the Classic Load Balancers User Guide.',
                                            'Url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-create-https-ssl-load-balancer.html'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'Other',
                                            'Id': clbArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'Other': { 'LoadBalancerName': clbName }
                                            }
                                        }
                                    ],
                                    'Compliance': { 'Status': 'ARCHIVED' },
                                    'RecordState': 'PASSED'
                                }
                            ]
                        )
                        print(response)
                    except Exception as e:
                        print(e)
        else:
            print('Ignoring internal CLB')
            pass

def clb_https_listener_tls12_policy_check():
    # loop through classic load balancers
    response = elb.describe_load_balancers()
    for classicbalancer in response['LoadBalancerDescriptions']:
        clbName = str(classicbalancer['LoadBalancerName'])
        clbArn = 'arn:aws:elasticloadbalancing:' + awsRegion + ':' + awsAccountId + ':loadbalancer/' + clbName
        for listeners in classicbalancer['ListenerDescriptions']:
            listenerPolicies = str(listeners['PolicyNames'])
            if listenerPolicies == '[]':
                print('No policies identified, likely no SSL or HTTPS listener')
            elif listenerPolicies == 'ELBSecurityPolicy-TLS-1-2-2017-01':
                try:
                    # This is a passing finding
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': clbArn + '/classic-loadbalancer-tls12-policy-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': clbArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 0 },
                                'Confidence': 99,
                                'Title': '[ELB.2] Classic load balancers should use TLS 1.2 listener policies',
                                'Description': 'Classic load balancer ' + clbName + ' does not use a TLS 1.2 listener policy.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on classic load balancer listener policies refer to the Predefined SSL Security Policies for Classic Load Balancers section of the Classic Load Balancers User Guide.',
                                        'Url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-policy-table.html'
                                    }
                                },
                                'ProductFields': { 'Product Name': 'ElectricEye' },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': clbArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'LoadBalancerName': clbName }
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
                try:
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': clbArn + '/classic-loadbalancer-tls12-policy-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': clbArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 60 },
                                'Confidence': 99,
                                'Title': '[ELB.2] Classic load balancers should use TLS 1.2 listener policies',
                                'Description': 'Classic load balancer ' + clbName + ' does not use a TLS 1.2 listener policy. Refer to the remediation instructions to remediate this behavior',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on classic load balancer listener policies refer to the Predefined SSL Security Policies for Classic Load Balancers section of the Classic Load Balancers User Guide.',
                                        'Url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-policy-table.html'
                                    }
                                },
                                'ProductFields': { 'Product Name': 'ElectricEye' },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': clbArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'LoadBalancerName': clbName }
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

def clb_cross_zone_balancing_check():
    # loop through classic load balancers
    response = elb.describe_load_balancers()
    for classicbalancer in response['LoadBalancerDescriptions']:
        clbName = str(classicbalancer['LoadBalancerName'])
        clbArn = 'arn:aws:elasticloadbalancing:' + awsRegion + ':' + awsAccountId + ':loadbalancer/' + clbName
        response = elb.describe_load_balancer_attributes(LoadBalancerName=clbName)
        crossZoneCheck = str(response['LoadBalancerAttributes']['CrossZoneLoadBalancing']['Enabled'])
        if crossZoneCheck == 'False':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': clbArn + '/classic-loadbalancer-cross-zone-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': clbArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 20 },
                            'Confidence': 99,
                            'Title': '[ELB.3] Classic load balancers should have cross-zone load balancing configured',
                            'Description': 'Classic load balancer ' + clbName + ' does not have cross-zone load balancing configured. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on cross-zone load balancing refer to the Configure Cross-Zone Load Balancing for Your Classic Load Balancer section of the Classic Load Balancers User Guide.',
                                    'Url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-disable-crosszone-lb.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': clbArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'LoadBalancerName': clbName }
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
                            'Id': clbArn + '/classic-loadbalancer-cross-zone-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': clbArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[ELB.3] Classic load balancers should have cross-zone load balancing configured',
                            'Description': 'Classic load balancer ' + clbName + ' has cross-zone load balancing configured.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on cross-zone load balancing refer to the Configure Cross-Zone Load Balancing for Your Classic Load Balancer section of the Classic Load Balancers User Guide.',
                                    'Url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-disable-crosszone-lb.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': clbArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'LoadBalancerName': clbName }
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

def clb_connection_draining_check():
    # loop through classic load balancers
    response = elb.describe_load_balancers()
    for classicbalancer in response['LoadBalancerDescriptions']:
        clbName = str(classicbalancer['LoadBalancerName'])
        clbArn = 'arn:aws:elasticloadbalancing:' + awsRegion + ':' + awsAccountId + ':loadbalancer/' + clbName
        response = elb.describe_load_balancer_attributes(LoadBalancerName=clbName)
        connectionDrainCheck = str(response['LoadBalancerAttributes']['ConnectionDraining']['Enabled'])
        if connectionDrainCheck == 'False':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': clbArn + '/classic-loadbalancer-connection-draining-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': clbArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 20 },
                            'Confidence': 99,
                            'Title': '[ELB.4] Classic load balancers should have connection draining configured',
                            'Description': 'Classic load balancer ' + clbName + ' does not have connection draining configured. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on connection draining refer to the Configure Connection Draining for Your Classic Load Balancer section of the Classic Load Balancers User Guide.',
                                    'Url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/config-conn-drain.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': clbArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'LoadBalancerName': clbName }
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
                            'Id': clbArn + '/classic-loadbalancer-connection-draining-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': clbArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[ELB.4] Classic load balancers should have connection draining configured',
                            'Description': 'Classic load balancer ' + clbName + ' does not have connection draining configured.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on connection draining refer to the Configure Connection Draining for Your Classic Load Balancer section of the Classic Load Balancers User Guide.',
                                    'Url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/config-conn-drain.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': clbArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'LoadBalancerName': clbName }
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

def clb_access_logging_check():
    # loop through classic load balancers
    response = elb.describe_load_balancers()
    for classicbalancer in response['LoadBalancerDescriptions']:
        clbName = str(classicbalancer['LoadBalancerName'])
        clbArn = 'arn:aws:elasticloadbalancing:' + awsRegion + ':' + awsAccountId + ':loadbalancer/' + clbName
        response = elb.describe_load_balancer_attributes(LoadBalancerName=clbName)
        accessLogCheck = str(response['LoadBalancerAttributes']['AccessLog']['Enabled'])
        if accessLogCheck == 'False':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': clbArn + '/classic-loadbalancer-access-logging-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': clbArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 40 },
                            'Confidence': 99,
                            'Title': '[ELB.5] Classic load balancers should enable access logging',
                            'Description': 'Classic load balancer ' + clbName + ' does not have access logging enabled. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on access logging refer to the Access Logs for Your Classic Load Balancer section of the Classic Load Balancers User Guide.',
                                    'Url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/access-log-collection.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': clbArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'LoadBalancerName': clbName }
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
                            'Id': clbArn + '/classic-loadbalancer-access-logging-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': clbArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[ELB.5] Classic load balancers should enable access logging',
                            'Description': 'Classic load balancer ' + clbName + ' does not have access logging enabled.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on access logging refer to the Access Logs for Your Classic Load Balancer section of the Classic Load Balancers User Guide.',
                                    'Url': 'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/access-log-collection.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': clbArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'LoadBalancerName': clbName }
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

def classic_load_balancer_auditor():
    internet_facing_clb_https_listener_check()
    clb_https_listener_tls12_policy_check()
    clb_cross_zone_balancing_check()
    clb_connection_draining_check()
    clb_access_logging_check()

classic_load_balancer_auditor()