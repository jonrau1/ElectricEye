import boto3
import datetime
import os
# import boto3 clients
sts = boto3.client('sts')
amb = boto3.client('managedblockchain')
securityhub = boto3.client('securityhub')
# create account id & region variables
awsAccountId = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']
# loop through AMB Fabric networks
try:
    response = amb.list_networks(Framework='HYPERLEDGER_FABRIC')
    myFabricNetworks = response['Networks']
except Exception as e:
    print(e)

def amb_fabric_node_chaincode_logging_check():
    for networks in myFabricNetworks:
        fabricNetworkId = str(networks['Id'])
        try:
            response = amb.list_members(NetworkId=fabricNetworkId,Status='AVAILABLE',IsOwned=True)
            for members in response['Members']:
                memberId = str(members['Id'])
                try:
                    response = amb.list_nodes(NetworkId=fabricNetworkId,MemberId=memberId,Status='AVAILABLE')
                    for nodes in response['Nodes']:
                        peerNodeId = str(nodes['Id'])
                        try:
                            response = amb.get_node(NetworkId=fabricNetworkId,MemberId=memberId,NodeId=peerNodeId)
                            nodeArn = 'arn:aws:managedblockchain:' + awsRegion + ':' + awsAccountId + ':nodes/' + peerNodeId
                            chaincodeLogCheck = str(response['Node']['LogPublishingConfiguration']['Fabric']['ChaincodeLogs']['Cloudwatch']['Enabled'])
                            if chaincodeLogCheck == 'False':
                                try:
                                    # ISO Time
                                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                                    response = securityhub.batch_import_findings(
                                        Findings=[
                                            {
                                                'SchemaVersion': '2018-10-08',
                                                'Id': nodeArn + '/managedblockchain-fabric-node-chaincode-logs-check',
                                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                                'GeneratorId': nodeArn,
                                                'AwsAccountId': awsAccountId,
                                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                                'FirstObservedAt': iso8601Time,
                                                'CreatedAt': iso8601Time,
                                                'UpdatedAt': iso8601Time,
                                                'Severity': { 'Label': 'LOW' },
                                                'Confidence': 99,
                                                'Title': '[AMB.Fabric.1] Amazon Managed Blockchain Fabric peer nodes should have chaincode logging enabled',
                                                'Description': 'Amazon Managed Blockchain Fabric peer node ' + peerNodeId + ' does not have chaincode logging enabled. Chaincode logs help you analyze and debug the business logic and execution of chaincode on a peer node. They contain the results of instantiating, invoking, and querying the chaincode. Refer to the remediation instructions if this configuration is not intended',
                                                'Remediation': {
                                                    'Recommendation': {
                                                        'Text': 'For more information on logging and monitoring Amazon Managed Blockchain refer to the Enabling and Disabling Logs section of the Amazon Managed Blockchain Management Guide',
                                                        'Url': 'https://docs.aws.amazon.com/managed-blockchain/latest/managementguide/monitoring-cloudwatch-logs.html#monitoring-enable'
                                                    }
                                                },
                                                'ProductFields': {
                                                    'Product Name': 'ElectricEye'
                                                },
                                                'Resources': [
                                                    {
                                                        'Type': 'AwsManagedBlockchainPeerNode',
                                                        'Id': nodeArn,
                                                        'Partition': 'aws',
                                                        'Region': awsRegion,
                                                        'Details': {
                                                            'Other': { 
                                                                'networkId': fabricNetworkId,
                                                                'memberId': memberId,
                                                                'nodeId': peerNodeId
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
                                                'Id': nodeArn + '/managedblockchain-fabric-node-chaincode-logs-check',
                                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                                'GeneratorId': nodeArn,
                                                'AwsAccountId': awsAccountId,
                                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                                'FirstObservedAt': iso8601Time,
                                                'CreatedAt': iso8601Time,
                                                'UpdatedAt': iso8601Time,
                                                'Severity': { 'Label': 'INFORMATIONAL' },
                                                'Confidence': 99,
                                                'Title': '[AMB.Fabric.1] Amazon Managed Blockchain Fabric peer nodes should have chaincode logging enabled',
                                                'Description': 'Amazon Managed Blockchain Fabric peer node ' + peerNodeId + ' has chaincode logging enabled.',
                                                'Remediation': {
                                                    'Recommendation': {
                                                        'Text': 'For more information on logging and monitoring Amazon Managed Blockchain refer to the Enabling and Disabling Logs section of the Amazon Managed Blockchain Management Guide',
                                                        'Url': 'https://docs.aws.amazon.com/managed-blockchain/latest/managementguide/monitoring-cloudwatch-logs.html#monitoring-enable'
                                                    }
                                                },
                                                'ProductFields': {
                                                    'Product Name': 'ElectricEye'
                                                },
                                                'Resources': [
                                                    {
                                                        'Type': 'AwsManagedBlockchainPeerNode',
                                                        'Id': nodeArn,
                                                        'Partition': 'aws',
                                                        'Region': awsRegion,
                                                        'Details': {
                                                            'Other': { 
                                                                'networkId': fabricNetworkId,
                                                                'memberId': memberId,
                                                                'nodeId': peerNodeId
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
                            print(e)
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)

def amb_fabric_node_peernode_logging_check():
    for networks in myFabricNetworks:
        fabricNetworkId = str(networks['Id'])
        try:
            response = amb.list_members(NetworkId=fabricNetworkId,Status='AVAILABLE',IsOwned=True)
            for members in response['Members']:
                memberId = str(members['Id'])
                try:
                    response = amb.list_nodes(NetworkId=fabricNetworkId,MemberId=memberId,Status='AVAILABLE')
                    for nodes in response['Nodes']:
                        peerNodeId = str(nodes['Id'])
                        try:
                            response = amb.get_node(NetworkId=fabricNetworkId,MemberId=memberId,NodeId=peerNodeId)
                            nodeArn = 'arn:aws:managedblockchain:' + awsRegion + ':' + awsAccountId + ':nodes/' + peerNodeId
                            peerNodeLogCheck = str(response['Node']['LogPublishingConfiguration']['Fabric']['PeerLogs']['Cloudwatch']['Enabled'])
                            if peerNodeLogCheck == 'False':
                                try:
                                    # ISO Time
                                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                                    response = securityhub.batch_import_findings(
                                        Findings=[
                                            {
                                                'SchemaVersion': '2018-10-08',
                                                'Id': nodeArn + '/managedblockchain-fabric-node-peernode-logs-check',
                                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                                'GeneratorId': nodeArn,
                                                'AwsAccountId': awsAccountId,
                                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                                'FirstObservedAt': iso8601Time,
                                                'CreatedAt': iso8601Time,
                                                'UpdatedAt': iso8601Time,
                                                'Severity': { 'Label': 'LOW' },
                                                'Confidence': 99,
                                                'Title': '[AMB.Fabric.2] Amazon Managed Blockchain Fabric peer nodes should have peer node logging enabled',
                                                'Description': 'Amazon Managed Blockchain Fabric peer node ' + peerNodeId + ' does not have peer node logging enabled. Peer node logs help you debug timeout errors associated with proposals and identify rejected proposals that do not meet the endorsement policies. Peer node logs contain messages generated when your client submits transaction proposals to peer nodes, requests to join channels, enrolls an admin peer, and lists the chaincode instances on a peer node. Peer node logs also contain the results of chaincode installation. Refer to the remediation instructions if this configuration is not intended',
                                                'Remediation': {
                                                    'Recommendation': {
                                                        'Text': 'For more information on logging and monitoring Amazon Managed Blockchain refer to the Enabling and Disabling Logs section of the Amazon Managed Blockchain Management Guide',
                                                        'Url': 'https://docs.aws.amazon.com/managed-blockchain/latest/managementguide/monitoring-cloudwatch-logs.html#monitoring-enable'
                                                    }
                                                },
                                                'ProductFields': {
                                                    'Product Name': 'ElectricEye'
                                                },
                                                'Resources': [
                                                    {
                                                        'Type': 'AwsManagedBlockchainPeerNode',
                                                        'Id': nodeArn,
                                                        'Partition': 'aws',
                                                        'Region': awsRegion,
                                                        'Details': {
                                                            'Other': { 
                                                                'networkId': fabricNetworkId,
                                                                'memberId': memberId,
                                                                'nodeId': peerNodeId
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
                                                'Id': nodeArn + '/managedblockchain-fabric-node-peernode-logs-check',
                                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                                'GeneratorId': nodeArn,
                                                'AwsAccountId': awsAccountId,
                                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                                'FirstObservedAt': iso8601Time,
                                                'CreatedAt': iso8601Time,
                                                'UpdatedAt': iso8601Time,
                                                'Severity': { 'Label': 'INFORMATIONAL' },
                                                'Confidence': 99,
                                                'Title': '[AMB.Fabric.2] Amazon Managed Blockchain Fabric peer nodes should have peer node logging enabled',
                                                'Description': 'Amazon Managed Blockchain Fabric peer node ' + peerNodeId + ' has peer node logging enabled.',
                                                'Remediation': {
                                                    'Recommendation': {
                                                        'Text': 'For more information on logging and monitoring Amazon Managed Blockchain refer to the Enabling and Disabling Logs section of the Amazon Managed Blockchain Management Guide',
                                                        'Url': 'https://docs.aws.amazon.com/managed-blockchain/latest/managementguide/monitoring-cloudwatch-logs.html#monitoring-enable'
                                                    }
                                                },
                                                'ProductFields': {
                                                    'Product Name': 'ElectricEye'
                                                },
                                                'Resources': [
                                                    {
                                                        'Type': 'AwsManagedBlockchainPeerNode',
                                                        'Id': nodeArn,
                                                        'Partition': 'aws',
                                                        'Region': awsRegion,
                                                        'Details': {
                                                            'Other': { 
                                                                'networkId': fabricNetworkId,
                                                                'memberId': memberId,
                                                                'nodeId': peerNodeId
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
                            print(e)
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)

def amb_fabric_member_ca_logging_check():
    for networks in myFabricNetworks:
        fabricNetworkId = str(networks['Id'])
        try:
            response = amb.list_members(NetworkId=fabricNetworkId,Status='AVAILABLE',IsOwned=True)
            for members in response['Members']:
                memberId = str(members['Id'])
                try:
                    response = amb.get_member(NetworkId=fabricNetworkId,MemberId=memberId)
                    memberArn = 'arn:aws:managedblockchain:' + awsRegion + ':' + awsAccountId + ':members/' + memberId
                    memberCaLogCheck = str(response['Member']['LogPublishingConfiguration']['Fabric']['CaLogs']['Cloudwatch']['Enabled'])
                    if memberCaLogCheck == 'False':
                        try:
                            # ISO Time
                            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                            response = securityhub.batch_import_findings(
                                Findings=[
                                    {
                                        'SchemaVersion': '2018-10-08',
                                        'Id': memberArn + '/managedblockchain-member-ca-logs-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': memberArn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Label': 'LOW' },
                                        'Confidence': 99,
                                        'Title': '[AMB.Fabric.3] Amazon Managed Blockchain Fabric members should have certificate authority (CA) logging enabled',
                                        'Description': 'Amazon Managed Blockchain Fabric member ' + memberId + ' does not have certificate authority (CA) logging enabled. CA logs help you determine when a member in your account joins the network, or when new peers register with a member CA. You can use CA logs to debug problems related to certificates and enrollment. CA logging can be enabled and disabled for each member. A single log stream for the CA exists for each member. Refer to the remediation instructions if this configuration is not intended',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'For more information on logging and monitoring Amazon Managed Blockchain refer to the Enabling and Disabling Logs section of the Amazon Managed Blockchain Management Guide',
                                                'Url': 'https://docs.aws.amazon.com/managed-blockchain/latest/managementguide/monitoring-cloudwatch-logs.html#monitoring-enable'
                                            }
                                        },
                                        'ProductFields': {
                                            'Product Name': 'ElectricEye'
                                        },
                                        'Resources': [
                                            {
                                                'Type': 'AwsManagedBlockchainMember',
                                                'Id': memberArn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'Other': { 
                                                        'networkId': fabricNetworkId,
                                                        'memberId': memberId
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
                                        'Id': memberArn + '/managedblockchain-member-ca-logs-check',
                                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                        'GeneratorId': memberArn,
                                        'AwsAccountId': awsAccountId,
                                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Label': 'INFORMATIONAL' },
                                        'Confidence': 99,
                                        'Title': '[AMB.Fabric.3] Amazon Managed Blockchain Fabric members should have certificate authority (CA) logging enabled',
                                        'Description': 'Amazon Managed Blockchain Fabric member ' + memberId + ' has certificate authority (CA) logging enabled.',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'For more information on logging and monitoring Amazon Managed Blockchain refer to the Enabling and Disabling Logs section of the Amazon Managed Blockchain Management Guide',
                                                'Url': 'https://docs.aws.amazon.com/managed-blockchain/latest/managementguide/monitoring-cloudwatch-logs.html#monitoring-enable'
                                            }
                                        },
                                        'ProductFields': {
                                            'Product Name': 'ElectricEye'
                                        },
                                        'Resources': [
                                            {
                                                'Type': 'AwsManagedBlockchainMember',
                                                'Id': memberArn,
                                                'Partition': 'aws',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'Other': { 
                                                        'networkId': fabricNetworkId,
                                                        'memberId': memberId
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
                    print(e)
        except Exception as e:
            print(e)

def amb_fabric_auditor():
    amb_fabric_node_chaincode_logging_check()
    amb_fabric_node_peernode_logging_check()
    amb_fabric_member_ca_logging_check()

amb_fabric_auditor()