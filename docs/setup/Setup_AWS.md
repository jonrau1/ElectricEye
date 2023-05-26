# ElectricEye Cloud Security Posture Management for AWS

This documentation is dedicated to using ElectricEye for evaluation of AWS Environments using CSPM and Attack Surface Monitoring capabilities.

## Table of Contents

- [AWS IAM Permissions](#aws-iam-permissions)
- [Configuring TOML](#configuring-toml)
- [Use ElectricEye for AWS](#use-electriceye-for-aws)
- [Configuring the AWS Security Group Auditor](#configuring-the-aws-security-group-auditor)
- [Building & Pushing ElectricEye Docker Image to ECR](#build-and-push-the-docker-image-to-ecr)
- [AWS Attack Surface Monitoring](#aws-attack-surface-monitoring)
- [AWS Checks & Services](#aws-checks--services)

## AWS IAM Permissions

ElectricEye separates the logic of the Auditors from that of retreiving credentials, looking up OUs and Accounts within your AWS Organization (if you're a Delegated Administrator for any Organizations service), and AWS-native Outputs (e.g., Amazon SQS, Amazon DynamoDB, AWS Security Hub).

All AWS API interactivity is handled by `boto3` (and to a lesser extent lower-level APIs in `botocore`) which both use your [available AWS credentials](https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html) from wherever they can be available from. For instance, `boto3` will first look for static credentials (AWS IAM User Access Keys) in `~/.aws/credentials`, and then look for AWS credential environment variables, then look for Session credentials from EC2 Instance Profiles or your IAM Role, Federated credentials, and so on. These first credentials are what are responsible for performing lookups against Systems Manager, Secrets Manager, and sending findings to cloud-native resources as previously stated. The below table details the API permissions required based on the interactivity.

| ElectricEye Interactivity | AWS IAM Permission | Absolutely Required? | Extra Considerations |
|---|---|---|---|
| Assuming the `aws_electric_eye_iam_role_name` Roles to use the AWS Auditors | `sts:AssumeRole` | **YES** | Ensure you meet all of your `condition` keys if you customize the Trust flow for the remote Roles |
| Retrieving Accounts from your AWS Organization | `organizations:ListAccounts` | **NO** | You must either be in your Organizations Management Account or you must be a Delegated Administrator for an Organizations-enabled Service such as AWS Firewall Manager or Amazon GuardDuty |
| Retrieving Accounts from one or more of your AWS Organizational Units | `organizations:ListAccountsForParent` | **NO** | You must either be in your Organizations Management Account or you must be a Delegated Administrator for an Organizations-enabled Service such as AWS Firewall Manager or Amazon GuardDuty |
| Sending findings to AWS Security Hub | `securityhub:BatchImportFindings` | **NO** | Ensure that AWS Security Hub is enabled in your Account & Region |
| Sending findings to Amazon SQS | `sqs:SendMessage` | **NO** | Ensure that your SQS Queue's Resource Policy also allows your IAM principal to `sqs:SendMessage` to it. </br> You will also require `kms:Decrypt` permissions and access to the key (via Key Policy) if you encrypt your Queue with a Customer Managed Key. |
| Sending findings to Amazon DynamoDB | `dynamodb:PutItem` | **NO** | You will also require `kms:Decrypt` permissions and access to the key (via Key Policy) if you encrypt your Table with a Customer Managed Key |
| Retrieving credentials from AWS Systems Manager Parameter Store | `ssm:GetParameter*` | **NO** | You will also require `kms:Decrypt` permissions and access to the key (via Key Policy) if you encrypt your SecureString Parameters with a Customer Managed Key |
| Retrieving credentials from AWS Secrets Manager | `secretsmanager:GetSecretValue` | **NO** | You will also require `kms:Decrypt` permissions and access to the key (via Key Policy) if you encrypt your Secrets with a Customer Managed Key |
| If you run ElectricEye within a container without a seperate block device or file share managed, you will need to send file-based Outputs to S3, maybe | `s3:PutObject` | **NO** | If you do use S3, ensure that your Bucket Policy allows you to perform `s3:PutObject`. </br> You will also require `kms:Decrypt` permissions and access to the key (via Key Policy) if you encrypt your Bucket with a Customer Managed Key. |

For executing the actually AWS Auditors (and their Checks), ElectricEye will Assume an IAM Role that trusts whichever IAM Princpal you run ElectricEye from (e.g., an EC2 Instance Profile's IAM Role, ECS Execution Role, IAM Roles Anywhere Certifcate on local machines, etc.) which is why you must provide an IAM Role name within the TOML even if you are only conducting assessments in your own Account. This is done to keep the Auditor-specific activity of ElectricEye easily, well, auditable as well as provide an easy-to-operate method of parallelizing ElectricEye across multiple Accounts without having to grant write or privileged read permissions to those Roles by virtue of keeping the setup logic out of the Auditor logic.

The easiest way to set up this Role and permissions is either creating a StackSet from the [CloudFormation template](../../cloudformation/ElectricEye_Organizations_StackSet.yaml) or using the [standalone JSON policy](../../policies/ElectricEye_AWS_Policy.json) within your own provisioning logic - be it JSON-based CFN, Pulumi, Terraform or otherwise. By default the CloudFormation stack will create an IAM Role that Trusts whichever Account you will centrally operate ElectricEye from - however - you can modify this to trust specific IAM Principals and add conditions such as SourceIP constraints if ElectricEye will operate behind NAT Gateways with Elastic IPs or from within another trusted network.

## Configuring TOML

This section explains how to configure ElectricEye using a TOML configuration file. The configuration file contains settings for credentials, regions, accounts, and global settings and is located [here](../../eeauditor/external_providers.toml).

To configure the TOML file, you need to modify the values of the variables in the `[global]` and `[regions_and_accounts.aws]` sections of the file. Here's an overview of the key variables you need to configure:

- `aws_multi_account_target_type`: Set this variable to specify if you want to run ElectricEye against a list of AWS Accounts (`Accounts`), a list of accounts within specific OUs (`OU`), or every account in an AWS Organization (`Organization`).

- `credentials_location`: Set this variable to specify the location of where credentials are stored and will be retrieved from. You can choose from AWS Systems Manager Parameter Store (`AWS_SSM`), AWS Secrets Manager (`AWS_SECRETS_MANAGER`), or from the TOML file itself (`CONFIG_FILE`) which is **NOT** recommended.

**NOTE** When retrieving from SSM or Secrets Manager, your current Profile / Boto3 Session is used and *NOT* the ElectricEye Role that is specified in `aws_electric_eye_iam_role_name`. Ensure you have `ssm:GetParameter`, `secretsmanager:GetSecretValue`, and relevant `kms` permissions as needed to retrieve this values.

- `shodan_api_key_value`: This variable specifies the location (or actual value) of your Shodan.io API Key based on the option for `credentials_location`. This is an optional value but encouraged as having your resources being index by Shodan can be a useful pre-attack indicator if it is accurate information *and* your configurations are bad to begin with. This is only used for the **Amazon_Shodan_Auditor**.

- `aws_account_targets`: This variable specifies a list of AWS accounts, OU IDs, or an organization's principal ID that you want to run ElectricEye against. If you do not specify any values, and your `aws_multi_account_target_type` is set to `Accounts` then your current AWS Account will be evaluated.

If you are running this against your Organization **leave this option empty**. Additionally, the Account you are running ElectricEye from must either be the AWS Organizations Management Account or an Account which is a Delegated Admin for an Organizations-scoped service such as AWS FMS, Amazon GuardDuty, or otherwise.

- `aws_regions_selection`: This variable specifies the AWS regions that you want to scan. If left blank, the current AWS region is used. You can provide a list of AWS regions or simply use `["All"]` to scan all regions.

- `aws_electric_eye_iam_role_name`: This variable specifies the ***Name*** of the AWS IAM role that ElectricEye will assume and utilize to execute its Checks. The role name must be the same for all accounts, including your current account. To facilitate this, use [this CloudFormation template](../../cloudformation/ElectricEye_Organizations_StackSet.yaml) and deploy it as an AWS CloudFormation StackSet. This is done to keep the credentials used for **Auditors** separate from the credentials you use for Outputs and for retrieving Secrets, it also makes it easier to audit (via CloudTrail or otherwise) the usage of the ElectricEye role.

By configuring these variables in the TOML file, you can customize ElectricEye's behavior to suit your specific AWS environments.

## Use ElectricEye for AWS

1. Before beginning ensure you have review the [Permissions section](#aws-iam-permissions) section to understand which AWS IAM Permissions your current profile requires and to setup the AWS IAM Roles that ElectricEye will assume to use the Auditors.

2. With >=Python 3.6 installed, install & upgrade `pip3` and setup `virtualenv`.

```bash
sudo apt install -y python3-pip
pip3 install --upgrade pip
pip3 install virtualenv --user
virtualenv .venv
```

3. This will create a virtualenv directory called `.venv` which needs to be activated.

```bash
#For macOS and Linux
. .venv/bin/activate

#For Windows
.venv\scripts\activate
```

4. Clone the repo and install all dependencies.

```bash
git clone https://github.com/jonrau1/ElectricEye.git
cd ElectricEye
pip3 install -r requirements.txt

# if use AWS CloudShell
pip3 install --user -r requirements.txt
```

5. Use the Controller to conduct different kinds of Assessments.

    - 5A. Retrieve all options for the Controller.

    ```bash
    python3 eeauditor/controller.py --help
    ```

    - 5B. Evaluate your entire AWS environment.

    ```bash
    python3 eeauditor/controller.py -t AWS
    ```

    - 5C. Evaluate your AWS environment against a specifc Auditor (runs all Checks within the Auditor).

    ```bash
    python3 eeauditor/controller.py -t AWS -a AWS_IAM_Auditor
    ```

    - 5D. Evaluate your AWS environment against a specific Check within any Auditor, it is ***not required*** to specify the Auditor name as well. The below examples runs the `[Athena.1] Athena workgroups should be configured to enforce query result encryption` check.

    ```bash
    python3 eeauditor/controller.py -t AWS -c athena_workgroup_encryption_check
    ```

## Configuring the AWS Security Group Auditor

The Auditor for Amazon EC2 Security Groups (the EC2-VPC Security Groups, not the EC2-Classic SGs some of us old dirty bastards used back in the day) is configured using a JSON [file](../../eeauditor/auditors/aws/electriceye_secgroup_auditor_config.json) which contains titles, check IDs, to-from IANA port numbers and protocols that map to high-danger services you should not leave open to the world such as SMB, Win NetBIOS, databases, caches, et al. While this is not the same as figuring out what your how your actual assets & services are configured (see the [EASM](#aws-external-attack-surface-reporting) section for that) this is a good hygeine check.

The JSON file is already prefilled with several dozen checks, however you can easily append more to the list. Shown below are how `udp` and `tcp` rules are configured.

```json
[
    {
        "ToPort": 1194,
        "FromPort": 1194,
        "Protocol": "udp",
        "CheckTitle": "[SecurityGroup.28] Security groups should not allow unrestricted OpenVPN (UDP 1194) access",
        "CheckId": "security-group-openvpn-open-check",
        "CheckDescriptor": "OpenVPN (UDP 1194)"
    },
    {
        "ToPort": 5672,
        "FromPort": 5672,
        "Protocol": "tcp",
        "CheckTitle": "[SecurityGroup.29] Security groups should not allow unrestricted access to AmazonMQ/RabbitMQ (TCP 5672)",
        "CheckId": "security-group-rabbitmq-open-check",
        "CheckDescriptor": "AmazonMQ / RabbitMQ / AMQP (TCP 5672)"
    }
]
```

#### `ToPort`

The IANA Port number at the top of the range for whatever service needs internet access, e.g., if your service required ports 135-139, then 139 is the `ToPort`

#### `FromPort`

The IANA Port number at the bottom of the range for whatever service needs internet access, e.g., if your service required ports 135-139, then 135 is the `ToPort`

#### `Protocol`

A Protocol identifier that matches the Protocol within the [AWS `SecurityGroupRule` Data Schema](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_SecurityGroupRule.html) such as `tcp`, `udp`, or `icmp`. Ensure this matches the IANA ports, depending on the service you may need different protocols. Note that AWS Security Group Rules cannot have multiple Protocols defined (unless it is "all" (`-1`)) so if you wanted to write a rule to check for DNS you need both `tcp 53` and `udp 53` rules.

#### `CheckTitle`

The `Title` within the AWS Security Finding Format, aka the title of the finding, ensure you follow the rule number order and the guidelines - or choose your own.

#### `CheckId`

An all lowercase, dash-separated string that is appended to the `Id` and `GeneratorId` within the AWS Security Finding Format, this is the ensure uniqueness of the Check performed by the Auditor

#### `CheckDescriptor`

A descriptor of what the protocol & port service is, this is added into the `Description` field within the AWS Security Finding Format and can be anything you want as long as it does not contain double-quotes (`""`)

## Build and push the Docker image to ECR

**Note:** You must have [permissions to push images](https://docs.aws.amazon.com/AmazonECR/latest/userguide/docker-push-ecr-image.html) to ECR before performing this step. These permissions are not included in the instance profile example.

1. Update your machine and clone this repository

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y unzip awscli docker.ce python3 python3-pip
pip3 install --upgrade pip
pip3 install --upgrade awscli
pip3 install --upgrade boto3
git clone https://github.com/jonrau1/ElectricEye.git
```

2. Create an ECR Repository with the AWS CLI

```bash
aws ecr create-repository \
    --repository-name electriceye \
    --image-scanning-configuration scanOnPush=true
```

3. Build and push the ElectricEye Docker image. Be sure to replace the values for your region, partition, Account ID and name of the ECR repository

```bash
cd ElectricEye
aws ecr get-login-password --region $AWS_REGION | sudo docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com
```

**Note**: If you are using AWS CLI v1 use the following in place of the line above

```bash
sudo $(aws ecr get-login --no-include-email --region $AWS_REGION)
```

```bash
sudo docker build -t electriceye .
sudo docker tag electriceye:v1 $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/electriceye:v1
sudo docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/electriceye:v1
```

4. Navigate to the ECR console and copy the `URI` of your Docker image.

## AWS Attack Surface Monitoring

If you only wanted to run Attack Surface Monitoring checks use the following command which show an example of outputting the ASM checks into a JSON file for consumption into SIEM or BI tools.

```bash
python3 eeauditor/controller.py -t AWS -a ElectricEye_AttackSurface_Auditor -o json_normalized --output-file ElectricASM
```

The ASM Module uses NMAP at its core and will be expanded to include ZAP and Shodan workflows in the future.

## AWS Checks & Services

These are the following services and checks perform by each Auditor, there are currently **569 Checks** across **80 Auditors** that support the secure configuration of **106 services/components**

**Regarding AWS ElasticSearch Service/OpenSearch Service**: AWS has stopped supporting Elastic after Version 7.10 and released a new service named OpenSearch. The APIs/SDKs/CLI are interchangable. Only ASFF metadata has changed to reflect this, the Auditor Names, Check Names, and ASFF ID's have stayed the same.

**Regarding AWS Shield Advanced**: You must be actively subscribed to Shield Advanced with at least one Protection assigned to assess this Service.

**Regarding AWS Trusted Advisor**: You must be on AWS Business or Enterprise Support to interact with the `support` API for Trusted Advisor.

**Regarding AWS Health**: You must be on AWS Business or Enterprise Support to interact with the `support` API for Health.

**Regarding EC2**: As of 19 MAY 2023, the separate `Amazon_EC2_SSM_Auditor` and all of its checks have been merged into the `Amazon_EC2_Auditor` with only the control names changing from their `[EC2.SystemsManager.XX]` schema to the normal `[EC2.X]` one.

| Auditor File Name | Scanned Resource Name | Auditor Scan Description |
|---|---|---|
| Amazon_APIGW_Auditor | API Gateway Stage | Are stage metrics enabled |
| Amazon_APIGW_Auditor | API Gateway Stage | Is stage API logging enabled |
| Amazon_APIGW_Auditor | API Gateway Stage | Is stage caching enabled |
| Amazon_APIGW_Auditor | API Gateway Stage | Is cache encryption enabled |
| Amazon_APIGW_Auditor | API Gateway Stage | Is stage xray tracing configured |
| Amazon_APIGW_Auditor | API Gateway Stage | Is the stage protected by a WAF WACL |
| Amazon_APIGW_Auditor | API Gateway Rest API | Do Rest APIs use Policies |
| Amazon_APIGW_Auditor | API Gateway Rest API | Do Rest APIs use Authorizers |
| Amazon_AppStream_Auditor | AppStream 2.0 (Fleets) | Do Fleets allow Default Internet Access |
| Amazon_AppStream_Auditor | AppStream 2.0 (Images) | Are Images Public |
| Amazon_AppStream_Auditor | AppStream 2.0 (Users) | Are users reported as Compromised |
| Amazon_AppStream_Auditor | AppStream 2.0 (Users) | Do users use SAML authentication |
| Amazon_Athena_Auditor | Athena workgroup | Do workgroups enforce query result encryption |
| Amazon_Athena_Auditor | Athena workgroup | Do workgroups with query result encryption override client settings |
| Amazon_Athena_Auditor | Athena workgroup | Do workgroups publish metrics |
| Amazon_Athena_Auditor | Athena workgroup | Do workgroups auto-update the Athena engine version |
| Amazon_Autoscaling_Auditor | Autoscaling groups | Do ASGs protect instances from scale-in |
| Amazon_Autoscaling_Auditor | Autoscaling groups | Do ASGs with ELB or Target Groups use ELB health checks |
| Amazon_Autoscaling_Auditor | Autoscaling groups | Do ASGs use at least half or more of a Region's open AZs |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros with trusted signers use key pairs |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distro origins have Origin Shield enabled |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros use the default viewer certificate |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros have Georestriction enabled |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros have Field-Level Encryption enabled |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros have WAF enabled |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros enforce Default Viewer TLS 1.2 |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros enforce Custom Origin TLS 1.2 |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros enforce Custom Origin HTTPS-only connections |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros enforce Default Viewer HTTPS with SNI |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros have logging enabled |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros have default root objects |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros enforce Default Viewer HTTPS-only connections |
| Amazon_CloudFront_Auditor | CloudFront Distribution | Do distros enforce S3 Origin Object Access Identity |
| Amazon_CloudSearch_Auditor | CloudSearch Domain | Do Domains enforce HTTPS-only |
| Amazon_CloudSearch_Auditor | CloudSearch Domain | Do Domains use TLS 1.2 |
| Amazon_CognitoIdP_Auditor | Cognito Identity Pool | Does the Password policy comply with AWS CIS Foundations Benchmark |
| Amazon_CognitoIdP_Auditor | Cognito Identity Pool | Cognito Temporary Password Age |
| Amazon_CognitoIdP_Auditor | Cognito Identity Pool | Does the Identity pool enforce MFA |
| Amazon_CognitoIdP_Auditor | Cognito Identity Pool | Is the Identity pool protected by WAF |
| Amazon_DocumentDB_Auditor | DocumentDB Instance | Are Instances publicly accessible |
| Amazon_DocumentDB_Auditor | DocumentDB Instance | Are Instance encrypted |
| Amazon_DocumentDB_Auditor | DocumentDB Instance | Is audit logging enabled |
| Amazon_DocumentDB_Auditor | DocumentDB Cluster | Is the Cluster configured for HA |
| Amazon_DocumentDB_Auditor | DocumentDB Cluster | Is the Cluster deletion protected |
| Amazon_DocumentDB_Auditor | DocumentDB Cluster | Is cluster audit logging on |
| Amazon_DocumentDB_Auditor | DocumentDB Cluster | Is cluster TLS enforcement on |
| Amazon_DocumentDB_Auditor | DocDB Snapshot | Are docdb cluster snapshots encrypted |
| Amazon_DocumentDB_Auditor | DocDB Snapshot | Are docdb cluster snapshots public |
| Amazon_DynamoDB_Auditor | DynamoDB Table | Do tables use KMS CMK for encryption |
| Amazon_DynamoDB_Auditor | DynamoDB Table | Do tables have PITR enabled |
| ~~Amazon_DynamoDB_Auditor~~ | ~~DynamoDB Table~~ | ~~Do tables have TTL enabled~~ </br> **THIS FINDING HAS BEEN RETIRED** |
| Amazon_DAX_Auditor | DAX Cluster | Do clusters encrypt data at rest |
| Amazon_DAX_Auditor | DAX Cluster | Do clusters encrypt data in transit |
| Amazon_DAX_Auditor | DAX Cluster | Do clusters have cache item TTL defined |
| Amazon_EBS_Auditor | EBS Volume | Is the Volume attached |
| Amazon_EBS_Auditor | EBS Volume | Is the Volume configured to be deleted on instance termination |
| Amazon_EBS_Auditor | EBS Volume | Is the Volume encrypted |
| Amazon_EBS_Auditor | EBS Snapshot | Is the Snapshot encrypted |
| Amazon_EBS_Auditor | EBS Snapshot | Is the Snapshot public |
| Amazon_EBS_Auditor | Account | Is account level encryption by default enabled |
| Amazon_EBS_Auditor | EBS Volume | Does the Volume have a snapshot |
| Amazon_EC2_Auditor | EC2 Instance | Is IMDSv2 enabled |
| Amazon_EC2_Auditor | EC2 Instance | Is Secure Enclave used |
| Amazon_EC2_Auditor | EC2 Instance | Is the instance internet-facing |
| Amazon_EC2_Auditor | EC2 Instance | Is Source/Dest Check disabled |
| Amazon_EC2_Auditor | AWS Account | Is Serial Port Access restricted |
| Amazon_EC2_Auditor | EC2 Instance | Is instance using an AMI baked in last 3 months |
| Amazon_EC2_Auditor | EC2 Instance | Is instance using a correctly registered AMI |
| Amazon_EC2_Auditor | Account | Are instances spread across Multiple AZs |
| Amazon_EC2_Auditor | EC2 Instance | Is the instance managed by SSM |
| Amazon_EC2_Auditor | EC2 Instance | Does the instance have a successful SSM association |
| Amazon_EC2_Auditor | EC2 Instance | Is the SSM Agent up to date |
| Amazon_EC2_Auditor | EC2 Instance | Is the Patch status up to date |
| Amazon_EC2_Auditor | EC2 Instance | Is the instance scanned by Amazon Inspector V2 |
| Amazon_EC2_Auditor | EC2 Instance | Are there any explotiable vulnerabilities |
| Amazon_EC2_Image_Builder_Auditor | Image Builder | Are pipeline tests enabled |
| Amazon_EC2_Image_Builder_Auditor | Image Builder | Is EBS encrypted |
| Amazon_EC2_Security_Group_Auditor | Security Group | Are all ports (-1) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is FTP (tcp20-21) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is TelNet (tcp23) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is WSDCOM-RPC (tcp135) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is SMB (tcp445) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is MSSQL (tcp1433) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is OracleDB (tcp1521) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is MySQL/MariaDB (tcp3306) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is RDP (tcp3389) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is PostgreSQL (tcp5432) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Kibana (tcp5601) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Redis (tcp6379) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Splunkd (tcp8089) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Elasticsearch (tcp9200) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Elasticsearch (tcp9300) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Memcached (udp11211) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Redshift (tcp5439) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is DocDB (tcp27017) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Cassandra (tcp9142) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Kafka (tcp9092) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is NFS (tcp2049) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Rsync (tcp873) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is TFTP (udp69) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Docker API (tcp2375) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is K8s API (tcp10250) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is SMTP (tcp25) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is NetBioas (tcp137-139) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is OpenVPN (udp1194) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is RabbitMQ (tcp5672) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is Spark WebUI (tcp4040) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is POP3 (tcp110) open to the internet |
| Amazon_EC2_Security_Group_Auditor | Security Group | Is VMWare ESXi (tcp8182) open to the internet |
| Amazon_ECR_Auditor | ECR Registry (Account) | Is there a registry access policy |
| Amazon_ECR_Auditor | ECR Registry (Account) | Is image replication configured |
| Amazon_ECR_Auditor | ECR Repository | Is the Repository vuln scanning with Basic or Enhanced (Inspector V2) scanning |
| Amazon_ECR_Auditor | ECR Repository | Is there an image lifecycle policy |
| Amazon_ECR_Auditor | ECR Repository | Is there a repo access policy |
| Amazon_ECR_Auditor | Image (Container) | Does the latest container have any vulns |
| Amazon_ECS_Auditor | ECS Cluster | Is container insights enabled |
| Amazon_ECS_Auditor | ECS Cluster | Is a default cluster provider configured |
| Amazon_ECS_Auditor | ECS Task Definition | Is the Task Definition using a Privileged container |
| Amazon_ECS_Auditor | ECS Task Definition | Do EC2-ECS containers use SELinux or AppArmor |
| Amazon_ECS_Auditor | ECS Task Definition | Do containers use a Root user |
| Amazon_EFS_Auditor | EFS File System | Are file systems encrypted |
| Amazon_EFS_Auditor | EFS File System | Does the File system have a custom policy attached |
| Amazon_EKS_Auditor | EKS Cluster | Is the API Server publicly accessible |
| Amazon_EKS_Auditor | EKS Cluster | Are one of the *three* latest K8s version used |
| Amazon_EKS_Auditor | EKS Cluster | Are auth or audit logs enabled |
| Amazon_EKS_Auditor | EKS Cluster | Is K8s Secrets envelope encryption used |
| Amazon_EKS_Auditor | EKS Cluster | Is a deprecated K8s version used |
| Amazon_Elasticache_Redis_Auditor | Elasticache Redis Cluster | Is an AUTH Token used |
| Amazon_Elasticache_Redis_Auditor | Elasticache Redis Cluster | Is the cluster encrypted at rest |
| Amazon_Elasticache_Redis_Auditor | Elasticache Redis Cluster | Does the cluster encrypt in transit |
| Amazon_ElasticBeanstalk_Auditor | Elastic Beanstalk environment | Is IMDSv1 disabled |
| Amazon_ElasticBeanstalk_Auditor | Elastic Beanstalk environment | Is platform auto-update and instance refresh enabled |
| Amazon_ElasticBeanstalk_Auditor | Elastic Beanstalk environment | Is enhanced health reporting enabled |
| Amazon_ElasticBeanstalk_Auditor | Elastic Beanstalk environment | Is CloudWatch log streaming enabled |
| Amazon_ElasticBeanstalk_Auditor | Elastic Beanstalk environment | Is AWS X-Ray tracing enabled |
| Amazon_ElasticsearchService_Auditor | OpenSearch domain | Are dedicated masters used |
| Amazon_ElasticsearchService_Auditor | OpenSearch domain | Is Cognito auth used |
| Amazon_ElasticsearchService_Auditor | OpenSearch domain | Is encryption at rest used |
| Amazon_ElasticsearchService_Auditor | OpenSearch domain | Is Node2Node encryption used |
| Amazon_ElasticsearchService_Auditor | OpenSearch domain | Is HTTPS-only enforced |
| Amazon_ElasticsearchService_Auditor | OpenSearch domain | Is a TLS 1.2 policy used |
| Amazon_ElasticsearchService_Auditor | OpenSearch domain | Are there available version updates |
| Amazon_ElasticsearchService_Auditor | OpenSearch domain | Is ES in a VPC |
| Amazon_ElasticsearchService_Auditor | OpenSearch domain | Is ES Publicly Accessible |
| Amazon_ELB_Auditor | ELB (Classic Load Balancer) | Do internet facing ELBs have a secure listener |
| Amazon_ELB_Auditor | ELB (Classic Load Balancer) | Do secure listeners enforce TLS 1.2 |
| Amazon_ELB_Auditor | ELB (Classic Load Balancer) | Is cross zone load balancing enabled |
| Amazon_ELB_Auditor | ELB (Classic Load Balancer) | Is connection draining enabled |
| Amazon_ELB_Auditor | ELB (Classic Load Balancer) | Is access logging enabled |
| Amazon_ELBv2_Auditor | ELBv2 (ALB) | Is access logging enabled for ALBs |
| Amazon_ELBv2_Auditor | ELBv2 (ALB/NLB) | Is deletion protection enabled |
| Amazon_ELBv2_Auditor | ELBv2 (ALB/NLB) | Do internet facing ELBs have a secure listener |
| Amazon_ELBv2_Auditor | ELBv2 (ALB/NLB) | Do secure listeners enforce TLS 1.2 |
| Amazon_ELBv2_Auditor | ELBv2 (ALB/NLB) | Are invalid HTTP headers dropped |
| Amazon_ELBv2_Auditor | ELBv2 (NLB) | Do NLBs with TLS listeners have access logging enabled |
| Amazon_ELBv2_Auditor | ELBv2 (ALB) | Do ALBs have HTTP Desync protection enabled |
| Amazon_ELBv2_Auditor | ELBv2 (ALB) | Do ALBs SGs allow access to non-Listener ports |
| Amazon_ELBv2_Auditor | ELBv2 (ALB) | Ares ALBs protected by WAF |
| Amazon_EMR_Auditor | EMR Cluster | Do clusters have a sec configuration attached |
| Amazon_EMR_Auditor | EMR Cluster | Do cluster sec configs enforce encryption in transit |
| Amazon_EMR_Auditor | EMR Cluster | Do cluster sec configs enforce encryption at rest for EMRFS |
| Amazon_EMR_Auditor | EMR Cluster | Do cluster sec configs enforce encryption at rest for EBS |
| Amazon_EMR_Auditor | EMR Cluster | Do cluster sec configs enforce Kerberos authN |
| Amazon_EMR_Auditor | EMR Cluster | Is cluster termination protection enabled |
| Amazon_EMR_Auditor | EMR Cluster | Is cluster logging enabled |
| Amazon_EMR_Auditor | AWS Account | Is EMR public SG block configured for the Account in the region |
| Amazon_EMR_Serverless_Auditor | EMR Serverless Application | Is Application in a VPC |
| Amazon_EMR_Serverless_Auditor | EMR Serverless Application | Does Application use custom container runtime |
| Amazon_InspectorV2_Audtior | Inspector scanning configuration | Is Inspector V2 scanning enabled at all |
| Amazon_InspectorV2_Audtior | Inspector scanning configuration | Is Inspector V2 scanning enabled for EC2 |
| Amazon_InspectorV2_Audtior | Inspector scanning configuration | Is Inspector V2 scanning enabled for ECR |
| Amazon_InspectorV2_Audtior | Inspector scanning configuration | Is Inspector V2 scanning enabled for Lambda |
| Amazon_InspectorV2_Audtior | Inspector scanning configuration | Is Inspector V2 scanning enabled for EC2 Deep Inspection |
| Amazon_Kinesis_Analytics_Auditor | Kinesis analytics application | Does application log to CloudWatch |
| Amazon_Kinesis_Data_Streams_Auditor | Kinesis data stream | Is stream encryption enabled |
| Amazon_Kinesis_Data_Streams_Auditor | Kinesis data stream | Is enhanced monitoring enabled |
| Amazon_Kinesis_Firehose_Auditor | Firehose delivery stream | Is delivery stream encryption enabled |
| Amazon_Managed_Blockchain_Auditor | Fabric peer node | Are chaincode logs enabled |
| Amazon_Managed_Blockchain_Auditor | Fabric peer node | Are peer node logs enabled |
| Amazon_Managed_Blockchain_Auditor | Fabric member | Are member CA logs enabled |
| Amazon_MQ_Auditor | Amazon MQ message broker | Message brokers should be encrypted with customer-managed KMS CMKs |
| Amazon_MQ_Auditor | Amazon MQ message broker | Message brokers should have audit logging enabled |
| Amazon_MQ_Auditor | Amazon MQ message broker | Message brokers should have general logging enabled |
| Amazon_MQ_Auditor | Amazon MQ message broker | Message broker should not be publicly accessible |
| Amazon_MQ_Auditor | Amazon MQ message broker | Message brokers should be configured to auto upgrade to the latest minor version |
| Amazon_MSK_Auditor | MSK Cluster | Is inter-cluster encryption used |
| Amazon_MSK_Auditor | MSK Cluster | Is client-broker communications TLS-only |
| Amazon_MSK_Auditor | MSK Cluster | Is enhanced monitoring used |
| Amazon_MSK_Auditor | MSK Cluster | Is Private CA TLS auth used |
| Amazon_MWAA_Auditor | Airflow Environment | Is a KMS CMK used for encryption |
| Amazon_MWAA_Auditor | Airflow Environment | Is the Airflow URL Public |
| Amazon_MWAA_Auditor | Airflow Environment | Are DAG Processing logs configured |
| Amazon_MWAA_Auditor | Airflow Environment | Are Scheduler logs configured |
| Amazon_MWAA_Auditor | Airflow Environment | Are Task logs configured |
| Amazon_MWAA_Auditor | Airflow Environment | Are Webserver logs configured |
| Amazon_MWAA_Auditor | Airflow Environment | Are Worker logs configured |
| Amazon_Neptune_Auditor | Neptune instance | Is Neptune instance configured for HA |
| Amazon_Neptune_Auditor | Neptune instance | Is Neptune instance storage encrypted |
| Amazon_Neptune_Auditor | Neptune instance | Does Neptune instance use IAM DB Auth |
| Amazon_Neptune_Auditor | Neptune cluster | Are TLS connections enforced |
| ~~Amazon_Neptune_Auditor~~ | ~~Neptune cluster~~ | ~~Is audit logging enabled~~ </br> **THIS FINDING HAS BEEN RETIRED** |
| Amazon_Neptune_Auditor | Neptune instance | Does Neptune instance export audit logs |
| Amazon_Neptune_Auditor | Neptune instance | Is Neptune instance deletion protected |
| Amazon_Neptune_Auditor | Neptune instance | Does Neptune instance automatically update minor versions |
| Amazon_Neptune_Auditor | Neptune cluster | Are Neptune clusters configured to auto-scale |
| Amazon_Neptune_Auditor | Neptune cluster | Are Neptune clusters configured to cache query results |
| Amazon_QLDB_Auditor | QLDB Ledger | Does ledger have deletion protection |
| Amazon_QLDB_Auditor | QLDB Export | Is export encryption enabled |
| Amazon_RDS_Auditor | RDS DB Instance | Is HA configured |
| Amazon_RDS_Auditor | RDS DB Instance | Are DB instances publicly accessible |
| Amazon_RDS_Auditor | RDS DB Instance | Is DB storage encrypted |
| Amazon_RDS_Auditor | RDS DB Instance | Do supported DBs use IAM Authentication |
| Amazon_RDS_Auditor | RDS DB Instance | Are supported DBs joined to a domain |
| Amazon_RDS_Auditor | RDS DB Instance | Is performance insights enabled |
| Amazon_RDS_Auditor | RDS DB Instance | Is deletion protection enabled |
| Amazon_RDS_Auditor | RDS DB Instance | Is database CloudWatch logging enabled |
| Amazon_RDS_Auditor | RDS Snapshot | Are snapshots encrypted |
| Amazon_RDS_Auditor | RDS Snapshot | Are snapshots public |
| Amazon_RDS_Auditor | RDS DB Cluster (Aurora) | Is Database Activity Stream configured |
| Amazon_RDS_Auditor | RDS DB Cluster (Aurora) | Is the cluster encrypted |
| Amazon_RDS_Auditor | RDS DB Instance | Does Instance have any snapshots |
| Amazon_RDS_Auditor | RDS DB Instance | Does the instance security group allow risky access |
| Amazon_RDS_Auditor | Event Subscription (Account) | Does an Event Subscription to monitor DB instances exist |
| Amazon_RDS_Auditor | Event Subscription (Account) | Does an Event Subscription to monitor paramter groups exist |
| Amazon_RDS_Auditor | RDS DB Instance | Do PostgreSQL instances use a version susceptible to Lightspin "log_fwd" attack |
| Amazon_RDS_Auditor | RDS DB Instance | Do Aurora PostgreSQL instances use a version susceptible to Lightspin "log_fwd" attack |
| Amazon_Redshift_Auditor | Redshift cluster | Is the cluster publicly accessible |
| Amazon_Redshift_Auditor | Redshift cluster | Is the cluster encrypted at rest |
| Amazon_Redshift_Auditor | Redshift cluster | Is enhanced VPC routing enabled |
| Amazon_Redshift_Auditor | Redshift cluster | Is cluster audit logging enabled |
| Amazon_Redshift_Auditor | Redshift cluster | Does the cluster use the default Admin username |
| Amazon_Redshift_Auditor | Redshift cluster | Is cluster user activity logging enabled |
| Amazon_Redshift_Auditor | Redshift cluster | Does the cluster enforce encrypted in transit |
| Amazon_Redshift_Auditor | Redshift cluster | Does the cluster take automated snapshots |
| Amazon_Redshift_Auditor | Redshift cluster | Is the cluster configured for automated major version upgrades |
| Amazon_Redshift_Serverless_Auditor | Redshift Serverless namespace | Do namespaces use IAM Roles for cross-service access |
| Amazon_Redshift_Serverless_Auditor | Redshift Serverless namespace | Do namespaces export all audit logs |
| Amazon_Redshift_Serverless_Auditor | Redshift Serverless namespace | Do namespaces use KMS CMKs |
| Amazon_Redshift_Serverless_Auditor | Redshift Serverless workgroup | Do workgroups use enhanced VPC routing |
| Amazon_Redshift_Serverless_Auditor | Redshift Serverless workgroup | Are workgroups publicly accessible |
| Amazon_Redshift_Serverless_Auditor | Redshift Serverless workgroup | Do workgroups enable user activity logging parameters |
| Amazon_Route53_Auditor | Route53 Hosted Zone | Do Hosted Zones have Query Logging enabled |
| Amazon_Route53_Auditor | Route53 Hosted Zone | Do Hosted Zones have traffic policies associated |
| Amazon_Route53_Resolver_Auditor | VPC | Do VPCs have Query Logging enabled |
| Amazon_Route53_Resolver_Auditor | VPC | Do VPCs have DNS Firewalls associated |
| Amazon_Route53_Resolver_Auditor | VPC | Do VPCs enabled DNSSEC resolution |
| Amazon_Route53_Resolver_Auditor | VPC | Do VPCs with DNS Firewall fail open |
| Amazon_S3_Auditor | S3 Bucket | Is bucket encryption enabled |
| Amazon_S3_Auditor | S3 Bucket | Is a bucket lifecycle enabled |
| Amazon_S3_Auditor | S3 Bucket | Is bucket versioning enabled |
| Amazon_S3_Auditor | S3 Bucket | Does the bucket policy allow public access |
| Amazon_S3_Auditor | S3 Bucket | Does the bucket have a policy |
| Amazon_S3_Auditor | S3 Bucket | Is server access logging enabled |
| Amazon_S3_Auditor | Account | Is account level public access block configured |
| Amazon_SageMaker_Auditor | SageMaker Notebook | Is notebook encryption enabled |
| Amazon_SageMaker_Auditor | SageMaker Notebook | Is notebook direct internet access enabled |
| Amazon_SageMaker_Auditor | SageMaker Notebook | Is the notebook in a vpc |
| Amazon_SageMaker_Auditor | SageMaker Endpoint | Is endpoint encryption enabled |
| Amazon_SageMaker_Auditor | SageMaker Model | Is model network isolation enabled |
| Amazon_Shield_Advanced_Auditor | Route53 Hosted Zone | Are Rt53 hosted zones protected by Shield Advanced |
| Amazon_Shield_Advanced_Auditor | Classic Load Balancer | Are CLBs protected by Shield Adv |
| Amazon_Shield_Advanced_Auditor | ELBv2 (ALB/NLB) | Are ELBv2s protected by Shield Adv |
| Amazon_Shield_Advanced_Auditor | Elastic IP | Are EIPs protected by Shield Adv |
| Amazon_Shield_Advanced_Auditor | CloudFront Distribution | Are CF Distros protected by Shield Adv |
| Amazon_Shield_Advanced_Auditor | Account (DRT IAM Role) | Does the DRT have account authZ via IAM role |
| ~~Amazon_Shield_Advanced_Auditor~~ | ~~Account (DRT S3 Access)~~ | ~~Does the DRT have access to WAF logs S3 buckets~~ </br> **THIS FINDING HAS BEEN RETIRED** |
| Amazon_Shield_Advanced_Auditor | Account (Shield subscription) | Is Shield Adv subscription on auto renew |
| Amazon_Shield_Advanced_Auditor | Global Accelerator Accelerator | Are GA Accelerators protected by Shield Adv |
| Amazon_Shield_Advanced_Auditor | Account | Has Shield Adv mitigated any attacks in the last 7 days |
| Amazon_SNS_Auditor | SNS Topic | Is the topic encrypted |
| Amazon_SNS_Auditor | SNS Topic | Does the topic have plaintext (HTTP) subscriptions |
| Amazon_SNS_Auditor | SNS Topic | Does the topic allow public access |
| Amazon_SNS_Auditor | SNS Topic | Does the topic allow cross-account access |
| Amazon_SQS_Auditor | SQS Queue | Are there old messages |
| Amazon_SQS_Auditor | SQS Queue | Is Server Side Encryption Enabled |
| Amazon_SQS_Auditor | SQS Queue | Is the SQS Queue publically accessible |
| Amazon_VPC_Auditor | VPC | Is the default VPC out and about |
| Amazon_VPC_Auditor | VPC | Is flow logging enabled |
| Amazon_VPC_Auditor | Subnet | Do subnets map public IPs |
| Amazon_VPC_Auditor | Subnet | Do subnets have available IP space |
| Amazon_WorkSpaces_Auditor | Workspace | Is user volume encrypted |
| Amazon_WorkSpaces_Auditor | Workspace | Is root volume encrypted |
| Amazon_WorkSpaces_Auditor | Workspace | Is running mode set to auto-off |
| Amazon_WorkSpaces_Auditor | DS Directory | Does directory allow default internet access |
| Amazon_Xray_Auditor | XRay Encryption Config | Is KMS CMK encryption used |
| AMI_Auditor | Amazon Machine Image (AMI) | Are owned AMIs public |
| AMI_Auditor | Amazon Machine Image (AMI) | Are owned AMIs encrypted |
| AWS_Accounts_Auditor | AWS Account alternate contacts | Is a Billing alternative contact identified |
| AWS_Accounts_Auditor | AWS Account alternate contacts | Is a Operations alternative contact identified |
| AWS_Accounts_Auditor | AWS Account alternate contacts | Is a Security alternative contact identified |
| AWS_ACM_Auditor | ACM Certificate | Are certificates revoked |
| AWS_ACM_Auditor | ACM Certificate | Are certificates in use |
| AWS_ACM_Auditor | ACM Certificate | Is certificate transparency logging enabled |
| AWS_ACM_Auditor | ACM Certificate | Have certificates been correctly renewed |
| AWS_ACM_Auditor | ACM Certificate | Are certificates correctly validated |
| AWS_Amplify_Auditor | AWS Amplify | Does the app have basic auth enabled on the branches |
| AWS_Amplify_Auditor | AWS Amplify | Does the app have auto deletion for branches enabled |
| AWS_AppMesh_Auditor | App Mesh mesh | Does the mesh egress filter DROP_ALL |
| AWS_AppMesh_Auditor | App Mesh virtual node | Does the backend default client policy enforce TLS |
| AWS_AppMesh_Auditor | App Mesh virtual node | Do virtual node backends have STRICT TLS mode configured for inbound connections |
| AWS_AppMesh_Auditor | App Mesh virtual node | Do virtual nodes have an HTTP access log location defined |
| AWS_Backup_Auditor | EC2 Instance | Are EC2 instances backed up |
| AWS_Backup_Auditor | EBS Volume | Are EBS volumes backed up |
| AWS_Backup_Auditor | DynamoDB tables | Are DynamoDB tables backed up |
| AWS_Backup_Auditor | RDS DB Instance | Are RDS DB instances backed up |
| AWS_Backup_Auditor | EFS File System | Are EFS file systems backed up |
| AWS_Backup_Auditor | Neptune cluster | Are Neptune clusters backed up |
| AWS_Backup_Auditor | DocumentDB cluster | Are DocumentDB clusters backed up |
| AWS_Cloud9_Auditor | Cloud9 Environment | Are Cloud9 Envs using SSM for access |
| AWS_CloudFormation_Auditor | CloudFormation Stack | Is drift detection enabled |
| AWS_CloudFormation_Auditor | CloudFormation Stack | Are stacks monitored |
| AWS_CloudHSM_Auditor | CloudHSM Cluster | Is the CloudHSM Cluster in a degraded state |
| AWS_CloudHSM_Auditor | CloudHSM HSM Module | Is the CloudHSM hardware security module in a degraded state |
| AWS_CloudHSM_Auditor | CloudHSM Backups | Is there at least one backup in a READY state |
| AWS_CloudTrail_Auditor | CloudTrail | Is the trail multi-region |
| AWS_CloudTrail_Auditor | CloudTrail | Does the trail send logs to CWL |
| AWS_CloudTrail_Auditor | CloudTrail | Is the trail encrypted by KMS |
| AWS_CloudTrail_Auditor | CloudTrail | Are global/management events logged |
| AWS_CloudTrail_Auditor | CloudTrail | Is log file validation enabled |
| AWS_CodeArtifact_Auditor | CodeArtifact Repo | Does the CodeArtifact Repo have a least privilege resource policy attached |
| AWS_CodeArtifact_Auditor | CodeArtifact Domain | Does the CodeArtifact Domain have a least privilege resource policy attached |
| AWS_CodeBuild_Auditor | CodeBuild project | Is artifact encryption enabled |
| AWS_CodeBuild_Auditor | CodeBuild project | Is Insecure SSL enabled |
| AWS_CodeBuild_Auditor | CodeBuild project | Are plaintext environmental variables used |
| AWS_CodeBuild_Auditor | CodeBuild project | Is S3 logging encryption enabled |
| AWS_CodeBuild_Auditor | CodeBuild project | Is CloudWatch logging enabled |
| AWS_CodeBuild_Auditor | CodeBuild project | Does CodeBuild store PATs or Basic Auth creds |
| AWS_CodeBuild_Auditor | CodeBuild project | Is the CodeBuild project public |
| AWS_CodeBuild_Auditor | CodeBuild project | Are CodeBuild projects using privileged containers |
| AWS_CodeDeploy_Auditor | CodeDeploy deployment group | Are CloudWatch alarms configured for state changes |
| AWS_CodeDeploy_Auditor | CodeDeploy deployment group | Are SNS topic notifications configured for event changes |
| AWS_CodeDeploy_Auditor | CodeDeploy deployment group | Is there an auto-rollback policy enabled |
| AWS_Directory_Service_Auditor | DS Directory | Is RADIUS enabled |
| AWS_Directory_Service_Auditor | DS Directory | Is CloudWatch log forwarding enabled |
| AWS_DMS_Auditor | DMS Replication Instance | Are DMS instances publicly accessible |
| AWS_DMS_Auditor | DMS Replication Instance | Is DMS multi-az configured |
| AWS_DMS_Auditor | DMS Replication Instance | Are minor version updates configured |
| AWS_Global_Accelerator_Auditor | Global Accelerator Endpoint | Is the endpoint healthy |
| AWS_Global_Accelerator_Auditor | Global Accelerator Accelerator | Are flow logs enabled for accelerator |
| AWS_Health_Auditor | AWS Health Event | Are there active Security Events |
| AWS_Health_Auditor | AWS Health Event | Are there active Abuse Events |
| AWS_Health_Auditor | AWS Health Event | Are there active Risk Events |
| AWS_Glue_Auditor | Glue Crawler | Is S3 encryption configured for the crawler |
| AWS_Glue_Auditor | Glue Crawler | Is CWL encryption configured for the crawler |
| AWS_Glue_Auditor | Glue Crawler | Is job bookmark encryption configured for the crawler |
| AWS_Glue_Auditor | Glue Data Catalog | Is data catalog encryption configured |
| AWS_Glue_Auditor | Glue Data Catalog | Is connection password encryption configured |
| AWS_Glue_Auditor | Glue Data Catalog | Is a resource policy configured |
| AWS_IAM_Auditor | IAM Access Key | Are access keys over 90 days old |
| AWS_IAM_Auditor | IAM User | Do users have permissions boundaries |
| AWS_IAM_Auditor | IAM User | Do users have MFA |
| AWS_IAM_Auditor | IAM User | Do users have in-line policies attached |
| AWS_IAM_Auditor | IAM User | Do users have managed policies attached |
| AWS_IAM_Auditor | Password policy (Account) | Does the IAM password policy meet or exceed AWS CIS Foundations Benchmark standards |
| AWS_IAM_Auditor | Server certs (Account) | Are they any Server certificates stored by IAM |
| AWS_IAM_Auditor | IAM Policy | Do managed IAM policies adhere to least privilege principles |
| AWS_IAM_Auditor | IAM User | Do User IAM inline policies adhere to least privilege principles |
| AWS_IAM_Auditor | IAM Group | Do Group IAM inline policies adhere to least privilege principles |
| AWS_IAM_Auditor | IAM Role | Do Role IAM inline policies adhere to least privilege principles |
| AWS_IAMRA_Auditor | IAMRA Trust Anchor | Do Trust Anchors contain self-signed certificates |
| AWS_IAMRA_Auditor | IAMRA Trust Anchor | Do Trust Anchors use a Certificate Revocation List (CRL) |
| AWS_IAMRA_Auditor | IAMRA Profile | Do IAMRA Profiles specify a Session Policy |
| AWS_IAMRA_Auditor | IAMRA Profile | Do IAMRA Profiles specify a Permission Boundary |
| AWS_IAMRA_Auditor | IAM Role | Do IAM Roles associated with IAMRA use Condition statements in the Trust Policy |
| AWS_Keyspaces_Auditor | Keyspaces table | Are Keyspaces Tables encrypted with a KMS CMK |
| AWS_Keyspaces_Auditor | Keyspaces table | Do Keyspaces Tables have PTR enabled |
| AWS_Keyspaces_Auditor | Keyspaces table | Are Keyspaces Tables in an unusable state |
| AWS_KMS_Auditor | KMS key | Is key rotation enabled |
| AWS_KMS_Auditor | KMS key | Does the key allow public access |
| AWS_Lambda_Auditor | Lambda function | Has function been used or updated in the last 30 days |
| AWS_Lambda_Auditor | Lambda function | Is tracing enabled |
| AWS_Lambda_Auditor | Lambda function | Is code signing used |
| AWS_Lambda_Auditor | Lambda layer | Is the layer public |
| AWS_Lambda_Auditor | Lambda function | Is the function public |
| AWS_Lambda_Auditor | Lambda function | Is the function using a supported runtime |
| AWS_Lambda_Auditor | Lambda function | Are functions in VPCs highly available in at least 2 AZs |
| AWS_Lambda_Auditor | Lambda function | Do functions have vulnerabilities |
| AWS_License_Manager_Auditor | License Manager configuration | Do LM configurations enforce a hard limit on license consumption |
| AWS_License_Manager_Auditor | License Manager configuration | Do LM configurations enforce auto-disassociation |
| AWS_MemoryDB_Auditor | MemoryDB Cluster | Do clusters use TLS |
| AWS_MemoryDB_Auditor | MemoryDB Cluster | Do clusters use KMS CMK for encryption at rest |
| AWS_MemoryDB_Auditor | MemoryDB Cluster | Are clusters configured for auto minor version updates |
| AWS_MemoryDB_Auditor | MemoryDB Cluster | Are cluster events monitored with SNS |
| AWS_MemoryDB_Auditor | MemoryDB User | MemDB Admin users should be reviewed |
| AWS_MemoryDB_Auditor | MemoryDB User | MemDB users should use passwords |
| AWS_RAM_Auditor | RAM Resource Share | Is the resource share status not failed |
| AWS_RAM_Auditor | RAM Resource Share | Does the resource allow external principals |
| AWS_Secrets_Manager_Auditor | Secrets Manager secret | Is the secret over 90 days old |
| AWS_Secrets_Manager_Auditor | Secrets Manager secret | Is secret auto-rotation enabled |
| AWS_Security_Hub_Auditor | Security Hub (Account) | Are there active high or critical findings in Security Hub |
| AWS_Security_Services_Auditor | IAM Access Analyzer (Account) | Is IAM Access Analyzer enabled |
| AWS_Security_Services_Auditor | GuardDuty (Account) | Is GuardDuty enabled |
| AWS_Security_Services_Auditor | Detective (Account) | Is Detective enabled |
| AWS_Security_Services_Auditor | Macie2 | Is Macie enabled |
| ~~AWS_Security_Services_Auditor~~ | ~~AWS WAFv2 (Regional)~~ | ~~Are Regional Web ACLs configured~~ </br> **THIS FINDING HAS BEEN RETIRED** |
| ~~AWS_Security_Services_Auditor~~ | ~~AWS WAFv2 (Global)~~ | ~~Are Global Web ACLs (for CloudFront) configured~~ </br> **THIS FINDING HAS BEEN RETIRED** |
| AWS_Systems_Manager_Auditor | SSM Document | Are self owned SSM Documents publicly shared |
| AWS_Systems_Manager_Auditor | SSM Association | Does an SSM Association that targets all Instances conduct SSM Agent updates |
| AWS_Systems_Manager_Auditor | SSM Association | Does an SSM Association that targets all Instances conduct patching |
| AWS_Systems_Manager_Auditor | SSM Association | Does an SSM Association that targets all Instances conduct inventory gathering |
| AWS_TrustedAdvisor_Auditor | Trusted Advisor Check | Is the Trusted Advisor check for MFA on Root Account failing |
| AWS_TrustedAdvisor_Auditor | Trusted Advisor Check | Is the Trusted Advisor check for ELB Listener Security failing |
| AWS_TrustedAdvisor_Auditor | Trusted Advisor Check | Is the Trusted Advisor check for CloudFront SSL Certs in IAM Cert Store failing |
| AWS_TrustedAdvisor_Auditor | Trusted Advisor Check | Is the Trusted Advisor check for CloudFront SSL Cert on Origin Server failing |
| AWS_TrustedAdvisor_Auditor | Trusted Advisor Check | Is the Trusted Advisor check for Exposed Access Keys failing |
| AWS_WAFv2_Auditor | AWS WAFv2 (Regional) | Do Regional WAFs use Cloudwatch Metrics |
| AWS_WAFv2_Auditor | AWS WAFv2 (Regional) | Do Regional WAFs use Request Sampling |
| AWS_WAFv2_Auditor | AWS WAFv2 (Regional) | Do Regional WAFs have Logging enabled |
| AWS_WAFv2_Auditor | AWS WAFv2 (Global) | Do Global WAFs use Cloudwatch Metrics |
| AWS_WAFv2_Auditor | AWS WAFv2 (Global) | Do Global WAFs use Request Sampling |
| AWS_WAFv2_Auditor | AWS WAFv2 (Global) | Do Global WAFs have Logging enabled |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a FTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a SSH service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a Telnet service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a SMTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a HTTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a POP3 service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a Win NetBIOS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a SMB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a RDP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a MSSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a MySQL/MariaDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a NFS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a Docker API service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a OracleDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a PostgreSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a Kibana service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a VMWARE ESXi service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a HTTP Proxy service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a SplunkD service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a Kubernetes API Server service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a Redis service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a Kafka service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a MongoDB/DocDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a Rabbit/AmazonMQ service publicly accessible |
| ElectricEye_AttackSurface_Auditor | EC2 instance | Is a SparkUI service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a FTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a SSH service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a Telnet service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a SMTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a HTTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a POP3 service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a Win NetBIOS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a SMB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a RDP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a MSSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a MySQL/MariaDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a NFS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a Docker API service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a OracleDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a PostgreSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a Kibana service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a VMWARE ESXi service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a HTTP Proxy service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a SplunkD service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a Kubernetes API Server service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a Redis service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a Kafka service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a MongoDB/DocDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a Rabbit/AmazonMQ service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Application load balancer | Is a SparkUI service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a FTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a SSH service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a Telnet service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a SMTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a HTTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a POP3 service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a Win NetBIOS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a SMB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a RDP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a MSSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a MySQL/MariaDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a NFS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a Docker API service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a OracleDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a PostgreSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a Kibana service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a VMWARE ESXi service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a HTTP Proxy service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a SplunkD service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a Kubernetes API Server service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a Redis service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a Kafka service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a MongoDB/DocDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a Rabbit/AmazonMQ service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Classic load balancer | Is a SparkUI service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a FTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a SSH service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a Telnet service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a SMTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a HTTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a POP3 service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a Win NetBIOS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a SMB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a RDP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a MSSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a MySQL/MariaDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a NFS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a Docker API service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a OracleDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a PostgreSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a Kibana service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a VMWARE ESXi service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a HTTP Proxy service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a SplunkD service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a Kubernetes API Server service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a Redis service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a Kafka service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a MongoDB/DocDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a Rabbit/AmazonMQ service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Elastic IP | Is a SparkUI service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a FTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a SSH service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a Telnet service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a SMTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a HTTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a POP3 service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a Win NetBIOS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a SMB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a RDP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a MSSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a MySQL/MariaDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a NFS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a Docker API service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a OracleDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a PostgreSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a Kibana service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a VMWARE ESXi service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a HTTP Proxy service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a SplunkD service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a Kubernetes API Server service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a Redis service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a Kafka service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a MongoDB/DocDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a Rabbit/AmazonMQ service publicly accessible |
| ElectricEye_AttackSurface_Auditor | CloudFront Distribution | Is a SparkUI service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a FTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a SSH service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a Telnet service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a SMTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a HTTP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a POP3 service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a Win NetBIOS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a SMB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a RDP service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a MSSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a MySQL/MariaDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a NFS service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a Docker API service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a OracleDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a PostgreSQL service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a Kibana service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a VMWARE ESXi service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a HTTP Proxy service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a SplunkD service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a Kubernetes API Server service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a Redis service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a Kafka service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a MongoDB/DocDB service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a Rabbit/AmazonMQ service publicly accessible |
| ElectricEye_AttackSurface_Auditor | Route53 Hosted Zone | Is a SparkUI service publicly accessible |
| Amazon_Secrets_Auditor | CodeBuild project | Do CodeBuild projects have secrets in plaintext env vars |
| Amazon_Secrets_Auditor | CloudFormation Stack | Do CloudFormation Stacks have secrets in parameters |
| Amazon_Secrets_Auditor | ECS Task Definition | Do ECS Task Definitions have secrets in env vars |
| Amazon_Secrets_Auditor | EC2 Instance | Do EC2 instances have secrets in User Data |
| Amazon_Shodan_Auditor | EC2 Instance | Are EC2 instances w/ public IPs indexed |
| Amazon_Shodan_Auditor | ELBv2 (ALB) | Are internet-facing ALBs indexed |
| Amazon_Shodan_Auditor | RDS Instance | Are public accessible RDS instances indexed |
| Amazon_Shodan_Auditor | OpenSearch domain | Are ES Domains outside a VPC indexed |
| Amazon_Shodan_Auditor | ELB (CLB) | Are internet-facing CLBs indexed |
| Amazon_Shodan_Auditor | DMS Replication Instance | Are public accessible DMS instances indexed |
| Amazon_Shodan_Auditor | Amazon MQ message broker | Are public accessible message brokers indexed |
| Amazon_Shodan_Auditor | CloudFront Distribution | Are CloudFront distros indexed |
| Amazon_Shodan_Auditor | Global Accelerator Accelerator | Are Global Accelerator Accelerators indexed |

Continue to check this section for information on active, retired, and renamed checks or using the `--list-checks` command in the CLI!