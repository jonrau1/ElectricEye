# ElectricEye Cloud Security Posture Management for AWS

This documentation is dedicated to using ElectricEye for evaluation of AWS Environments using CSPM and External Attack Surface Management (EASM) capabilities.

## Table of Contents

- [Configuring TOML](#configuring-toml)
- [Use ElectricEye for AWS](#use-electriceye-for-aws)
- [Configuring the AWS Security Group Auditor](#configuring-the-aws-security-group-auditor)
- [Building & Pushing ElectricEye Docker Image to ECR](#build-and-push-the-docker-image-to-ecr)
- [AWS EASM Reporting](#aws-external-attack-surface-reporting)

## Configuring TOML

This section explains how to configure ElectricEye using a TOML configuration file. The configuration file contains settings for credentials, regions, accounts, and global settings and is located [here](../../eeauditor/external_providers.toml).

To configure the TOML file, you need to modify the values of the variables in the `[global]` and `[regions_and_accounts.aws]` sections of the file. Here's an overview of the key variables you need to configure:

- `aws_multi_account_target_type`: Set this variable to specify if you want to run ElectricEye against a list of AWS Accounts (`Accounts`), a list of accounts within specific OUs (`OU`), or every account in an AWS Organization (`Organization`).

- `credentials_location`: Set this variable to specify the location of where credentials are stored and will be retrieved from. You can choose from AWS Systems Manager Parameter Store (`AWS_SSM`), AWS Secrets Manager (`AWS_SECRETS_MANAGER`), or from the TOML file itself (`CONFIG_FILE`) which is **NOT** recommended.

**NOTE** When retrieving from SSM or Secrets Manager, your current Profile / Boto3 Session is used and *NOT* the ElectricEye Role that is specified in `aws_electric_eye_iam_role_name`. Ensure you have `ssm:GetParameter`, `secretsmanager:GetSecretValue`, and relevant `kms` permissions as needed to retrieve this values.

- `shodan_api_key_value`: This variable specifies the location (or actual value) of your Shodan.io API Key based on the option for `credentials_location`. This is an optional value but encouraged as having your resources being index by Shodan can be a useful pre-attack indicator if it is accurate information *and* your configurations are bad to begin with.

- `aws_account_targets`: This variable specifies a list of AWS accounts, OU IDs, or an organization's principal ID that you want to run ElectricEye against. If you do not specify any values, and your `aws_multi_account_target_type` is set to `Accounts` then your current AWS Account will be evaluated.

If you are running this against your Organization **leave this option empty**. Additionally, the Account you are running ElectricEye from must either be the AWS Organizations Management Account or an Account which is a Delegated Admin for an Organizations-scoped service such as AWS FMS, Amazon GuardDuty, or otherwise.

- `aws_regions_selection`: This variable specifies the AWS regions that you want to scan. If left blank, the current AWS region is used. You can provide a list of AWS regions or simply use `["All"]` to scan all regions.

- `aws_electric_eye_iam_role_name`: This variable specifies the ***Name*** of the AWS IAM role that ElectricEye will assume and utilize to execute its Checks. The role name must be the same for all accounts, including your current account. To facilitate this, use [this CloudFormation template](../../cloudformation/ElectricEye_Organizations_StackSet.yaml) and deploy it as an AWS CloudFormation StackSet. This is done to keep the credentials used for **Auditors** separate from the credentials you use for Outputs and for retrieving Secrets, it also makes it easier to audit (via CloudTrail or otherwise) the usage of the ElectricEye role.

By configuring these variables in the TOML file, you can customize ElectricEye's behavior to suit your specific AWS environments.

## Use ElectricEye for AWS

1. Navigate to the IAM console and select on **Policies** under **Access management**. Select **Create policy** and under the JSON tab, copy and paste the contents [Instance Profile IAM Policy](../policies/ElectricEye_AWS_Policy.json). Select **Review policy**, create a name, and then select **Create policy**. This Policy can be attached as to EC2 Instance Profiles, ECS Task Policies, and other locations.

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

    - 5D. Evaluate your AWS environment against a specific Check within any Auditor, it is ***not required*** to specify the Auditor name as well. The below examples runs the "[Athena.1] Athena workgroups should be configured to enforce query result encryption" check.

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

## AWS External Attack Surface Reporting

If you only wanted to run Attack Surface Monitoring checks use the following command which show an example of outputting the ASM checks into a JSON file for consumption into SIEM or BI tools.

```bash
python3 eeauditor/controller.py -t AWS -a ElectricEye_AttackSurface_Auditor -o json_normalized --output-file ElectricASM
```