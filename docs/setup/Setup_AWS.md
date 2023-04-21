# ElectricEye Cloud Security Posture Management for AWS

This documentation is dedicated to using ElectricEye for evaluation of AWS Environments using CSPM and External Attack Surface Management (EASM) capabilities, as well as running ElectricEye *in* AWS

## Table of Contents

- [Quickstart on AWS](#quickstart-on-aws)
- [Building & Pushing ElectricEye Docker Image to ECR](#build-and-push-the-docker-image-to-ecr)
- [AWS Multi-Account & Multi-Region Usage](#multi-account-usage)
- [AWS EASM Reporting](#aws-external-attack-surface-reporting)

## Quickstart on AWS

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

## Multi Account Usage

ElectricEye supports running all Auditors in remote AWS Accounts as long as the remote AWS Account trusts your ***current*** AWS Account or IAM Principal. Consider deploying a StackSet from the [ElectricEye Organizations StackSet template](../cloudformation/ElectricEye_Organizations_StackSet.yaml) for easier setup.

- To specify a remote Account supply both an Account ID using `--assume-role-account` and the name of the IAM Role in that Account using `--assume-role-name`. ElectricEye will attempt to Assume the role and create a new Boto3 Session.

```bash
python3 eeauditor/controller.py -t AWS --assume-role-account 111111111111 --assume-role-name CrossAccountElectricEyeRole -o stdout
```

- To target all Accounts in a specific Organizational Unit, use the following snippet, this will only run on Active Accounts and fail gracefully for Accounts without the specified Role.

```bash
ACCOUNTS_IN_OU=$(aws organizations list-accounts-for-parent --parent-id ou-p6ba-2hwy74oa --query 'Accounts[?Status==`ACTIVE`].Id' --output text)
for accountId in $ACCOUNTS_IN_OU; do python3 ElectricEye/eeauditor/controller.py -t AWS --assume-role-account $accountId --assume-role-name CrossAccountElectricEyeRole -o stdout; done
```

- To target all Accounts in your entire AWS Organization, use the following snippet, this will only run on Active Accounts and fail gracefully for Accounts without the specified Role.

```bash
ACCOUNTS_IN_ORG=$(aws organizations list-accounts --query 'Accounts[?Status==`ACTIVE`].Id' --output text)
for accountId in $ACCOUNTS_IN_ORG; do python3 ElectricEye/eeauditor/controller.py -t AWS -a Amazon_EC2_Auditor --assume-role-account $accountId --assume-role-name CrossAccountElectricEyeRole -o stdout; done
```

- You can additionally override the Region for multi-Region assessments by supplying an AWS Region using `--region-override`, ensure the Region you specify match your current Partition (e.g., GovCloud, AWS China, etc.) otherwise ElectricEye will be very upset at you.

```bash
python3 eeauditor/controller.py -t AWS --assume-role-account 111111111111 --assume-role-name CrossAccountElectricEyeRole --region-override eu-central-1 -o stdout
```

- You can also override your current Region without specifying a remote Account, ElectricEye will still attempt to swap to the proper Region for Auditors that require running in a specific Region such as us-east-1 for AWS Health, AWS Trusted Advisor (`support`), AWS WAFv2 in Global context (`cloudfront`) and us-west-2 for Global Accelerator.

```bash
python3 eeauditor/controller.py -t AWS --region-override us-west-1 -o stdout
```

- Lastly, you can loop through all AWS Regions for evaulation as well

```bash
AWS_REGIONS=$(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text)
for regionId in $AWS_REGIONS; do python3 ElectricEye/eeauditor/controller.py -t AWS --region-override $regionId -o stdout; done
```

## AWS External Attack Surface Reporting

If you only wanted to run Attack Surface Monitoring checks use the following command which show an example of outputting the ASM checks into a JSON file for consumption into SIEM or BI tools.

```bash
python3 eeauditor/controller.py -t AWS -a ElectricEye_AttackSurface_Auditor -o json_normalized --output-file ElectricASM
```