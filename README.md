# ElectricEye
Continuously monitor your AWS services for configurations that can lead to degradation of confidentiality, integrity or availability. All results will be sent to Security Hub for further aggregation and analysis.

***Up here in space***<br/>
***I'm looking down on you***<br/>
***My lasers trace***<br/>
***Everything you do***<br/>
<sub>*Judas Priest, 1982*</sub>

## Table of Contents
- [Description](https://github.com/jonrau1/ElectricEye#description)
- [Solution Architecture](https://github.com/jonrau1/ElectricEye#solution-architecture)
- [Setting Up](https://github.com/jonrau1/ElectricEye#setting-up)
  - [Build and push the Docker image](https://github.com/jonrau1/ElectricEye#build-and-push-the-docker-image)
  - [(OPTIONAL) Setup Shodan.io API Key](https://github.com/jonrau1/ElectricEye/tree/shodan-auditor#optional-setup-shodanio-api-key)
  - [Setup baseline infrastructure via Terraform](https://github.com/jonrau1/ElectricEye#setup-baseline-infrastructure-via-terraform)
  - [Setup baseline infrastructure via AWS CloudFormation](https://github.com/jonrau1/ElectricEye#setup-baseline-infrastructure-via-aws-cloudformation)
  - [Manually execute the ElectricEye ECS Task](https://github.com/jonrau1/ElectricEye#manually-execute-the-electriceye-ecs-task-you-only-need-to-do-this-once)
- [Supported Services and Checks](https://github.com/jonrau1/ElectricEye#supported-services-and-checks)
- [Add-on Modules](https://github.com/jonrau1/ElectricEye#add-on-modules)
  - [Config Findings Pruner](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/config-deletion-pruner)
  - [ElectricEye-Response](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response)
  - [ElectricEye-ChatOps](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-chatops)
  - [ElectricEye-Reports](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-reports)
- [Known Issues & Limitiations](https://github.com/jonrau1/ElectricEye#known-issues--limitations)
- [FAQ](https://github.com/jonrau1/ElectricEye#faq)
  - [13. How much does this solution cost to run?](https://github.com/jonrau1/ElectricEye#13-how-much-does-this-solution-cost-to-run)
  - [14. What are those other tools you mentioned?](https://github.com/jonrau1/ElectricEye#14-what-are-those-other-tools-you-mentioned)
- [Contributing](https://github.com/jonrau1/ElectricEye#contributing)
  - [ToDo](https://github.com/jonrau1/ElectricEye#to-do)
- [License](https://github.com/jonrau1/ElectricEye#license)

## Description
ElectricEye is a set of Python scripts (affectionately called **Auditors**) that continuously monitor your AWS infrastructure looking for configurations related to confidentiality, integrity and availability that do not align with AWS best practices. All findings from these scans will be sent to AWS Security Hub where you can perform basic correlation against other AWS and 3rd Party services that send findings to Security Hub. Security Hub also provides a centralized view from which account owners and other responsible parties can view and take action on findings.

ElectricEye runs on AWS Fargate, which is a serverless container orchestration service. On a schedule, Fargate will download all of the auditor scripts from a S3 bucket, run the checks and send results to Security Hub. All infrastructure will be deployed via Terraform to help you apply this solution to many accounts and/or regions. All findings (passed or failed) will contain AWS documentation references in the `Remediation.Recommendation` section of the ASFF (and the **Remediation** section of the Security Hub UI) to further educate yourself and others on.

Personas who can make use of this tool are DevOps/DevSecOps engineers, SecOps analysts, Cloud Center-of-Excellence personnel, Site Relability Engineers (SREs), Internal Audit and/or Compliance Analysts.

## Solution Architecture
![Architecture](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/Architecture.jpg)
1. A [time-based CloudWatch Event](https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html) starts up an ElectricEye task every 12 hours (or whatever time period you set)
2. The name of S3 bucket containing the ElectricEye scripts is saved as a [Systems Manager Parameter](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html) which is passed to the ElectricEye Task as an [environmental variable](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#container_definition_environment)
3. The ElectricEye Docker image is pulled from [Elastic Container Registry (ECR)](https://aws.amazon.com/ecr/) when the task runs
4. Using the bucket name from SSM Parameter Store, the Task will [download](https://docs.aws.amazon.com/cli/latest/reference/s3/cp.html) all scripts from S3
5. ElectricEye executes the scripts to scan your AWS infrastructure for both compliant and non-compliant configurations
6. All findings are sent to Security Hub using the [BatchImportFindings API](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_BatchImportFindings.html), findings about compliant resources are automatically [archived](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-concepts.html).

Refer to the [Supported Services and Checks](https://github.com/jonrau1/ElectricEye#supported-services-and-checks) section for an up-to-date list of supported services and checks performed by the Auditors.

## Setting Up
These steps are split across their relevant sections. All CLI commands are executed from an Ubuntu 18.04LTS [Cloud9 IDE](https://aws.amazon.com/cloud9/details/), modify them to fit your OS. If you do use Cloud9, navigate to Settings (represented by a Gear icon) > AWS Settings and **unmark** the selection for `AWS managed temporary credentials` (move the toggle to your left-hand side) as shown below. If you do not, you instance profile will not apply properly.
![Cloud9TempCred](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/cloud9-temp-creds.JPG)

**Note:** Ensure AWS Security Hub is enabled in the region you are attempting to run ElectricEye

### Build and push the Docker image
**Note:** You must have [permissions to push images](https://docs.aws.amazon.com/AmazonECR/latest/userguide/docker-push-ecr-image.html) to ECR before performing this step.

1. Update your machine and clone this repository
```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y unzip awscli docker.ce python3 python3-pip
pip3 install boto3
git clone https://github.com/jonrau1/ElectricEye.git
```

2. Create an ECR Repository with the AWS CLI
```bash
aws ecr create-repository --repository-name <REPO_NAME>
```

3. Build and push the ElectricEye Docker image. Be sure to replace the values for your region, Account ID and name of the ECR repository
```bash
cd ElectricEye
sudo $(aws ecr get-login --no-include-email --region <AWS_REGION>)
sudo docker build -t <REPO_NAME> .
sudo docker tag <REPO_NAME>:latest <ACCOUNT_ID>.dkr.ecr.<AWS_REGION>.amazonaws.com/<REPO_NAME>:latest
sudo docker push <ACCOUNT_ID>.dkr.ecr.<AWS_REGION>.amazonaws.com/<REPO_NAME>:latest
```

4. Navigate to the ECR console and copy the `URI` of your Docker image. It will be in the format of `<ACCOUNT_ID>.dkr.ecr.<AWS_REGION.amazonaws.com/<REPO_NAME>:latest`. Save this as you will need it when configuring Terraform or CloudFormation.

### (OPTIONAL) Setup Shodan.io API Key
This is an optional step to setup a Shodan.io API key to determine if you internet-facing resources have been indexed. This is not an exact science as a lot of abstracted services (ES, RDS, ELB) share IP space with other resources and AWS addresses (non-EIP / BYOIP) are semi-ephemeral and always change. You may end up having indexed resources that were indexed when someone else was using the IP space, you should still review it either way just to make sure.

1. Create a Shodan account and retrieve your Shodan.io API Key [from here](https://developer.shodan.io/dashboard).

2. Create a Systems Manager Parameter Store `SecureString` parameter for this API key: `aws ssm put-parameter --name electriceye-shodan-api-key --description 'Shodan.io API Key' --type SecureString --value <API-KEY-HERE>`

In both the Terraform config files and CloudFormation templates the value for this key is prepopulated with the value `placeholder`, overwrite them with this parameter you just created to be able to use the Shodan checks.

### Setup baseline infrastructure via Terraform
Before starting [attach this IAM policy](https://github.com/jonrau1/ElectricEye/blob/master/policies/Instance_Profile_IAM_Policy.json) to your [Instance Profile](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html) (if you are using Cloud9 or EC2).

**Important Note:** The policy for the instance profile is ***highly dangerous*** given the S3, VPC and IAM related permissions given to it, Terraform needs a wide swath of CRUD permissions and even permissions for things that aren't deployed by the config files. For rolling ElectricEye out in a Production or an otherwise highly-regulated environment, consider adding [IAM Condition Keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions-resources-contextkeys.html#context_keys_table), using CI/CD (no human access) and backing up your Terraform state files to a S3 backend to add guardrails around this deployment. I would avoid adding these permissions to an IAM user, and any roles that use this should only be assumable by where you are deploying it from, consider adding other Condition Keys to the Trust Policy.

In this stage we will install and deploy the ElectricEye infrastructure via Terraform. To securely backup your state file, you should explore the usage of a [S3 backend](https://www.terraform.io/docs/backends/index.html), this is also described in this [AWS Security Blog post](https://aws.amazon.com/blogs/security/how-use-ci-cd-deploy-configure-aws-security-services-terraform/).

1. Install the dependencies for Terraform. **Note:** these configuration files are written for `v 0.11.x` and will not work with `v 0.12.x` Terraform installations and rewriting for that spec is not in the immediate roadmap.
```bash
wget https://releases.hashicorp.com/terraform/0.11.14/terraform_0.11.14_linux_amd64.zip
unzip terraform_0.11.14_linux_amd64.zip
sudo mv terraform /usr/local/bin/
terraform --version
```

2. Change directories, and modify the `variables.tf` config file to include the URI of your Docker image as shown in the screenshot below. Optionally replace the value of the Shodan API Key parameter with yours if you created it in the previous optional step.
```bash
cd terraform-config-files
nano variables.tf
```
![Variables.tf modification](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/variables-tf-uri-modification.JPG)

3. Initialize, plan and apply your state with Terraform, this step should not take too long.
```bash
terraform init
terraform plan
terraform apply -auto-approve
```

4. Navigate to the S3 console and locate the name of the S3 bucket created by Terraform for the next step. It should be in the format of `electriceye-artifact-bucket-(AWS_REGION)-(ACCOUNT-NUMBER)` if you left everything else default in `variables.tf`

5. Navigate to the `auditors` directory and upload the code base to your S3 bucket
```bash
cd -
cd auditors
aws s3 sync . s3://<your-bucket-name>
```

6. Navigate to the `insights` directory and execute the Python script to have Security Hub Insights created. Insights are saved searches that can also be used as quick-view dashboards (though no where near the sophsication of a QuickSight dashboard)
```bash
cd -
cd insights
python3 electriceye-insights.py
```

In the next stage your will run the ElectricEye ECS task manually, after Terraform deploys this solution it will automatically run and it will fail due to a lack of auditors in the S3 bucket. You can skip the next section if you intend to have ElectricEye run automatically.

### Setup baseline infrastructure via AWS CloudFormation
1. Download the [CloudFormation template](https://github.com/jonrau1/ElectricEye/blob/master/cloudformation/ElectricEye_CFN.yaml) and create a Stack. Refer to the [Get Started](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/GettingStarted.Walkthrough.html) section of the *AWS CloudFormation User Guide* if you have not done this before.

2. Enter the URI of the Docker image in the space for the parameter **ElectricEyeContainerInfo**. Leave all other parameters as the default value, unless you already used `10.77.0.0/16` as the CIDR for one of your VPCs and plan to attach this VPC to your [T-Gateway](https://aws.amazon.com/transit-gateway/). Then create your stack.
![Run task dropdown](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/cfn-parameter-uri-modification.JPG)

3. Navigate to the S3 console and locate the name of the S3 bucket created by CloudFormation for the next step. It should be in the format of `electric-eye-artifact-bucket--(AWS_REGION)-(ACCOUNT-NUMBER)`

4. Navigate to the `auditors` directory and upload the code base to your S3 bucket
```bash
cd -
cd auditors
aws s3 sync . s3://<your-bucket-name>
```

5. Navigate to the `insights` directory and execute the Python script to have Security Hub Insights created. Insights are saved searches that can also be used as quick-view dashboards (though no where near the sophsication of a QuickSight dashboard)
```bash
cd -
cd insights
python3 electriceye-insights.py
```

### Manually execute the ElectricEye ECS Task (you only need to do this once)
In this stage we will use the console the manually run the ElectricEye ECS task.

1. Navigate to the ECS Console, select **Task Definitions** and toggle the `electric-eye` task definition. Select the **Actions** dropdown menu and select **Run Task** as shown in the below screenshot.
![Run task dropdown](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/run-ecs-task-dropdown.JPG)

2. Configure the following settings in the **Run Task** screen as shown in the screenshot below
- Launch type: **Fargate**
- Platform version: **LATEST**
- Cluster: **electric-eye-vpc-ecs-cluster** (unless named otherwise)
- Number of tasks: **1**
- Task group: ***LEAVE THIS BLANK***
- Cluster VPC: **electric-eye-vpc**
- Subnets: ***any eletric eye Subnet***
- Security groups: **electric-eye-vpc-sec-group** (you will need to select **Modify** and choose from another menu)
- Auto-assign public IP: **ENABLED**
![ECS task menu](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/ecs-task-menu-modifications.JPG)

3. Select **Run task**, in the next screen select the hyperlink in the **Task** column and select the **Logs** tab to view the result of the logs. **Note** logs coming to this screen may be delayed, and you may have several auditors report failures due to the lack of in-scope resources.

## Supported Services and Checks
These are the following services and checks perform by each Auditor. There are currently **160** checks supported across **49** AWS services / components using **36** Auditors. There are currently **60** supported response and remediation Playbooks with coverage across **31** AWS services / components supported by [ElectricEye-Response](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response).

**Regarding Shield Advanced checks:** You must be subscribed to Shield Advanced, be on Business/Enterprise Support and be in us-east-1 to perform all checks. The Shield Adv API only lives in us-east-1, and to have the DRT look at your account you need Biz/Ent support, hence the pre-reqs.

| Auditor File Name                      | AWS Service                   | Auditor Scan Description                                              |
|----------------------------------------|-------------------------------|-----------------------------------------------------------------------|
| Amazon_APIGW_Auditor.py                | API Gateway Stage             | Are stage metrics enabled                                             |
| Amazon_APIGW_Auditor.py                | API Gateway Stage             | Is stage API logging enabled                                          |
| Amazon_APIGW_Auditor.py                | API Gateway Stage             | Is stage caching enabled                                              |
| Amazon_APIGW_Auditor.py                | API Gateway Stage             | Is cache encryption enabled                                           |
| Amazon_APIGW_Auditor.py                | API Gateway Stage             | Is stage xray tracing configured                                      |
| Amazon_APIGW_Auditor.py                | API Gateway Stage             | Is the stage protected by a WAF WACL                                  |
| Amazon_AppStream_Auditor.py            | AppStream 2.0 (Fleets)        | Do Fleets allow Default<br>Internet Access                            |
| Amazon_AppStream_Auditor.py            | AppStream 2.0 (Images)        | Are Images Public                                                     |
| Amazon_AppStream_Auditor.py            | AppStream 2.0 (Users)         | Are users reported as Compromised                                     |
| Amazon_AppStream_Auditor.py            | AppStream 2.0 (Users)         | Do users use SAML authentication                                      |
| Amazon_CognitoIdP_Auditor.py           | Cognito Identity Pool         | Does the Password policy comply<br>with AWS CIS Foundations Benchmark |
| Amazon_CognitoIdP_Auditor.py           | Cognito Identity Pool         | Cognito Temporary Password Age                                        |
| Amazon_CognitoIdP_Auditor.py           | Cognito Identity Pool         | Does the Identity pool enforce MFA                                    |
| Amazon_DocumentDB_Auditor.py           | DocumentDB Instance           | Are Instances publicly accessible                                     |
| Amazon_DocumentDB_Auditor.py           | DocumentDB Instance           | Are Instance encrypted                                                |
| Amazon_DocumentDB_Auditor.py           | DocumentDB Instance           | Is audit logging enabled                                              |
| Amazon_DocumentDB_Auditor.py           | DocumentDB Cluster            | Is the Cluster configured for HA                                      |
| Amazon_DocumentDB_Auditor.py           | DocumentDB Cluster            | Is the Cluster deletion protected                                     |
| Amazon_DocumentDB_Auditor.py           | DocumentDB Cluster            | Is cluster audit logging on                                           |
| Amazon_DocumentDB_Auditor.py           | DocumentDB Cluster            | Is cluster TLS enforcement on                                         |
| Amazon_DocumentDB_Auditor.py           | DocDB Snapshot                | Are docdb cluster snapshots encrypted                                 |
| Amazon_DocumentDB_Auditor.py           | DocDB Snapshot                | Are docdb cluster snapshots public                                    |
| Amazon_EBS_Auditor.py                  | EBS Volume                    | Is the Volume attached                                                |
| Amazon_EBS_Auditor.py                  | EBS Volume                    | Is the Volume configured to be<br>deleted on instance termination     |
| Amazon_EBS_Auditor.py                  | EBS Volume                    | Is the Volume encrypted                                               |
| Amazon_EBS_Auditor.py                  | EBS Snapshot                  | Is the Snapshot encrypted                                             |
| Amazon_EBS_Auditor.py                  | EBS Snapshot                  | Is the Snapshot public                                                |
| Amazon_EBS_Auditor.py                  | Account                       | Is account level encryption by<br>default enabled                     |
| Amazon_EC2_Security_Group_Auditor.py   | Security Group                | Are all ports (-1) open to the internet                               |
| Amazon_EC2_Security_Group_Auditor.py   | Security Group                | Is FTP (tcp20-21) open to the internet                                |
| Amazon_EC2_Security_Group_Auditor.py   | Security Group                | Is TelNet (tcp23) open to the internet                                |
| Amazon_EC2_Security_Group_Auditor.py   | Security Group                | Is WSDCOM-RPC (tcp135) open to the<br>internet                        |
| Amazon_EC2_Security_Group_Auditor.py   | Security Group                | Is SMB (tcp445) open to the internet                                  |
| Amazon_EC2_Security_Group_Auditor.py   | Security Group                | Is MSSQL (tcp1433) open to the internet                               |
| Amazon_EC2_Security_Group_Auditor.py   | Security Group                | Is OracleDB (tcp1521) open to the internet                            |
| Amazon_EC2_Security_Group_Auditor.py   | Security Group                | Is MySQL/MariaDB (tcp3306) open to <br>the internet                   |
| Amazon_EC2_Security_Group_Auditor.py   | Security Group                | Is RDP (tcp3389) open to the internet                                 |
| Amazon_EC2_Security_Group_Auditor.py   | Security Group                | Is PostgreSQL (tcp5432) open to the <br>internet                      |
| Amazon_EC2_Security_Group_Auditor.py   | Security Group                | Is Kibana (tcp5601) open to the internet                              |
| Amazon_EC2_Security_Group_Auditor.py   | Security Group                | Is Redis (tcp6379) open to the internet                               |
| Amazon_EC2_Security_Group_Auditor.py   | Security Group                | Is Splunkd (tcp8089) open to the internet                             |
| Amazon_EC2_Security_Group_Auditor.py   | Security Group                | Is Elasticsearch (tcp9200) open to<br>the internet                    |
| Amazon_EC2_Security_Group_Auditor.py   | Security Group                | Is Elasticsearch (tcp9300) open to<br>the internet                    |
| Amazon_EC2_Security_Group_Auditor.py   | Security Group                | Is Memcached (udp11211) open to the <br>internet                      |
| Amazon_EC2_Security_Group_Auditor.py   | Security Group                | Is Redshift (tcp5439) open to the internet                            |
| Amazon_EC2_Security_Group_Auditor.py   | Security Group                | Is DocDB (tcp27017) open to the internet                              |
| Amazon_EC2_SSM_Auditor.py              | EC2 Instance                  | Is the instance managed by SSM                                        |
| Amazon_EC2_SSM_Auditor.py              | EC2 Instance                  | Does the instance have a successful<br>SSM association                |
| Amazon_EC2_SSM_Auditor.py              | EC2 Instance                  | Is the SSM Agent up to date                                           |
| Amazon_EC2_SSM_Auditor.py              | EC2 Instance                  | Is the Patch status up to date                                        |
| Amazon_ECR_Auditor.py                  | ECR Repository                | Does the repository support<br>scan-on-push                           |
| Amazon_ECR_Auditor.py                  | ECR Repository                | Is there an image lifecycle policy                                    |
| Amazon_ECR_Auditor.py                  | ECR Repository                | Is there a repo access policy                                         |
| Amazon_EFS_Auditor.py                  | EFS File System               | Are file systems encrypted                                            |
| Amazon_EKS_Auditor.py                  | EKS Cluster                   | Is the API Server publicly<br>accessible                              |
| Amazon_EKS_Auditor.py                  | EKS Cluster                   | Is K8s version 1.14 used                                              |
| Amazon_EKS_Auditor.py                  | EKS Cluster                   | Are auth or audit logs enabled                                        |
| Amazon_Elasticache_Redis_Auditor.py    | Elasticache Redis Cluster     | Is an AUTH Token used                                                 |
| Amazon_Elasticache_Redis_Auditor.py    | Elasticache Redis Cluster     | Is the cluster encrypted at rest                                      |
| Amazon_Elasticache_Redis_Auditor.py    | Elasticache Redis Cluster     | Does the cluster encrypt in transit                                   |
| Amazon_ElasticsearchService_Auditor.py | Elasticsearch Domain          | Are dedicated masters used                                            |
| Amazon_ElasticsearchService_Auditor.py | Elasticsearch Domain          | Is Cognito auth used                                                  |
| Amazon_ElasticsearchService_Auditor.py | Elasticsearch Domain          | Is encryption at rest used                                            |
| Amazon_ElasticsearchService_Auditor.py | Elasticsearch Domain          | Is Node2Node encryption used                                          |
| Amazon_ElasticsearchService_Auditor.py | Elasticsearch Domain          | Is HTTPS-only enforced                                                |
| Amazon_ElasticsearchService_Auditor.py | Elasticsearch Domain          | Is a TLS 1.2 policy used                                              |
| Amazon_ElasticsearchService_Auditor.py | Elasticsearch Domain          | Are there available version updates                                   |
| Amazon_ELB_Auditor.py                  | ELB (Classic Load Balancer)   | Do internet facing ELBs have a <br>secure listener                    |
| Amazon_ELB_Auditor.py                  | ELB (Classic Load Balancer)   | Do secure listeners enforce TLS 1.2                                   |
| Amazon_ELB_Auditor.py                  | ELB (Classic Load Balancer)   | Is cross zone load balancing enabled                                  |
| Amazon_ELB_Auditor.py                  | ELB (Classic Load Balancer)   | Is connection draining enabled                                        |
| Amazon_ELB_Auditor.py                  | ELB (Classic Load Balancer)   | Is access logging enabled                                             |
| Amazon_ELBv2_Auditor.py                | ELBv2 (ALB)                   | Is access logging enabled for ALBs                                    |
| Amazon_ELBv2_Auditor.py                | ELBv2 (ALB/NLB)               | Is deletion protection enabled                                        |
| Amazon_ELBv2_Auditor.py                | ELBv2 (ALB/NLB)               | Do internet facing ELBs have a <br>secure listener                    |
| Amazon_ELBv2_Auditor.py                | ELBv2 (ALB/NLB)               | Do secure listeners enforce TLS 1.2                                   |
| Amazon_ELBv2_Auditor.py                | ELBv2 (ALB/NLB)               | Are invalid HTTP headers dropped                                      |
| Amazon_ELBv2_Auditor.py                | ELBv2 (NLB)                   | Do NLBs with TLS listeners have access<br>logging enabled             |
| Amazon_Kinesis_Data_Streams_Auditor.py | Kinesis Data Stream           | Is stream encryption enabled                                          |
| Amazon_Kinesis_Data_Streams_Auditor.py | Kinesis Data Stream           | Is enhanced monitoring enabled                                        |
| Amazon_MSK_Auditor.py                  | MSK Cluster                   | Is inter-cluster encryption used                                      |
| Amazon_MSK_Auditor.py                  | MSK Cluster                   | Is client-broker communications<br>TLS-only                           |
| Amazon_MSK_Auditor.py                  | MSK Cluster                   | Is enhanced monitoring used                                           |
| Amazon_MSK_Auditor.py                  | MSK Cluster                   | Is Private CA TLS auth used                                           |
| Amazon_Neptune_Auditor.py              | Neptune instance              | Is Neptune configured for HA                                          |
| Amazon_Neptune_Auditor.py              | Neptune instance              | Is Neptune storage encrypted                                          |
| Amazon_Neptune_Auditor.py              | Neptune instance              | Does Neptune use IAM DB Auth                                          |
| Amazon_Neptune_Auditor.py              | Neptune cluster               | Is SSL connection enforced                                            |
| Amazon_Neptune_Auditor.py              | Neptune cluster               | Is audit logging enabled                                              |
| Amazon_RDS_Auditor.py                  | RDS DB Instance               | Is HA configured                                                      |
| Amazon_RDS_Auditor.py                  | RDS DB Instance               | Are DB instances publicly accessible                                  |
| Amazon_RDS_Auditor.py                  | RDS DB Instance               | Is DB storage encrypted                                               |
| Amazon_RDS_Auditor.py                  | RDS DB Instance               | Do supported DBs use IAM Authentication                               |
| Amazon_RDS_Auditor.py                  | RDS DB Instance               | Are supported DBs joined to a domain                                  |
| Amazon_RDS_Auditor.py                  | RDS DB Instance               | Is performance insights enabled                                       |
| Amazon_RDS_Auditor.py                  | RDS DB Instance               | Is deletion protection enabled                                        |
| Amazon_RDS_Auditor.py                  | RDS DB Instance               | Is database CloudWatch logging enabled                                |
| Amazon_RDS_Auditor.py                  | RDS Snapshot                  | Are snapshots encrypted                                               |
| Amazon_RDS_Auditor.py                  | RDS Snapshot                  | Are snapshots public                                                  |
| Amazon_Redshift_Auditor.py             | Redshift cluster              | Is the cluster publicly accessible                                    |
| Amazon_Redshift_Auditor.py             | Redshift cluster              | Is the cluster encrypted                                              |
| Amazon_Redshift_Auditor.py             | Redshift cluster              | Is enhanced VPC routing enabled                                       |
| Amazon_Redshift_Auditor.py             | Redshift cluster              | Is cluster audit logging enabled                                      |
| Amazon_S3_Auditor.py                   | S3 Bucket                     | Is bucket encryption enabled                                          |
| Amazon_S3_Auditor.py                   | S3 Bucket                     | Is a bucket lifecycle enabled                                         |
| Amazon_S3_Auditor.py                   | Account                       | Is account level public access block<br>configured                    |
| Amazon_SageMaker_Auditor.py            | SageMaker Notebook            | Is notebook encryption enabled                                        |
| Amazon_SageMaker_Auditor.py            | SageMaker Notebook            | Is notebook direct internet access<br>enabled                         |
| Amazon_SageMaker_Auditor.py            | SageMaker Notebook            | Is the notebook in a vpc                                              |
| Amazon_SageMaker_Auditor.py            | SageMaker Endpoint            | Is endpoint encryption enabled                                        |
| Amazon_SageMaker_Auditor.py            | SageMaker Model               | Is model network isolation enabled                                    |
| Amazon_Shield_Advanced_Auditor.py      | Route53 Hosted Zone           | Are Rt53 hosted zones protected by<br>Shield Advanced                 |
| Amazon_Shield_Advanced_Auditor.py      | Classic Load Balancer         | Are CLBs protected by Shield Adv                                      |
| Amazon_Shield_Advanced_Auditor.py      | ELBv2 (ALB/NLB)               | Are ELBv2s protected by Shield Adv                                    |
| Amazon_Shield_Advanced_Auditor.py      | Elastic IP                    | Are EIPs protected by Shield Adv                                      |
| Amazon_Shield_Advanced_Auditor.py      | CloudFront Distribution       | Are CF Distros protected by Shield Adv                                |
| Amazon_Shield_Advanced_Auditor.py      | Account (DRT IAM Role)        | Does the DRT have account authz via IAM<br>role                       |
| Amazon_Shield_Advanced_Auditor.py      | Account (DRT S3 Access)       | Does the DRT have access to WAF logs<br>S3 buckets                    |
| Amazon_Shield_Advanced_Auditor.py      | Account (Shield subscription) | Is Shield Adv subscription on auto <br>renew                          |
| Amazon_SNS_Auditor.py                  | SNS Topic                     | Is the topic encrypted                                                |
| Amazon_SNS_Auditor.py                  | SNS Topic                     | Does the topic have plaintext (HTTP)<br>subscriptions                 |
| Amazon_VPC_Auditor.py                  | VPC                           | Is the default VPC out and about                                      |
| Amazon_VPC_Auditor.py                  | VPC                           | Is flow logging enabled                                               |
| Amazon_WorkSpaces_Auditor.py           | Workspace                     | Is user volume encrypted                                              |
| Amazon_WorkSpaces_Auditor.py           | Workspace                     | Is root volume encrypted                                              |
| Amazon_WorkSpaces_Auditor.py           | Workspace                     | Is running mode set to auto-off                                       |
| Amazon_WorkSpaces_Auditor.py           | DS Directory                  | Does directory allow default internet<br>access                       |
| AMI_Auditor.py                         | Amazon Machine Image (AMI)    | Are owned AMIs public                                                 |
| AMI_Auditor.py                         | Amazon Machine Image (AMI)    | Are owned AMIs encrypted                                              |
| AWS_Backup_Auditor.py                  | EC2 Instance                  | Are EC2 instances backed up                                           |
| AWS_Backup_Auditor.py                  | EBS Volume                    | Are EBS volumes backed up                                             |
| AWS_Backup_Auditor.py                  | DynamoDB tables               | Are DynamoDB tables backed up                                         |
| AWS_Backup_Auditor.py                  | RDS DB Instance               | Are RDS DB instances backed up                                        |
| AWS_Backup_Auditor.py                  | EFS File System               | Are EFS file systems backed up                                        |
| AWS_CloudFormation_Auditor.py          | CloudFormation Stack          | Is drift detection enabled                                            |
| AWS_CloudFormation_Auditor.py          | CloudFormation Stack          | Are stacks monitored                                                  |
| AWS_CloudTrail_Auditor.py              | CloudTrail                    | Is the trail multi-region                                             |
| AWS_CloudTrail_Auditor.py              | CloudTrail                    | Does the trail send logs to CWL                                       |
| AWS_CloudTrail_Auditor.py              | CloudTrail                    | Is the trail encrypted by KMS                                         |
| AWS_CloudTrail_Auditor.py              | CloudTrail                    | Are global/management events logged                                   |
| AWS_CloudTrail_Auditor.py              | CloudTrail                    | Is log file validation enabled                                        |
| AWS_CodeBuild_Auditor.py               | CodeBuild project             | Is artifact encryption enabled                                        |
| AWS_CodeBuild_Auditor.py               | CodeBuild project             | Is Insecure SSL enabled                                               |
| AWS_CodeBuild_Auditor.py               | CodeBuild project             | Are plaintext environmental<br>variables used                         |
| AWS_CodeBuild_Auditor.py               | CodeBuild project             | Is S3 logging encryption enabled                                      |
| AWS_CodeBuild_Auditor.py               | CodeBuild project             | Is CloudWatch logging enabled                                         |
| AWS_Directory_Service_Auditor.py       | DS Directory                  | Is RADIUS enabled                                                     |
| AWS_Directory_Service_Auditor.py       | DS Directory                  | Is CloudWatch log forwarding enabled                                  |
| AWS_DMS_Auditor.py                     | DMS Replication Instance      | Are DMS instances publicly accessible                                 |
| AWS_DMS_Auditor.py                     | DMS Replication Instance      | Is DMS multi-az configured                                            |
| AWS_DMS_Auditor.py                     | DMS Replication Instance      | Are minor version updates configured                                  |
| AWS_Secrets_Manager_Auditor.py         | Secrets Manager secret        | Is the secret over 90 days old                                        |
| AWS_Secrets_Manager_Auditor.py         | Secrets Manager secret        | Is secret auto-rotation enabled                                       |
| AWS_Security_Hub_Auditor.py            | Security Hub (Account)        | Are there active high or critical<br>findings in Security Hub         |
| AWS_Security_Services_Auditor.py       | IAM Access Analyzer (Account) | Is IAM Access Analyzer enabled                                        |
| AWS_Security_Services_Auditor.py       | GuardDuty (Account)           | Is GuardDuty enabled                                                  |
| Shodan_Auditor.py                      | EC2 Instance                  | Are EC2 instances w/ public IPs indexed                               |
| Shodan_Auditor.py                      | ELBv2 (ALB)                   | Are internet-facing ALBs indexed                                      |
| Shodan_Auditor.py                      | RDS Instance                  | Are public accessible RDS instances indexed                           |
| Shodan_Auditor.py                      | Elasticsearch Domain          | Are ES Domains outside a VPC indexed                                  |

## Add-on Modules
The following are optional add-on's to ElectricEye that will extend its functionality via reporting, alerting, enrichment and/or finding lifecycle management.

- [Config Findings Pruner](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/config-deletion-pruner)
  - This add-on utilizes the AWS Config recorder, an Amazon CloudWatch Event rule and AWS Lambda function to parse out the ARN / ID of a resource that has been deleted and use the Security Hub `UpdateFindings` API to archive the deleted resource based on its ARN / ID.
- [ElectricEye-Response](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response)
  - ElectricEye-Response is a multi-account automation framework for response and remediation actions heavily influenced by [work I did when employed by AWS](https://aws.amazon.com/blogs/security/automated-response-and-remediation-with-aws-security-hub/). From your Security Hub Master, you can launch response and remediation actions by using CloudWatch Event rules, Lambda functions, Security Token Service (STS) and downstream services (such as Systems Manager Automation or Run Command). You can run these in a targetted manner (using Custom Actions) or fully automatically (using the CloudWatch detail type of `Security Hub Findings - Imported`).
- [ElectricEye-ChatOps](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-chatops)
  - ElectricEye-ChatOps utilizes EventBridge / CloudWatch Event Rules to consume `HIGH` and `CRITICAL` severity findings created by ElectricEye from Security Hub and route them to a Lambda function. Lambda will parse out certain elements from the Security Hub finding, create a message and post it to a Slack App's webhook for consumption by your security engineers or other personnel in a Slack channel.
- [ElectricEye-Reports](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-reports)
  - ***EXPERIMENTAL***: ElectricEye-Reports is a fully serverless solution that extends Security Hub and ElectricEye by sending select finding information to [Amazon QuickSight](https://aws.amazon.com/quicksight/) via services such as Amazon Kinesis and Amazon DynamoDB. From QuickSight, you can create rich and detailed graphics that can be shared, embedded in your enterprise applications and analyzed for purposes such as gamification of security compliance, executive reporting, business line reporting, risk assessments, audit reports, etc.

## Known Issues & Limitations
This section is likely to wax and wane depending on future releases, PRs and changes to AWS APIs.

- If you choose to build and run ElectricEye without the IAC on your own and use an existing VPC or, in the future, decide to build internet-facing services in the ElectricEye VPC you may run into Shodan.io false positives. The `socket` python module will use the DNS servers available to them; getting the IPv4 address for a DNS name (from RDS or ES endpoints for example) in your VPC will return the private IP address and lead to false positives with Shodan

- No way to dynamically change Severity. All Severity Label's in Security Hub come from a conversion of `Severity.Normalized` which ranges from 1-100, to modify these values you will need to fork and modify to fit your organization's definition of severity based on threat modeling and risk appetite for certain configurations.

- No tag-based scoping or exemption process out of the box. You will need to manually archive these, remove checks not pertinent to you and/or create your own automation to automatically archive findings for resources that shouldn't be in-scope.

- Some resources, such as Elasticsearch Service or Elastic File System, cannot be changed after creation for some checks and will continue to show as non-compliant until you manually migrate them, or create automation to auto-archive these findings.

- CloudFormation checks are noisy, consider deleting the `AWS_CloudFormation_Auditor.py` file unless your organization mandates the usage of Drift detection and Alarm based monitoring for stack rollbacks.

- AppStream 2.0 Image checks are noisy, there is not a way to differentiate between AWS and customer-owned AS 2.0 images and you will get at least a dozen failed findings because of this coming from AWS-managed instances.

## FAQ
### 0. Why is continuous compliance monitoring (CCM) important?
One of the main benefits to moving to the cloud is the agility it gives you to quickly iterate on prototypes, drive business value and globally scale. That is what is known as a double-edge sword, because you can also quickly iterate into an insecure state. CCM gives you near real-time security configuration information from which you can: assess risk to your applications and data, determine if you fell out of compliance with regulatory or industry framework requirements and/or determine if you fell out of your organizational privacy protection posture, among other things. Depending on how you deliver software or services, this will allow your developers to continue being agile in their delivery while remediating any security issues that pop up. If security is owned by a central function, CCM allows them to at least *keep up* with the business, make informed risk-based decisions and quickly take action and either remediate, mitigate or accept risks due to certain configurations.

ElectricEye won't take the place of a crack squad of principal security engineers or stand-in for a compliance, infosec, privacy or risk function but it will help you stay informed to the security posture of your AWS environment across a multitude of services. You should also implement secure software delivery, privacy engineering, secure-by-design configuration, and application security programs and rely on automation where you can to develop a mature cloud security program.

Or, you could just not do security at all and look like pic below:
![ThreatActorKittens](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/plz-no.jpg)

### 1. Why should I use this tool?
Primarily because it is free to *use* (you still need to pay for the infrastructure). This tool will also help cover services not currently covered by AWS Config rules or AWS Security Hub security standards. This tool is also natively integrated with Security Hub, no need to create additional services to perform translation into the AWS Security Finding Format and call the `BatchImportFindings` API to send findings to Security Hub.

There is logic that will auto-archive findings as they move in and out of compliance, there are also other add-ons such as multi-account response & remediation, Kibana support, QuickSight support, ChatBot integration and other goodies to be able to drop this into your cloud security team and get at least some use out of it.

Finally, you can look like the GIF below, where your security team is Jacob Trouba (New York Rangers #8 in white) laying sick open-ice hits on pesky security violations represented by Dal Colle (New York Islanders #28 in that ugly uniform).
![OpenIceHit](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/old-school-hockey-trouba.gif)

### 2. Will this tool help me become compliant with (insert framework of some sort here)?
No. If you wanted to use this tool to satisfy an audit, I would recommend you work closely with your GRC and Legal functions to determine if the checks performed by ElectricEye will legally satisfy the requirements of any compliance framework or regulations you need to comply with. If you find that it does, you can use the `Compliance.RelatedRequirements` array within the ASFF to denote those. I would recommend forking and modifying the code for that purpose. 

However, if you 1) work on behalf of an organization who can provide attestations that these technical controls satisfy the spirit of certain requirements in certain industry or regulatory standards and 2) would like to provide an attestation for the betterment of the community please email me to discuss.

### 3. Can this be the primary tool I use for AWS security assessments?
Only you can make that determination. More is always better, there are far more mature projects that exist such as [Prowler](https://github.com/toniblyx/prowler), [PacBot](https://github.com/tmobile/pacbot), [Cloud Inquisitor](https://github.com/RiotGames/cloud-inquisitor) and [Scout2](https://github.com/nccgroup/ScoutSuite). You should perform a detailed analysis about which tools support what services, what checks, what your ultimate downstream tool will be for taking actions or analyzing findings (Splunk, Kibana, Security Hub, Demisto, Phantom, QuickSight, etc.) and how many false-positives or false-negatives are created by what tool. Some of those tools also do other things, and that is not to mention the endless list of logging, monitoring, tracing and AppSec related tools you will also need to use. There are additional tools listed in [FAQ #14](https://github.com/jonrau1/ElectricEye#14-what-are-those-other-tools-you-mentioned) below.

### 4. Why didn't you build Config rules do these?
I built ElectricEye with Security Hub in mind, using custom Config rules would require a lot of additional infrastructure and API calls to parse out a specific rule, map what little information Config gives to the ASFF and also perform more API calls to enrich the findings and send it, that is not something I would want to do. Additionally, you are looking at $0.001/rule evaluation/region and then have to pay for the Lambda invocations and (potentially) for any findings above the first 10,000 going to Security Hub a month.

### 5. What are the advantages over AWS Security Hub security standards? Why shouldn't I use those instead?
You should use them! The only notable "advantage" would be ElectricEye might support a resource before a Security Hub security standard does, or it may support a check that Security Hub security standards do not. At the very least, you should use the CIS AWS Foundations Benchmark standard, it contains common sense checks that audit IAM users and basic security group misconfigurations.

### 6. What are the advantages over Config Conformance Packs? Why shouldn't I use those instead?
Similar to above, ElectricEye may support another service or another type of check that Config rules do not, on top of the additional charges you pay for using Conformance packs ($0.0012 per evaluation per Region). That said, you should probably continue to use the IAM-related Config rules as many of them are powered by [Zelkova](https://aws.amazon.com/blogs/security/protect-sensitive-data-in-the-cloud-with-automated-reasoning-zelkova/), which uses automated reasoning to analyze policies and the future consequences of policies.

### 7. Can I scope these checks by tag or by a certain resource?
No. That is something in mind for the future, and a very good idea for a PR. The only way to do so now is to manually rewrite the checks and/or delete any auditors you don't need from use.

### 8. Why do I have to set this up per account? Why can't I just scan all of my resources across all accounts?
First, the IAM permissions needed to run all of the auditors' scans are numerous, and while not particularly destructive, give a lot of Read/List rights which can be an awesome recon tool (very fitting given the name of the tool) for a malicious insider or threat actor. Giving it cross-account just makes that totally-not-cool individual's job of mass destruction so much easier, this security information can give them all sorts of ideas for attacks to launch. Lastly, it could also make provisioning a little harder, given that you have to keep up to 1000s (depending on how many accounts you have) of roles up-to-date as ElectricEye adds new capabilities.

These are lazy answers above, I did not want to make this a master-member tool because security should be democratized. You are **NOT** doing your account owners, DevOps teams or anyone else in the business any favors if you are just running scans and slapping a report you did up in Quicksight in front of them. By allowing them to view their findings in their own Security Hub console and take action on them, you are empowering and entrusting them with security goodness and fortune shall smile upon you. With that, I will not make this master-member nor accept any PRs that attempt to.

Plus, Security Hub supports master-member patterns, so you can get your nasty security-as-a-dashboard paws on the findings there.

### 9. Why don't you support (insert service name here)?
I will, eventually. If you really need a specific check supported RIGHT NOW please create an Issue, and if it is feasible, I will tackle it. PRs are welcome for any additions.

### 10. Where is that automated remediation you like so much?
~~You probably have me confused with someone else...That is a Phase 2 plan: after I am done scanning all the things, we can remediate all of the things.~~

Work has started in [ElectricEye-Response](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response)

### 11. Why do some of the severity scores / labels for the same failing check have different values?!
Some checks, such as the EC2 Systems Manager check for having the latest patches installed are dual-purpose and will have different severities. For instance, that check looks if you have any patch state infromation reported at all, if you do not you likely are not even managing that instance as part of the patch baseline. If a missing or failed patch is reported, then the severity is bumped up since you ARE managing patches but something happened and now the patch is not being installed.

In a similar vein, some findings that have a severity score of 0 (severity label of `INFORMATIONAL`) and a Compliance status of `PASSED` may not be Archived if it is something you may want to pay attention to. An example of this are EBS Snapshots that are shared with other accounts, it is no where near as bad as being public but you should audit these accounts to make sure you are sharing with folks who should be shared with (I cannot tell who that is, your SecOps analyst should be able to).

### 12. What if I run into throttling issues, how can I get the findings?
For now, I put (lazy) sleep steps in the bash script that runs all of the auditors. It should hopefully add enough cooldown to avoid getting near the 10TPS rate limit, let alone the 30TPS burst limit of the BIF API. You are throttled after bursting, but the auditors do not run in parallel for this reason, so you should not run into that unless for some reason you have 1000s of a single type of resource in a single region.

That said, it is possible some of you crazy folks have that many resources. A To-Do is improve ElectricEye's architecture (while increasing costs) and write up batches of findings to SQS which will be parsed and sent to BIF via Lambda. So even if you had 1000 resources, if I did the full batch of 100, you wouldn't tip that scale and have some retry ability. A similar pattern could technically be done with Kinesis, but more research for the best pattern is needed.

### 13. How much does this solution cost to run?
The costs are extremely negligible, as the primary costs are Fargate vCPU and Memory per GB per Hour and then Security Hub finding ingestion above 10,000 findings per Region per Month (the first 10,000 is perpetually free). We will use two scenarios as an example for the costs, you will likely need to perform your own analysis to forecast potential costs. ElectricEye's ECS Task Definition is ***2 vCPU and 4GB of Memory by default***. I made a [very rough cost calculator](https://github.com/jonrau1/ElectricEye/blob/master/cost-calculator/electriceye-cost-calculations.csv) in CSV you can refer to, I will try to reflect the latest that is on the ReadMe to the worksheet, but no promises.

#### Fargate Costs
**30 Day Period: Running ElectricEye every 12 hours and it takes 5 minutes per Run**</br>
5 hours of total runtime per month: **$0.493700/region/account/month**

**30 Day Period: Running ElectricEye every 3 hours and it takes 10 minutes per Run**</br>
40 hours of total runtime per month: **$3.949600/region/account/month**

#### Security Hub Costs
**Having 5 resources per check in scope for 108 checks running 60 times a month (every 12 hours)**</br>
32,400 findings with 22,400 in scope for charges: **$0.6720/region/account/month**

**Having 15 resources per check in scope for 108 checks running 240 times a month (every 3 hours)**</br>
388,800 findings with 378,800 in scope for charges: **$11.3640/region/account/month**

If you take the most expensive examples of having 15 resources in scope for 108 checks being run every 3 hours (for 40 total hours of Fargate runtime and 378K findings in Security Hub) that would be a combined monthly cost of **$15.3136** with a yearly cost of **$183.76** per region per month. If you were running across *4 regions* that would be **$735.05** and across *18 regions* would be **$3,307.74** per year per account.

If you ran in 2 regions across 50 accounts your approx. cost would be **$18,376.32** per year, bump that up to 4 regions and 500 accounts and you are looking at approx. **$367,526.40** a year (price is the same for 1 region, 2000 accounts). You could potentially save up to 70% on Fargate costs by modifying ElectricEye to run on [Fargate Spot](https://aws.amazon.com/blogs/aws/aws-fargate-spot-now-generally-available/).

The best way to estimate your Security Hub costs is to refer to the Usage tab within the Settings sub-menu, this will give you your total usage types, items in scope for it and estimated items per month with a forecasted cost.

### 14. What are those other tools you mentioned?
You should consider taking a look at all of these:
#### Secrets Scanning
- [truffleHog](https://github.com/dxa4481/truffleHog)
- [git-secrets](https://github.com/awslabs/git-secrets)
#### SAST
- [Bandit](https://github.com/PyCQA/bandit) (for Python)
- [GoSec](https://github.com/securego/gosec) (for Golang)
- [NodeJsScan](https://github.com/ajinabraham/NodeJsScan) (for NodeJS)
- [tfsec](https://github.com/liamg/tfsec) (for Terraform "SAST")
#### Linters
- [hadolint](https://github.com/hadolint/hadolint) (for Docker)
- [cfn-python-lint](https://github.com/aws-cloudformation/cfn-python-lint) (for CloudFormation)
- [cfn-nag](https://github.com/stelligent/cfn_nag) (for CloudFormation)
#### DAST
- [Zed Attack Proxy (ZAP)](https://owasp.org/www-project-zap/)
#### AV
- [ClamAV](https://www.clamav.net/documents/clamav-development)
- [aws-s3-virusscan](https://github.com/widdix/aws-s3-virusscan) (for S3 buckets, obviously)
- [BinaryAlert](http://www.binaryalert.io/) (serverless, YARA backed for S3 buckets)
#### IDS/IPS
- [Suricata](https://suricata-ids.org/)
- [Snort](https://www.snort.org/)
- [Zeek](https://www.zeek.org/)
#### DFIR
- [Fenrir](https://github.com/Neo23x0/Fenrir) (bash-based IOC scanner)
- [Loki](https://github.com/Neo23x0/Loki) (Python-based IOC scanner w/ Yara)
- [GRR Rapid Response](https://github.com/google/grr) (Python agent-based IR)
- this one is deprecated but... [MIG](http://mozilla.github.io/mig/)
#### Threat Hunting
- [ThreatHunter-Playbook](https://github.com/hunters-forge/ThreatHunter-Playbook)
- [Mordor](https://github.com/hunters-forge/mordor)
#### Misc
- [LambdaGuard](https://github.com/Skyscanner/LambdaGuard)

## Contributing
I am very happy to accept PR's for the following:
- Adding new Auditors
- Adding new checks to existing Auditors
- Adding new ElectricEye-Response playbooks
- Adding new Event Patterns for ElectricEye-ChatOps
- Fixing my stupid grammar errors, spelling errors and inconsistencies
- Removing any unused IAM permissions that may have popped up
- Adding new forms of deployment scripts or IAC (Salt stacks, Ansible playbooks, etc.)
- Adding Terraform `v0.12.x` support
- My to-do list

If you are working on another project whether open-source or commercial and want to include parts of ElectricEye (or the full thing) in your product / project, please contact me and at least give me credit. If it is a commercial offering that you'll be charging for, the GPL-3.0 says you should make it fully obvious that the customers can get it for free here.

### Contributors
- Alpha Testing: [Mark Yancey](https://www.linkedin.com/in/mark-yancey-jr-aspiring-cloud-security-professional-a52bb9126/)

### To-Do
- [] Create an ElectricEye Logo
- [] Investigate publishing ASFF schema to SQS>Lambda>BIF API for scale/throttle handling
- [X] Add in Shodan.io checks for internet-facing resources (RDS, Redshift, DocDB, Elasticsearch, EC2, ELBv2, etc)
  - Need to test out DocDB, Redshift and MSK
- [X] Upload response and remediation playbooks and IAC for them - Custom Action Version (Semi Auto)
- [X] Upload response and remediation playbooks and IAC for them - Imported Findings (Full Auto)
- [X] Create an Alerting framework with ~~ChatBot~~ Slack for Critical findings
- [] Create a Reporting module for use with QuickSight
  - An **EXPERIMENTAL** take is located here: [ElectricEye-Reports](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-reports)
- [] Localization of ReadMe in: Spanish, Arabic, German, Italian, French, Japenese, etc.

## License
This library is licensed under the GNU General Public License v3.0 (GPL-3.0) License. See the LICENSE file.