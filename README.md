# ElectricEye
Continuously monitor your AWS serivces for misconfigurations that can lead to degradation of confidentiality, integrity or availability. All results will be sent to Security Hub for further aggregation and analysis. 

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
  - [Deploy the baseline infrastructure](https://github.com/jonrau1/ElectricEye#deploy-the-baseline-infrastructure)
  - [Manually execute the ElectricEye ECS Task](https://github.com/jonrau1/ElectricEye#manually-execute-the-electriceye-ecs-task-you-only-need-to-do-this-once)
- [Supported Services and Checks](https://github.com/jonrau1/ElectricEye#supported-services-and-checks)
- [Known Issues & Limitiations](https://github.com/jonrau1/ElectricEye#known-issues--limitiations)
- [FAQ](https://github.com/jonrau1/ElectricEye#faq)

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
6. All findings are sent to Security Hub using the [BatchImportFindings API](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_BatchImportFindings.html), findings about compliant resources are automatically [archived](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-concepts.html) as to not clutter Security Hub

Refer to the [Supported Services and Checks](https://github.com/jonrau1/ElectricEye#supported-services-and-checks) section for an up-to-date list of supported services and checks performed by the Auditors.

## Setting Up
These steps are split across their relevant sections. All CLI commands are executed from an Ubuntu 18.04LTS [Cloud9 IDE](https://aws.amazon.com/cloud9/details/), modify them to fit your OS.

### Build and push the Docker image
Before starting [attach this IAM policy](https://github.com/jonrau1/ElectricEye/blob/master/policies/Instance_Profile_IAM_Policy.json) to your [Instance Profile](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html) (if you are using Cloud9 or EC2).

**Important Note:** The policy for the instance profile is ***highly dangerous*** given the S3, VPC and IAM related permissions given to it, Terraform needs a wide swath of CRUD permissions and even permissions for things that aren't deployed by the config files. For rolling ElectricEye out in a Production or an otherwise highly-regulated environment, consider adding [IAM Condition Keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions-resources-contextkeys.html#context_keys_table), using CI/CD (no human access) and backing up your Terraform state files to a S3 backend to add guardrails around this deployment. I would avoid adding these permissions to an IAM user, and any roles that use this should only be assumable by where you are deploying it from, consider adding other Condition Keys to the Trust Policy.

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

4. Navigate to the ECR console and copy the `URI` of your Docker image. It will be in the format of `<ACCOUNT_ID>.dkr.ecr.<AWS_REGION.amazonaws.com/<REPO_NAME>:latest`. Save this as you will need it when configuring Terraform.

Do not navigate away from this directory, as you will enter more code in the next stage.

### Setup baseline infrastructure
In this stage we will install and deploy the ElectricEye infrastructure via Terraform. To securely backup your state file, you should explore the usage of a [S3 backend](https://www.terraform.io/docs/backends/index.html), this is also described in this [AWS Security Blog post](https://aws.amazon.com/blogs/security/how-use-ci-cd-deploy-configure-aws-security-services-terraform/).

1. Install the dependencies for Terraform. **Note:** these configuration files are written for `v 0.11.x` and will not work with `v 0.12.x` Terraform installations and rewriting for that spec is not in the immediate roadmap.
```bash
wget https://releases.hashicorp.com/terraform/0.11.14/terraform_0.11.14_linux_amd64.zip
unzip terraform_0.11.14_linux_amd64.zip
sudo mv terraform /usr/local/bin/
terraform --version
```

2. Change directories, and modify the `variables.tf` config file to include the URI of your Docker image as shown in the screenshot below
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
These are the following services and checks perform by each Auditor. There are currently **100** checks supported across **34** AWS services / components.

**Important Note:** You need to have Shield Advance enabled and Business or Enterprise support to run through the full list of Shield Advanced auditor checks

| Auditor File Name                      | AWS Service                   | Auditor Scan Description                                              |
|----------------------------------------|-------------------------------|-----------------------------------------------------------------------|
| Amazon_AppStream_Auditor.py            | AppStream 2.0 (Fleets)        | Do Fleets allow Default<br>Internet Access                            |
| Amazon_AppStream_Auditor.py            | AppStream 2.0 (Images)        | Are Images Public                                                     |
| Amazon_AppStream_Auditor.py            | AppStream 2.0 (Users)         | Are users reported as Compromised                                     |
| Amazon_AppStream_Auditor.py            | AppStream 2.0 (Users)         | Do users use SAML authentication                                      |
| Amazon_CognitoIdP_Auditor.py           | Cognito Identity Pool         | Does the Password policy comply<br>with AWS CIS Foundations Benchmark |
| Amazon_CognitoIdP_Auditor.py           | Cognito Identity Pool         | Cognito Temporary Password Age                                        |
| Amazon_CognitoIdP_Auditor.py           | Cognito Identity Pool         | Does the Identity pool enforce MFA                                    |
| Amazon_DocumentDB_Auditor.py           | DocumentDB Instance           | Are Instances publicly accessible                                     |
| Amazon_DocumentDB_Auditor.py           | DocumentDB Instance           | Are Instance encrypted                                                |
| Amazon_DocumentDB_Auditor.py           | DocumentDB Cluster            | Is the Cluster configured for HA                                      |
| Amazon_DocumentDB_Auditor.py           | DocumentDB Cluster            | Is the Cluster deletion protected                                     |
| Amazon_EBS_Auditor.py                  | EBS Volume                    | Is the Volume attached                                                |
| Amazon_EBS_Auditor.py                  | EBS Volume                    | Is the Volume configured to be<br>deleted on instance termination     |
| Amazon_EBS_Auditor.py                  | EBS Volume                    | Is the Volume encrypted                                               |
| Amazon_EBS_Auditor.py                  | EBS Snapshot                  | Is the Snapshot encrypted                                             |
| Amazon_EBS_Auditor.py                  | EBS Snapshot                  | Is the Snapshot public                                                |
| Amazon_EBS_Auditor.py                  | Account                       | Is account level encryption by<br>default enabled                     |
| Amazon_EC2_SSM_Auditor.py              | EC2 Instance                  | Is the instance managed by SSM                                        |
| Amazon_EC2_SSM_Auditor.py              | EC2 Instance                  | Does the instance have a successful<br>SSM association                |
| Amazon_EC2_SSM_Auditor.py              | EC2 Instance                  | Is the SSM Agent up to date                                           |
| Amazon_EC2_SSM_Auditor.py              | EC2 Instance                  | Is the Patch status up to date                                        |
| Amazon_ECR_Auditor.py                  | ECR Repository                | Does the repository support<br>scan-on-push                           |
| Amazon_EKS_Auditor.py                  | EKS Cluster                   | Is the API Server publicly<br>accessible                              |
| Amazon_EKS_Auditor.py                  | EKS Cluster                   | Is K8s version 1.14 used                                              |
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
| Amazon_ELBv2_Auditor.py                | ELBv2 (ALB/NLB)               | Is access logging enabled                                             |
| Amazon_ELBv2_Auditor.py                | ELBv2 (ALB/NLB)               | Is deletion protection enabled                                        |
| Amazon_ELBv2_Auditor.py                | ELBv2 (ALB/NLB)               | Do internet facing ELBs have a <br>secure listener                    |
| Amazon_ELBv2_Auditor.py                | ELBv2 (ALB/NLB)               | Do secure listeners enforce TLS 1.2                                   |
| Amazon_Kinesis_Data_Streams_Auditor.py | Kinesis Data Stream           | Is stream encryption enabled                                          |
| Amazon_Kinesis_Data_Streams_Auditor.py | Kinesis Data Stream           | Is enhanced monitoring enabled                                        |
| Amazon_MSK_Auditor.py                  | MSK Cluster                   | Is inter-cluster encryption used                                      |
| Amazon_MSK_Auditor.py                  | MSK Cluster                   | Is client-broker communications<br>TLS-only                           |
| Amazon_MSK_Auditor.py                  | MSK Cluster                   | Is enhanced monitoring used                                           |
| Amazon_MSK_Auditor.py                  | MSK Cluster                   | Is Private CA TLS auth used                                           |
| Amazon_Neptune_Auditor.py              | Neptune instance              | Is Neptune configured for HA                                          |
| Amazon_Neptune_Auditor.py              | Neptune instance              | Is Neptune storage encrypted                                          |
| Amazon_Neptune_Auditor.py              | Neptune instance              | Does Neptune use IAM DB Auth                                          |
| Amazon_RDS_Auditor.py                  | RDS DB Instance               | Is HA configured                                                      |
| Amazon_RDS_Auditor.py                  | RDS DB Instance               | Are DB instances publicly accessible                                  |
| Amazon_RDS_Auditor.py                  | RDS DB Instance               | Is DB storage encrypted                                               |
| Amazon_RDS_Auditor.py                  | RDS DB Instance               | Do supported DBs use IAM Authentication                               |
| Amazon_RDS_Auditor.py                  | RDS DB Instance               | Are supported DBs joined to a domain                                  |
| Amazon_RDS_Auditor.py                  | RDS DB Instance               | Is performance insights enabled                                       |
| Amazon_RDS_Auditor.py                  | RDS DB Instance               | Is deletion protection enabled                                        |
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
| Amazon_VPC_Auditor.py                  | VPC                           | Is the default VPC out and about                                      |
| Amazon_VPC_Auditor.py                  | VPC                           | Is flow logging enabled                                               |
| Amazon_WorkSpaces_Auditor.py           | Workspace                     | Is user volume encrypted                                              |
| Amazon_WorkSpaces_Auditor.py           | Workspace                     | Is root volume encrypted                                              |
| Amazon_WorkSpaces_Auditor.py           | Workspace                     | Is running mode set to auto-off                                       |
| Amazon_WorkSpaces_Auditor.py           | Workspace Directory           | Does directory allow default internet<br>access                       |
| AMI_Auditor.py                         | Amazon Machine Image (AMI)    | Are owned AMIs public                                                 |
| AMI_Auditor.py                         | Amazon Machine Image (AMI)    | Are owned AMIs encrypted                                              |
| AWS_Backup_Auditor.py                  | EC2 Instance                  | Are EC2 instances backed up                                           |
| AWS_Backup_Auditor.py                  | EBS Volume                    | Are EBS volumes backed up                                             |
| AWS_Backup_Auditor.py                  | DynamoDB tables               | Are DynamoDB tables backed up                                         |
| AWS_Backup_Auditor.py                  | RDS DB Instance               | Are RDS DB instances backed up                                        |
| AWS_CloudFormation_Auditor.py          | CloudFormation Stack          | Is drift detection enabled                                            |
| AWS_CloudFormation_Auditor.py          | CloudFormation Stack          | Are stacks monitored                                                  |
| AWS_CodeBuild_Auditor.py               | CodeBuild project             | Is artifact encryption enabled                                        |
| AWS_CodeBuild_Auditor.py               | CodeBuild project             | Is Insecure SSL enabled                                               |
| AWS_CodeBuild_Auditor.py               | CodeBuild project             | Are plaintext environmental<br>variables used                         |
| AWS_CodeBuild_Auditor.py               | CodeBuild project             | Is S3 logging encryption enabled                                      |
| AWS_CodeBuild_Auditor.py               | CodeBuild project             | Is CloudWatch logging enabled                                         |
| AWS_Secrets_Manager_Auditor.py         | Secrets Manager secret        | Is the secret over 90 days old                                        |
| AWS_Secrets_Manager_Auditor.py         | Secrets Manager secret        | Is secret auto-rotation enabled                                       |
| AWS_Security_Hub_Auditor.py            | Security Hub (Account)        | Are there active high or critical<br>findings in Security Hub         |
| AWS_Security_Services_Auditor.py       | IAM Access Analyzer (Account) | Is IAM Access Analyzer enabled                                        |
| AWS_Security_Services_Auditor.py       | GuardDuty (Account)           | Is GuardDuty enabled                                                  |

## Known Issues & Limitations
This section is likely to wax and wane depending on future releases, PRs and changes to AWS APIs.

- No way to dynamically change Severity. All Severity Label's in Security Hub come from a conversion of `Severity.Normalized` which ranges from 1-100, to modify these values you will need to fork and modify to fit your organization's definition of severity based on threat modeling and risk appetite for certain configurations.

- DocumentDB and RDS Describe APIs bleed over each other's information, leading to failed RDS checks that are really DocDB and vice versa. The only recourse is to continually archive these findings. The root of a DocumentDB ARN is from RDS, [as described here](https://docs.aws.amazon.com/documentdb/latest/developerguide/documentdb-arns.html#documentdb-arns-constructing).

- No tag-based scoping or exemption process out of the box. You will need to manually archive these, remove checks not pertinent to you and/or create your own automation to automatically archive findings for resources that shouldn't be in-scope.

- Some resources, such as Elasticsearch Service, cannot be remediated after creation for some checks and will continue to show as non-compliant until you manually migrate them, or create automation to auto-archive these findings.

- CloudFormation checks are noisy, consider deleting the `AWS_CloudFormation_Auditor.py` file unless your organization mandates the usage of Drift detection and Alarm based monitoring for stack rollbacks.

- AppStream 2.0 Image checks are noisy, there is not a way to differentiate between AWS and customer-owned AS 2.0 images and you will get at least a dozen failed findings because of this coming from AWS-managed instances.

## FAQ
### 0. Why is continuous compliance monitoring (CCM) important?
One of the main benefits to moving to the cloud is the agility it gives you to quickly iterate on prototypes, drive business value and globally scale. That is what is known as a double-edge sword, because you can also quickly iterate into an insecure state. CCM gives you near real-time security configuration information from which you can: assess risk to your applications and data, determine if you fell out of compliance with regulatory or industry framework requirements and/or determine if you fell out of your organizational privacy protection posture, among other things. Depending on how you deliver software or services, this will allow your developers to continue being agile in their delivery while remediating any security issues that pop up. If security is owned by a central function, CCM allows them to at least *keep up* with the business, make informed risk-based decisions and quickly take action and either remediate, mitigate or accept risks due to certain configurations.

ElectricEye won't take the place of a crack squad of principal security engineers or stand-in for a compliance, infosec, privacy or risk function but it will help you stay informed to the security posture of your AWS environment across a multitude of services. You should also implement secure software delivery, privacy engineering, secure-by-design configuration, and application security programs and rely on automation where you can to develop a mature cloud security program.

Or, you could just not do security at all and look like pic below:
![ThreatActorKittens](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/plz-no.jpg)

### 1. Why should I use this tool?
Primarily because it is free to *use* (you still need to pay for the infrastructure). This tool will also help cover services not currently covered by AWS Config rules or AWS Security Hub compliance standards. This tool is also natively integrated with Security Hub, no need to create additional services to perform translation into the AWS Security Finding Format and calling the BatchImportFindings API to send findings to Security Hub.

### 2. Will this tool help me become compliant with (insert industry or regulatory framework here)?
No. If you wanted to use this tool to satisfy an audit, I would recommend you work closely with your GRC and Legal functions to determine if the checks performed by ElectricEye will legally satisfy the requirements of any compliance framework or regulations you need to comply with. If you find that it does, you can use the `Compliance.RelatedRequirements` array within the ASFF to denote those. I would recommend forking and modifying the code for that purpose. 

Howver, if you 1) work on behalf of an organization who can provide attestations that these technical controls satisfy the spirit of certain requirements in certain industry or regulatory standards and 2) would like to provide an attestation for the betterment of the community please email me to discuss.

### 3. Can this be the primary tool I use for AWS security assessments?
Only you can make that determination. More is always better, there are far more mature projects that exist such as [Prowler](https://github.com/toniblyx/prowler), [PacBot](https://github.com/tmobile/pacbot), [Cloud Inquisitor](https://github.com/RiotGames/cloud-inquisitor) and [Scout2](https://github.com/nccgroup/ScoutSuite). You should perform a detailed analysis about which tools support what services, what checks, what your ultimate downstream tool will be for taking actions or analyzing findings (Splunk, Kibana, Security Hub, Demisto, Phantom, QuickSight, etc.) and how many false-positives or false-negatives are created by what tool. Some of those tools also do other things, and that is not to mention the endless list of logging, monitoring, tracing and AppSec related tools you will also need to use. There are additional tools listed in [FAQ #13](https://github.com/jonrau1/ElectricEye#12-what-are-those-other-tools-you-mentioned) below.

### 4. Why didn't you build Config rules do these?
I built ElectricEye with Security Hub in mind, using custom Config rules would require a lot of additional infrastructure and API calls to parse out a specific rule, map what little information Config gives to the ASFF and also perform more API calls to enrich the findings and send it, that is not something I would want to do. Additionally, you are looking at $0.001/rule evaluation/region and then have to pay for the Lambda invocations and (potentially) for any findings above the first 10,000 going to Security Hub a month.

### 5. What are the advantages over AWS Security Hub compliance standards? Why shouldn't I use those instead?
You should use them! The only notable "advantage" would be ElectricEye might support a resource before a Security Hub compliance standard does, or it may support a check that Security Hub compliance standards do not. At the very least, you should use the CIS AWS Foundations Benchmark standard, it contains common sense checks that audit IAM users and basic security group misconfigurations.

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
You probably have me confused with someone else...That is a Phase 2 plan: after I am done scanning all the things, we can remediate all of the things.

### 11. Why do some of the severity scores / labels for the same failing check have different values?!
Some checks, such as the EC2 Systems Manager check for having the latest patches installed are dual-purpose and will have different severities. For instance, that check looks if you have any patch state infromation reported at all, if you do not you likely are not even managing that instance as part of the patch baseline. If a missing or failed patch is reported, then the severity is bumped up since you ARE managing patches but something happened and now the patch is not being installed.

In a similar vein, some findings that have a severity score of 0 (severity label of `INFORMATIONAL`) and a Compliance status of `PASSED` may not be Archived if it is something you may want to pay attention to. An example of this are EBS Snapshots that are shared with other accounts, it is no where near as bad as being public but you should audit these accounts to make sure you are sharing with folks who should be shared with (I cannot tell who that is, your SecOps analyst should be able to).

### 12. What if I run into throttling issues, how can I get the findings?
For now, I put (lazy) sleep steps in the bash script that runs all of the auditors. It should hopefully add enough cooldown to avoid getting near the 10TPS rate limit, let alone the 30TPS burst limit of the BIF API. You are throttled after bursting, but the auditors do not run in parallel for this reason, so you should not run into that unless for some reason you have 1000s of a single type of resource in a single region.

That said, it is possible some of you crazy folks have that many resources. A To-Do is improve ElectricEye's architecture (while increasing costs) and write up batches of findings to SQS which will be parsed and sent to BIF via Lambda. So even if you had 1000 resources, if I did the full batch of 100, you wouldn't tip that scale and have some retry ability. A similar pattern could technically be done with Kinesis, but more research for the best pattern is needed.

### 13. How much does this solution cost to run?
The costs are extremely negligible, as the primary costs are Fargate vCPU and Memory per GB per Hour and then Security Hub finding ingestion above 10,000 findings per Region per Month (the first 10,000 is perpetually free). We will use two scenarios as an example for the costs, you will likely need to perform your own analysis to forecast potential costs. ElectricEye's ECS Task Definition is 2 vCPU and 4GB of Memory by default.

#### Fargate Costs
**30 Day Period: Running ElectricEye every 12 hours and it takes 5 minutes per Run**</br>
5 hours of total runtime per month: **$0.49370/region/account/month**

**30 Day Period: Running ElectricEye every 6 hours and it takes 10 minutes per Run**</br>
20 hours of total runtime per month: **$1.61920/region/account/month**

#### Security Hub Costs
**Having 10 resources per check in scope for all 49 checks running 120 times a month (every 12 hours)**</br>
58,800 findings, 48,800 in scope for charges: **$1.46 /region/account/month**

**Having 5 resources per check in scope for all 49 checks running 60 times a month (every 12 hours)**</br>
14,700 findings, 4700 in scope for charges: **$0.14/region/account/month**

With the above examples, if you had Fargate running for 20 hours a month and generated 48,800 metered findings it would cost **$3.08320** per region per account per month. If you had Fargate running 5 hours a month and generated 4700 metered findings it would cost **$0.63470** per region per account per month.

To put it another way, the most expensive example in these scenarios would cost **$37.00** per year per region per account. That means running ElectricEye in that price range across 50 accounts and 4 regions would be **$7,399.68** a year. You could potentially save up to 70% on Fargate costs by modifying ElectricEye to run on [Fargate Spot](https://aws.amazon.com/blogs/aws/aws-fargate-spot-now-generally-available/).

### 14. What are those other tools you mentioned?
You should consider taking a look at all of these:

<br>**Secrets Scanning**</br>
- [truffleHog](https://github.com/dxa4481/truffleHog)
- [git-secrets](https://github.com/awslabs/git-secrets)

<br>**SAST**</br>
- [Bandit](https://github.com/PyCQA/bandit) (for Python)
- [GoSec](https://github.com/securego/gosec) (for Golang)
- [NodeJsScan](https://github.com/ajinabraham/NodeJsScan) (for NodeJS)
- [tfsec](https://github.com/liamg/tfsec) (for Terraform "SAST")

<br>**Linters**</br>
- [hadolint](https://github.com/hadolint/hadolint) (for Docker)
- [cfn-python-lint](https://github.com/aws-cloudformation/cfn-python-lint) (for CloudFormation)
- [cfn-nag](https://github.com/stelligent/cfn_nag) (for CloudFormation)

<br>**DAST**</br>
- [Zed Attack Proxy (ZAP)](https://owasp.org/www-project-zap/)

<br>**AV**</br>
- [ClamAV](https://www.clamav.net/documents/clamav-development)
- [aws-s3-virusscan](https://github.com/widdix/aws-s3-virusscan) (for S3 buckets, obviously)
- [BinaryAlert](http://www.binaryalert.io/) (serverless, YARA backed for S3 buckets)

<br>**IDS/IPS**</br>
- [Suricata](https://suricata-ids.org/)
- [Snort](https://www.snort.org/)
- [Zeek](https://www.zeek.org/)

<br>**DFIR**</br>
- [Fenrir](https://github.com/Neo23x0/Fenrir) (bash-based IOC scanner)
- [Loki](https://github.com/Neo23x0/Loki) (Python-based IOC scanner w/ Yara)
- [GRR Rapid Response](https://github.com/google/grr) (Python agent-based IR)
- this one is deprecated but... [MIG](http://mozilla.github.io/mig/)

<br>**Threat Hunting**</br>
- [ThreatHunter-Playbook](https://github.com/hunters-forge/ThreatHunter-Playbook)
- [Mordor](https://github.com/hunters-forge/mordor)

<br>**Misc**</br>
- [LambdaGuard](https://github.com/Skyscanner/LambdaGuard)