# ElectricEye
Scans your AWS serivces for misconfigurations that can lead to degradation of confidentiality, integrity or availability. All results will be sent to Security Hub for further aggregation and analysis. 

***Up here in space***<br/>
***I'm looking down on you***<br/>
***My lasers trace***<br/>
***Everything you do***<br/>
<sub>*Judas Priest, 1982*</sub>

## Description
ElectricEye is a set of Python scripts (affectionately called **Auditors**) that scan your AWS infrastructure looking for configurations related to confidentiality, integrity and availability that do not align with AWS best practices. All findings from these scans will be sent to AWS Security Hub where you can perform basic correlation against other AWS and 3rd Party services that send findings to Security Hub. Security Hub also provides a centralized view from which account owners and other responsible parties can view and take action on findings.

ElectricEye runs on AWS Fargate, which is a serverless container orchestration service. A Docker image will be scheduled to be run on top of Fargate, download all of the auditor code from a S3 bucket, run through scans and send results to Security Hub. All infrastructure will be deployed via Terraform to help you apply this solution to many accounts and/or regions. All findings (passed or failed) will contain AWS documentation references in the `Remediation.Recommendation` section of the ASFF (the Remediaiton section of the Security Hub UI) to further educate yourself and others on.

Personas who can make use of this tool are DevOps/DevSecOps engineers, SecOps analysts, Cloud Center-of-Excellence personnel, Site Relability Engineers (SREs), Internal Audit and/or Compliance Analysts.

## Solution Architecture
![Architecture](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/Architecture.jpg)
1. A [time-based CloudWatch Event](https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html) starts up an ElectricEye task every 12 hours (or whatever time period you set)
2. The name of S3 bucket containing the ElectricEye scripts is saved as a [Systems Manager Parameter](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html) which is passed to the ElectricEye Task as an [environmental variable](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#container_definition_environment)
3. The ElectricEye Docker image is pulled from [Elastic Container Registry (ECR)](https://aws.amazon.com/ecr/) when the task runs
4. Using the bucket name from SSM Parameter Store, the Task will [download](https://docs.aws.amazon.com/cli/latest/reference/s3/cp.html) all scripts from S3
5. ElectricEye executes the scripts to scan your AWS infrastructure for both compliant and non-compliant configurations
6. All findings are sent to Security Hub using the [BatchImportFindings API](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_BatchImportFindings.html), findings about compliant resources are automatically [archived](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-concepts.html) as to not clutter Security Hub

Refer to the [Supported Services and Checks](https://github.com/jonrau1/ElectricEye#supported-services-and-checks) section for an update to date list of support services and checks performed by the Auditors.

## Setting Up
These steps are split across their relevant sections. All CLI commands are executed from an Ubuntu 18.04LTS [Cloud9 IDE](https://aws.amazon.com/cloud9/details/), modify them to fit your OS.

#### Build and push the Docker image
Before starting attach this IAM policy to your [Instance Profile](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html) (if you are using Cloud9 or EC2).
1. Update your machine and clone this repository
```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y unzip awscli docker.ce
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

4. Navigate to the ECR console and copy the `URI` of your Docker image. It will be in the format of `<ACCOUNT_ID>.dkr.ecr.<AWS_REGION.amazonaws.com/<REPO_NAME>:latest`

Do not navigate away from this directory, as you will enter more code in the next stage.

#### Deploy the baseline infrastructure
In this stage we will install and deploy the ElectricEye infrastructure via Terraform. To securely backup your state file, you should explore the usage of a [S3 backend](https://www.terraform.io/docs/backends/index.html), this is also described in this [AWS Security Blog post](https://aws.amazon.com/blogs/security/how-use-ci-cd-deploy-configure-aws-security-services-terraform/).

1. Install the dependencies for Terraform. **Note:** these configuration files are written for `v 0.11.x` and will not work with `v 0.12.x` Terraform installations and rewriting for that spec is not in the immediate roadmap.
```bash
wget https://releases.hashicorp.com/terraform/0.11.14/terraform_0.11.14_linux_amd64.zip
unzip terraform_0.11.14_linux_amd64.zip
sudo mv terraform /usr/local/bin/
terraform --version
```

#### Upload scan code to S3
Steps

#### Manually execute the ElectricEye ECS Task (you only need to do this once)
Steps

## Supported Services and Checks
These are the following services and checks perform by each Auditor. There are currently **49** checks supported across **14** services.

| Auditor File Name                      | AWS Service                | Scan Performed                                                        |
|----------------------------------------|----------------------------|-----------------------------------------------------------------------|
| Amazon_AppStream_Auditor.py            | AppStream 2.0 (Fleets)     | Do Fleets allow Default<br>Internet Access                            |
| Amazon_AppStream_Auditor.py            | AppStream 2.0 (Images)     | Are Images Public                                                     |
| Amazon_AppStream_Auditor.py            | AppStream 2.0 (Users)      | Are users reported as Compromised                                     |
| Amazon_AppStream_Auditor.py            | AppStream 2.0 (Users)      | Do users use SAML authentication                                      |
| Amazon_CognitoIdP_Auditor.py           | Cognito Identity Pool      | Does the Password policy comply<br>with AWS CIS Foundations Benchmark |
| Amazon_CognitoIdP_Auditor.py           | Cognito Identity Pool      | Cognito Temporary Password Age                                        |
| Amazon_CognitoIdP_Auditor.py           | Cognito Identity Pool      | Does the Identity pool enforce MFA                                    |
| Amazon_DocumentDB_Auditor.py           | DocumentDB Instance        | Are Instances publicly accessible                                     |
| Amazon_DocumentDB_Auditor.py           | DocumentDB Instance        | Are Instance encrypted                                                |
| Amazon_DocumentDB_Auditor.py           | DocumentDB Cluster         | Is the Cluster configured for HA                                      |
| Amazon_DocumentDB_Auditor.py           | DocumentDB Cluster         | Is the Cluster deletion protected                                     |
| Amazon_ECR_Auditor.py                  | ECR Repository             | Does the repository support<br>scan-on-push                           |
| Amazon_EKS_Auditor.py                  | EKS Cluster                | Is the API Server publicly<br>accessible                              |
| Amazon_EKS_Auditor.py                  | EKS Cluster                | Is K8s 1.14 used                                                      |
| Amazon_Elasticache_Redis_Auditor.py    | Elasticache Redis Cluster  | Is an AUTH Token used                                                 |
| Amazon_Elasticache_Redis_Auditor.py    | Elasticache Redis Cluster  | Is the cluster encrypted at rest                                      |
| Amazon_Elasticache_Redis_Auditor.py    | Elasticache Redis Cluster  | Does the cluster encrypt in transit                                   |
| Amazon_ElasticsearchService_Auditor.py | Elasticsearch Domain       | Are dedicated masters used                                            |
| Amazon_ElasticsearchService_Auditor.py | Elasticsearch Domain       | Is Cognito auth used                                                  |
| Amazon_ElasticsearchService_Auditor.py | Elasticsearch Domain       | Is encryption at rest used                                            |
| Amazon_ElasticsearchService_Auditor.py | Elasticsearch Domain       | Is Node2Node encryption used                                          |
| Amazon_ElasticsearchService_Auditor.py | Elasticsearch Domain       | Is HTTPS-only enforced                                                |
| Amazon_ElasticsearchService_Auditor.py | Elasticsearch Domain       | Is a TLS 1.2 policy used                                              |
| Amazon_ElasticsearchService_Auditor.py | Elasticsearch Domain       | Are there available version updates                                   |
| Amazon_MSK_Auditor.py                  | MSK Cluster                | Is inter-cluster encryption used                                      |
| Amazon_MSK_Auditor.py                  | MSK Cluster                | Is client-broker communications<br>TLS-only                           |
| Amazon_MSK_Auditor.py                  | MSK Cluster                | Is enhanced monitoring used                                           |
| Amazon_MSK_Auditor.py                  | MSK Cluster                | Is Private CA TLS auth used                                           |
| Amazon_RDS_Auditor.py                  | RDS DB Instance            | Is HA configured                                                      |
| Amazon_RDS_Auditor.py                  | RDS DB Instance            | Are DB instances publicly accessible                                  |
| Amazon_RDS_Auditor.py                  | RDS DB Instance            | Is DB storage encrypted                                               |
| Amazon_RDS_Auditor.py                  | RDS DB Instance            | Do supported DBs use IAM Authentication                               |
| Amazon_RDS_Auditor.py                  | RDS DB Instance            | Are supported DBs joined to a domain                                  |
| Amazon_RDS_Auditor.py                  | RDS DB Instance            | Is performance insights enabled                                       |
| Amazon_RDS_Auditor.py                  | RDS DB Instance            | Is deletion protection enabled                                        |
| AMI_Auditor.py                         | Amazon Machine Image (AMI) | Are owned AMIs public                                                 |
| AMI_Auditor.py                         | Amazon Machine Image (AMI) | Are owned AMIs encrypted                                              |
| AWS_Backup_Auditor.py                  | EC2 Instance               | Are EC2 instances backed up                                           |
| AWS_Backup_Auditor.py                  | EBS Volume                 | Are EBS volumes backed up                                             |
| AWS_Backup_Auditor.py                  | DynamoDB tables            | Are DynamoDB tables backed up                                         |
| AWS_Backup_Auditor.py                  | RDS DB Instance            | Are RDS DB instances backed up                                        |
| AWS_CloudFormation_Auditor.py          | CloudFormation Stack       | Is drift detection enabled                                            |
| AWS_CloudFormation_Auditor.py          | CloudFormation Stack       | Are stacks monitored                                                  |
| AWS_CodeBuild_Auditor.py               | CodeBuild project          | Is artifact encryption enabled                                        |
| AWS_CodeBuild_Auditor.py               | CodeBuild project          | Is Insecure SSL enabled                                               |
| AWS_CodeBuild_Auditor.py               | CodeBuild project          | Are plaintext environmental<br>variables used                         |
| AWS_CodeBuild_Auditor.py               | CodeBuild project          | Is S3 logging encryption enabled                                      |
| AWS_CodeBuild_Auditor.py               | CodeBuild project          | Is CloudWatch logging enabled                                         |
| AWS_Security_Hub_Auditor.py            | Security Hub (Account)     | Are there active high or critical<br>findings in Security Hub         |

## Known Issues & Limitiations
This section is likely to wax and wane depending on future releases, PRs and changes to AWS APIs.

- DocumentDB and RDS Describe APIs bleed over each other's information, leading to failed RDS checks that are really DocDB and vice versa. The only recourse is to continually archive these findings. The root of a DocumentDB ARN is from RDS, [as described here](https://docs.aws.amazon.com/documentdb/latest/developerguide/documentdb-arns.html#documentdb-arns-constructing).

- No tag-based scoping or exemption process out of the box. You will need to manually archive these, remove checks not pertinent to you and/or create your own automation to automatically archive findings for resources that shouldn't be in-scope.

- Some resources, such as Elasticsearch Service, cannot be remediate after creation for some checks and will continue to show as non-compliant until you manually migrate them, or create automation to silence these findings.

- CloudFormation checks are noisy, consider deleting the `AWS_CloudFormation_Auditor.py` file unless your organization mandates the usage of Drift detection and Alarm based monitoring for stack rollbacks.

## FAQ
#### 1. Why should I use this tool?
Primarily because it is free. This tool will also help cover services not currently covered by AWS Config rules or AWS Security Hub compliance standards. This tool is also natively integrated with Security Hub, no need to create additional services to perform translation into the AWS Security Finding Format and calling the BatchImportFindings API to send findings to Security Hub.

#### 2. Will this tool help me become compliant with (insert regulatory framework here)?
No. If you wanted to use this tool to satisfy an audit, I would recommend you work closely with your GRC and Legal functions to determine if the checks performed by ElectricEye will legally satisfy the requirements of any compliance framework or regulations you need to comply with. If you find that it does, you can use the `Compliance.RelatedRequirements` array within the ASFF to denote those. I would recommend forking and modifying the code for that purpose.

#### 3. Can this be the primary tool I use for AWS security scanning?
Only you can make that determination. More is always better, there are far more mature projects that exist such as [Prowler](https://github.com/toniblyx/prowler), [PacBot](https://github.com/tmobile/pacbot), [Cloud Inquisitor](https://github.com/RiotGames/cloud-inquisitor) and [Scout2](https://github.com/nccgroup/ScoutSuite). You should perform a detailed analysis about which tools support what checks, what your ultimate downstream tool will be for taking actions or analyzing findings (Splunk, Kibana, Security Hub, etc.) and how many false-positives or false-negatives are created by what tool. Some of those tools also do other things, and that is not to mention the endless list of logging, monitoring, tracing and AppSec related tools you will also need to use.

#### 4. Why didn't you build Config rules do these?
I built ElectricEye with Security Hub in mind, using custom Config rules would require a lot of additional infrastructure and API calls to parse out a specific rule, map what little information Config gives to the ASFF and also perform more API calls to enrich the findings and send it, that is not something I would want to do. Additionally, you are looking at $0.001/rule evaluation/region and then have to pay for the Lambda invocations and (potentially) for any findings above the first 10,000 going to Security Hub a month.

#### 5. What are the advantages over AWS Security Hub compliance standards? Why shouldn't I use those instead?
You should use them! The only notable "advantage" would be ElectricEye might support a resource before a Security Hub compliance standard does, or it may support a check that Security Hub compliance standards do not.

#### 6. What are the advantages over Config Conformance Packs? Why shouldn't I use those instead?
Similar to above, ElectricEye may support another service or another type of check that Config rules do not, on top of the additional charges you pay for using Conformance packs ($0.0012 per evaluation per Region).

#### 7. Can I scope these checks by tag or by a certain resource?
No. That is a great idea for a PR though, and something that is actively being looked at.

#### 8. Why do I have to set this up per account? Why can't I just scan all of my resources across all accounts?
Doing these scans per accounts let your on-call / account owner to view it within their own Security Hub versus not knowing they are potentially using dangerous configurations. Security should be democratized.

#### 9. Why don't you support (insert service name here)?
I will, eventually. Open up an issue if you really want it or open up a PR if you figured it out.

#### 10. Where is that automated remediation you like so much?
You probably have me confused with someone else...That is a Phase 2 plan: after I am done scanning all the things, we can remediate all of the things.

#### 11. What are those other tools you mentioned?
You should consider taking a look at any of these:

<br>**Secrets Scanning**</br>
- [truffleHog](https://github.com/dxa4481/truffleHog)
- [git-secrets](https://github.com/awslabs/git-secrets)

<br>**Static Analysis**</br>
- [Bandit](https://github.com/PyCQA/bandit) (for Python)
- [GoSec](https://github.com/securego/gosec) (for Golang)
- [NodeJsScan](https://github.com/ajinabraham/NodeJsScan) (for NodeJS)
- [tfsec](https://github.com/liamg/tfsec) (for Terraform "SAST")

<br>**Linters**</br>
- [hadolint](https://github.com/hadolint/hadolint) (for Docker)
- [cfn-python-lint](https://github.com/aws-cloudformation/cfn-python-lint) (for CloudFormation)
- [cfn-nag](https://github.com/stelligent/cfn_nag) (for CloudFormation)

<br>**Dynamic Analysis**</br>
- [Zed Attack Proxy (ZAP)](https://owasp.org/www-project-zap/)

<br>**Anti-Virus**</br>
- [ClamAV](https://www.clamav.net/documents/clamav-development)

<br>**IDS/IPS**</br>
- [Suricata](https://suricata-ids.org/)
- [Snort](https://www.snort.org/)
- [Zeek](https://www.zeek.org/)