# ElectricEye Response
Pre-defined multi-account response and remediation Playbooks for Security Hub and ElectricEye.

## Table of Contents
- [Description](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/README.md#description)
- [Solution Architecture](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/README.md#solution-architecture)
- [Prerequisites](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/README.md#prerequisites)
- [Setting Up](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/README.md#setting-up)
  - [Deploying ElectricEye-Response Cross-Account Role via StackSets](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/README.md#deploying-electriceye-response-cross-account-role-via-stacksets)
  - [Semi-Auto ElectricEye-Response with CloudFormation](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/README.md#semi-auto-electriceye-response-with-cloudformation)
    - [Extras](https://github.com/jonrau1/ElectricEye/tree/master/add-ons/electriceye-response/extras)
  - [Full-Auto ElectricEye-Response with CloudFormation](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/README.md#full-auto-electriceye-response-with-cloudformation)
  - [Full-Auto ElectricEye-Response with Terraform](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/README.md#full-auto-electriceye-response-with-terraform)
- [Playbook Reference Repository](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/README.md#playbook-reference-repository)
- [Known Issues and Limitations](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/README.md#known-issues-and-limitations)
- [FAQ](https://github.com/jonrau1/ElectricEye/tree/master/add-ons/electriceye-response#faq)
- [License](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/README.md#license)

## Description
ElectricEye-Response is a multi-account automation framework for response and remediation actions heavily influenced by [work I did when employed by AWS](https://aws.amazon.com/blogs/security/automated-response-and-remediation-with-aws-security-hub/). From your Security Hub Master, you can launch response and remediation actions by using CloudWatch Event rules, Lambda functions, Security Token Service (STS) and downstream services (such as Systems Manager Automation or Run Command). You can run these in a targetted manner (using Custom Actions) or fully automatically (using the CloudWatch detail type of `Security Hub Findings - Imported`).

These are written to support native Security Hub security standards (CIS, PCI-DSS, etc.) as well as ElectricEye Auditor checks. The role that ElectricEye-Response will assume to perform cross-account response actions will be deployed via CloudFormation (to take advantage of StackSets). The bulk of the codebase will be deployed via Terraform for fully-automatic remediation or via CloudFormation (for Custom Actions using custom providers).

***You should choose which version of ElectricEye-Response you use based on your organizational standard operating procedures (SOPs) for security engineering and/or incident response. The full-auto playbooks will not take into consideration any exceptions you have in place as currently designed.*** Due to the lack of exception acknowledgement, the full-auto version of ElectricEye-Response will not contain all actions.

## Solution Architecture
![ResponseThis](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/electriceye-response-sad.jpg)
1.	A CloudFormation StackSet is used to deploy the cross-account role to multiple member accounts
2.	Findings from compliance standards and ElectricEye are collected in Security Hub, identifying compliant and non-compliant resources
3.	A Security Hub Master will aggregate findings from member accounts
4.	CloudWatch Events / EventBridge rules will monitor for non-compliant findings and automatically invoke Lambda functions based on the type of failed check
5.	Depending on the Account that owns the finding, Lambda will either attempt to assume a cross account role or use its own execution role to perform remediation actions. **Note**: Two Lambda function icons are shown for illustration purposes only, a single function will contain this “if/else” logic
6.	If the finding belongs to a Member account, Lambda will assume the role deployed in Step 1
7.	Temporary security credentials with permissions to perform the remediation is given to the Lambda function and the non-compliant resource is brought back into a compliant state
8.	Findings that are remediated will have an annotation added via the Security Hub UpdateFindings API noting if the remediation was successful, successfully remediated findings will be archived

## Prerequisites
- ElectricEye-Response must be deployed to the account your Security Hub Master is located
- For using StackSets you must have the required [execution roles](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-prereqs.html) configured
- AWS Config and the PCI-DSS / CIS security standards enabled in your member accounts (ElectricEye-Response will work without these turned on)

## Setting Up
These steps are split across their relevant sections. All CLI commands are executed from an Ubuntu 18.04LTS [Cloud9 IDE](https://aws.amazon.com/cloud9/details/), modify them to fit your OS.

**Important Notes:** The IAM policy for deploying Terraform is highly dangerous and potentially destructive, as with the core module. Additionally, the cross-account role and the Master account's Lambda execution role are potentially dangerous due to the amount of Update and Delete permissions they have. The cross-account role also trusts SSM and Backup in addition to your Master account and should be monitored closely for any abuse.

### Deploying ElectricEye-Response Cross-Account Role via StackSets
In this stage we will use CloudFormation Stack Sets to deploy the multi-account role to our Security Hub member accounts
1.	Download the CloudFormation template, it is titled `ElectricEye-Response_CrossAccount_CFN.yml`
2.	Navigate to the CloudFormation Console and select **StackSets** from the navigation pane on the left-hand side
3.	Select **Create StackSet**, choose **Upload a template file** and select **Choose file** to upload the CloudFormation template you download and select **Next**
4.	Enter a StackSet name and enter in the account number of your Security Hub Master account for the IAM role to trust and select **Next** as shown below
![StackSetParams](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/electriceye-response-xaccount-stackset-param.JPG)
5.	In the next screen select the **IAM admin role** and enter the **IAM role name** for the execution role in your member accounts and select **Next** as shown below
![StackSetPerms](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/electriceye-response-xaccount-stackset-perms.JPG)
6.	For **Deployment locations** either manually enter your Security Hub member *account* or *organizational unit (OU)* numbers. You can also provide a CSV file of all account numbers instead of manually entering them
7.	Specify the **region(s)** you will deploy this stack to and optionally modify the **Deployment options** and select **Next** as shown below
![StackSetRegions](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/electriceye-response-xaccount-stackset-regions.JPG)
8.	On the next screen acknowledge the information box under **Capabilities** and select **Submit**
9.	Select the **Stack instances** tab and continually refresh as the StackSet deploys the IAM role. Once all accounts are showing the status of “current” you can proceed to the next stage

### Semi-Auto ElectricEye-Response with CloudFormation
In this section we will deploy Custom Actions, CloudWatch Events and Lambda functions to the Security Hub Master using a CloudFormation template.

**Important Note:** The maximum account limit for Custom Actions is 50 per Region per Account for Security Hub, there is also a 200 max resource limit per CloudFormation Stack and for that reason there are two templates (the second template is named `ElectricEye-Response_SemiAutoPlaybooks_DirectorsCut_CFN.yml` it has other Playbooks that the main Template does not if you wanted to copy & paste between them), we will only be using the first one. You can side-step this by setting up some actions as a mix of Full-Auto and Semi-Auto based on your organizational policies, but then you will be using both CFN and Terraform to deploy these. 

1. Create a S3 bucket, clone this repository and upload the contents of `lambda-packages` to your S3 bucket. Take note of your S3 bucket name as you will need it as a parameter in the CloudFormation stack
```bash
aws s3 mb s3://[MY-BUCKET-NAME-HERE]
git clone https://github.com/jonrau1/ElectricEye.git
cd ElectricEye/add-ons/electriceye-response/lambda-packages
aws s3 sync . s3://[MY-BUCKET-NAME-HERE]
```

2. Download the CloudFormation template, it is named `ElectricEye-Response_SemiAutoPlaybooks_CFN.yml` and create a Stack. Enter a name and values for the Parameters. If you do not use WAF, ServiceNow or JIRA you can leave their values as `placeholder`, the only parameter you need is the S3 bucket created in Step 1 as shown below. For information on creating the ServiceNow or JIRA parameters refer to the [Extras Readme](https://github.com/jonrau1/ElectricEye/tree/master/add-ons/electriceye-response/extras).
![SemiAutoParams](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/electriceye-response-semi-auto-CFN-params.jpg)

3. Once the Stack finishes creating you will be able launch these semi-automatic response and remediation Playbooks using Security Hub custom actions. Select the **Findings** tab in the Security Hub console, select any finding and choose the **Actions** menu to be presented with a view as shown below.
![SemiAutoActions](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/electriceye-response-semi-auto-dropdown.jpg)

### Full-Auto ElectricEye-Response with CloudFormation
***WORK IN PROGRESS***

### Full-Auto ElectricEye-Response with Terraform
In this section we will deploy CloudWatch Events and Lambda functions to the Security Hub Master using Terraform. **Important Note:** Only certain playbooks are contained within the full-auto version of ElectricEye-Response. Actions such as Shield Advanced protection, creating one-time Backups or deleting EC2 instances should likely **NOT** be executed without a human pulling the trigger.

All CLI commands are executed from an Ubuntu 18.04LTS [Cloud9 IDE](https://aws.amazon.com/cloud9/details/), modify them to fit your OS. Before starting [attach this IAM policy](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/policies/electriceye-response-terraform-policy.json) to your [Instance Profile](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html) (if you are using Cloud9 or EC2).

1. Update your machine and install the dependencies for Terraform. **Note:** these configuration files are written for `v 0.11.x` and will not work with `v 0.12.x` Terraform installations and rewriting for that spec is not in the immediate roadmap.
```bash
sudo apt update
sudo apt upgrade -y
sudo apt install wget -y
wget https://releases.hashicorp.com/terraform/0.11.14/terraform_0.11.14_linux_amd64.zip
unzip terraform_0.11.14_linux_amd64.zip
sudo mv terraform /usr/local/bin/
terraform --version
```

2. Clone this repository, change directories to the `ElectricEye-Response` root folder and clone the contents of `lambda-packages` to `terraform`
```bash
git clone https://github.com/jonrau1/ElectricEye.git
cd ElectricEye/add-ons/electriceye-response
cp -a lambda-packages/. terraform/
```

3. Change directories and then initialize, plan and apply your state with Terraform.
```bash
cd terraform
terraform init
terraform plan
terraform apply -auto-approve
```

That is all it takes to execute full auto response and remediation actions with ElectricEye-Response. As alluded to above, only a small subsection of actions across the CIS, PCI and ElectricEye Auditor checks are supported. If you want to add others, fork this repo and follow along `main.tf` to create other full auto playbooks.

## Playbook Reference Repository
There are currently **62** supported response and remediation Playbooks with coverage across **32** AWS services / components supported by ElectricEye-Response.


|                 Playbook Name                |                                          AWS Service In Scope                                         |                                                                                                         Action Taken                                                                                                         |
|:--------------------------------------------:|:-----------------------------------------------------------------------------------------------------:|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| AzureDevOps_WorkItem_Playbook.py             |                                                  Any                                                  | Creates an Azure DevOps Issue in a specified Project                                                                                                                                                                         |
| CloudTrail_FileValidation_Playbook.py        |                                               CloudTrail                                              | Re-enable Log File Validation                                                                                                                                                                                                |
| Cognito_UserPool_CIS_PW_Policy_Playbook.py   |                                           Cognito User Pool                                           | Applies a CIS-compliant password policy to the user pool                                                                                                                                                                     |
| Cognito_UserPool_Temp_PW_Policy_Playbook.py  |                                           Cognito User Pool                                           | Configures temporary passwords to expire after 24 hours                                                                                                                                                                      |
| Create_JIRA_Issue_Playbook.py                |                                                  Any                                                  | Creates JIRA "Bug" Issues in a Project of your choice using the<br>Jira-Python library                                                                                                                                       |
| Disable_Expired_Access_Key_Playbook.py       |                                            IAM Access Keys                                            | Will disable all access keys for a user over 90 days old                                                                                                                                                                     |
| DocDB_Cluster_DelProt_Playbook.py            |                                             DocDB Cluster                                             | Enables deletion protection on cluster                                                                                                                                                                                       |
| DocDB_Privatize_Snapshot_Playbook.py         |                                             DocDB Snapshot                                            | Removes public access from docdb cluster snapshot                                                                                                                                                                            |
| EBS_Encryption_Policy_Playbook.py            |                                             Account (EBS)                                             | Applies account-level EBS encryption-by-default policy                                                                                                                                                                       |
| EBS_Privatize_Snapshot_Playbook.py           |                                              EBS Snapshot                                             | Remove Public access to Snapshot                                                                                                                                                                                             |
| EC2_Isolation_Playbook.py                    |                                              EC2 Instance                                             | Create a new Security Group without any rules and <br>attach it to the instance thus isolating it                                                                                                                            |
| EC2_SnapNDestory_Playbook.py                 |                                              EC2 Instance                                             | Stop, snapshot and terminate an instance                                                                                                                                                                                     |
| EC2_StopNSnap_Playbook.py                    |                                              EC2 Instance                                             | Stop and snapshot an instance                                                                                                                                                                                                |
| ECR_Lifecycle_Policy_Playbook.py             |                                                ECR Repo                                               | Adds a lifecycle policy to the repo to expire untagged images<br>over 2                                                                                                                                                      |
| ELBV2_DelProt_Playbook.py                    |                                            ELBv2 (ALB/NLB)                                            | Enable ELBv2 deletion protection                                                                                                                                                                                             |
| ELBV2_Drop_Invalid_HTTP_Header_Playbook.py   |                                            ELBv2 (ALB/NLB)                                            | Configure ELBv2 to drop Invalid<br>HTTP headers                                                                                                                                                                              |
| ES_Enable_Error_Logging_Playbook.py          |                                               ES Domain                                               | Enables error logging by creating and apply a new<br>cloudwatch log group and resource policy                                                                                                                                |
| ES_HTTPS_TLS12_Playbook.py                   |                                               ES Domain                                               | Enables HTTPS-only comms with a TLS 1.2 policy                                                                                                                                                                               |
| IAM_CIS_PW_Policy_Playbook.py                |                                            Account (IAM PW)                                           | Applies a CIS-compliant IAM password policy                                                                                                                                                                                  |
| KDS_Apply_Encryption_Playbook.py             |                                          Kinesis Data Stream                                          | Applies AWS-managed encryption to stream                                                                                                                                                                                     |
| KMS_CMK_Rotation_Playbook.py                 |                                                KMS CMK                                                | Enable KMS CMK Rotation                                                                                                                                                                                                      |
| PCI_Edition_SSM_ApplyPatch_Playbook.py       |                                              EC2 Instance                                             | Applies patch via run command. Meant for full auto remediation for<br>the PCI-DSS SSM.Patch check                                                                                                                            |
| RDS_DelProt_Playbook.py                      |                                              RDS Instance                                             | Enable RDS instance deletion protection                                                                                                                                                                                      |
| RDS_Multi_AZ_Playbook.py                     |                                              RDS Instance                                             | Configure RDS instance in Multi-AZ                                                                                                                                                                                           |
| RDS_Privatize_Instance_Playbook.py           |                                              RDS Instance                                             | Remove Public access to RDS Instance                                                                                                                                                                                         |
| RDS_Privatize_Snapshot_Playbook.py           |                                              RDS Snapshot                                             | Remove Public access to Snapshot                                                                                                                                                                                             |
| Redshift_Encryption_Playbook.py              |                                            Redshift cluster                                           | Apply default encryption to cluster                                                                                                                                                                                          |
| Redshift_Privatize_Playbook.py               |                                            Redshift cluster                                           | Remove Public access from cluster                                                                                                                                                                                            |
| Release_EIP_Playbook.py                      |                                               Elastic IP                                              | Release unallocated EIP                                                                                                                                                                                                      |
| Release_SG_Playbook.py                       |                                             Security Group                                            | Release unattached SG                                                                                                                                                                                                        |
| Remove_All_SG_Rules_Playbook.py              |                                             Security Group                                            | Remove ALL ingress and egress rules from SG                                                                                                                                                                                  |
| Remove_Open_DocDB_Playbook.py                |                                             Security Group                                            | Remove ingress to 27017 from SG                                                                                                                                                                                              |
| Remove_Open_MySQL_Playbook.py                |                                             Security Group                                            | Remove ingress to 3306 from SG                                                                                                                                                                                               |
| Remove_Open_RDP_Playbook.py                  |                                             Security Group                                            | Remove ingress to 3389 from SG                                                                                                                                                                                               |
| Remove_Open_SSH_Playbook.py                  |                                             Security Group                                            | Remove ingress to 22 from SG                                                                                                                                                                                                 |
| Remove_Open_PostgreSQL_Playbook.py           |                                             Security Group                                            | Remove ingress to 5432 from SG                                                                                                                                                                                               |
| Remove_Open_Oracle_Playbook.py               |                                             Security Group                                            | Remove ingress to 1521 from SG                                                                                                                                                                                               |
| Remove_Open_MSSQL_Playbook.py                |                                             Security Group                                            | Remove ingress to 1433 from SG                                                                                                                                                                                               |
| Remove_Open_SMB_Playbook.py                  |                                             Security Group                                            | Remove ingress to 445 from SG                                                                                                                                                                                                |
| Remove_Open_Telnet_Playbook.py               |                                             Security Group                                            | Remove ingress to 23 from SG                                                                                                                                                                                                 |
| Remove_Open_Kibana_Playbook.py               |                                             Security Group                                            | Remove ingress to 5601 from SG                                                                                                                                                                                               |
| Remove_Open_Memcached_Playbook.py            |                                             Security Group                                            | Remove ingress to 11211 from SG                                                                                                                                                                                              |
| Remove_Open_Redis_Playbook.py                |                                             Security Group                                            | Remove ingress to 6379 from SG                                                                                                                                                                                               |
| Remove_Open_Redshift_Playbook.py             |                                             Security Group                                            | Remove ingress to 5439 from SG                                                                                                                                                                                               |
| S3_Encryption_Playbook.py                    |                                               S3 Bucket                                               | Enable SSE-S3 encryption on Bucket                                                                                                                                                                                           |
| S3_PrivateACL_Playbook.py                    |                                               S3 Bucket                                               | Puts 'PRIVATE' ACL on bucket                                                                                                                                                                                                 |
| S3_Public_Access_Policy_Playbook.py          |                                              Account (S3)                                             | Applies account-level S3 block-public-access-by<br>-default policy                                                                                                                                                           |
| S3_Put_Lifecycle_Playbook.py                 |                                               S3 Bucket                                               | move current and versioned objects to OZ_IA after 180<br>move current and versioned objects to Glacier after 365<br>delete current and versioned objects after 7 years (2555 days)<br>delete multi-part fails after 24 hours |
| S3_Versioning_Playbook.py                    |                                               S3 Bucket                                               | Enable bucket versioning                                                                                                                                                                                                     |
| ShieldAdv_AutoRenew_Playbook.py              |                                          AWS Account (Shield)                                         | Sets Shield Subscription to auto-renew                                                                                                                                                                                       |
| ShieldAdv_Protection_Playbook.py             |      Route53 Hosted Zone<br>CloudFront distro<br>ELB<br>ELBv2<br>Global Accelerator<br>Elastic IP     | Creates Shield Advanced protection for<br>a resource                                                                                                                                                                         |
| SNS_Default_Encryption_Playbook.py           |                                               SNS Topic                                               | Applies AWS-managed key to SNS topic                                                                                                                                                                                         |
| SSM_ApplyPatch_Playbook.py                   |                                              EC2 Instance                                             | Invokes AWS-RunPatchBaseline document on instance                                                                                                                                                                            |
| SSM_DeleteEC2_Playbook.py                    |                                              EC2 Instance                                             | Invokes AWS-TerminateEC2Instance document on instance                                                                                                                                                                        |
| SSM_InspectorAgent_Playbook.py               |                                              EC2 Instance                                             | Invokes AmazonInspector-ManageAWSAgent document on instance                                                                                                                                                                  |
| SSM_RefreshAssoc_Playbook.py                 |                                              EC2 Instance                                             | Invokes AWS-RefreshAssociation document on instance                                                                                                                                                                          |
| SSM_SNOW_Incident_Playbook.py                |                                                  Any                                                  | Invokes AWS-CreateServiceNowIncident document to create Incidents<br>in ServiceNow. Relies heavily on Env Vars from Lambda                                                                                                   |
| SSM_UpdateAgent_Playbook.py                  |                                              EC2 Instance                                             | Invokes AWS-UpdateSSMAgent document on instance                                                                                                                                                                              |
| Start_Backup_Playbook.py                     | EC2 Instance<br>EBS Volume<br>DyanmoDB Table<br>Storage Gateway<br>RDS Instance<br>Elastic File Share | Creates a "one-time" backup for a resource in AWS Backup                                                                                                                                                                     |
| VPC_Flow_Logs_Playbook.py                    |                                            VPC (Flow Logs)                                            | Creates new CloudWatch and IAM resources unique to a VPC and enables<br>flow logging                                                                                                                                         |
| WAFv1_GuardDutyProbe_UpdateIPSet_Playbook.py |                                              WAFv1 IP Set                                             | From a GuardDuty port-probe finding, retrieves all<br>malicious IP addresses from original GuardDuty finding<br>and adds them to a WAFv1 IP Set                                                                              |
| WAFv2_GuardDutyProbe_UpdateIPSet_Playbook.py |                                              WAFv2 IP Set                                             | From a GuardDuty port-probe finding, retrieves all<br>malicious IP addresses from original GuardDuty finding<br>and adds them to a WAFv2 IP Set                                                                              |

## Known Issues and Limitations
- Security Hub Security Standards currently use a finding that is scoped to the `AwsAccount` resource in the ASFF to roll up all results and give you a pass/fail/not available score on the control. Due to this, you may encountere failures or exceptions in your CloudWatch logs from these findings.

- As designed these playbooks will not consider any exceptions you may have. Please open a PR for this functionality, it may make sense to develop that as a Step Function state machine versus a Lambda function.

## FAQ
### 0. What are response and remediation playbooks and why should I use them?
**Tl;dr** Playbooks let you rapidly take action on Security Hub findings from security standards and ElectricEye versus doing it all manually

Response and remediation playbooks, for the purpose of this sub-module, are a collection of AWS services that automate actions based on inputs. Playbooks, and their usage, fall into a larger category called Security Orchestration, Automation and Response (SOAR). Traditionally your SecOps teams or Incident Response (IR) analysts maintain correlation rules and detections in your SIEM (or use Security Hub Insights to look at interesting aggregations), and when a potential incident is detected, they jump into action. These actions may involve rolling back your infrastructure to desired state (i.e. not having every port open on your security group), capturing logs, performing basic memory capture on an instance, creating a new rule in your WAF or anything else. These actions all take time, and sometimes happen too late (as is the case for detective controls + reactive security.)

While SOAR (through the use of playbooks or otherwise) won't take the place of preventative controls, they drastically reduce your mean time to response (MTTR), free up your humans to perform more detailed investigations or remediation and serve as force multiplier for your security team. Instead of having to page someone, cut a ticket, and hope they were paying attention to that Kibana dashboard or CloudWatch alarm, you can have playbooks fire off for known bad events (open security group, no encryption, no backups) without a second thought. If you do not want these actions to be taken automatically you can take advantage of Security Hub Custom Actions to invoke the playbooks. Think of it as an a la carte menu of actions an analyst can quickly take, instead of writing long IR playbooks, they can print out the [Playbook Reference Repository](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/README.md#playbook-reference-repository) section and choose which one to use based on event.

If nothing else, listen to what `Smokey the SOAR Bear` has to say:
![SmokeyTheSoarBear](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/smokey-the-soar-bear.jpg)

### 1. What services make up a Playbook?
ElectricEye-Response uses both CloudWatch / EventBridge Rules and Lambda functions as the primary mechanism in which to respond to (and potentially remediate) an incident (incident in this case being a Security Hub finding). Some other services may be layered in such as Security Hub Custom Actions and Systems Manager Automation or Command Documents. It goes without saying there are various types of IAM roles in use as well (Lambda execution roles, Event Target rules, assumed Roles, etc.)

### 2. What happens if I invoke a Custom Action for the wrong finding?
Likely nothing bad. If you kicked off a destory EBS volume playbook for a Neptune cluster it won't destory your Neptune cluster, you will just get an exception error in your logs. There are some Playbooks (account level ones, mostly) that are not focused on a resource, and will fire off regardless of what sort of finding you invoked it from. Using the example above, if you mistakenly select the EBS Account-level default encryption policy playbook for your Neptune cluster, it will apply that to whatever account owns the finding and the finding you choose will be updated.

### 3. Will the usage of Playbooks make me compliant with (insert framework of some sort here)?
No. If you wanted to use ElectricEye-Response to satisfy an audit, I would recommend you work closely with your GRC and Legal functions to determine if the implemented playbooks will legally satisfy the requirements of any compliance framework or regulations you need to comply with. I will only go as far to say that the **Respond** category of NIST CSF may kinda sorta fall into the spirit of this.

That said, as in the core module, if you 1) work on behalf of an organization who can provide attestations that these playbooks satisfy the spirit of certain requirements in certain industry or regulatory standards and 2) would like to provide an attestation for the betterment of the community please email me to discuss.

### 4. Can I scope fully-automatic Playbook invocations to only a certain resource or tag?
Sorta. You can expand the CloudWatch / EventBridge Event Rule filter to have an array of Resource.Id's or any other field in the ASFF present. This becomes a "whitelist" style where you are choosing which resources SHOULD be in scope, Event rule filters (to my knowledge) do not have an *IS NOT* sort of boolean logic.

### 5. Why don't you support (insert action here)?
Loaded question. I likely will, if you really need the ability to create a new Neptune parameter set or something open an Issue and if it is relatively trivial I will take it on. Complex actions that need long wait conditions or need to run powershell or shell scripts on a host will require additional investigation and invesment.

### 6. How quickly do the playbooks remediate the resource?
From invocation it should only take a few seconds for the resource to be brought back into a compliant state. If you send a large group of findings at a time, that may only slightly increase. It is important to note that the time from when a resource moves into a non-compliant state and gets sent to Security Hub greatly depends on many factors. For instance, a lot of the Security Hub security standards are powered by configuration change-triggered rules from Config, but it can still take up to 15 minutes for the Config event to be translated to ASFF, batched and sent to Security Hub. These timetables are similar for native integrations as well (GuardDuty, Inspector, etc.) and ElectricEye is totally periodic so the time variance can be very large.

### 7. How many findings can I select to invoke a Custom Action? Does that work?
Yes, it does work. You can send up to 20 findings (or 240kb) to CloudWatch Events / EventBridge from Security Hub (also why only 20 results show in the Findings page, I imagine). The receiving Lambda function will loop through the various findings and various `Resources` arrays to perform remediation and update the note using the `UpdateFindings` API.

### 8. From my Security Hub Master, can I select findings belonging to different accounts and invoke a Custom Action?
Yes. There is logic in the Python code to differentiate if the Master or a Member account owns the finding. If the Member(s) own the finding, the code will loop through as normal, assume the cross-account role and execute the remediation and call the `UpdateFindings` API. The same limitation applies as in FAQ #7, you can only send up to 20 findings or 240kb worth to CloudWatch Events / EventBridge.

### 9. I am getting exception errors with from the Playbooks related to permissions but I deployed your resources, what is happening?
You likely have a resource-based policy on the resource you are attempting to remediate that is preventing the assumed role from remediating it. Services such as S3, SNS, SQS, CloudFront, ECR, Elasticsearch Service and others support additional access policies which can prevent you from taking action. Permissions Boundaries and Service Control Policies (SCPs) can also prevent certain actions from happening. You should work with the resource owner to allow access from the ElectricEye-Response IAM roles or educate them in not creating vulnerable or non-compliant infrastructure services.

### 10. Why don't you use Systems Manager Automation Documents?
I use managed Automation documents where they make sense. The time investment to learn another abstraction of invoking AWS APIs over relying on my core competencies is counter-intuitive to me, additionally, custom docs would need to be deployed via IAC to all member accounts and maintained which can add some problems. All that said, if you have a really awesome SSM Doc that you are 110% convinced should be included in ElectricEye-Response, please open an Issue and we can discuss the merits of inclusion.

### 11. Why don't you use Step Functions?
I do not know how to write them, let alone set them up via IAC. There are some Playbooks on the roadmap that will (theoretically) need to be implemented via Step Functions, so I will gain the profiency eventually. I won't accept PRs on any Step Function based playbooks for the time being.

## License
This library is licensed under the GNU General Public License v3.0 (GPL-3.0) License. See the LICENSE file.