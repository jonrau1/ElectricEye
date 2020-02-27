# ElectricEye (ElectricEye-Response)
Continuously monitor your AWS services for configurations that can lead to degradation of confidentiality, integrity or availability. All results will be sent to Security Hub for further aggregation and analysis.

***Up here in space***<br/>
***I'm looking down on you***<br/>
***My lasers trace***<br/>
***Everything you do***<br/>
<sub>*Judas Priest, 1982*</sub>

## Table of Contents
- [Description](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/README.md#description)
- [Solution Architecture](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/README.md#solution-architecture)
- [Prerequisites](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/README.md#prerequisites)
- [Setting Up](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/README.md#setting-up)
  - [Deploying ElectricEye-Response Cross-Account Role via StackSets](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/README.md#deploying-electriceye-response-cross-account-role-via-stacksets)
  - [Semi-Auto ElectricEye-Response with CloudFormation](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/README.md#semi-auto-electriceye-response-with-cloudformation)
  - [Full-Auto ElectricEye-Response with Terraform](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/README.md#full-auto-electriceye-response-with-terraform)
- [Known Issues and Limitations](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/README.md#known-issues-and-limitations)
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

***WORK IN PROGRESS***

### Full-Auto ElectricEye-Response with Terraform
In this section we will deploy CloudWatch Events and Lambda functions to the Security Hub Master using Terraform. **Important Note:** Only certain playbooks are contained within the full-auto version of ElectricEye-Response. Actions such as Shield Advanced protection, creating one-time Backups or deleting EC2 instances should likely **NOT** be executed without a human pulling the trigger.

All CLI commands are executed from an Ubuntu 18.04LTS [Cloud9 IDE](https://aws.amazon.com/cloud9/details/), modify them to fit your OS. Before starting [attach this IAM policy](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/policies/electriceye-response-terraform-policy.json) to your [Instance Profile](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html) (if you are using Cloud9 or EC2).

***WORK IN PROGRESS***

## Known Issues and Limitations
- Security Hub Security Standards currently use a finding that is scoped to the `AwsAccount` resource in the ASFF to roll up all results and give you a pass/fail/not available score on the control. Due to this, you may encountere failures or exceptions in your CloudWatch logs from these findings.

- As designed these playbooks will not consider any exceptions you may have. Please open a PR for this functionality, it may make sense to develop that as a Step Function state machine versus a Lambda function.

## License
This library is licensed under the GNU General Public License v3.0 (GPL-3.0) License. See the LICENSE file.