# Config Deletion Pruner
ElectricEye `config-deletion-pruner` will auto-archive findings related to deleted resources in AWS Config. This functionality utilizes the AWS Config recorder, an Amazon CloudWatch Event rule and AWS Lambda function to parse out the ARN / ID of a resource that has been deleted and use the Security Hub `UpdateFindings` API to archive the deleted resource based on its ARN / ID.

## Solution Architecture
![ThePrunes](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/config-deletion-pruner/config-deletion-pruner.jpg)

## Setting Up
These steps are split across 3 different implementation techniques (manually, via Terraform and via CloudFormation). All CLI commands are executed from an Ubuntu 18.04LTS [Cloud9 IDE](https://aws.amazon.com/cloud9/details/), modify them to fit your OS.

### Deploy Config Deletion Pruner via the AWS Management Console
This section shows you how to manually create the Config Deletion Pruner solution via the Console.

1. Create a new Lambda function with a `Python 3.8` runtime and a role that has the `securityhub:UpdateFindings` and basic execution role permissions (for writing CloudWatch metrics and logs)

2. Paste in the [following code](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/config-deletion-pruner/lambda_function.py) to the Lambda function and save it.

3. Navigate to the CloudWatch (or EventBridge) console and create a new `Rule` and paste in the [following event pattern](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/config-deletion-pruner/CloudWatch_Event_Rule_Config_Item_Deletion.json).

4. Select **Add target** and specify the Lambda function you created in **Step 1**. Select **Configure details** and specify and name and description and select **Create rule**

5. As resources that are recorded by AWS Config are deleted, all related findings will be set to an `ARCHIVED` record state in Security Hub and a `Note` will be added to the finding as shown below.
![PrunerNote](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/config-deletion-pruner/config-pruner-finding-note.jpg)

### Deploy Config Deletion Pruner via Terraform
This section will deploy the Config Deletion Pruner solution with Terraform.

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

2. Clone this repository, change directories and then edit the `variables.tf` config file to change your Region as appropiate, then initialize, plan and apply your state with Terraform.

```bash
git clone https://github.com/jonrau1/ElectricEye.git
cd ElectricEye/add-ons/config-deletion-pruner/terraform
nano variables.tf
terraform init
terraform plan
terraform apply -auto-approve
```

### Deploy ElectricEye-ChatOps with CloudFormation
This section will deploy the Config Deletion Pruner solution with CloudFormation, you can optionally use [StackSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html) to deploy this solution to multiple Security Hub member accounts.

1. Download the [CloudFormation template](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/config-deletion-pruner/cloudformation/ConfigPruner_CFNTemplate.yml) and create a Stack. Refer to the [Get Started](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/GettingStarted.Walkthrough.html) section of the *AWS CloudFormation User Guide* if you have not done this before.

## FAQ
1. What resources does the Config Deletion Pruner solution support?
It supports anything that AWS Config supports resource recording for, a full list can be found at [AWS Config Supported AWS Resource Types and Resource Relationships](https://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html).

2. Why do you only Archive the findings? Why can you not delete them?
AWS Security Hub does not allow you to delete findings, for now, all you can do is archive them and findings will be "aged-off" (deleted) 90 days after the last update of a finding ID. Due to the way ElectricEye implements finding ID (typically a concatenation of the resource ARN and a string of what the specifc check was for) if you ever delete a resource and later recreate it with the same name, it would appear as if it was never deleted in the first place.

3. Why are both ARNs and resource IDs used to attempt archival?
ElectricEye and (a vast majority) of the Security Hub security standard controls use the ARN to identify a resource, however, some partner products do not all use ARNs and this method helps ensure a high chance that your delete resource has their findings archived.

4. I deleted a resource but the findings are still Active in Security Hub, why?
This is either due to your resource not being support by Config (see FAQ#1) or you are throttled by the `UpdateFindings` API. Currently the `UpdateFindings` API supports a rate of 3TPS and a relatively low burst (7 or 10 TPS, I don't remember which). Because the Config Pruner attempts 2 calls (for resource ID and for resource ARN), if you have a large amount of findings in scope for the resource (or a large amount of resources being deleted at once) you will likely be throttled. You should review your logs for 429 Errors and create a CloudWatch Alarm watching for this or for failed invocations of the Lambda function. More information on error codes can be found in the [UpdateFindings](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_UpdateFindings.html#API_UpdateFindings_SeeAlso) section of the *AWS Security Hub API Reference*.

5. How can I keep track of the history of my resources / findings as they are delete / Archived, respectively?
The Config Pruner Lambda function will write logs to CloudWatch Logs, and Config publishes the results of resource deletions to CloudWatch Events / EventBridge (which is where this solution parses the information from) as well as a SNS Topic (if you have one configured). You should consider backing up the Lambda logs to durable storage (such as S3 via a Kinesis Data Firehose log subscription with a S3 Destination) or writing them to ElasticSearch, or another SIEM. A large-scale asset management solution like a Configuration Management Database (CMDB) could also be a worthwhile solution, but *way* beyond the scope of this.

6. What is the easiest way to view all of my Archived findings?
The core module has an Insight (Security Hub saved search) that lists all Archived findings by `Resource.Type` from ElectricEye. You can use that Insight and expand it to include not just ElectricEye-created findings. As noted in FAQ#4, if you are being throttled by `UpdateFindings` you will likely get an inaccurate picture using that method.

## License
This library is licensed under the GNU General Public License v3.0 (GPL-3.0) License. See the LICENSE file.