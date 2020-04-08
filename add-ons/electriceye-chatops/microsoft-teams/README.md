# ElectricEye-ChatOps (Microsoft Teams Edition)
ElectricEye-ChatOps utilizes EventBridge / CloudWatch Event Rules to consume `HIGH` and `CRITICAL` severity findings created by ElectricEye from Security Hub and route them to a Lambda function. Lambda will parse out certain elements from the Security Hub finding, create a message and send it to a Microsoft Teams channel.

## Solution Architecture
![ElectricEyeChatOpsTeams](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/electriceye-chatops-teams-architecture.jpg)
1. ElectricEye sends findings to Security Hub
2. Security Hub events are emitted to CloudWatch Events/EventBridge
3. An Event Rule sends High and Critical severity ElectricEye findings to Lambda
4. Lambda retrieves the Webhook URL for a Microsoft Teams Channel from Systems Manager Parameter Store
5. Lambda parses high-level information from the finding (Resource, Account, Severity and Title), forms a JSON message and uses the Python3 `requests` library to POST to the Teams webhook

## Setting Up
These steps are split across 3 sections. All CLI commands are executed from an Ubuntu 18.04LTS [Cloud9 IDE](https://aws.amazon.com/cloud9/details/), modify them to fit your OS.

### Create Microsoft Teams Webhook
In this section we will generate a webhook for our Teams Channel and create a SSM parameter for it

1. From Teams create a new channel for this integration by selecting the **More options** menu `(...)` and choosing **Add channel** as shown below
![MSTeamsCreateChannel](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/teams-create-channel.JPG)

2. Enter a Channel **Name** and optionally enter a **Description** and set your **Privacy policy** and select **Add**. After creation choose the **More options** menu and select **Connectors**

3. Search for **Incoming Webhook** and select **Configure**. Enter a webhook Name, optionally upload an image and select **Create** as shown below.
![MSTeamsNameWebhook](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/teams-name-webhook.JPG)

4. In the second screen scroll to the bottom and copy the **URL** and select **Done**. Create a new SSM parameter with the following command: `aws ssm put-parameter --name MSTeamsWebhook --description 'Contains the Microsoft Teams Channel Webhook URL for ElectricEye-ChatOps' --value <TEAMS_WEBHOOK_URL> --type String`

### Deploy ElectricEye-ChatOps (Teams Edition) with CloudFormation
This section will deploy the ElectricEye-ChatOps solution with CloudFormation, you can optionally use [StackSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html) to deploy this solution to multiple Security Hub member accounts.

1. Download the [CloudFormation template](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-chatops/microsoft-teams/cloudformation/ElectricEye_ChatOps_Teams_CFN.yml) and create a Stack. Refer to the [Get Started](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/GettingStarted.Walkthrough.html) section of the *AWS CloudFormation User Guide* if you have not done this before.

2. Enter in a **Stack Name** and the name of the Parameter created in the previous section into **TeamsWebHookParameter**. If you are not in `us-east-1` overwrite the default value for **Python3RequestsLayer**. You can refer to the [Klayers Repo](https://github.com/keithrozario/Klayers/tree/master/deployments/python3.8/arns) or provide your own Lambda Layer that has the Python3 `requests` library and supports `Python3.7` / `Python3.8` runtimes.
![TeamsParams](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/cfn-teams-parameters.JPG)

3. After the Stack has created you can go ahead and manually run ElectricEye, or just wait around for the next scheduled run. If you configured everything correctly you should receive some finding messages in your channel.
![ChatOpsTeamsMessage](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/teams-sechub-finding.JPG)

### Deploy ElectricEye-ChatOps (Teams Edition) with Terraform
### Deploy ElectricEye-ChatOps with Terraform
This section will deploy the ElectricEye-ChatOps solution with Terraform.

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

2. Clone this repository, change directories and then edit the `variables.tf` config file to add your SSM Parameter and (optionally) change the default value of the ARN for the Python3 Lambda Layer for Requests. You can refer to the [Klayers Repo](https://github.com/keithrozario/Klayers/tree/master/deployments/python3.8/arns) or provide your own Lambda Layer that has the Python3 `requests` library and supports `Python3.7` / `Python3.8` runtimes.
![TeamsTFParams](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/teams-tf-params.JPG)

```bash
git clone https://github.com/jonrau1/ElectricEye.git
cd ElectricEye/add-ons/electriceye-chatops/terraform
nano variables.tf
```

3. Initialize, plan and apply your state with Terraform.
```bash
terraform init
terraform plan
terraform apply -auto-approve
```

## License
This library is licensed under the GNU General Public License v3.0 (GPL-3.0) License. See the LICENSE file.