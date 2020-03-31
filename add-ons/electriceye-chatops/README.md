# ElectricEye-ChatOps
ElectricEye-ChatOps utilizes EventBridge / CloudWatch Event Rules to consume `HIGH` and `CRITICAL` severity findings created by ElectricEye from Security Hub and route them to a Lambda function. Lambda will parse out certain elements from the Security Hub finding, create a message and post it to a Slack App's webhook for consumption by your security engineers or other personnel in a Slack channel.

**Important Note:** When deploying this solution you should consider both signal-to-noise ratios and cost implications. The easiest pattern is to run this from your Security Hub Master account so you get all findings from all member accounts. If you have dev/sandbox accounts your ChatOps processes may not care about, you should consider deploying this to high-danger/PROD/public/PII-laden accounts only.

If you decide to roll this from your Master that is rockin' the full 1000 account limit, your Slack App is going to be like...
![FunpostingTime](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/funposting-time.gif)

...and your security engineers / SREs / anyone else will likely just uninstall Slack from their company-issued devices.

## Solution Architecture
![ElectricEyeChatOps](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/electriceye-chatops-architecture.jpg)
1. ElectricEye sends findings to Security Hub
2. Security Hub events are emitted to CloudWatch Events/EventBridge
3. An Event Rule sends High and Critical severity ElectricEye findings to Lambda
4. Lambda retrieves the Webhook URL of a Slack App from Systems Manager Parameter Store
5. Lambda parses high-level information from the finding (Resource, Account, Severity and Title), forms a JSON message and uses the Python3 `requests` library to POST to the Incoming Webhook URL
6. The Slack App posts the message to a desginated Slack channel (where panic is likely to ensue)

## Setting Up
These steps are split across 3 sections. All CLI commands are executed from an Ubuntu 18.04LTS [Cloud9 IDE](https://aws.amazon.com/cloud9/details/), modify them to fit your OS.

**Note**: If you want to use Microsoft Teams instead of Slack [go here](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-chatops/microsoft-teams)

### Create a Slack App
It goes without saying your should have a Slack Workspace. If you don't, [check out this Slack help center article](https://slack.com/help/articles/206845317-Create-a-Slack-workspace)

1. Navigate to **https://api.slack.com/** and select **Create New App**

2. Enter an **App Name**, select your **Development Slack Workspace** and choose **Create App** as shown below
![SlackAppCreation](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/electriceye-chatops-createapp.JPG)

3. Under **Add features and functionality** select **Incoming Webhooks**, in the next screen select the `On-Off` toggle for **Activate Incoming Webhooks** as shown below
![SlackAppWebhook](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/electriceye-chatops-webhookactivate.JPG)

4. Scroll to the bottom of the screen and select **Add New Webhook to Workspace**, on the next screen select what **Channel** ElectricEye-ChatOps should post Security Hub findings to and choose Allow as shown below.
![SlackAppAuthChannel](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/electriceye-chatops-authchannel.JPG)

5. Copy the **Webhook URL** and create a SSM Parameter with the AWS CLI: `aws ssm put-parameter --name ElectricEyeSlackWebhook --description 'Contains the Slack Webhook URL for ElectricEye-ChatOps' --value <SLACK_WEBHOOK_URL> --type String`

### Deploy ElectricEye-ChatOps with CloudFormation
This section will deploy the ElectricEye-ChatOps solution with CloudFormation, you can optionally use [StackSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html) to deploy this solution to multiple Security Hub member accounts.

1. Download the [CloudFormation template](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-chatops/cloudformation/ElectricEye_ChatOps_CFN.yml) and create a Stack. Refer to the [Get Started](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/GettingStarted.Walkthrough.html) section of the *AWS CloudFormation User Guide* if you have not done this before.

2. Enter in a **Stack Name** and the name of the Parameter created in the previous section into **SlackWebHookParameter**. If you are not in `us-east-1` overwrite the default value for **Python3RequestsLayer**. You can refer to the [Klayers Repo](https://github.com/keithrozario/Klayers/tree/master/deployments/python3.8/arns) or provide your own Lambda Layer that has the Python3 `requests` library and supports `Python3.7` / `Python3.8` runtimes.
![ChatOpsStackParams](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/chatops-stack-params.jpg)

3. After the Stack has created you can go ahead and manually run ElectricEye, or just wait around for the next scheduled run. If you configured everything correctly you should receive some findings (hopefully not a lot, unless you *really hate* security best practices) like below.
![ChatOpsSlackMessage](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/electriceye-chatops-slackmessages.jpg)

***Optional:*** If you want to send High and Critical findings from *all* Security Hub integrations to Slack modify the Event Pattern started on Line 97 of `ElectricEye_ChatOps_CFN.yml` to the following:
```yaml
EventPattern: 
  source: 
    - aws.securityhub
  detail-type: 
    - Security Hub Findings - Imported
  detail: 
    findings:
      ProductFields:
        aws/securityhub/SeverityLabel:
        - HIGH
        - CRITICAL
```

You can optionally remove the High severity findings, these can get noisy if you have a lot of encryption-missing related findings.

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
![ChatOpsTFParams](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/chatops-tf-params.jpg)

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

You can swap the Event Pattern to the below if you want only Critical findings
```json
{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "findings": {
      "ProductFields": {
        "Product Name": [
          "ElectricEye"
        ],
        "aws/securityhub/SeverityLabel": [
          "CRITICAL"
        ]
      }
    }
  }
}
```

Or, you can swap the Event Pattern to the below if you want Critical and High findings from all products
```json
{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "findings": {
      "ProductFields": {
        "aws/securityhub/SeverityLabel": [
          "CRITICAL",
          "HIGH"
        ]
      }
    }
  }
}
```

## License
This library is licensed under the GNU General Public License v3.0 (GPL-3.0) License. See the LICENSE file.