# ElectricEye-Pagerduty-Integration
The Pagerduty integration for ElectricEye, similar to ElectricEye-ChatOps, utilizes EventBridge / CloudWatch Event Rules to consume `HIGH` and `CRITICAL` severity findings created by ElectricEye from Security Hub and route them to a Lambda function. Lambda will parse out certain elements from the Security Hub finding such as the title, remediation information and resource information and to form a Pagerduty Incident to be sent using the EventsV2 API. Pagerduty is an on-call management / incident management tool that has built-in intelligence and automation to route escalations, age-off incidents and can be integrated downstream with other tools.

**Important Note:** Like ElectricEye-ChatOps, when deploying this solution you should consider both signal-to-noise ratios and cost implications. You likely will not want sandbox / dev accounts generating Incidents for low and medium findings. You should selectively choose the accounts you deploy this solution to and keep the High / Critical settings the same so only truly important findings are created as Pagerduty Incidents.

## Solution Architecture
![ElectricEyeChatOps](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/ElectricEye-ChatOps-PagerDuty-Architecture.jpg)
1. ElectricEye sends findings to Security Hub
2. Security Hub events are emitted to CloudWatch Events/EventBridge
3. An Event Rule sends High and Critical severity ElectricEye findings to Lambda
4. Lambda retrieves the Integration Key of a Pagerduty service from Systems Manager Parameter Store
5. Lambda transforms fields from the [AWS Security Finding Format](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html#securityhub-findings-format-attributes) (ASFF) such as title, description, remediation information, severity and resource information and maps it into the Pagerduty Common Event format (PD-CEF) before creating an Incident using the EventsV2 API
6. Incidents are created in Pagerduty and alert individuals based on on-call rotation and escalation rules

## Setting Up
These steps are split across 3 sections. All CLI commands are executed from an Ubuntu 18.04LTS [Cloud9 IDE](https://aws.amazon.com/cloud9/details/), modify them to fit your OS.

### Configuring Pagerduty
In this section you'll get your Pagerduty subdomain set up to receive findings from ElectricEye.

1. Sign up for a free Pagerduty account [here](https://www.pagerduty.com/sign-up/) and sign into your subdomain

2. Once signed in choose the **Configuration** menu on the top tab and select **Teams**

3. On the right-hand side select **+ New team**, choose a name (such as ElectricEye-Incidents), add optional tags (such as `Secops`) and select **Save** as shown below
![PagerdutyCreateTeam](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/pagerduty-create-team.JPG)

4. Choose the **Configuration** menu again as in Step 2, select **Escalation Policies** and when you have switched screens select **+ New Escalation Policy** on the right-hand side

5. Enter a **Name** and **Description** for your escalation policy, choose the team created in Step 3 and optionally add tags (such as `Secops`) and a repeat rule if the Incident is not acknowledged and select **Save** as shown below
![PagerdutyCreateEscalationPolicy](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/pagerduty-create-escalation-policy.JPG)

6. Choose the **Configuration** menu again (as in Steps 2 and 4) and select **Services** and when you have switched screens select **+ New Service** on the right-hand side

7. Enter a **Name** and **Description**. Under **Integration Type** choose **Use our API directly** and ensure that **Events API v2** is selected. Overwrite **Integration Name** with the name you gave your Service as shown below and then scroll down
![PagerdutyCreateServiceOne](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/pagerduty-create-service-pt1.JPG)

8. Further down the screen choose the **Escalation Policy** created in Step 5 while leaving all other options default. In the **Alert Grouping** section choose **Intelligently based on the alert content and past groups** and select **Add Service** as shown below
![PagerdutyCreateServiceTwo](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/pagerduty-create-service-pt2.JPG)

9. After your service has created copy the **Integration Key** on the next screen and then create a SSM parameter with the following command: `aws ssm put-parameter --name electriceye-pagerduty --description 'Sends high severity ElectricEye findings to Pagerduty' --type SecureString --value <INTEGRATION-KEY-HERE>`

### Deploy ElectricEye-Pagerduty-Integration with CloudFormation
In this section we'll learn how to deploy the ElectricEye Pagerduty integration solution with CloudFormation, you can optionally use [StackSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html) to deploy this solution to multiple Security Hub member accounts.

1. Download the [CloudFormation template](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-pagerduty-integration/cloudformation/ElectricEye_Pagerduty_CFN.yml) and create a Stack. Refer to the [Get Started](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/GettingStarted.Walkthrough.html) section of the *AWS CloudFormation User Guide* if you have not done this before.

2. Enter in a **Stack Name**, if you changed the parameter name from Step 9 in the previous section enter in what you named it as the value for **PagerdutyIntegrationKeyParameter**. If you are not in `us-east-1` overwrite the default value for **Python3RequestsLayer**. You can refer to the [Klayers Repo](https://github.com/keithrozario/Klayers/tree/master/deployments/python3.8/arns) or provide your own Lambda Layer that has the Python3 `requests` library and supports `Python3.7` / `Python3.8` runtimes.
![PagerdutyCFNParameters](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/pagerduty-cfn-params.JPG)

3. After the Stack has created you can go ahead and manually run ElectricEye, or just wait around for the next scheduled run. If you configured everything correctly you should start getting emailed / paged from the Incidents in Pagerduty. You may want to fine-tune the Event Pattern to only get a subset of findings that match certain resource types or only critical, every encryption-related finding is `HIGH` severity by design and can be overwhelming.
![PagerdutyElectricEyeFinding](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/pagerduty-electriceye-alert.JPG)

### Deploy ElectricEye-Pagerduty-Integration with Terraform
In this section we'll learn how to deploy the ElectricEye Pagerduty integration solution with Terraform.

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

2. Clone this repository, change directories and then edit the `variables.tf` config file. If you changed the parameter name from Step 9 in the previous section enter in what you named it as the value for **Pagerduty_Integration_Key_Parameter**. If you are not in `us-east-1` overwrite the default value for **Python3_Requests_Layer_ARN**. You can refer to the [Klayers Repo](https://github.com/keithrozario/Klayers/tree/master/deployments/python3.8/arns) or provide your own Lambda Layer that has the Python3 `requests` library and supports `Python3.7` / `Python3.8` runtimes.
![PagerdutyTFParams](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/pagerduty-tf-variables.JPG)

```bash
git clone https://github.com/jonrau1/ElectricEye.git
cd ElectricEye/add-ons/electriceye-pagerduty-integration/terraform
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
                ]
            },
            "Severity": {
                "Label": [
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
                "Product Name": [
                    "ElectricEye"
                ]
            },
            "Severity": {
                "Label": [
                    "HIGH",
                    "CRITICAL"
                ]
            }
        }
    }
}
```

## License
This library is licensed under the GNU General Public License v3.0 (GPL-3.0) License. See the LICENSE file.