# Config Deletion Pruner
ElectricEye `config-deletion-pruner` will auto-archive findings related to deleted resources in AWS Config. This functionality utilizes the AWS Config recorder, an Amazon CloudWatch Event rule and AWS Lambda function to parse out the ARN / ID of a resource that has been deleted and use the Security Hub `UpdateFindings` API to archive the deleted resource based on its ARN / ID.

## Solution Architecture
![ThePrunes](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/config-deletion-pruner/config-deletion-pruner.jpg)

## How To
The following steps should be performed in the AWS Management Console.

1. Create a new Lambda function with a `Python 3.8` runtime and a role that has the `securityhub:UpdateFindings` and basic execution role permissions (for writing CloudWatch metrics and logs)

2. Paste in the [following code](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/config-deletion-pruner/lambda_function.py) to the Lambda function and save it.

3. Navigate to the CloudWatch (or EventBridge) console and create a new `Rule` and paste in the [following event pattern](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/config-deletion-pruner/CloudWatch_Event_Rule_Config_Item_Deletion.json).

4. Select **Add target** and specify the Lambda function you created in **Step 1**. Select **Configure details** and specify and name and description and select **Create rule**

5. As resources that are recorded by AWS Config are deleted, all related findings will be set to an `ARCHIVED` record state in Security Hub and a `Note` will be added to the finding as shown below.
![PrunerNote](https://github.com/jonrau1/ElectricEye/blob/master/add-ons/config-deletion-pruner/config-pruner-finding-note.jpg)

## License
This library is licensed under the GNU General Public License v3.0 (GPL-3.0) License. See the LICENSE file.