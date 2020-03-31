# ElectricEye-ChatOps (Microsoft Teams Edition)
ElectricEye-ChatOps utilizes EventBridge / CloudWatch Event Rules to consume `HIGH` and `CRITICAL` severity findings created by ElectricEye from Security Hub and route them to a Lambda function. Lambda will parse out certain elements from the Security Hub finding, create a message and send it to a Microsoft Teams channel.

***COMING SOON***

## License
This library is licensed under the GNU General Public License v3.0 (GPL-3.0) License. See the LICENSE file.