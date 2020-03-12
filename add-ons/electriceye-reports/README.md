# ElectricEye-Reports (Experimental)
ElectricEye-Reports is a fully serverless solution that extends Security Hub and ElectricEye by sending select finding information to [Amazon QuickSight](https://aws.amazon.com/quicksight/) via services such as Amazon Kinesis and Amazon DynamoDB. From QuickSight, you can create rich and detailed graphics that can be shared, embedded in your enterprise applications and analyzed for purposes such as gamification of security compliance, executive reporting, business line reporting, risk assessments, audit reports, etc.

**IMPORTANT NOTE**: This is an experimental feature that is not fully fleshed out

## Solution Architecture
![ElectricEyeChatOps](https://github.com/jonrau1/ElectricEye/blob/master/screenshots/ElectricEye-Reports-Architecture.jpg)
1. ElectricEye sends findings to Security Hub
2. Security Hub events are emitted to CloudWatch Events/EventBridge
3. An Event Rule sends all ElectricEye findings to Lambda
4. A Lambda function writes high-level information from the findings into a DynamoDB table to include the ID, Title, Severity, Account, Region, etc.
5. DynamoDB Streams invoke another function which writes DynamoDB table items as records into Kinesis Data Firehose (KDF)
6. KDF batches and delivers records to a S3 bucket
7. AWS Glue is used to crawl the records delivered to S3
8. A Glue Crawler writes the records to a Data Catalog which can be queried by Amazon Athena
9. QuickSight is connected to Athena and analyses / dashboards can be created

## Setting Up
***WORK IN PROGRESS***

Some pseudo-code is located in this directory as a starting point, no further IAC or instructions is available at this time.

## License
This library is licensed under the GNU General Public License v3.0 (GPL-3.0) License. See the LICENSE file.