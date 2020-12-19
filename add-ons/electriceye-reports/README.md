# ElectricEye-Reports

ElectricEye-Reports is an add-on that allows you the created detailed business intelligence (BI) reports from ElectricEye findings in Security Hub using [Amazon QuickSight](https://aws.amazon.com/quicksight/), a "...scalable, serverless, embeddable, machine learning-powered business intelligence (BI) service built for the cloud." Using QuickSight, you can create detailed reports that breakdown all of your ElectricEye findings by Severity, Region, Resource Type, as well as breakout by-Compliance Control reporting and further enrich the dataset in this solution with business-context such as Cost Center, Division, Business Owner, and other metadata. With this data you can create visualizations that can be used by a many Personas across Information Security, IT Audit, IT Operations, Product Development, and Risk functions - such as tracking compliance with specific controls, measuring Key Risk Indicators (KRIs), or preparing evidence for a formal audit certification/attestation/examination.

![I like Graphs](./screenshots/CrazyCharts.gif)

This solution will utilize AWS Serverless technologies such as AWS CodeBuild, Amazon S3, and QuickSight to create a Minimal Viable Product (MVP) for the purpose of collecting multi-Account and multi-Region ElectricEye findings and populating the necessary "primitives" within QuickSight to create visualizations (also known as [Analyses](https://docs.aws.amazon.com/quicksight/latest/user/working-with-analyses.html) and [Dashboards](https://docs.aws.amazon.com/quicksight/latest/user/working-with-dashboards.html)). Due to the hands-on nature of QuickSight and the necessity of utilizing Security Hub's AWS Organizations integration, there will be some prerequisites to the usage of this solution. Additionally, being an MVP, any modification of the data extracted from Security Hub may negatively impact the successful execution of this add-on's codebase.

## Prerequisites

- ElectricEye is creating findings in Security Hub, lol.

- All Member Accounts are sending findings to Security Hub via the AWS Organizations integration. (**Note** This will need to be setup once per AWS Region)

- An Amazon QuickSight Subscription is setup in the Region you will run this solution. For more information on setting up a Subscription, and the types of Subscriptions, see [here](https://docs.aws.amazon.com/quicksight/latest/user/signing-up.html).

- Access to a S3 Bucket that you can upload a ZIP file (used for CodeCommit Repo creation by [AWS CloudFormation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codecommit-repository-s3.html)) and JSON files to for this Add-on.

- Access to a workstation / server with the AWS CLI installed and necessary IAM Permissions.

## Solution Architecture

![ElectricEyeReports](./screenshots/ElectricEyeReports-Architecture.jpg)

1. Findings from all Member Accounts are sent to the Security Hub Master across every Region the Organizations integration is enabled in.

2. An[ Amazon EventBridge](https://docs.aws.amazon.com/eventbridge/latest/userguide/what-is-amazon-eventbridge.html) [Scheduled Rule](https://docs.aws.amazon.com/eventbridge/latest/userguide/scheduled-events.html#rate-expressions) (Rate-based) will trigger an [AWS CodeBuild Project](https://docs.aws.amazon.com/codebuild/latest/userguide/concepts.html#concepts-how-it-works) over a desired time-period (hourly, daily, weekly, etc.)

3. Upon initialization, CodeBuild will retrieve the necessary code artifacts (a Python script and a [Build specification ](https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html)) from [AWS CodeCommit](https://docs.aws.amazon.com/codecommit/latest/userguide/welcome.html), a managed Git-based repository.

4. A list of all opted-in AWS Regions for your Account is retrieved from the [AWS EC2 DescribeRegions](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-regions.html) API.

5. The list of Regions is iterated through, creating a [Regionally-aware Boto3 Session](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/core/session.html) for every iteration, this Session is used to [retrieve all ElectricEye findings](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub.html#SecurityHub.Paginator.GetFindings) from the trailing week from Security Hub and is written to a JSON file. The contents of the finding will look like this in their final form:

```json
[
  {
    "Finding Type": "Software and Configuration Checks/AWS Security Best Practices",
    "Account ID": "0000000",
    "Severity": "INFORMATIONAL",
    "Title": "[ShieldAdvanced.8] Shield Advanced subscription should be set to auto-renew",
    "Resource Type": "AwsAccount",
    "Resource ID": "AWS::::Account:0000000",
    "Region": "us-east-1",
    "Compliance Status": "PASSED",
    "Workflow State": "RESOLVED",
    "Compliance Control": "NIST CSF ID.AM-2"
  }
]
```

6. The JSON file is [GZIP'ed](https://www.gzip.org/) and uploaded to Amazon S3 along with an uncompressed [JSON Manifest file](https://docs.aws.amazon.com/quicksight/latest/user/supported-manifest-file-format.html) used by QuickSight to create [Data Sources from S3-hosted data](https://docs.aws.amazon.com/quicksight/latest/user/working-with-data-sources.html).

7. A QuickSight Data Source is created from the JSON Manifest which references the GZIP'ed JSON file we created in Step 5.

8. A QuickSight Data Set is [prepared](https://docs.aws.amazon.com/quicksight/latest/user/preparing-data.html) from the Data Source in Step 7. This Data Set will perform transformations of the raw JSON file, load it into QuickSight's [SPICE Engine](https://docs.aws.amazon.com/quicksight/latest/user/how-quicksight-works.html), and be used for the creation of an [Analysis](https://docs.aws.amazon.com/quicksight/latest/user/working-with-analyses.html).

9. (Manual Step) an Analysis is created from the Data Set from Step 8 that will contain [Visualizations](https://docs.aws.amazon.com/quicksight/latest/user/working-with-visuals.html) and [Insights](https://docs.aws.amazon.com/quicksight/latest/user/making-data-driven-decisions-with-ml-in-quicksight.html). These can be saved into a [Dashboard](https://docs.aws.amazon.com/quicksight/latest/user/working-with-dashboards.html) which can be shared, [emailed](https://docs.aws.amazon.com/quicksight/latest/user/sending-reports.html), [printed](https://docs.aws.amazon.com/quicksight/latest/user/printing1.html), or [embedded](https://docs.aws.amazon.com/quicksight/latest/user/embedded-analytics-dashboards-for-everyone.html) into downstream enterprise applications.

**Important Note:** While not shown this solution will also create a Group comprised of every user within your QuickSight Subscription in the [Default Namespace](https://docs.aws.amazon.com/quicksight/latest/user/namespaces.html) which will have full permissions to the Data Sources and Data Sets.

## Setting Up

### Running via Automation (AWS CodeBuild)

This section details the steps to setup ElectricEye-Reports via Automation. This will use a CloudFormation template and does not currently support Terraform.

1. Clone this repo and upload the ZIP Archive containing the code for CodeBuild to an Amazon S3 Bucket.

```bash
git clone https://github.com/jonrau1/ElectricEye.git
cd ElectricEye/add-ons/electriceye-reports/automation
aws s3 cp codecommit-archive.zip s3://$YOUR_BUCKET_HERE/codecommit-archive.zip
```

2. Create and Deploy a CloudFormation Stack (**ElectricEyeReports_CloudFormation.yaml**) from the `ElectricEye/add-ons/electriceye-reports/automation` directory.

3. EventBridge may not start your CodeBuild Project right away, to force the execution use the following AWS CLI command.

```bash
aws codebuild start-build \
    --project-name ElectricEyeReports
```

4. To ensure the Data Set created succesfully navigate to your QuickSight console and look for the `ElectricEyeComplianceFindingsDataset` Data Set, if you see it, you're good to go!

![ElectricEye Dataset in the Menu](./screenshots/ElectricEyeDatasetMenu.JPG)

### Running locally

TODO

## Creating Visualizations

This section will provide a brief walkthrough of creating a new Analysis with some Visualizations you can use to get started.

1. Select the ElectricEye Data Set and within the QuickSight Console and choose **Create analysis** as shown below.

![Create QS Analysis](./screenshots/createAnalysis.JPG)

2. Within the Analysis Console you can choose your **Visuals** from the bottom left-hand side in the UI. Select the Pie Chart tooltip from the `Visual types`, you can hover your cursor over the icons to get the name as shown below.

![Create Piechart](./screenshots/createPieChart.JPG)

3. At the top center-left of the UI you should see `Field wells`, these are where you select the **Dimensions** for your Visuals. Select a value to `Group/Color` such as *Compliance Status* by dragging the values from `Fields list` on the left-hand side and into the `Field well` as shown below.

![GroupBy Field Well](./screenshots/groupByFieldWell.JPG)

4. Due to how the compliance controls were parsed from the ASFF, the number of findings is artificially inflated. To deduplicate values we will add a **Value** into the field well based on the unique counts of Finding IDs which are always unique. Drag the *Finding ID* field into the `Field well` for **Value** and then select the dropdown menu to change **Aggregate** to **Count Distinct** as shown below.

![Finding ID Unique](./screenshots/fieldIdUniqueCount.JPG)

5. To reformat the Visual you can use the **Configure visual** option from the hover-over menu on the right-hand side of a Visual (represented by a gear icon) as shown below, select this and advanced to the next step.

![Visual Configure Menu](./screenshots/visualConfigureMenu.JPG)

6. Most of the Visual Configuration options are self-explantory, such as font sizes. The more useful configurations typically live in the `Data labels` section which allow you to modify elements in your visual such as the metric presenation. Select the `Show metric` checkbox and ensure the `Metric label style` is set to **Value and percent** to show the Total Count and Percentage of findings by *Compliance Status* as shown below.

![Pie Chart Data Labels](./screenshots/pieChartLabelMetrics.JPG)

7. If at any time you wanted to change how the Visual looks you can select a new one for `Visual types`, such as a Donut Chart which has the option to show the total of the **Value** `Field well` by aggregate. As shown below, in this case, the donut chart shows the total amount of unique findings by Finding ID you extracted from Security Hub.

![Pie Chart to Donut Chart](./screenshots/fromPiesToDonuts.JPG)

**Note:** Not every visual type can fully transfer all style changes over and may require additional modification of the `Field wells`.

8. To quickly create similar Visuals you can use the **Duplicate visual** option from the **Menu Options** from the hover-over menu on the right-hand side of a Visual (represented by an ellipsis) as shown below. This can be useful for creating multiple group-by visualizations for an at-a-glance view of various dimensions for ElectricEye findings, such as Region breakdown or Severity.

![Duplicate Visual](./screenshots/duplicateVisual.JPG)

9. To create a new Visual choose the **Add** option at the top-left of the UI and select `Add visual` as shown below. Once the new visual is added you can select the `Visual type` and modify the `Fields wells` as demonstrated in Steps 2 - 6.

![Add New Visual](./screenshots/addNewVisual.JPG)

10. We will now demonstrate how to use dyanmic filters to show only information we want - in our case we want to show *only* NIST CSF compliance controls and their status. To start select the **Vertical stacked bar chart** and expand the size by dragging the bottom-right of the Visual border as shown below.

![Expand Stacked Bars](./screenshots/extendoStackedBars.JPG)

11. To create the visual shown in the screenshot below configure the following `Field well` and `Field list` pairs.
    - **X Axis**: *Compliance Control*
    - **Value**: *Finding ID* - Aggregate this by *Count distinct* as shown in Step 4
    - **Group/Color**: *Compliance Status*

![Compliance Control Status Chart Fields](./screenshots/complianceControlStatusStacked.JPG)

12. Now that we have the raw view correct, let's modify the formatting by using a Filter. On the left-hand side of the UI select the **Filters** menu and create a new filter by selecting the "plus" icon at the top-left of the UI and select *Compliance Control* as shown below. 

![Filter Menu](./screenshots/addNewFilterMenu.JPG)

13. Select the new Filter and change the `Filter type` to a **Custom filter** with a **Starts with** operator and enter *NIST CSF* into the filter box and select Apply as shown below.

![NIST CSF Dynamic Filter](./screenshots/nistCsfStartsWithFilter.JPG)

At this point you can choose to configure the visualization as shwon in Steps 5 and 6, it is reccomended to change the Chart Titles and show Metrics. You can also choose to sort the fields by using the tooltips within each Axis of a bar chart style visual as well as click-and-drag various elements of the Visual to resize them. Some of the examples of that are shown in the screenshot below.

![NIST CSF Stacked Final](./screenshots/nistCsfFinalVis.JPG)

There are much more modifications and configurations that can be done with Visuals, you can also add additional Sheets, create tabular views, and add ML-Backed insights to identify key trends and data source anomalies. In the future, you can consider adding Timestamps (they must be reformatted from the Security Hub IS08601 to a different kind of timestamp for QuickSight) if you wanted to capture anomaly-based trends overtime or measure time-series movement of compliance controls using the Key Performance Indicator (KPI) Visual type. For more information you should also consider looking at various AWS QuickSight Blogs.

## FAQ

#### 1. What information is extracted from the ElectricEye findings?

Only certain elements are parsed from the [AWS Security Finding Format](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html) (ASFF), this is primarily due to the fact that the Resource-level information greatly varies by Finding and would not be feasible to collect efficiently. Secondarily, only certain information makes sense to gather for the purpose of a BI report such as the finding's title, the related compliance controls, severity, status, and ownership (Account and Region) of the finding. The full data schema is included under Step 5 within the Solution Architecture Section.

#### 2. How are the related compliance controls extracted from the findings in a way that can be individually reported on?

The object shape for the related compliance controls is a nested array of strings underneath the [`Compliance`](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-attributes.html#asff-compliance) object within the ASFF. Due to the inability for QuickSight to deconstruct a List / Array, it will be iterated through using a Python `for` loop and written to its own individual object within the overall JSON schema. This will artificially inflate the total amount of findings that are written to a JSON file for the [Finding ID](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-attributes.html#asff-top-level-attributes) is recorded to provide a unique counter for the breakout of compliance controls within QuickSight. For more information on how I mapped the compliance controls see the [top-level README starting at FAQ#17](https://github.com/jonrau1/ElectricEye#17-at-a-high-level-how-did-you-map-the-electriceye-auditors-into-these-compliance-frameworks).

#### 3. How long does it take the parse the ElectricEye findings and their compliance controls?

It varies and is directly dependent on the amount of resources in-scope for ElectricEye checks, how many Regions ElectricEye is ran in, and how many Accounts are onboarded to your AWS Security Hub Master. For a single account with several hundred findings per Region this can take 2 -3 minutes, for a large organization with at least 100 accounts and 1000s of findings per Region this can possibly take in excess of an hour. As a quick benchmark, it takes 15 seconds to parse 1300 findings into 15.7K individual control-level findings for a single account with findings in 3 Regions.

#### 4. Can I change the scope of information parsed from the ASFF?

Yes. However, the data preparation of the QuickSight Data Set is directly dependent on the JSON schema for this Add-on remaining the same. If you change the format or shape of the JSON schema you will likely break the Data Set and will need to add any additional transformations or data column mappings.

#### 5. What sort of data preparation for the QuickSight Data Set is done in this Add-on?

Transformation all the data points in Strings and ensuring that the JSON Keys are properly mapped into Column Names. If you were to create a Data Set direclty from the Data Source the column names are mapped correctly but some data types are not mapped to Strings, for instance the Account ID is transformed into an Integer and the Workflow State and AWs Region are mapped into Geolocation Types (due to their name).

#### 6. Why can you not create an Analysis?

The creation of an Analysis in the API is dependent on a Template being created from an existing Analysis in your own QuickSight Subscription. Unlike something like a CloudWatch Dashboard which has a consumable JSON schema, that is not possible to create nor share across Accounts.

#### 7. Will this solution ever include example embedding?

Yes, eventually. The QuickSight Embedded Analytics SDK is only available in JavaScript, which I am not proficient in, so I will need to explore how to use this and create a way to host the Dashboard.

#### 8. I have other datasets I want to merge with this one, how can I do that in QuickSight?

QuickSight has a native workflow tool within the Data Set Editing view that allows you to perform SQL-Like JOINS across datasets. If you had a dataset that mapped your AWS Accounts into business lines for instance, you can perform an INNER or LEFT Join form the Data Set created in this Add-on with that one. This new Data Set can be saved as its own Data Set and not affect the downstream solution for this Add-on.

#### 9. Why use QuickSight? Why not another BI / Visualization tool such as Kibana or PowerBI?

QuickSight offers direct APIs to prepapre and transform the data, is more cost effective than hosting your own Elasticsearch/Kibana server, way more cost effective than using Amazon Elasticsearch Service, and PowerBI is a silly Microsoft tool.

#### 10. Why is the Default Namespace used for the creation of the QuickSight Group?

The default namespace supports password-based logins for members of the QuickSight Subscription that do not have AWS Accounts (they also support AD Creds). Custom namespaces can only be accessed using Identity Federation/SSO - that makes sense for a multi-tenant SaaS App but not for a central security team accessing the visualizations.

## License
This library is licensed under the GNU General Public License v3.0 (GPL-3.0) License. See the LICENSE file.