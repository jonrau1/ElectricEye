#This file is part of ElectricEye.
#SPDX-License-Identifier: Apache-2.0

#Licensed to the Apache Software Foundation (ASF) under one
#or more contributor license agreements.  See the NOTICE file
#distributed with this work for additional information
#regarding copyright ownership.  The ASF licenses this file
#to you under the Apache License, Version 2.0 (the
#"License"); you may not use this file except in compliance
#with the License.  You may obtain a copy of the License at

#http://www.apache.org/licenses/LICENSE-2.0

#Unless required by applicable law or agreed to in writing,
#software distributed under the License is distributed on an
#"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#KIND, either express or implied.  See the License for the
#specific language governing permissions and limitations
#under the License.

from processor.outputs.output_base import ElectricEyeOutput
import json
import pandas as pd
import matplotlib.pyplot as plt
from os import path
from datetime import datetime

here = path.abspath(path.dirname(__file__))

@ElectricEyeOutput
class JsonProvider(object):
    __provider__ = "html_compliance"

    def write_findings(self, findings: list, output_file: str, **kwargs):
        if len(findings) == 0:
            print("There are not any findings to write to file!")
            exit(0)

        # Process the findings
        processedFindings = self.process_findings(findings)
        # Delete the un-processed findings
        del findings

        uniqueControls = self.get_unique_controls(processedFindings)
        # Gather and sort the control data enriched with aggregated asset information
        assetInfoAggregation = self.get_asset_information_per_control(processedFindings)
        assetDataPerControl = []
        for control, details in assetInfoAggregation.items():
            controlAssetPayload = {"ControlId": control}
            controlAssetPayload.update(details)
            assetDataPerControl.append(controlAssetPayload)

        # Do one more pass on the aggregated information and add a passing % per control
        assetDataPerControlWithPercentage = []
        for controlData in assetDataPerControl:
            passingPercentage = (controlData["PassingControls"] / controlData["ResourcesImpacted"]) * 100
            roundedPercentage = f"{round(passingPercentage, 2)}%"
            controlData["RawPassingScore"] = passingPercentage
            controlData["PassingPercentage"] = roundedPercentage
            assetDataPerControlWithPercentage.append(controlData)

        del assetDataPerControl
        # Get the aggregated pass/fail info per control
        controlsAggregation = self.generate_controls_aggregation(uniqueControls, processedFindings)

        self.html_creation(processedFindings, controlsAggregation, assetDataPerControlWithPercentage, output_file)

        print("Created HTML Compliance report!")

    def process_findings(self, findings):
        """
        Returns a processed list of findings
        """

        processedFindings = []

        for finding in findings:
            processedFindings.append(
                {
                    "AssetId": finding["Resources"][0]["Id"],
                    "ProviderAccountId": finding["ProductFields"]["ProviderAccountId"],
                    "Provider": finding["ProductFields"]["Provider"],
                    "AssetRegion": finding["ProductFields"]["AssetRegion"],
                    "AssetClass": finding["ProductFields"]["AssetClass"],
                    "AssetService": finding["ProductFields"]["AssetService"],
                    "AssetComponent": finding["ProductFields"]["AssetComponent"],
                    "ComplianceStatus": finding["Compliance"]["Status"],
                    "ComplianceRelatedRequirements": finding["Compliance"]["RelatedRequirements"],
                }
            )

        print(f"Processed {len(processedFindings)} findings")

        return processedFindings

    def get_unique_controls(self, processedFindings):
        """
        This function returns a list of unique controls across all processed findings
        """

        uniqueControls = []

        for findings in processedFindings:
            for controls in findings["ComplianceRelatedRequirements"]:
                if controls == "NIST SP 800-53 Rev. 4 AC-1NIST SP 800-53 Rev. 4 AC-3NIST SP 800-53 Rev. 4 AC-17NIST SP 800-53 Rev. 4 AC-22ISO 27001:2013 A.13.1.2":
                    continue
                if controls not in uniqueControls:
                    uniqueControls.append(controls)
                else:
                    continue

        print(f"{len(uniqueControls)} unique controls processed")

        return uniqueControls

    def get_asset_information_per_control(self, processedFindings):
        """
        This function returns a DataFrame of controls with the sum of each Account, Asset, and Region in scope for a control
        """

        controlDict = {}

        for asset in processedFindings:
            for control in asset["ComplianceRelatedRequirements"]:
                if control == "NIST SP 800-53 Rev. 4 AC-1NIST SP 800-53 Rev. 4 AC-3NIST SP 800-53 Rev. 4 AC-17NIST SP 800-53 Rev. 4 AC-22ISO 27001:2013 A.13.1.2":
                    continue

                if control not in controlDict:
                    controlDict[control] = {
                        "UniqueAssetClass": set(),
                        "UniqueAssetComponent": set(), 
                        "UniqueAssetService": set(),
                        "ResourcesImpacted": set(),
                        "PassingControls": set(),
                        "FailingControls": set(),
                    }
                controlDict[control]["UniqueAssetClass"].add(asset["AssetClass"])
                controlDict[control]["UniqueAssetComponent"].add(asset["AssetComponent"])
                controlDict[control]["UniqueAssetService"].add(asset["AssetService"])
                controlDict[control]["ResourcesImpacted"].add(asset["AssetId"])
                if asset["ComplianceStatus"] == "PASSED":
                    controlDict[control]["PassingControls"].add(asset["AssetId"])
                else:
                    controlDict[control]["FailingControls"].add(asset["AssetId"])

        # Now transform the sets into counts
        for control, details in controlDict.items():
            for key, unique_set in details.items():
                controlDict[control][key] = len(unique_set)

        print("Completed aggregation of Asset details per Control for all frameworks.")
            
        return controlDict

    def generate_controls_aggregation(self, uniqueControls, processedFindings):
        """
        This function returns a complex dictionary that records the statistics of all audit readiness frameworks by passing and failing checks
        """

        # Aggregate by control framework
        controlsStatusAggregation = {
            "NIST CSF V1.1": {},
            "NIST SP 800-53 Rev. 4": {},
            "AICPA TSC": {},
            "ISO 27001:2013": {}
        }
        # Populate the data structure of pass/fail by individual controls
        for controlTitle in uniqueControls:
            if controlTitle.startswith("NIST CSF V1.1"):
                controlsStatusAggregation["NIST CSF V1.1"][controlTitle] = {"Passed": 0, "Failed": 0}
            elif controlTitle.startswith("NIST SP 800-53 Rev. 4"):
                controlsStatusAggregation["NIST SP 800-53 Rev. 4"][controlTitle] = {"Passed": 0, "Failed": 0}
            elif controlTitle.startswith("AICPA TSC"):
                controlsStatusAggregation["AICPA TSC"][controlTitle] = {"Passed": 0, "Failed": 0}
            elif controlTitle.startswith("ISO 27001:2013"):
                controlsStatusAggregation["ISO 27001:2013"][controlTitle] = {"Passed": 0, "Failed": 0}

        del uniqueControls

        # Now start to count up the pass & fails
        for finding in processedFindings:
            status = finding["ComplianceStatus"]
            for controls in finding["ComplianceRelatedRequirements"]:
                if controls == "NIST SP 800-53 Rev. 4 AC-1NIST SP 800-53 Rev. 4 AC-3NIST SP 800-53 Rev. 4 AC-17NIST SP 800-53 Rev. 4 AC-22ISO 27001:2013 A.13.1.2":
                    continue

                if controls.startswith("NIST CSF V1.1"):
                    if status == "PASSED":
                        controlsStatusAggregation["NIST CSF V1.1"][controls]["Passed"] += 1
                    else:
                        controlsStatusAggregation["NIST CSF V1.1"][controls]["Failed"] += 1
                elif controls.startswith("NIST SP 800-53 Rev. 4"):
                    if status == "PASSED":
                        controlsStatusAggregation["NIST SP 800-53 Rev. 4"][controls]["Passed"] += 1
                    else:
                        controlsStatusAggregation["NIST SP 800-53 Rev. 4"][controls]["Failed"] += 1
                elif controls.startswith("AICPA TSC"):
                    if status == "PASSED":
                        controlsStatusAggregation["AICPA TSC"][controls]["Passed"] += 1
                    else:
                        controlsStatusAggregation["AICPA TSC"][controls]["Failed"] += 1
                elif controls.startswith("ISO 27001:2013"):
                    if status == "PASSED":
                        controlsStatusAggregation["ISO 27001:2013"][controls]["Passed"] += 1
                    else:
                        controlsStatusAggregation["ISO 27001:2013"][controls]["Failed"] += 1

        print("Finished aggregating Pass/Fail stats for all controls.")

        return controlsStatusAggregation

    def generate_control_table(self, framework, controls, aggregatedAssetControlsData):
        """
        This function returns a JSON object that contains the Control ID and information about the control from the framework/standard author
        joined with the information from "get_asset_information_per_control" which is used for the HTML table in the report
        """

        tableContent = []

        print(f"Generating a table of controls objectives and aggregated asset information for {len(controls)} controls in {framework}")
        
        with open(f"{here}/control_objectives.json") as jsonfile:
            data = json.load(jsonfile)

        for controlInfo in data:
            if controlInfo["ControlTitle"].startswith(framework):
                contentRow = {
                    "ControlTitle": controlInfo["ControlTitle"],
                    "ControlDescription": controlInfo["ControlDescription"]
                }
                tableContent.append(contentRow)

        if tableContent:
            tableDf = pd.DataFrame(tableContent)
            aggAssetControlsDf = pd.DataFrame(aggregatedAssetControlsData)

            tableContentDf = tableDf.merge(
                how="left",
                right=aggAssetControlsDf,
                left_on="ControlTitle",
                right_on="ControlId"
            )

            del tableContentDf["ControlId"]

            tableContent = json.loads(tableContentDf.to_json(index=False,orient="table"))

            del tableContentDf

            print(f"Finished generating the table for {framework}")

            return tableContent["data"]
        else:
            return []

    def generate_executive_summary(self, processedFindings):
        """
        Returns a paragraph for the summary header section of the report
        """

        countUniqueControls = len(self.get_unique_controls(processedFindings))
        countFindings = len(processedFindings)

        providerAssesed = processedFindings[0]["Provider"]

        # Compliance Passed v Failed
        totalPassed = [finding for finding in processedFindings if finding["ComplianceStatus"] == "PASSED"]

        passingPercentage = (len(totalPassed) / countFindings) * 100
        roundedPercentage = f"{round(passingPercentage, 2)}%"

        regionsAssessed = []
        accountsAssessed = []
        assetClassesAssesed = []
        assetServicesAssessed = []
        assetComponentsAssessed = []
        uniqueResourcesIds = []

        # Append uniques into lists
        for finding in processedFindings:
            if finding["AssetRegion"] not in regionsAssessed:
                regionsAssessed.append(finding["AssetRegion"])

            if finding["ProviderAccountId"] not in accountsAssessed:
                accountsAssessed.append(finding["ProviderAccountId"])

            if finding["AssetClass"] not in assetClassesAssesed:
                assetClassesAssesed.append(finding["AssetClass"])

            if finding["AssetService"] not in assetServicesAssessed:
                assetServicesAssessed.append(finding["AssetService"])

            if finding["AssetComponent"] not in assetComponentsAssessed:
                assetComponentsAssessed.append(finding["AssetComponent"])

            if finding["AssetId"] not in uniqueResourcesIds:
                uniqueResourcesIds.append(finding["AssetId"])

        # Use len to get counts
        countRegionsAssessed = len(regionsAssessed)
        countAccountsAssessed = len(accountsAssessed)
        countAssetClassesAssesed = len(assetClassesAssesed)
        countAssetServicesAssessed = len(assetServicesAssessed)
        countAssetComponentsAssessed = len(assetComponentsAssessed)
        countUniqueResourceIds = len(uniqueResourcesIds)

        # Use join to create sentences of certain lists
        regionSentence = ", ".join(regionsAssessed)
        accountSentence = ", ".join(accountsAssessed)
        assetClassSentence = ", ".join(assetClassesAssesed)
        assetServiceSentence = ", ".join(assetServicesAssessed)
        assetComponentSentence = ", ".join(assetComponentsAssessed)

        summary = f"""
            ElectricEye is a multi-cloud, multi-SaaS Python CLI tool for Asset Management, Security Posture Management & Attack Surface Monitoring supporting 100s of services and evaluations to harden your public cloud & SaaS environments with controls mapped to NIST CSF, 800-53, ISO 27001, AICPA TSC (SOC2), and more! Each Check within ElectricEye evaluates a specific component for a specific service for a specific Cloud Service Provider or SasS Vendor such as Amazon EC2 Instance, Oracle Cloud Autonomous Date Warehouses, Google Cloud SQL instances, M365 Conditional Access Policies, ServiceNow Secure Access Configurations, and more. For each of those checks, several controls mapping to NIST CSF are provided which are in turn mapped to other major frameworks which can aid in audit readiness or other internal audit or controls management exercises. This report is not an attestation, certificate, or fancy plaque you paid for that says "SOC2" on it.</br>


            </br>During the evaluation for {providerAssesed}, ElectricEye generated {countFindings} findings with a passing rate for every single finding is {roundedPercentage} for {countUniqueResourceIds} unique Assets across {countAccountsAssessed} Cloud/SaaS Accounts ({accountSentence}) in {countRegionsAssessed} cloud Regions/Zones/Datacenter locations ({regionSentence}).</br>
            
            </br>Across all of these findings generated by ElectricEye, {countUniqueControls} controls were assessed across all frameworks which covered {countAssetClassesAssesed} distinct Asset Classes comprising of {countAssetServicesAssessed} distinct Asset Services which in turn are comprising of {countAssetComponentsAssessed} Asset Components</br>

            </br> Asset Classes: </br>
            <ul>{assetClassSentence}</ul>
            </br> Asset Services: </br>
            <ul>{assetServiceSentence}</ul>
            </br> Asset Components: </br>
            <ul>{assetComponentSentence}</ul>

            </br>This report provides a per-Control breakdown for each Framework that ElectricEye supports, showing you both how many Findings were passed or failed as well as the total passing score per Framework. Below each set of graphics, a table is provided which includes the specific Control identifiers that were checked for the current evaluation, the control description or control objectives (provided by the owners/authors of the standard or framework itself), as well as aggregated Asset information which includes how many unique Classes, Services, and Components were covered per Control as well as the overall Findings per Control.</br>

            </br>This report can be used as a point-in-time snapshot for control sampling or as a guideline before the start of an engagement for audit readiness, cloud hygeine, or other internal audit or GRC related projects. For better and more controlled sampling and time-series analysis, it is recommended to use another output such as JSON or CSV and storing those data snapshots within a data lake or data warehouse for better aggregation and querying.</br>
        """

        print("Generating Summary report.")

        return summary

    def create_visuals(self, controlsAggregation, assetDataPerControl):
        # Loop through every high level framework aggregation to generate findings
        for framework in controlsAggregation:
            print(f"Creating a visualization for the {framework} framework!")
            # remove shit we don't need so the filename doesn't get dicked up
            frameworkSavefile = str(framework).replace(".","").replace(" ", "").lower()
            # access the dict with the specific aggregations
            controlsData = controlsAggregation[framework]

            # Loop the newly assembled list, only taking the controls for a specific framework at a time and use the info
            # to assemble into a dataframe to combine with another dataframe based on controls information
            if framework == "NIST CSF V1.1":
                aggregatedAssetControlsData = [info for info in assetDataPerControl if info["ControlId"].startswith("NIST CSF V1.1")]
            elif framework == "NIST SP 800-53 Rev. 4":
                aggregatedAssetControlsData = [info for info in assetDataPerControl if info["ControlId"].startswith("NIST SP 800-53 Rev. 4")]
            elif framework == "AICPA TSC":
                aggregatedAssetControlsData = [info for info in assetDataPerControl if info["ControlId"].startswith("AICPA TSC")]
            elif framework == "ISO 27001:2013":
                aggregatedAssetControlsData = [info for info in assetDataPerControl if info["ControlId"].startswith("ISO 27001:2013")]
            else:
                aggregatedAssetControlsData = []

            # Parse out the specific unique controls (again) to get the right information on the controls for the HTML table
            controls = [control for control in controlsData]
            tableContent = self.generate_control_table(framework, controls, aggregatedAssetControlsData)
            # Sort the table to match the descending values of the matplot lib charts
            tableContent = sorted(tableContent, key=lambda x: x["ResourcesImpacted"], reverse=False)

            # Reverse order sorting of the controls, that will put the controls with the most failures closer to the X-Axis
            controlsData = dict(sorted(controlsData.items(), key=lambda item: item[1]["Passed"] + item[1]["Failed"], reverse=True))

            # create a figure with two subplots: one for the bar chart and one for the donut chart
            fig, axs = plt.subplots(nrows=2, figsize=(38, 22), tight_layout=True)
            """# Set the text size within the elements
            plt.rcParams['font.size'] = 16  # Change the default font size
            plt.rcParams['axes.labelsize'] = 14  # Increase the size of axis labels
            plt.rcParams['axes.titlesize'] = 16  # Increase the size of the figure title
            plt.rcParams['xtick.labelsize'] = 16  # Increase the size of x-tick labels
            plt.rcParams['ytick.labelsize'] = 16  # Increase the size of y-tick labels"""

            # sum of all passed and failed to calculate percentages later
            controlsPassedSum = controlsFailedSum = 0

            # iterate over the dictionary to plot each bar chart
            for i, (key, value) in enumerate(controlsData.items()):
                passed = value["Passed"]
                failed = value["Failed"]

                controlsPassedSum += passed
                controlsFailedSum += failed
                # Create horizontal bar chart, add a label to the X-Axis, and finally add values for the bars
                #Set a title, axs[0].set_title(f"ElectricEye {frameworkTitle} Audit Readiness Report - {timeNow}", fontsize=14, fontweight="bold")
                axs[0].barh(key, passed, color="#6aaf35")
                axs[0].barh(key, failed, left=passed, color="#fe6e73")
                axs[0].set_xlabel("Total Checks In Scope", fontsize=16)
                axs[0].text(passed, i, str(passed), color="black", va="center")  # label for "Passed"
                axs[0].text(passed + failed, i, str(failed), color="red", va="center")  # label for "Failed"

            # create a legend for the bar chart
            passed_patch = plt.Rectangle((0,0),1,1,fc="#6aaf35", edgecolor = "none")
            failed_patch = plt.Rectangle((0,0),1,1,fc="#fe6e73",  edgecolor = "none")
            axs[0].legend([passed_patch, failed_patch], ["Passed", "Failed"], loc="upper right")

            # create a donut chart with the overall passing and failing percentages
            sizes = [controlsPassedSum, controlsFailedSum]
            colors = ["#6aaf35", "#fe6e73"]

            axs[1].pie(sizes, labels=["Passed", "Failed"], colors=colors, autopct="%1.1f%%", startangle=90)
            # this creates the hole in the middle, effectively making the pie chart a donut chart
            axs[1].add_artist(plt.Circle((0,0),0.70,fc="white"))  

            # Set the facecolor of the figure and the plots to a very light gray
            plt.rcParams["savefig.facecolor"]="f9f9f9"
            plt.rcParams["axes.facecolor"]="f9f9f9"

            # Save the charts as a SVG and then read out the contents to pass to HTML
            fig.savefig(f"{here}/{frameworkSavefile}.svg", format="svg")
            with open(f"{here}/{frameworkSavefile}.svg", "r") as f:
                svgImageContents = f.read()

            yield tableContent, svgImageContents, framework

    def generate_stylesheet(self):
        """
        This function generates a stylesheet for the compliance report
        """
        stylesheet = '''
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: Arial,sans-serif;
            font-size: 16px;
        }

        body {
            display: flex;
            background-attachment: fixed;
            background-size: 100%;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }

        .summary__header {
            box-shadow: 0 .4rem .8rem #0005;
            margin-top: 20px;
            border-radius: .5rem;
            width: auto;
            height: auto;
            max-width: 97%;
            background-color: #ecebed;
            padding: .8rem 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .summary__header__image {
            max-width: 120px;
            max-height: 120px;
            align-items: center;
        }

        figure {
            margin-left: 0.5%;
            margin-right: 1%;
        }

        figcaption {
            font-size: 18px;
            font-weight: bold;
            justify-content: center;
            text-align: center;
        }

        table {
            width: 100%;
        }

        table, th, td {
            border-collapse: collapse;
            padding: 1rem;
            text-align: left;
        }

        thead th {
            position: sticky;
            top: 0;
            left: 0;
            cursor: pointer;
            text-transform: capitalize;
            font-weight: bold;
            text-align: left;
            background-color: #7ec0e0;
        }

        thead tr {
            border-bottom: 2px solid #dddddd;
        }

        tbody tr:nth-child(even) {
            background-color: #0000000b;
        }

        svg {
            width: auto;
            height: auto;
            max-width: 100%;
            overflow: hidden;
        }

        .chart__image {
            border-radius: .2rem;
            margin-top: 25px;
            margin-bottom: 25px;
        }

        .table__body {
            width: 98%;
            max-height: 98%;
            background-color: #fffb;
            margin: .8rem auto;
            border-radius: .6rem;
            box-shadow: 0 .4rem .8rem #0005;
            overflow: auto;
            overflow: overlay;
        }

        .table__body::-webkit-scrollbar{
            width: 0.5rem;
            height: 0.5rem;
        }

        .table__body::-webkit-scrollbar-thumb{
            border-radius: .5rem;
            background-color: #0004;
            visibility: hidden;
        }

        .table__body:hover::-webkit-scrollbar-thumb{ 
            visibility: visible;
        }

        .framework__header {
            margin-top: 20px;
            margin-bottom: 20px;
            border-radius: .5rem;
            padding: .8rem 1rem;
            
            width: auto;
            height: auto;
            max-height: 90%;
            max-width: 97%;

            display: flex;
            justify-content: space-between;
            align-items: center;

            background-color: #ecebed;
            box-shadow: 0 .4rem .8rem #0005;
        }

        .framework__header__image {
            align-items: center;
        }

        p {
            font-weight: bold;
        }

        .score {
            padding: .4rem 0;
            border-radius: 2.5rem;
            text-align: center;
            max-width: 95%;
        }

        .score.reallybad {
            background-color: rgb(214, 63, 56);
            color: #ffc400;
        }

        .score.bad {
            background-color: rgb(254, 110, 115);
            color: #fff;
        }

        .score.meh {
            background-color: rgb(248, 146, 86);
        }

        .score.good {
            background-color: #d1db00;
        }

        .score.great {
            background-color: #6aaf35;
            color: white;
        }

        footer {
            height: 1.5rem; /* Footer height */
            text-align: center;
            color: black;
        }
        '''

        return stylesheet

    def framework_section_information_generator(self, framework):
        """
        This function returns an <img> / <svg> tag along with some background information about frameworks to use as a spacer between the charts and tables
        """
        # NIST CSF V1.1
        if framework == "NIST CSF V1.1":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/nist_csf_v11.jpg" class="framework__header__image">'
            frameworkInfo = "The NIST Cybersecurity Framework is voluntary guidance, based on existing standards, guidelines, and practices to help organizations better manage and reduce cybersecurity risk. It fosters cybersecurity risk  management and related communications among both internal and external stakeholders, and for larger organizations, helps to better integrate and align cybersecurity risk management with broader enterprise risk management processes as described in the NISTIR 8286 series.The Framework is organized by five key Functions: Identify, Protect, Detect, Respond, Recover. These five widely understood terms, when considered together, provide a comprehensive view of the lifecycle for managing cybersecurity over time."
        
        # 800-53 R4
        elif framework == "NIST SP 800-53 Rev. 4":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/nist_80053_rev4.jpg" class="framework__header__image">'
            frameworkInfo = "This publication provides a catalog of security and privacy controls for federal information systems and organizations and a process for selecting controls to protect organizational operations (including mission, functions, image, and reputation), organizational assets, individuals, other organizations, and the Nation from a diverse set of threats including hostile cyber attacks, natural disasters, structural failures, and human errors (both intentional and unintentional). The security and privacy controls are customizable and implemented as part of an organization-wide process that manages information security and privacy risk. The controls address a diverse set of security and privacy requirements across the federal government and critical infrastructure, derived from legislation, Executive Orders, policies, directives, regulations, standards, and/or mission/business needs. The publication also describes how to develop specialized sets of controls, or overlays, tailored for specific types of missions/business functions, technologies, or environments of operation. Finally, the catalog of security controls addresses security from both a functionality perspective (the strength of security functions and mechanisms provided) and an assurance perspective (the measures of confidence in the implemented security capability). Addressing both security functionality and assurance helps to ensure that information technology component products and the information systems built from those products using sound system and security engineering principles are sufficiently trustworthy."
        
        # AICPA TSC/SOC
        elif framework == "AICPA TSC":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/aicpa_soc.jpg" class="framework__header__image">'
            frameworkInfo = f"""
                The 2017 Trust Services Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy presents control criteria established by the Assurance Services Executive Committee (ASEC) of the AICPA for use in attestation or consulting engagements to evaluate and report on controls over the security, availability, processing integrity, confidentiality, or privacy of information and systems (a) across an entire entity; (b) at a subsidiary, division, or operating unit level; (c) within a function relevant to the entity's operational, reporting, or compliance objectives; or (d) for a particular type of information used by the entity. The trust services criteria were designed to provide flexibility in application and use for a variety of different subject matters. The following are the types of subject matters a practitioner may be engaged to report on using the trust services criteria:</br>
                
                </br>The effectiveness of controls within an entity's cybersecurity risk management program to achieve the entity's cybersecurity objectives using the trust services criteria relevant to security, availability, and confidentiality as control criteria in a SOC for Cybersecurity examination.</br>

                </br>The suitability of design and operating effectiveness of controls included in management's description of a service organization's system relevant to one or more of the trust services criteria over security, availability, processing integrity, confidentiality, or privacy throughout a specified period to achieve the entity's objectives based on those criteria in a type 2 SOC 2 engagement. A type 2 SOC 2 engagement, which includes an opinion on the operating effectiveness of controls, also includes a detailed description of tests of controls performed by the service auditor and the results of those tests. A type 1 SOC 2 engagement addresses the same subject matter as a type 2 SOC 2 engagement; however, a type 1 SOC 2 report does not contain an opinion on the operating effectiveness of controls nor a detailed description of tests of controls performed by the service auditor and the results of those tests.</br>

                </br>The design and operating effectiveness of a service organization's controls over a system relevant to one or more of the trust services criteria over security, availability, processing integrity, confidentiality, and privacy in a SOC 3 engagement. A SOC 3 report contains an opinion on the operating effectiveness of controls but does not include a detailed description of tests of controls performed by the service auditor and the results of those tests.</br>
            """
        
        # ISO 27001:2013/2017
        elif framework == "ISO 27001:2013":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/iso_27k1_2013.jpg" class="framework__header__image">'
            frameworkInfo = "ISO 27001 is an international standard that provides a framework for establishing, implementing, maintaining, and continually improving an information security management system (ISMS). The standard defines a set of requirements and controls to help organizations manage and protect their information assets. Annex A of ISO 27001 contains a comprehensive list of controls that organizations can choose to implement based on their specific needs and risk assessment. These controls are categorized into 14 sections, covering various aspects of information security. Organizations use the Annex A controls as a reference to identify the specific measures they need to implement to protect their information assets. These controls are based on best practices and provide a systematic approach to managing information security risks. By implementing these controls, organizations can establish a robust information security management system, reduce the likelihood and impact of security incidents, meet regulatory requirements, and build trust with customers and stakeholders. The ISO 27001 standard and Annex A controls are widely recognized and adopted globally as a means to ensure the confidentiality, integrity, and availability of information assets and to demonstrate a commitment to information security management."
        
        # 800-171 R2
        elif framework == "NIST SP 800-171 Rev. 2":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/nist_800171_rev2.jpg" class="framework__header__image">'
            frameworkInfo = "TODO"
        else:
            return []

        frameworkHeader = f'''
            <section class="framework__header">
                <figure>{imgSource}</figure>
                <h4>{frameworkInfo}</h4>
            </section>
        '''

        return frameworkHeader

    def html_creation(self, processedFindings, controlsAggregation, assetDataPerControl, outputFile):
        """
        This function assembles an HTML Report of matplotlib SVGs and tables
        """

        dateNow = str(datetime.utcnow()).split(".")[0].split(" ")[0]

        # Beginning of the HTML doc with sytlesheet
        htmlPrefix = f'''
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta http-equiv="X-UA-Compatible" content="ie=edge">
            <title>ElectricEye Compliance Status</title>
        </head>
        <style>
            {self.generate_stylesheet()}
        </style>
        <body>
        <section class="summary__header">
            <figure>
                <img src="https://raw.githubusercontent.com/jonrau1/ElectricEye/oracle-cloud-1/screenshots/logo.svg" class="summary__header__image">
                <figcaption>ElectricEye Audit Readiness Report -- {dateNow}</figcaption>
            </figure>
            <h4>{self.generate_executive_summary(processedFindings)}</h4>
        </section>
        '''
        # Retrieve the info table contents and the SVG from matplotlib of the bar chart/pie chart for the compliance framework
        for visual in self.create_visuals(controlsAggregation, assetDataPerControl):
            tableContents = visual[0]
            svgImage = visual[1]
            # Generate the section header for a specified framework
            frameworkHeader = self.framework_section_information_generator(visual[2])

            html = f'''
            {frameworkHeader}
            <div class="chart__image">{svgImage}</div>
            <section class="table__body">
                <div class="compliance__info__table">
                <table>
                    <thead>
                        <tr>
                            <th>Control Title</th>
                            <th>Control Objective</th>
                            <th>Control Passing Score</th>
                            <th>Unique Asset Classes Impacted</th>
                            <th>Unique Asset Services Impacted</th>
                            <th>Unique Asset Components Impacted</th>
                            <th>Total Check Evaluations in Scope</th>
                            <th>Passing Controls</th>
                            <th>Failing Controls</th>
                        </tr>
                    </thead>
                <tbody>
            '''
            # Loop the contents of the table to add the rows
            for content in tableContents:
                # Create a <p> with label depending on the "raw score" - 100.0 is the best and 0.0 is the worst.
                percentage = content["PassingPercentage"]
                rawScore = content["RawPassingScore"]
                if rawScore >= 99.0:
                    passingPercentage = f'<td><p class="score great">{percentage}</p></td>'
                elif 70.0 < rawScore < 99.0:
                    passingPercentage = f'<td><p class="score good">{percentage}</p></td>'
                elif 40.0 < rawScore < 70.0:
                    passingPercentage = f'<td><p class="score meh">{percentage}</p></td>'
                elif 15.0 < rawScore < 40.0:
                    passingPercentage = f'<td><p class="score bad">{percentage}</p></td>'
                else:
                    passingPercentage = f'<td><p class="score reallybad">{percentage}</p></td>'
                # Setup the table rows
                newTd = f'''
                    <tr>
                        <td>{content["ControlTitle"]}</td>
                        <td>{content["ControlDescription"]}</td>
                        {passingPercentage}
                        <td>{content["UniqueAssetClass"]}</td>
                        <td>{content["UniqueAssetService"]}</td>
                        <td>{content["UniqueAssetComponent"]}</td>
                        <td>{content["ResourcesImpacted"]}</td>
                        <td>{content["PassingControls"]}</td>
                        <td>{content["FailingControls"]}</td>
                    </tr>
                '''
                html += newTd
            # Close the Table & Section
            html += """
                    </tbody>
                </table> 
            </section>
            """
            htmlPrefix += html
        # Close the Body and HTML tags
        htmlEnd = '''
        <footer>Created by ElectricEye: https://github.com/jonrau1/ElectricEye</footer>
        </body>
        </html>
        '''

        htmlPrefix += htmlEnd

        with open(f"{here}/{outputFile}_audit_readiness_report.html", "w") as f:
            f.write(htmlPrefix)

        print("Finished creating HTML report for audit readiness")

## EOF